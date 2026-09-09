/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — CNI attachment binding rules (D-68).
 *
 * The decision half of the interface attachment binding table, kept free of
 * vlib and of the table's own data structures so that it is a pure function
 * of four observations:
 *
 *   - the requested (attachment_id, sw_if_index, if_incarnation);
 *   - the binding the table currently holds for that attachment_id, if any;
 *   - the binding the table currently holds for that sw_if_index, if any;
 *   - whether sw_if_index is a live interface and what its current
 *     incarnation is.
 *
 * Everything the table is allowed to do follows from these functions, which
 * is what makes the seven rules of D-68 checkable without a VPP process. The
 * same rules are pinned on the agent side against a fake dataplane
 * (pkg/srv6ec/localep), so a divergence between the two is a test failure
 * rather than a silent difference in behaviour.
 *
 * Design references:
 *   design/detail/00-overview.md §2.12 (D-68 規範文), D-31, D-68
 *   design/detail/02-headend-dataplane.md §2 (table 一覧), §8 (IF-2)
 *   design/detail/04-context-allocator.md §5 (sw_if_index を補完しない)
 */

#ifndef __included_cilium_srv6_ifbind_rules_h__
#define __included_cilium_srv6_ifbind_rules_h__

#include <vppinfra/types.h>
#include <vppinfra/clib.h>

/*
 * Upper bound on the attachment identity this table stores, in bytes.
 *
 * The identity is the CNI attachment ID, i.e. `containerID` optionally
 * followed by ':' and the container-side interface name. CNI itself puts no
 * length bound on a container ID (ValidateContainerID checks the character
 * set only), so the bound here is a property of this table and not of CNI:
 * it is what keeps one API message from turning into an unbounded heap
 * allocation.
 *
 * 255 was chosen so that the realistic identities fit with room to spare —
 * a containerd/CRI-O sandbox ID is 64 hex digits, and the interface name
 * component is at most 15 bytes (CNI's ValidateInterfaceName), i.e. 80 bytes
 * for the shape this plugin actually sees — while the per-binding key stays
 * small enough that the bound is not itself a memory problem. It is a u8's
 * worth of length, which is also why it is easy to state in the API
 * documentation.
 *
 * An identity longer than this is REJECTED, never truncated. Truncation is
 * exactly the failure mode that made the VPP core interface tag (63 usable
 * bytes) unusable as the binding carrier: two attachments of the same Pod
 * differ only in the ':ethN' suffix, so a silent truncation collapses them
 * into one identity and hands one Pod interface the other's endpoint
 * programming.
 */
#define CILIUM_SRV6_ATTACHMENT_ID_MAX 255

/*
 * Outcome of one add or delete request.
 *
 * The ACCEPT_* values are the only ones that may change the table. Every
 * REJECT_* value leaves it exactly as it was: there is no partial application
 * and no implicit replacement anywhere in this file.
 */
typedef enum
{
  CILIUM_SRV6_IFBIND_ACCEPT_INSERT = 0,
  /* The exact same tuple is already bound. Nothing changes. */
  CILIUM_SRV6_IFBIND_ACCEPT_IDEMPOTENT,
  CILIUM_SRV6_IFBIND_ACCEPT_REMOVE,

  /* Length or character set of attachment_id. */
  CILIUM_SRV6_IFBIND_REJECT_ID_INVALID,
  /* sw_if_index is not a live interface. */
  CILIUM_SRV6_IFBIND_REJECT_NO_INTERFACE,
  /* if_incarnation is not the interface's current one (D-31). */
  CILIUM_SRV6_IFBIND_REJECT_STALE_INCARNATION,
  /* attachment_id is already bound to a different handle. */
  CILIUM_SRV6_IFBIND_REJECT_ATTACHMENT_BOUND,
  /* the handle is already bound to a different attachment_id. */
  CILIUM_SRV6_IFBIND_REJECT_HANDLE_BOUND,
  /* delete that matches no binding exactly. */
  CILIUM_SRV6_IFBIND_REJECT_NO_SUCH_BINDING,
} cilium_srv6_ifbind_verdict_t;

/* One binding as the table currently holds it, or `present == 0`. */
typedef struct
{
  u8 present;
  u32 sw_if_index;
  u32 if_incarnation;
} cilium_srv6_ifbind_obs_t;

/* What the interface layer says about one sw_if_index. */
typedef struct
{
  u8 live;
  u32 if_incarnation;
} cilium_srv6_ifbind_ifobs_t;

/*
 * Character set of an attachment identity.
 *
 * Printable ASCII without space, which accepts every identity CNI can
 * produce (`[A-Za-z0-9][A-Za-z0-9_.-]*` for the container ID, ':' as the
 * separator, and an interface name that CNI forbids from containing
 * whitespace or '/') and rejects control characters, embedded NUL and
 * non-ASCII bytes. The identity is a lookup key that also appears in logs
 * and in a dump reply, so restricting it here is cheaper than making every
 * consumer defend itself.
 */
static_always_inline int
cilium_srv6_ifbind_id_valid (const u8 *id, u32 len)
{
  u32 i;

  if (id == 0 || len == 0 || len > CILIUM_SRV6_ATTACHMENT_ID_MAX)
    return 0;

  for (i = 0; i < len; i++)
    if (id[i] < 0x21 || id[i] > 0x7e)
      return 0;

  return 1;
}

/*
 * Decide one add.
 *
 * The order of the checks is the order of D-68's rules:
 *
 *   1. the identity is well-formed;
 *   2. the interface exists and the caller quoted its current incarnation
 *      (D-31) — a publisher that raced an interface replacement is refused
 *      rather than allowed to bind the new interface under the old lifetime;
 *   3. the exact same tuple is idempotent;
 *   4. the same attachment with a different handle is refused;
 *   5. the same handle with a different attachment is refused.
 *
 * 4 and 5 are refusals and not replacements on purpose. An implicit replace
 * would make the table's answer depend on message order rather than on what
 * the publisher observed, and the window in which the old handle is still
 * programmed for the old attachment is exactly the misdelivery D-68 exists
 * to close. The publisher withdraws the old binding first; that withdrawal
 * is what the agent observes and turns into an invalidation.
 */
static_always_inline cilium_srv6_ifbind_verdict_t
cilium_srv6_ifbind_decide_add (const u8 *id, u32 id_len, u32 sw_if_index, u32 if_incarnation,
			       cilium_srv6_ifbind_ifobs_t iface, cilium_srv6_ifbind_obs_t by_id,
			       cilium_srv6_ifbind_obs_t by_handle)
{
  if (!cilium_srv6_ifbind_id_valid (id, id_len))
    return CILIUM_SRV6_IFBIND_REJECT_ID_INVALID;

  if (!iface.live)
    return CILIUM_SRV6_IFBIND_REJECT_NO_INTERFACE;

  if (iface.if_incarnation != if_incarnation)
    return CILIUM_SRV6_IFBIND_REJECT_STALE_INCARNATION;

  if (by_id.present)
    {
      if (by_id.sw_if_index == sw_if_index && by_id.if_incarnation == if_incarnation)
	return CILIUM_SRV6_IFBIND_ACCEPT_IDEMPOTENT;
      return CILIUM_SRV6_IFBIND_REJECT_ATTACHMENT_BOUND;
    }

  if (by_handle.present)
    return CILIUM_SRV6_IFBIND_REJECT_HANDLE_BOUND;

  return CILIUM_SRV6_IFBIND_ACCEPT_INSERT;
}

/*
 * Decide one delete.
 *
 * A delete names the whole tuple and removes a binding only when all three
 * components match. That is what makes a delete that was in flight across an
 * interface replacement harmless: it quotes the incarnation of the lifetime
 * that has ended, the live binding carries the new one, and the request is
 * refused instead of removing a binding the caller never observed.
 *
 * The interface is deliberately *not* consulted. A binding whose interface is
 * gone has already been removed by the interface delete callback, and
 * requiring a live interface here would make the withdrawal of a binding
 * depend on the thing whose disappearance motivates it.
 */
static_always_inline cilium_srv6_ifbind_verdict_t
cilium_srv6_ifbind_decide_del (const u8 *id, u32 id_len, u32 sw_if_index, u32 if_incarnation,
			       cilium_srv6_ifbind_obs_t by_id)
{
  if (!cilium_srv6_ifbind_id_valid (id, id_len))
    return CILIUM_SRV6_IFBIND_REJECT_ID_INVALID;

  if (!by_id.present)
    return CILIUM_SRV6_IFBIND_REJECT_NO_SUCH_BINDING;

  if (by_id.sw_if_index != sw_if_index || by_id.if_incarnation != if_incarnation)
    return CILIUM_SRV6_IFBIND_REJECT_NO_SUCH_BINDING;

  return CILIUM_SRV6_IFBIND_ACCEPT_REMOVE;
}

#endif /* __included_cilium_srv6_ifbind_rules_h__ */
