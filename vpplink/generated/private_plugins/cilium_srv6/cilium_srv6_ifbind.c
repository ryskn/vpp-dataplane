/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — CNI attachment binding table (D-68),
 * control plane: publication, withdrawal and interface lifecycle.
 *
 * design/detail/00-overview.md §2.12 (D-68), D-31
 * design/detail/02-headend-dataplane.md §2, §8
 */

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/interface.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_ifbind.h>

cilium_srv6_ifbind_main_t cilium_srv6_ifbind_main;

static vlib_log_class_t cilium_srv6_ifbind_log_class;

#define CSB_LOG_NOTICE(fmt, ...) vlib_log_notice (cilium_srv6_ifbind_log_class, fmt, __VA_ARGS__)

/*
 * The table is control plane only: no graph node reads it, and the agent
 * observes it through srv6_if_attachment_dump. It therefore does not need the
 * worker barrier the trust map and the LocalEndpointTable are written under —
 * a packet in flight cannot observe a half-written binding because no packet
 * ever observes a binding at all. The endpoint programming a binding leads to
 * is installed separately with srv6_local_ep_add_del, which does take the
 * barrier.
 */

/* ------------------------------------------------------------------ */
/* lookups                                                             */
/* ------------------------------------------------------------------ */

/* The pool index bound to one attachment identity, or ~0. */
static u32
csb_index_by_attachment (cilium_srv6_ifbind_main_t *bm, const u8 *id, u32 id_len)
{
  uword *p;
  u8 *key = 0;
  u32 index;

  if (!bm->initialised || id == 0 || id_len == 0)
    return ~0;

  vec_add (key, id, id_len);
  p = mhash_get (&bm->by_attachment, key);
  index = p ? (u32) p[0] : (u32) ~0;
  vec_free (key);

  return index;
}

/* The pool index bound to one sw_if_index, or ~0. */
static u32
csb_index_by_sw_if_index (cilium_srv6_ifbind_main_t *bm, u32 sw_if_index)
{
  if (!bm->initialised || sw_if_index >= vec_len (bm->by_sw_if_index))
    return ~0;
  return bm->by_sw_if_index[sw_if_index];
}

const cilium_srv6_if_binding_t *
cilium_srv6_ifbind_by_sw_if_index (u32 sw_if_index)
{
  cilium_srv6_ifbind_main_t *bm = &cilium_srv6_ifbind_main;
  u32 index = csb_index_by_sw_if_index (bm, sw_if_index);

  if (index == (u32) ~0)
    return 0;

  return pool_elt_at_index (bm->bindings, index);
}

/* The observation the decision functions take, derived from a pool index. */
static cilium_srv6_ifbind_obs_t
csb_observe (cilium_srv6_ifbind_main_t *bm, u32 index)
{
  cilium_srv6_ifbind_obs_t obs = { 0 };
  cilium_srv6_if_binding_t *b;

  if (index == (u32) ~0)
    return obs;

  b = pool_elt_at_index (bm->bindings, index);
  obs.present = 1;
  obs.sw_if_index = b->sw_if_index;
  obs.if_incarnation = b->if_incarnation;
  return obs;
}

/*
 * What the guard's interface state (the D-31 incarnation authority) says
 * about one sw_if_index.
 *
 * This is deliberately the same state srv6_acl_interface_set and
 * srv6_local_ep_add_del validate against. D-68 forbids a second interface
 * generation concept: if this read were replaced by a private counter, a
 * binding could be accepted for an incarnation no other table agrees exists.
 */
static cilium_srv6_ifbind_ifobs_t
csb_observe_interface (u32 sw_if_index)
{
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  cilium_srv6_ifbind_ifobs_t iface = { 0 };
  const cilium_srv6_guard_if_t *e;

  if (sw_if_index >= vec_len (cm->ifs))
    return iface;

  e = vec_elt_at_index (cm->ifs, sw_if_index);
  if (!e->valid)
    return iface;

  iface.live = 1;
  iface.if_incarnation = e->incarnation;
  return iface;
}

/* ------------------------------------------------------------------ */
/* mutation                                                            */
/* ------------------------------------------------------------------ */

static void
csb_insert (cilium_srv6_ifbind_main_t *bm, const u8 *id, u32 id_len, u32 sw_if_index,
	    u32 if_incarnation)
{
  cilium_srv6_if_binding_t *b;
  u8 *key = 0;
  u32 index;

  pool_get_zero (bm->bindings, b);
  index = b - bm->bindings;

  vec_add (b->attachment_id, id, id_len);
  b->sw_if_index = sw_if_index;
  b->if_incarnation = if_incarnation;

  vec_add (key, id, id_len);
  mhash_set (&bm->by_attachment, key, (uword) index, 0);
  vec_free (key);

  vec_validate_init_empty (bm->by_sw_if_index, sw_if_index, ~0);
  bm->by_sw_if_index[sw_if_index] = index;

  bm->n_bindings++;
}

static void
csb_remove (cilium_srv6_ifbind_main_t *bm, u32 index)
{
  cilium_srv6_if_binding_t *b = pool_elt_at_index (bm->bindings, index);
  u8 *key = 0;

  vec_add (key, b->attachment_id, vec_len (b->attachment_id));
  mhash_unset (&bm->by_attachment, key, 0);
  vec_free (key);

  if (b->sw_if_index < vec_len (bm->by_sw_if_index) && bm->by_sw_if_index[b->sw_if_index] == index)
    bm->by_sw_if_index[b->sw_if_index] = ~0;

  vec_free (b->attachment_id);
  pool_put_index (bm->bindings, index);

  if (bm->n_bindings > 0)
    bm->n_bindings--;
}

/* ------------------------------------------------------------------ */
/* API-facing operation                                                */
/* ------------------------------------------------------------------ */

int
cilium_srv6_ifbind_verdict_to_api_error (cilium_srv6_ifbind_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_IFBIND_ACCEPT_INSERT:
    case CILIUM_SRV6_IFBIND_ACCEPT_IDEMPOTENT:
    case CILIUM_SRV6_IFBIND_ACCEPT_REMOVE:
      return 0;
    case CILIUM_SRV6_IFBIND_REJECT_ID_INVALID:
      return VNET_API_ERROR_INVALID_VALUE;
    case CILIUM_SRV6_IFBIND_REJECT_NO_INTERFACE:
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    case CILIUM_SRV6_IFBIND_REJECT_STALE_INCARNATION:
      return VNET_API_ERROR_INVALID_VALUE_2;
    case CILIUM_SRV6_IFBIND_REJECT_ATTACHMENT_BOUND:
    case CILIUM_SRV6_IFBIND_REJECT_HANDLE_BOUND:
      return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
    case CILIUM_SRV6_IFBIND_REJECT_NO_SUCH_BINDING:
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  return VNET_API_ERROR_UNSPECIFIED;
}

/*
 * srv6_if_attachment_add_del (02 §8).
 *
 * The caller must have bounded id_len before copying the identity out of the
 * API message; this function bounds it again because it is also reachable
 * from the CLI and from tests, and because a length check that only exists at
 * one call site is a length check that a second call site will not have.
 */
int
cilium_srv6_if_attachment_add_del (const u8 *attachment_id, u32 id_len, u32 sw_if_index,
				   u32 if_incarnation, u8 is_add)
{
  cilium_srv6_ifbind_main_t *bm = &cilium_srv6_ifbind_main;
  cilium_srv6_ifbind_verdict_t verdict;
  u32 by_id_index;

  if (!bm->initialised)
    return VNET_API_ERROR_FEATURE_DISABLED;

  /* Before the lookup, not only inside the decision: the lookup copies the
     identity into a temporary key, so an unbounded id_len would be an
     unbounded allocation made before anything rejected it. The decision
     functions check it again — they are pure and cannot assume a caller
     checked — and the API handler checks it a third time against the received
     message size, which is a different bound (00 §4.1). */
  if (!cilium_srv6_ifbind_id_valid (attachment_id, id_len))
    return VNET_API_ERROR_INVALID_VALUE;

  by_id_index = csb_index_by_attachment (bm, attachment_id, id_len);

  if (!is_add)
    {
      verdict = cilium_srv6_ifbind_decide_del (attachment_id, id_len, sw_if_index, if_incarnation,
					       csb_observe (bm, by_id_index));
      if (verdict != CILIUM_SRV6_IFBIND_ACCEPT_REMOVE)
	return cilium_srv6_ifbind_verdict_to_api_error (verdict);

      csb_remove (bm, by_id_index);
      return 0;
    }

  verdict = cilium_srv6_ifbind_decide_add (
    attachment_id, id_len, sw_if_index, if_incarnation, csb_observe_interface (sw_if_index),
    csb_observe (bm, by_id_index), csb_observe (bm, csb_index_by_sw_if_index (bm, sw_if_index)));

  switch (verdict)
    {
    case CILIUM_SRV6_IFBIND_ACCEPT_INSERT:
      csb_insert (bm, attachment_id, id_len, sw_if_index, if_incarnation);
      return 0;
    case CILIUM_SRV6_IFBIND_ACCEPT_IDEMPOTENT:
      return 0;
    default:
      return cilium_srv6_ifbind_verdict_to_api_error (verdict);
    }
}

/* ------------------------------------------------------------------ */
/* interface lifecycle                                                 */
/* ------------------------------------------------------------------ */

/*
 * D-68: a binding lives exactly as long as the interface it names.
 *
 * The delete side is the one that matters. Without it the table would keep
 * answering "attachment A is behind index 10" after index 10 was freed, and
 * VPP hands the freed index to the next interface it creates, so the answer
 * would come back pointing at another Pod. Removing the binding in the same
 * event that frees the index is what makes "the binding exists" and "the
 * interface exists" the same statement.
 *
 * The add side clears whatever is recorded for a reappearing index. Nothing
 * should be left there — the delete callback removed it — but an index that
 * carried a stale binding into a new interface lifetime is precisely the
 * misdelivery this table exists to prevent, so it is cleared rather than
 * trusted. The clearing is by sw_if_index alone and needs no incarnation:
 * this callback is the event in which the previous lifetime ended.
 */
static void
csb_interface_del (u32 sw_if_index)
{
  cilium_srv6_ifbind_main_t *bm = &cilium_srv6_ifbind_main;
  u32 index;

  index = csb_index_by_sw_if_index (bm, sw_if_index);
  if (index == (u32) ~0)
    return;

  CSB_LOG_NOTICE ("removed the CNI attachment binding of sw_if_index %u: the interface is gone",
		  sw_if_index);
  csb_remove (bm, index);
}

static clib_error_t *
cilium_srv6_ifbind_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  (void) vnm;
  (void) is_add;

  /* Both directions drop whatever is bound to this index: on delete because
     the interface is gone, on add because a new lifetime must not inherit a
     binding published for the previous one. */
  csb_interface_del (sw_if_index);

  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (cilium_srv6_ifbind_sw_interface_add_del);

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_ifbind_init (vlib_main_t *vm)
{
  cilium_srv6_ifbind_main_t *bm = &cilium_srv6_ifbind_main;

  (void) vm;

  clib_memset (bm, 0, sizeof (*bm));

  cilium_srv6_ifbind_log_class = vlib_log_register_class ("cilium-srv6", "ifbind");

  /* Vector string keys: mhash copies the identity into its own heap, so the
     table owns every byte it stores and no caller's buffer has to outlive
     the call. The value is a full uword so that reading it back through the
     `uword *` mhash_get returns is not a read of the pair's padding. */
  mhash_init_vec_string (&bm->by_attachment, sizeof (uword));

  bm->initialised = 1;

  return 0;
}

VLIB_INIT_FUNCTION (cilium_srv6_ifbind_init) = {
  .runs_after = VLIB_INITS ("vnet_interface_init"),
};
