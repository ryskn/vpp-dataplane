/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — End.Cilium and endpoint delivery (C8-b),
 * control plane.
 *
 * Responsibilities of this file:
 *
 *   - the SR domain node address set consulted by cilium-end-cilium
 *     (03 §3 / D-32), replaced only as a whole by a staged transaction
 *     (D-90, cilium_srv6_srdomain_rules.h),
 *   - the Block:uN_B:uC::/64 End.Cilium local SID: a plugin DPO type bound
 *     to a single /64 FIB entry, installed once at start up and independent
 *     of the number of Pods (03 §1, D-10),
 *   - the graph arc from cilium-ep-deliver to each Context entry's delivery
 *     forwarding object (03 §6 step 4),
 *   - the 03 §1.1 fail-closed ladder: while guard coverage is incomplete no
 *     local SID is installed, and losing coverage while it is installed
 *     removes it under the worker barrier and suspends every ACTIVE Context.
 *
 * design/detail/03-destination-dataplane.md §1, §1.1, §3, §6, §7
 * design/detail/00-overview.md §2 (D-10, D-32, D-35, D-46), §6
 * design/detail/06-observability.md §2, §3, §4
 */

#include <stdbool.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_types.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_context.h>
#include <cilium_srv6/cilium_srv6_endcilium.h>

cilium_srv6_endcilium_main_t cilium_srv6_endcilium_main;

cilium_srv6_ct_create_fn cilium_srv6_ct_create_hook;

static vlib_log_class_t cilium_srv6_endcilium_log_class;

#define CSE_LOG_ERR(fmt, ...)	 vlib_log_err (cilium_srv6_endcilium_log_class, fmt, __VA_ARGS__)
#define CSE_LOG_NOTICE(fmt, ...) vlib_log_notice (cilium_srv6_endcilium_log_class, fmt, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* conntrack hook (C10, 03 §6)                                         */
/* ------------------------------------------------------------------ */

/*
 * C10 is out of scope here; only the shape of the call is defined. The
 * pointer is written from the control plane under the worker barrier so
 * that no worker observes it half-published.
 */
void
cilium_srv6_ct_register (cilium_srv6_ct_create_fn fn)
{
  vlib_main_t *vm = vlib_get_main ();
  int taken = cilium_srv6_barrier_acquire (vm);

  cilium_srv6_ct_create_hook = fn;

  cilium_srv6_barrier_release (vm, taken);

  CSE_LOG_NOTICE ("conntrack hook %s", fn ? "registered" : "cleared");
}

/* ------------------------------------------------------------------ */
/* SR domain node address set (03 §3 / D-32)                           */
/* ------------------------------------------------------------------ */

/*
 * D-90 (errata #34 item 205): the set is replaced only as a whole. Every
 * decision is made by cilium_srv6_srdomain_rules.h; this file maps the
 * verdicts to API errors and takes the worker barrier around the one call
 * that changes what the workers read.
 */
static int
cse_sr_domain_verdict_to_api_error (cilium_srv6_sr_domain_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_SR_DOMAIN_OK:
    case CILIUM_SRV6_SR_DOMAIN_OK_REPLAY:
      return 0;
    case CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO:
      return VNET_API_ERROR_INVALID_VALUE;
    case CILIUM_SRV6_SR_DOMAIN_REJECT_BUSY:
      return VNET_API_ERROR_INSTANCE_IN_USE;
    case CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_REUSED:
      return VNET_API_ERROR_VALUE_EXIST;
    case CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN:
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    case CILIUM_SRV6_SR_DOMAIN_REJECT_PREFIX:
      return VNET_API_ERROR_INVALID_VALUE_2;
    case CILIUM_SRV6_SR_DOMAIN_REJECT_WILDCARD:
      return VNET_API_ERROR_INVALID_VALUE;
    case CILIUM_SRV6_SR_DOMAIN_REJECT_CAPACITY:
      return VNET_API_ERROR_LIMIT_EXCEEDED;
    case CILIUM_SRV6_SR_DOMAIN_REJECT_COUNT:
      return VNET_API_ERROR_INVALID_VALUE_3;
    }

  /* An unknown verdict is a refusal. */
  return VNET_API_ERROR_INVALID_VALUE;
}

/* srv6_sr_domain_txn_begin. Touches the staging buffer only. */
int
cilium_srv6_sr_domain_publish_begin (u64 txn_id)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;

  if (!em->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  return cse_sr_domain_verdict_to_api_error (
    cilium_srv6_sr_domain_txn_begin (&em->sr_domain_txn, txn_id));
}

/* srv6_sr_domain_txn_put. Touches the staging buffer only. */
int
cilium_srv6_sr_domain_publish_put (u64 txn_id, const ip6_address_t *prefix, u32 len)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;

  if (prefix == NULL)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (!em->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  return cse_sr_domain_verdict_to_api_error (
    cilium_srv6_sr_domain_txn_put (&em->sr_domain_txn, txn_id, prefix, len));
}

/*
 * srv6_sr_domain_txn_commit. The staged set is validated as a whole first;
 * only then, inside one worker barrier section, does it become the active
 * set. A refused commit changes nothing and leaves the transaction open.
 */
int
cilium_srv6_sr_domain_publish_commit (u64 txn_id, u32 n_prefixes)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_sr_domain_verdict_t v;
  u32 previous;
  int taken;

  if (!em->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  v = cilium_srv6_sr_domain_txn_commit_check (&em->sr_domain_txn, &em->sr_domain, txn_id,
					      n_prefixes);
  if (v != CILIUM_SRV6_SR_DOMAIN_OK)
    return cse_sr_domain_verdict_to_api_error (v);

  previous = em->sr_domain.n;

  taken = cilium_srv6_barrier_acquire (vm);
  cilium_srv6_sr_domain_txn_install (&em->sr_domain_txn, &em->sr_domain);
  cilium_srv6_barrier_release (vm, taken);

  CSE_LOG_NOTICE ("SR domain node address set replaced: %u -> %u prefixes (capacity %u)",
		  previous, em->sr_domain.n, em->sr_domain.capacity);

  return 0;
}

/* srv6_sr_domain_txn_abort. Touches the staging buffer only. */
int
cilium_srv6_sr_domain_publish_abort (u64 txn_id)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;

  if (!em->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  return cse_sr_domain_verdict_to_api_error (
    cilium_srv6_sr_domain_txn_abort (&em->sr_domain_txn, txn_id));
}

u8 *
format_cilium_srv6_sr_domain (u8 *s, va_list *args)
{
  const cilium_srv6_sr_domain_prefix_t *p = va_arg (*args, const cilium_srv6_sr_domain_prefix_t *);
  ip6_address_t a;

  a.as_u64[0] = p->addr[0];
  a.as_u64[1] = p->addr[1];

  return format (s, "%U/%u", format_ip6_address, &a, (u32) p->len);
}

/* ------------------------------------------------------------------ */
/* delivery arc (03 §6 step 4)                                         */
/* ------------------------------------------------------------------ */

u32
cilium_srv6_delivery_resolve (const dpo_id_t *dpo)
{
  dpo_id_t stacked = DPO_INVALID;
  u32 next_index;

  if (dpo == NULL || !dpo_id_is_valid (dpo))
    return ~0;

  /*
   * dpo_stack_from_node() resolves (and, if necessary, creates) the graph
   * edge from cilium-ep-deliver to the node the forwarding object dispatches
   * to. It takes the worker barrier itself when it has to add an edge, so
   * the caller must not already be inside a barrier section it opened.
   */
  dpo_stack_from_node (cilium_srv6_ep_deliver_node.index, &stacked, dpo);

  next_index = stacked.dpoi_next_node;
  dpo_reset (&stacked);

  return next_index;
}

void
cilium_srv6_delivery_set (u32 pool_index, u32 next_index)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;

  if (pool_index >= vec_len (em->delivery_next))
    return;

  em->delivery_next[pool_index] = next_index;
}

/* ------------------------------------------------------------------ */
/* End.Cilium local SID (D-10, 03 §1)                                  */
/* ------------------------------------------------------------------ */

static void
cse_localsid_prefix (const cilium_srv6_endcilium_main_t *em, fib_prefix_t *pfx)
{
  clib_memset (pfx, 0, sizeof (*pfx));
  pfx->fp_proto = FIB_PROTOCOL_IP6;
  pfx->fp_len = CILIUM_SRV6_LOCALSID_PREFIX_LEN;
  pfx->fp_addr.ip6 = em->localsid;
}

/*
 * Install the single Block:uN_B:uC::/64 FIB entry (D-10). One entry per
 * node, independent of the number of Pods: the Context is read from
 * DA bit 64..95 by cilium-end-cilium rather than from a per-Pod route.
 *
 * Must be called with the worker barrier held.
 */
static void
cse_localsid_install (cilium_srv6_endcilium_main_t *em)
{
  fib_prefix_t pfx;
  dpo_id_t dpo = DPO_INVALID;

  if (em->localsid_installed)
    return;

  cse_localsid_prefix (em, &pfx);
  dpo_set (&dpo, em->dpo_type, DPO_PROTO_IP6, 0);

  fib_table_entry_special_dpo_add (em->fib_index, &pfx, em->fib_source, FIB_ENTRY_FLAG_EXCLUSIVE,
				   &dpo);
  dpo_reset (&dpo);

  em->localsid_installed = 1;
  em->n_localsid_installs++;

  CSE_LOG_NOTICE ("End.Cilium local SID installed: %U/%u in fib-index %u", format_ip6_address,
		  &em->localsid, (u32) CILIUM_SRV6_LOCALSID_PREFIX_LEN, em->fib_index);
}

/* Must be called with the worker barrier held (03 §1.1). */
static void
cse_localsid_remove (cilium_srv6_endcilium_main_t *em)
{
  fib_prefix_t pfx;

  if (!em->localsid_installed)
    return;

  cse_localsid_prefix (em, &pfx);
  fib_table_entry_special_remove (em->fib_index, &pfx, em->fib_source);

  em->localsid_installed = 0;

  CSE_LOG_NOTICE ("End.Cilium local SID removed: %U/%u", format_ip6_address, &em->localsid,
		  (u32) CILIUM_SRV6_LOCALSID_PREFIX_LEN);
}

/*
 * Undo the delivery half of the 03 §1.1 fail-closed ladder. The order the
 * design prescribes on recovery is "local SID、SUSPENDED entry、route", so
 * every caller installs the local SID first and then calls this.
 */
static void
cse_resume_if_suspended (cilium_srv6_endcilium_main_t *em, const char *reason)
{
  if (!em->delivery_suspended)
    return;

  cilium_srv6_context_resume_all (reason);
  em->delivery_suspended = 0;
}

/*
 * srv6_uc_locator_set (IF-2, 03 §7).
 *
 * Builds Block:uN_B:uC:: from the configured SRV6_BLOCK (00 §6) and the
 * supplied uN_B / uC, validating the D-46 address plan invariants before
 * anything is touched.
 */
int
cilium_srv6_uc_locator_set (u32 table_id, u16 un_node, u16 uc, u8 is_add)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  ip6_address_t sid;
  u32 fib_index;
  int taken;

  if (!em->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (!is_add)
    {
      if (!em->locator_set)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      taken = cilium_srv6_barrier_acquire (vm);
      cse_localsid_remove (em);
      cilium_srv6_barrier_release (vm, taken);

      fib_table_unlock (em->fib_index, FIB_PROTOCOL_IP6, em->fib_source);

      /* delivery_suspended is deliberately left as it is: if the ladder had
       * suspended the Context entries they stay SUSPENDED, which is
       * fail-closed, and a later locator install resumes them in the order
       * 03 §1.1 prescribes. */
      em->locator_set = 0;
      em->fib_index = ~0;
      em->un_node = 0;
      em->uc = 0;
      clib_memset (&em->localsid, 0, sizeof (em->localsid));

      return 0;
    }

  /*
   * 00 §6 invariant 1 (D-46): uN_node comes from GIB_RANGE and uC_* from
   * LIB_RANGE, and the two ranges are disjoint. Without this a node whose
   * uN_node equals uC_Cilium would have its /48 uN entry and this /64
   * End.Cilium entry overlap, and transit packets would have DA bit 64..95
   * interpreted as a Context.
   */
  if (un_node < CILIUM_SRV6_GIB_FIRST || un_node > CILIUM_SRV6_GIB_LAST)
    return VNET_API_ERROR_INVALID_VALUE;

  if (uc < CILIUM_SRV6_LIB_FIRST || uc > CILIUM_SRV6_LIB_LAST)
    return VNET_API_ERROR_INVALID_VALUE_2;

  /*
   * The local SID is Block(32) : uN_B(16) : uC(16) :: /64, so SRV6_BLOCK has
   * to be exactly LB=32 for the layout of 01 §2.3 to hold. D-60 fixes LB=32 as
   * the only accepted length, which also makes an unset block (block_len == 0)
   * a rejection instead of a /0 block that would place the local SID at ::/64.
   * This is what the .api documents as "SRV6_BLOCK is unset or longer than 32
   * bits".
   */
  if (!cm->initialised || cm->block_len != CILIUM_SRV6_BLOCK_LEN)
    return VNET_API_ERROR_INVALID_VALUE_3;

  /*
   * 03 §1.1: "guard を外した状態で local SID を install してはならない."
   * D-35 additionally blocks installs while the dead-man switch is active.
   * Both are expressed by cilium_srv6_guard_context_install_allowed().
   */
  if (!cilium_srv6_guard_context_install_allowed ())
    return VNET_API_ERROR_FEATURE_DISABLED;

  /*
   * cm->block_u64[] is SRV6_BLOCK with its host bits already masked off, so
   * with block_len <= 32 everything from bit 32 on is zero and the uN_B /
   * uC fields can simply be written into bytes 4..7 (01 §2.3).
   */
  sid.as_u64[0] = cm->block_u64[0];
  sid.as_u64[1] = cm->block_u64[1];
  sid.as_u16[2] = clib_host_to_net_u16 (un_node);
  sid.as_u16[3] = clib_host_to_net_u16 (uc);

  /* Idempotent re-apply of the same locator. */
  if (em->locator_set)
    {
      if (em->table_id == table_id && em->un_node == un_node && em->uc == uc &&
	  0 == memcmp (&em->localsid, &sid, sizeof (sid)))
	{
	  /* Re-assert the FIB entry in case a previous install was undone by
	   * the fail-closed ladder and coverage has since returned. */
	  taken = cilium_srv6_barrier_acquire (vm);
	  cse_localsid_install (em);
	  cilium_srv6_barrier_release (vm, taken);
	  cse_resume_if_suspended (em, "locator re-applied (03 §1.1)");
	  return 0;
	}

      return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
    }

  fib_index = fib_table_find_or_create_and_lock (FIB_PROTOCOL_IP6, table_id, em->fib_source);
  if (fib_index == (u32) ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  em->fib_index = fib_index;
  em->table_id = table_id;
  em->un_node = un_node;
  em->uc = uc;
  em->localsid = sid;

  taken = cilium_srv6_barrier_acquire (vm);
  cse_localsid_install (em);
  cilium_srv6_barrier_release (vm, taken);

  em->locator_set = 1;
  cse_resume_if_suspended (em, "locator installed (03 §1.1)");

  return 0;
}

/* ------------------------------------------------------------------ */
/* 03 §1.1 fail-closed ladder                                          */
/* ------------------------------------------------------------------ */

/*
 * "guard 自体の故障などで即時 quarantine を保証できない場合は、worker
 *  barrier 下で End.Cilium local SID を remove し、全 ACTIVE entry を一時
 *  SUSPENDED へ遷移させて delivery を無効化する。" — 03 §1.1.
 *
 * The observable condition inside the plugin is guard coverage: an
 * interface that exists but on which the guard feature could not be
 * installed cannot be contained by quarantining it, because the guard is
 * not on its ingress path at all.
 *
 * The dead-man switch is deliberately NOT a trigger here: D-35 keeps
 * existing ACTIVE delivery running so that delaying the agent cannot be
 * used as an availability attack. It only blocks new Context and locator
 * installs, which cilium_srv6_guard_context_install_allowed() already does.
 */
static void
cse_readiness_tick (vlib_main_t *vm)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  int covered = cilium_srv6_guard_coverage_complete (&cilium_srv6_main);
  int taken;

  if (!em->initialised || !em->locator_set)
    return;

  if (!covered && !em->delivery_suspended)
    {
      taken = cilium_srv6_barrier_acquire (vm);
      cse_localsid_remove (em);
      cilium_srv6_barrier_release (vm, taken);

      /* Order of 03 §1.1: local SID first, then the ACTIVE entries. */
      cilium_srv6_context_suspend_all ("guard coverage lost (03 §1.1)");

      em->delivery_suspended = 1;
      em->n_delivery_suspends++;

      CSE_LOG_ERR ("guard coverage lost: End.Cilium local SID removed and "
		   "delivery suspended (suspend #%llu)",
		   em->n_delivery_suspends);
      return;
    }

  if (covered && em->delivery_suspended)
    {
      /* "復旧時は guard coverage 確認後に local SID、SUSPENDED entry、route
	 の順で再有効化する" — local SID first, then the entries. */
      taken = cilium_srv6_barrier_acquire (vm);
      cse_localsid_install (em);
      cilium_srv6_barrier_release (vm, taken);

      cse_resume_if_suspended (em, "guard coverage restored (03 §1.1)");

      CSE_LOG_NOTICE ("guard coverage restored: End.Cilium local SID "
		      "reinstalled in fib-index %u and delivery resumed",
		      em->fib_index);
    }
}

static uword
cilium_srv6_endcilium_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, CILIUM_SRV6_ENDCILIUM_TICK_INTERVAL);
      (void) vlib_process_get_events (vm, 0);

      cse_readiness_tick (vm);
    }

  return 0;
}

VLIB_REGISTER_NODE (cilium_srv6_endcilium_process_node, static) = {
  .function = cilium_srv6_endcilium_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cilium-srv6-endcilium-process",
  .process_log2_n_stack_bytes = 16,
};

/* ------------------------------------------------------------------ */
/* End.Cilium DPO type                                                 */
/* ------------------------------------------------------------------ */

/*
 * There is exactly one End.Cilium local SID per node, so the DPO carries no
 * per-object state and needs no reference counting. The FIB entry holds the
 * only reference.
 */
static void
cse_dpo_lock (dpo_id_t *dpo)
{
}

static void
cse_dpo_unlock (dpo_id_t *dpo)
{
}

static u8 *
format_cilium_srv6_end_cilium_dpo (u8 *s, va_list *args)
{
  const cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;

  (void) va_arg (*args, index_t);
  (void) va_arg (*args, u32);

  return format (s, "cilium-end-cilium: %U/%u", format_ip6_address, &em->localsid,
		 (u32) CILIUM_SRV6_LOCALSID_PREFIX_LEN);
}

static const dpo_vft_t cilium_srv6_end_cilium_dpo_vft = {
  .dv_lock = cse_dpo_lock,
  .dv_unlock = cse_dpo_unlock,
  .dv_format = format_cilium_srv6_end_cilium_dpo,
};

static const char *const cilium_srv6_end_cilium_ip6_nodes[] = {
  "cilium-end-cilium",
  NULL,
};

static const char *const *const cilium_srv6_end_cilium_nodes[DPO_PROTO_NUM] = {
  [DPO_PROTO_IP6] = cilium_srv6_end_cilium_ip6_nodes,
};

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_endcilium_init (vlib_main_t *vm)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;

  clib_memset (em, 0, sizeof (*em));

  cilium_srv6_endcilium_log_class = vlib_log_register_class ("cilium-srv6", "end-cilium");

  em->fib_index = ~0;
  em->fib_source = fib_source_allocate ("cilium-srv6", FIB_SOURCE_PRIORITY_HI, FIB_SOURCE_BH_API);
  em->dpo_type =
    dpo_register_new_type (&cilium_srv6_end_cilium_dpo_vft, cilium_srv6_end_cilium_nodes);

  em->process_node_index = cilium_srv6_endcilium_process_node.index;

  /* The SR domain buffers are sized from the startup configuration
   * (D-90), so they are allocated at main-loop-enter. Until then both sets
   * have no slots, the hot path predicate matches nothing, and the API
   * refuses every transaction with INIT_FAILED. */

  return 0;
}

VLIB_INIT_FUNCTION (cilium_srv6_endcilium_init) = {
  .runs_after = VLIB_INITS ("fib_module_init", "dpo_module_init"),
};

/*
 * The per-pool-index delivery arc array is sized from the Context pool
 * capacity, which is only final after the startup configuration has been
 * applied, so it is built at main-loop-enter like the Context tables.
 */
static clib_error_t *
cilium_srv6_endcilium_main_loop_enter (vlib_main_t *vm)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  const cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  u32 capacity = cxm->active_capacity ? cxm->active_capacity : CILIUM_SRV6_ACTIVE_CAPACITY_DEFAULT;
  u32 sr_capacity = cilium_srv6_main.sr_domain_capacity;
  cilium_srv6_sr_domain_prefix_t *active = 0;
  cilium_srv6_sr_domain_prefix_t *staged = 0;
  u32 i;

  if (em->initialised)
    return 0;

  vec_validate_aligned (em->delivery_next, capacity - 1, CLIB_CACHE_LINE_BYTES);
  for (i = 0; i < vec_len (em->delivery_next); i++)
    em->delivery_next[i] = ~0;

  /*
   * D-90: both buffers of the SR domain set exist from here on, at the
   * configured capacity, and are never reallocated (03 §9: no hot path
   * allocation). The configuration parser bounds the value; an out-of-range
   * value here can only mean the stanza was never parsed, so it falls back to
   * the default rather than allocating something unbounded.
   */
  if (sr_capacity < 1 || sr_capacity > CILIUM_SRV6_SR_DOMAIN_CAPACITY_MAX)
    sr_capacity = CILIUM_SRV6_SR_DOMAIN_CAPACITY_DEFAULT;

  vec_validate_aligned (active, sr_capacity - 1, CLIB_CACHE_LINE_BYTES);
  vec_validate_aligned (staged, sr_capacity - 1, CLIB_CACHE_LINE_BYTES);

  em->sr_domain.prefixes = active;
  em->sr_domain.n = 0;
  em->sr_domain.capacity = sr_capacity;

  em->sr_domain_txn.staged.prefixes = staged;
  em->sr_domain_txn.staged.n = 0;
  em->sr_domain_txn.staged.capacity = sr_capacity;
  em->sr_domain_txn.open_txn_id = 0;
  em->sr_domain_txn.committed_txn_id = 0;
  em->sr_domain_txn.n_commits = 0;

  em->initialised = 1;

  CSE_LOG_NOTICE ("End.Cilium ready: delivery arc table for %u pool indices, "
		  "SR domain set capacity %u prefixes (D-90)",
		  capacity, sr_capacity);

  return 0;
}

/*
 * No ordering constraint against the Context tables' own main-loop-enter
 * function is needed: active_capacity is set by cilium_srv6_context_init()
 * and possibly overridden by the `cilium-srv6-context` startup
 * configuration, and VLIB applies both before any main-loop-enter function
 * runs.
 */
VLIB_MAIN_LOOP_ENTER_FUNCTION (cilium_srv6_endcilium_main_loop_enter);
