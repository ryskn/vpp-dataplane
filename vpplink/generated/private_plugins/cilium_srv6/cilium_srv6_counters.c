/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — drop reason inventory (C5),
 * design/detail/06-observability.md §1 / §2 / §4.2.
 *
 * Three things live here:
 *
 *   1. The binding of every registered cilium_srv6 error counter to exactly
 *      one 06 §2 drop reason. This is the inventory 06 §1 asks for; without
 *      it "every drop is explainable" is an assertion nobody checks.
 *   2. The init-time validation of that binding. A counter added to a
 *      counters block without a reason, or a node whose n_errors no longer
 *      matches its table, stops the plugin from initialising. Failing at
 *      init rather than at read-out keeps the invariant from degrading
 *      silently in a running system.
 *   3. The read-out: `show cilium srv6 errors` (06 §4.2) and the data source
 *      of srv6_counters_dump (02 §8) / cilium_srv6_drop_total (06 §3).
 *
 * Values are summed across worker threads the way `show errors` does, and
 * `counters_last_clear` is honoured so that a `clear errors` is respected.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>

#include <cilium_srv6/cilium_srv6_counters.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

/* ------------------------------------------------------------------ */
/* reason names                                                        */
/* ------------------------------------------------------------------ */

static const char *const cilium_srv6_drop_reason_names[CILIUM_SRV6_DROP_N_REASON] = {
  [CILIUM_SRV6_DROP_UNSET] = "UNSET",
#define _(sym, str, desc) [CILIUM_SRV6_DROP_##sym] = str,
  foreach_cilium_srv6_drop_reason
#undef _
};

static const char *const cilium_srv6_drop_reason_descs[CILIUM_SRV6_DROP_N_REASON] = {
  [CILIUM_SRV6_DROP_UNSET] = "unclassified counter (implementation bug, 06 §1)",
#define _(sym, str, desc) [CILIUM_SRV6_DROP_##sym] = desc,
  foreach_cilium_srv6_drop_reason
#undef _
};

const char *
cilium_srv6_drop_reason_name (u8 reason)
{
  if (reason >= CILIUM_SRV6_DROP_N_REASON)
    return "INVALID";
  return cilium_srv6_drop_reason_names[reason];
}

const char *
cilium_srv6_drop_reason_desc (u8 reason)
{
  if (reason >= CILIUM_SRV6_DROP_N_REASON)
    return "out of range";
  return cilium_srv6_drop_reason_descs[reason];
}

u8 *
format_cilium_srv6_drop_reason (u8 *s, va_list *args)
{
  u32 reason = va_arg (*args, u32);

  return format (s, "%s", cilium_srv6_drop_reason_name ((u8) reason));
}

/* ------------------------------------------------------------------ */
/* the inventory                                                       */
/* ------------------------------------------------------------------ */

/*
 * One array per node, indexed by the generated error code. Every entry is
 * written explicitly, including the `severity info` counters, which are
 * bound to NOT_A_DROP. An entry that is left out keeps CILIUM_SRV6_DROP_UNSET
 * (value 0) and is rejected at init.
 */

/* cilium-srv6-guard (03 §1.1, D-9 / D-32 / D-54).

   The two fragment counters carry two different reasons (#64):
   uninspectable_fragment is the D-54 fail-closed drop of an offset-zero
   fragment whose security-relevant header chain the guard could not
   completely verify, fragment_not_permitted is the
   `untrusted-fragment-drop-all` hardening option refusing a fragment by
   configuration. Binding both to one reason would leave
   cilium_srv6_drop_total unable to separate them, because the reason label
   is the only key that metric has. */
static const u8 guard_reasons[CILIUM_SRV6_GUARD_N_ERROR] = {
  [CILIUM_SRV6_GUARD_ERROR_SID_BLOCK_INJECTION] = CILIUM_SRV6_DROP_SID_BLOCK_INJECTION,
  [CILIUM_SRV6_GUARD_ERROR_SID_BLOCK_QUARANTINED] = CILIUM_SRV6_DROP_SID_BLOCK_QUARANTINED,
  [CILIUM_SRV6_GUARD_ERROR_MALFORMED_INNER] = CILIUM_SRV6_DROP_MALFORMED_INNER,
  [CILIUM_SRV6_GUARD_ERROR_UNINSPECTABLE_FRAGMENT] = CILIUM_SRV6_DROP_UNINSPECTABLE_FRAGMENT,
  [CILIUM_SRV6_GUARD_ERROR_FRAGMENT_NOT_PERMITTED] = CILIUM_SRV6_DROP_FRAGMENT_NOT_PERMITTED,
  [CILIUM_SRV6_GUARD_ERROR_PASSED] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

/* cilium-end-cilium (03 §3, §8). */
static const u8 end_cilium_reasons[CILIUM_SRV6_END_CILIUM_N_ERROR] = {
  [CILIUM_SRV6_END_CILIUM_ERROR_UNTRUSTED_SOURCE] = CILIUM_SRV6_DROP_UNTRUSTED_SOURCE,
  [CILIUM_SRV6_END_CILIUM_ERROR_UNKNOWN_CONTEXT] = CILIUM_SRV6_DROP_UNKNOWN_CONTEXT,
  [CILIUM_SRV6_END_CILIUM_ERROR_INVALID_CONTEXT] = CILIUM_SRV6_DROP_INVALID_CONTEXT,
  [CILIUM_SRV6_END_CILIUM_ERROR_CONTEXT_RECYCLED] = CILIUM_SRV6_DROP_CONTEXT_RECYCLED,
  [CILIUM_SRV6_END_CILIUM_ERROR_SRV6_NOT_READY] = CILIUM_SRV6_DROP_SRV6_NOT_READY,
  [CILIUM_SRV6_END_CILIUM_ERROR_MALFORMED_OUTER] = CILIUM_SRV6_DROP_MALFORMED_OUTER,
  [CILIUM_SRV6_END_CILIUM_ERROR_MALFORMED_INNER] = CILIUM_SRV6_DROP_MALFORMED_INNER,
  [CILIUM_SRV6_END_CILIUM_ERROR_CONTEXT_IP_MISMATCH] = CILIUM_SRV6_DROP_CONTEXT_IP_MISMATCH,
  [CILIUM_SRV6_END_CILIUM_ERROR_DECAPSULATED] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

/* cilium-ep-deliver (03 §6, D-12). */
static const u8 ep_deliver_reasons[CILIUM_SRV6_EP_DELIVER_N_ERROR] = {
  [CILIUM_SRV6_EP_DELIVER_ERROR_CONTEXT_RECYCLED] = CILIUM_SRV6_DROP_CONTEXT_RECYCLED,
  [CILIUM_SRV6_EP_DELIVER_ERROR_DELIVERED] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

/* cilium-srv6-classify (02 §3, 01 §3.1). */
static const u8 classify_reasons[CILIUM_SRV6_CLASSIFY_N_ERROR] = {
  [CILIUM_SRV6_CLASSIFY_ERROR_UNKNOWN_SOURCE_EP] = CILIUM_SRV6_DROP_UNKNOWN_SOURCE_EP,
  [CILIUM_SRV6_CLASSIFY_ERROR_LINK_LOCAL_CONTROL] = CILIUM_SRV6_DROP_LINK_LOCAL_CONTROL,
  [CILIUM_SRV6_CLASSIFY_ERROR_SRC_IP_MISMATCH] = CILIUM_SRV6_DROP_SRC_IP_MISMATCH,
  [CILIUM_SRV6_CLASSIFY_ERROR_MALFORMED_INNER] = CILIUM_SRV6_DROP_MALFORMED_INNER,
  [CILIUM_SRV6_CLASSIFY_ERROR_FRAGMENT_UNRESOLVED] = CILIUM_SRV6_DROP_FRAGMENT_UNRESOLVED,
  [CILIUM_SRV6_CLASSIFY_ERROR_FRAGMENT_STALE_REINJECT] = CILIUM_SRV6_DROP_FRAGMENT_STALE_REINJECT,
  [CILIUM_SRV6_CLASSIFY_ERROR_POLICY_DENIED] = CILIUM_SRV6_DROP_POLICY_DENIED,
  [CILIUM_SRV6_CLASSIFY_ERROR_CLASSIFIED] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_CLASSIFY_ERROR_FRAGMENT_BYPASS] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

/* cilium-srv6-ct (02 §7.2, D-47). The stage drops nothing of its own. */
static const u8 ct_reasons[CILIUM_SRV6_CT_N_ERROR] = {
  [CILIUM_SRV6_CT_ERROR_FORWARD] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_CT_ERROR_REPLY_BYPASS] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_CT_ERROR_REPLY_REAUTH] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

/* cilium-srv6-program (02 §4.2). The punt_* counters are not drops: the
   packet goes to cilium-srv6-punt, which decides. */
static const u8 program_reasons[CILIUM_SRV6_PROGRAM_N_ERROR] = {
  [CILIUM_SRV6_PROGRAM_ERROR_POLICY_DENIED] = CILIUM_SRV6_DROP_POLICY_DENIED,
  [CILIUM_SRV6_PROGRAM_ERROR_MALFORMED_INNER] = CILIUM_SRV6_DROP_MALFORMED_INNER,
  [CILIUM_SRV6_PROGRAM_ERROR_ALLOWED] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PROGRAM_ERROR_PUNT_MISS] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PROGRAM_ERROR_PUNT_STALE] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PROGRAM_ERROR_PUNT_LEASE_EXPIRED] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PROGRAM_ERROR_PUNT_STALE_PATH] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

/* cilium-srv6-encap (02 §6, §9). stale_path and no_headroom are the two
   drops 06 §2 has no reason for; they get their own reasons rather than
   being folded into a neighbouring one (see cilium_srv6.api). */
static const u8 encap_reasons[CILIUM_SRV6_ENCAP_N_ERROR] = {
  [CILIUM_SRV6_ENCAP_ERROR_INNER_MTU_EXCEEDED] = CILIUM_SRV6_DROP_INNER_MTU_EXCEEDED,
  [CILIUM_SRV6_ENCAP_ERROR_SRV6_NOT_READY] = CILIUM_SRV6_DROP_SRV6_NOT_READY,
  [CILIUM_SRV6_ENCAP_ERROR_STALE_PATH] = CILIUM_SRV6_DROP_ENCAP_STALE_PATH,
  [CILIUM_SRV6_ENCAP_ERROR_NO_HEADROOM] = CILIUM_SRV6_DROP_ENCAP_NO_HEADROOM,
  [CILIUM_SRV6_ENCAP_ERROR_ENCAPSULATED] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

/* cilium-srv6-punt (02 §5.2). */
static const u8 punt_reasons[CILIUM_SRV6_PUNT_N_ERROR] = {
  [CILIUM_SRV6_PUNT_ERROR_SLOWPATH_OVERFLOW] = CILIUM_SRV6_DROP_SLOWPATH_OVERFLOW,
  [CILIUM_SRV6_PUNT_ERROR_PUNTED] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

/* cilium-srv6-ptb (02 §9, D-36). None of these is a drop: the node
   classifies an ICMPv6 Packet Too Big and passes every packet to ip6-punt.
   They are the `reason` labels of ptb_rejected_total (06 §3). */
static const u8 ptb_reasons[CILIUM_SRV6_PTB_N_ERROR] = {
  [CILIUM_SRV6_PTB_ERROR_ACCEPTED] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_PATH_UNUSABLE] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_NOT_READY] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_UNTRUSTED_INGRESS] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_SOURCE_NOT_IN_DOMAIN] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_MALFORMED] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_QUOTE_NOT_OURS] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_NO_RECORD] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_STALE_RECORD] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_SIZE_MISMATCH] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_STALE_PATH] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_DA_MISMATCH] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_INNER_MISMATCH] = CILIUM_SRV6_DROP_NOT_A_DROP,
  [CILIUM_SRV6_PTB_ERROR_MTU_OUT_OF_RANGE] = CILIUM_SRV6_DROP_NOT_A_DROP,
};

#define CILIUM_SRV6_COUNTER_NODE(name_, table_, descs_)                                            \
  {                                                                                                \
    .node_name = name_, .reasons = table_, .descs = descs_, .n_errors = ARRAY_LEN (table_),        \
    .node_index = ~0,                                                                              \
  }

static cilium_srv6_counter_node_t cilium_srv6_counter_nodes[] = {
  CILIUM_SRV6_COUNTER_NODE ("cilium-srv6-guard", guard_reasons, cilium_srv6_guard_error_counters),
  CILIUM_SRV6_COUNTER_NODE ("cilium-srv6-classify", classify_reasons,
			    cilium_srv6_classify_error_counters),
  CILIUM_SRV6_COUNTER_NODE ("cilium-srv6-ct", ct_reasons, cilium_srv6_ct_error_counters),
  CILIUM_SRV6_COUNTER_NODE ("cilium-srv6-program", program_reasons,
			    cilium_srv6_program_error_counters),
  CILIUM_SRV6_COUNTER_NODE ("cilium-srv6-encap", encap_reasons, cilium_srv6_encap_error_counters),
  CILIUM_SRV6_COUNTER_NODE ("cilium-srv6-punt", punt_reasons, cilium_srv6_punt_error_counters),
  CILIUM_SRV6_COUNTER_NODE ("cilium-srv6-ptb", ptb_reasons, cilium_srv6_ptb_error_counters),
  CILIUM_SRV6_COUNTER_NODE ("cilium-end-cilium", end_cilium_reasons,
			    cilium_srv6_end_cilium_error_counters),
  CILIUM_SRV6_COUNTER_NODE ("cilium-ep-deliver", ep_deliver_reasons,
			    cilium_srv6_ep_deliver_error_counters),
};

/* ------------------------------------------------------------------ */
/* init-time validation                                                */
/* ------------------------------------------------------------------ */

/*
 * 06 §1 as a checked property.
 *
 * Two failures are caught:
 *   - a counter with no reason (CILIUM_SRV6_DROP_UNSET), i.e. somebody added
 *     a counter to a counters block and did not classify it,
 *   - a table whose length no longer matches the node's registered n_errors,
 *     i.e. the node and this file drifted apart.
 *
 * Both are returned as an init error. A plugin that cannot explain its own
 * drops must not forward packets: the whole fail-closed argument of NFR-1 is
 * checked through these counters.
 */
static clib_error_t *
cilium_srv6_counters_init (vlib_main_t *vm)
{
  u32 i, code;

  for (i = 0; i < ARRAY_LEN (cilium_srv6_counter_nodes); i++)
    {
      cilium_srv6_counter_node_t *cn = &cilium_srv6_counter_nodes[i];
      vlib_node_t *n = vlib_get_node_by_name (vm, (u8 *) cn->node_name);

      if (n == NULL)
	return clib_error_return (0,
				  "cilium_srv6: counter inventory names an "
				  "unregistered graph node `%s'",
				  cn->node_name);

      if (n->n_errors != cn->n_errors)
	return clib_error_return (0,
				  "cilium_srv6: node `%s' registers %u error "
				  "counters but the 06 §2 inventory has %u",
				  cn->node_name, (u32) n->n_errors, cn->n_errors);

      cn->node_index = n->index;

      for (code = 0; code < cn->n_errors; code++)
	{
	  if (cn->reasons[code] == CILIUM_SRV6_DROP_UNSET ||
	      cn->reasons[code] >= CILIUM_SRV6_DROP_N_REASON)
	    return clib_error_return (0,
				      "cilium_srv6: counter `%s/%s' is not "
				      "bound to a 06 §2 drop reason; 06 §1 "
				      "forbids an unclassified drop",
				      cn->node_name, cn->descs[code].name);
	}
    }

  return 0;
}

/* No ordering constraint is needed: vlib_main() calls vlib_node_main_init()
   — which registers every node and its error counters — before it calls any
   init function, so n_errors is final by the time this runs. */
VLIB_INIT_FUNCTION (cilium_srv6_counters_init);

/* ------------------------------------------------------------------ */
/* read-out                                                            */
/* ------------------------------------------------------------------ */

/*
 * Sum one error counter over every worker thread, honouring the value the
 * last `clear errors` recorded. Same accounting as `show errors`.
 */
static u64
cilium_srv6_counter_sum (u32 error_index)
{
  u64 total = 0;

  foreach_vlib_main ()
    {
      vlib_error_main_t *em = &this_vlib_main->error_main;
      u64 c;

      if (error_index >= vec_len (em->counters))
	continue;

      c = em->counters[error_index];
      if (error_index < vec_len (em->counters_last_clear))
	c -= em->counters_last_clear[error_index];
      total += c;
    }

  return total;
}

void
cilium_srv6_counters_foreach (vlib_main_t *vm, u32 reason_filter, cilium_srv6_counter_fn fn,
			      void *opaque)
{
  u32 i, code;

  for (i = 0; i < ARRAY_LEN (cilium_srv6_counter_nodes); i++)
    {
      const cilium_srv6_counter_node_t *cn = &cilium_srv6_counter_nodes[i];
      vlib_node_t *n;

      if (cn->node_index == (u32) ~0)
	continue;

      n = vlib_get_node (vm, cn->node_index);
      if (n == NULL || n->n_errors != cn->n_errors)
	continue;

      for (code = 0; code < cn->n_errors; code++)
	{
	  cilium_srv6_counter_record_t r;

	  if (reason_filter != (u32) ~0 && cn->reasons[code] != reason_filter)
	    continue;

	  r.node_name = cn->node_name;
	  r.counter_name = cn->descs[code].name;
	  r.counter_desc = cn->descs[code].desc;
	  r.reason = cn->reasons[code];
	  r.severity = (u8) cn->descs[code].severity;
	  r.value = cilium_srv6_counter_sum (n->error_heap_index + code);

	  fn (&r, opaque);
	}
    }
}

static void
cilium_srv6_counters_total_fn (const cilium_srv6_counter_record_t *r, void *opaque)
{
  u64 *totals = opaque;

  totals[r->reason] += r->value;
}

void
cilium_srv6_counters_totals (vlib_main_t *vm, u64 *totals)
{
  clib_memset (totals, 0, CILIUM_SRV6_DROP_N_REASON * sizeof (u64));
  cilium_srv6_counters_foreach (vm, ~0, cilium_srv6_counters_total_fn, totals);
}

/* ------------------------------------------------------------------ */
/* CLI (06 §4.2: `show cilium srv6 errors`)                            */
/* ------------------------------------------------------------------ */

typedef struct
{
  vlib_main_t *vm;
  int verbose;
  u32 n_printed;
} cilium_srv6_errors_cli_t;

static void
cilium_srv6_errors_cli_fn (const cilium_srv6_counter_record_t *r, void *opaque)
{
  cilium_srv6_errors_cli_t *c = opaque;

  if (r->value == 0 && !c->verbose)
    return;

  vlib_cli_output (c->vm, "%-20llu %-28s %-26s %s", r->value,
		   cilium_srv6_drop_reason_name (r->reason), r->node_name, r->counter_name);
  c->n_printed++;
}

static clib_error_t *
cilium_srv6_show_errors_command_fn (vlib_main_t *vm, unformat_input_t *input,
				    vlib_cli_command_t *cmd)
{
  cilium_srv6_errors_cli_t ctx = { .vm = vm, .verbose = 0, .n_printed = 0 };
  u64 totals[CILIUM_SRV6_DROP_N_REASON];
  u64 drops = 0;
  u32 reason;

  if (unformat (input, "verbose"))
    ctx.verbose = 1;
  else if (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);

  cilium_srv6_counters_totals (vm, totals);

  vlib_cli_output (vm, "Drop totals by 06 §2 reason:");
  vlib_cli_output (vm, "%-28s %-20s %s", "reason", "packets", "meaning");

  for (reason = CILIUM_SRV6_DROP_NOT_A_DROP + 1; reason < CILIUM_SRV6_DROP_N_REASON; reason++)
    {
      if (totals[reason] == 0 && !ctx.verbose)
	continue;
      vlib_cli_output (vm, "%-28s %-20llu %s", cilium_srv6_drop_reason_name (reason),
		       totals[reason], cilium_srv6_drop_reason_desc (reason));
      drops += totals[reason];
    }

  if (drops == 0 && !ctx.verbose)
    vlib_cli_output (vm, "  (no drop counted; `show cilium srv6 errors verbose' lists every reason)");

  /*
   * 06 §2 lists two reasons the dataplane never produces: the headend slow
   * path decides them (pkg/srv6ec/compiler). Naming them here keeps an
   * operator from reading their absence as "this reason is not implemented".
   */
  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "DROP_NO_REMOTE_ENDPOINT and DROP_IDENTITY_UNRESOLVED are decided by the");
  vlib_cli_output (vm, "agent slow path (C4); read them with `cilium-dbg srv6 drops'.");

  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "Per counter:");
  vlib_cli_output (vm, "%-20s %-28s %-26s %s", "packets", "reason", "node", "counter");
  cilium_srv6_counters_foreach (vm, ~0, cilium_srv6_errors_cli_fn, &ctx);

  if (ctx.n_printed == 0)
    vlib_cli_output (vm, "  (all zero)");

  return 0;
}

/*
 * 06 §4 asks for this command explicitly, as the first-line investigation
 * tool "for when the agent is down" — which is exactly when the Prometheus
 * path of 06 §3 is unavailable.
 */
VLIB_CLI_COMMAND (cilium_srv6_show_errors_command, static) = {
  .path = "show cilium srv6 errors",
  .short_help = "show cilium srv6 errors [verbose]",
  .function = cilium_srv6_show_errors_command_fn,
};
