/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — infrastructure guard / ACL (C8-a), plugin CLI.
 *
 * design/detail/06-observability.md §4.2 asks for a guard/ACL installation
 * audit (`cilium-dbg srv6 acl-status`) and §4 asks for a VPP-side plugin
 * CLI usable while the agent is down. This is the VPP-side view.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/interface.h>
#include <vnet/interface_funcs.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_context.h>
#include <cilium_srv6/cilium_srv6_endcilium.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_ct.h>

static clib_error_t *
cilium_srv6_show_guard_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  vnet_main_t *vnm = vnet_get_main ();
  cilium_srv6_guard_if_t *e;
  f64 now = vlib_time_now (vm);
  u32 i;

  /* D-60: SRV6_BLOCK has no production default, so an operator has to be able
     to see whether the running block came from the configuration or from the
     test-only fallback. */
  vlib_cli_output (vm, "SRV6_BLOCK           : %U/%u (%s)", format_ip6_address, &cm->block,
		   (u32) cm->block_len,
		   cm->block_configured ? "configured" : "TEST DEFAULT, not configured");
  vlib_cli_output (vm,
		   "guard coverage       : %s (%u interface%s without "
		   "the guard installed)",
		   cilium_srv6_guard_coverage_complete (cm) ? "COMPLETE" : "INCOMPLETE",
		   cm->n_uncovered, cm->n_uncovered == 1 ? "" : "s");
  vlib_cli_output (vm, "context install      : %s",
		   cilium_srv6_guard_context_install_allowed () ? "allowed" : "BLOCKED");
  vlib_cli_output (vm,
		   "interfaces           : %u total, %u quarantined, "
		   "%u untrusted, %u trusted-fabric",
		   cm->n_valid, cm->n_quarantined, cm->n_untrusted, cm->n_trusted_fabric);
  vlib_cli_output (vm,
		   "agent keepalive      : %s, last %.1f s ago, "
		   "timeout %.1f s",
		   cm->keepalive_seen ? "seen" : "never received", now - cm->keepalive_last,
		   cm->keepalive_timeout);
  vlib_cli_output (vm, "dead-man switch      : %s, %llu activation%s",
		   cm->deadman_active ? "ACTIVE" : "idle", cm->deadman_activations,
		   cm->deadman_activations == 1 ? "" : "s");
  vlib_cli_output (vm,
		   "quarantine hysteresis: min hold %.1f s, route "
		   "withdraw delay %.1f s",
		   cm->quarantine_min_hold, cm->withdraw_delay);
  /* D-54: the fragment inspection rules are fixed; this is the one
     deployment-selectable part of them, so it has to be visible. */
  vlib_cli_output (vm, "untrusted fragments  : %s",
		   cm->untrusted_fragment_drop_all ?
		     "DROPPED unconditionally (untrusted-fragment-drop-all)" :
		     "inspected (offset-zero fragment must be fully inspectable)");
  vlib_cli_output (vm, "");

  vlib_cli_output (vm, "%-30s %10s %-15s %6s %6s %10s %10s", "interface", "incarn", "trust",
		   "guard", "promo", "hold(ms)", "wdraw(ms)");

  for (i = 0; i < vec_len (cm->ifs); i++)
    {
      e = vec_elt_at_index (cm->ifs, i);

      if (!e->valid)
	continue;

      vlib_cli_output (vm, "%-30U %10u %-15U %6s %6s %10u %10u", format_vnet_sw_if_index_name, vnm,
		       i, e->incarnation, format_cilium_srv6_trust, (u32) e->trust,
		       e->guard_installed ? "yes" : "NO", e->promotable ? "yes" : "no",
		       cilium_srv6_quarantine_hold_remaining_ms (e),
		       cilium_srv6_withdraw_delay_remaining_ms (e));
    }

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_guard_command, static) = {
  .path = "show cilium srv6 guard",
  .short_help = "show cilium srv6 guard",
  .function = cilium_srv6_show_guard_command_fn,
};

static clib_error_t *
cilium_srv6_set_acl_command_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  vnet_main_t *vnm = vnet_get_main ();
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 sw_if_index = ~0;
  u32 trust = ~0;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected an interface and a trust value");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_vnet_sw_interface, vnm, &sw_if_index))
	;
      else if (unformat (line_input, "quarantined"))
	trust = CILIUM_SRV6_TRUST_QUARANTINED;
      else if (unformat (line_input, "untrusted"))
	trust = CILIUM_SRV6_TRUST_UNTRUSTED;
      else if (unformat (line_input, "trusted-fabric"))
	trust = CILIUM_SRV6_TRUST_TRUSTED_FABRIC;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (sw_if_index == (u32) ~0 || trust == (u32) ~0)
    {
      error = clib_error_return (0, "expected an interface and a trust value");
      goto done;
    }

  if (sw_if_index >= vec_len (cm->ifs) || !cm->ifs[sw_if_index].valid)
    {
      error = clib_error_return (0, "interface is not under guard control");
      goto done;
    }

  /* The CLI uses the interface's current incarnation; the API path
     requires the caller to supply it (D-31). */
  rv = cilium_srv6_acl_interface_set (sw_if_index, cm->ifs[sw_if_index].incarnation, (u8) trust);
  if (rv)
    error = clib_error_return (0, "rejected (%d)", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (cilium_srv6_set_acl_command, static) = {
  .path = "set cilium srv6 acl",
  .short_help = "set cilium srv6 acl <interface> <quarantined|untrusted|trusted-fabric>",
  .function = cilium_srv6_set_acl_command_fn,
};

/* ------------------------------------------------------------------ */
/* EndpointContextTable / tombstone store (C8-c)                       */
/* ------------------------------------------------------------------ */

/* 06 §4.2 `cilium-dbg srv6 capacity`: ACTIVE reservation, tombstone and
 * churn quota pressure. Also the VPP-side view of the 06 §3 context_*
 * gauges when the agent is down (06 §4). */
static void
cilium_srv6_show_capacity (vlib_main_t *vm)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  u32 n_owners = (u32) pool_elts (cxm->ts_owners);

  vlib_cli_output (vm, "ACTIVE pool          : %u/%u used, %u active, %u suspended, "
		       "%u reserved (grace period)",
		   cilium_srv6_context_n_reserved (), cxm->active_capacity, cxm->n_active,
		   cxm->n_suspended, cilium_srv6_context_n_grace_pending ());
  vlib_cli_output (vm, "  capacity rejections: %llu (ERR_ACTIVE_CAPACITY), %llu blocked by "
		       "guard/dead-man",
		   cxm->n_capacity_rejections, cxm->n_install_blocked);
  vlib_cli_output (vm, "tombstone store      : %u/%u used, %u owner%s, soft quota %u/owner",
		   (u32) pool_elts (cxm->tombstones), cxm->tombstone_capacity, n_owners,
		   n_owners == 1 ? "" : "s",
		   clib_max (1, cxm->tombstone_capacity / clib_max (1, n_owners)));
  vlib_cli_output (vm, "  retention %.0f s, %llu evicted, %llu record failures (%llu full, "
		       "%llu quota), %llu GC reclaimed",
		   cxm->tombstone_retention, cxm->n_tombstone_evictions,
		   cxm->n_tombstone_record_failures_full + cxm->n_tombstone_record_failures_quota,
		   cxm->n_tombstone_record_failures_full, cxm->n_tombstone_record_failures_quota,
		   cxm->n_tombstone_gc_reclaimed);
  vlib_cli_output (vm, "grace period         : %.1f s, %llu completed, seq %llu..%llu readable",
		   cxm->grace_period, cxm->n_grace_completions,
		   cilium_srv6_grace_log_oldest_seq (), cxm->grace_next_seq);
  vlib_cli_output (vm, "totals               : %llu adds, %llu invalidates",
		   cxm->n_adds, cxm->n_invalidates);
}

static clib_error_t *
cilium_srv6_show_context_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vnet_main_t *vnm = vnet_get_main ();
  cilium_srv6_context_entry_t *e;
  u32 want_id = ~0;
  u32 index;
  int verbose = 0;

  if (!cxm->initialised)
    return clib_error_return (0, "Context tables are not initialised");

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "0x%x", &want_id))
	;
      else if (unformat (input, "%u", &want_id))
	;
      else if (unformat (input, "verbose"))
	verbose = 1;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  cilium_srv6_show_capacity (vm);
  vlib_cli_output (vm, "");

  /*
   * 03 §3 resolution order for a single Context ID: ActiveContextTable
   * first, ContextTombstoneTable only on a miss. Shows which drop reason a
   * packet for this ID would produce, which is what changes across a
   * tombstone eviction or a retention GC.
   */
  if (want_id != (u32) ~0)
    {
      u32 pool_index = ~0;

      switch (cilium_srv6_context_resolve (want_id, &pool_index))
	{
	case CILIUM_SRV6_CTX_FOUND:
	  e = cilium_srv6_context_entry_at (pool_index);
	  vlib_cli_output (vm, "context 0x%08x: ActiveContextTable hit, pool index %u, state %U",
			   want_id, pool_index, format_cilium_srv6_context_state,
			   e ? (u32) e->state : (u32) CILIUM_SRV6_CONTEXT_INVALID);
	  if (e && e->state != CILIUM_SRV6_CONTEXT_ACTIVE)
	    vlib_cli_output (vm, "  a packet would drop as DROP_SRV6_NOT_READY");
	  break;
	case CILIUM_SRV6_CTX_INVALIDATED:
	  vlib_cli_output (vm, "context 0x%08x: ContextTombstoneTable hit, a packet would drop "
			       "as DROP_INVALID_CONTEXT",
			   want_id);
	  break;
	case CILIUM_SRV6_CTX_UNKNOWN:
	  vlib_cli_output (vm, "context 0x%08x: not found, a packet would drop as "
			       "DROP_UNKNOWN_CONTEXT",
			   want_id);
	  break;
	}
      vlib_cli_output (vm, "");
    }

  if (want_id == (u32) ~0 && !verbose)
    return 0;

  vlib_cli_output (vm, "%-12s %-10s %8s %-30s %-20s %10s %14s %10s", "context", "state", "gen",
		   "endpoint", "interface", "dpo", "packets", "grace(ms)");

  {
    f64 now = vlib_time_now (vm);

    pool_foreach (e, cxm->entries)
      {
	if (want_id != (u32) ~0 && e->context_id != want_id)
	  continue;

	vlib_cli_output (vm, "0x%08x   %-10U %8u %-30U %-20U %10u %14llu %10u", e->context_id,
			 format_cilium_srv6_context_state, (u32) e->state, e->entry_generation,
			 format_ip6_address, &e->endpoint_ip, format_vnet_sw_if_index_name, vnm,
			 e->tx_sw_if_index, e->dpo_index, e->pkts,
			 cilium_srv6_grace_remaining_ms (e->context_id, now));
      }
  }

  if (!verbose)
    return 0;

  vlib_cli_output (vm, "");
  vlib_cli_output (vm, "%-12s %-14s %14s", "tombstone", "owner-class", "age(s)");

  {
    f64 now = vlib_time_now (vm);

    for (index = cxm->ts_age_head; index != (u32) ~0;)
      {
	const cilium_srv6_tombstone_t *t = pool_elt_at_index (cxm->tombstones, index);

	if (want_id == (u32) ~0 || t->context_id == want_id)
	  vlib_cli_output (vm, "0x%08x   %-14u %14.1f", t->context_id, t->owner_quota_class,
			   now - t->invalidated_at);

	index = t->age_next;
      }
  }

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_context_command, static) = {
  .path = "show cilium srv6 context",
  .short_help = "show cilium srv6 context [<context-id>] [verbose]",
  .function = cilium_srv6_show_context_command_fn,
};

/*
 * 03 §1.1 fail-closed ladder: when immediate quarantine cannot be
 * guaranteed, every ACTIVE Context is moved to SUSPENDED under the worker
 * barrier so that delivery stops without invalidating any Context. The
 * automatic trigger belongs to the End.Cilium local SID path (C8-b), which
 * does not exist yet; this CLI exercises the transition.
 */
static clib_error_t *
cilium_srv6_set_context_delivery_command_fn (vlib_main_t *vm, unformat_input_t *input,
					     vlib_cli_command_t *cmd)
{
  if (unformat (input, "suspend"))
    cilium_srv6_context_suspend_all ("operator request via CLI");
  else if (unformat (input, "resume"))
    cilium_srv6_context_resume_all ("operator request via CLI");
  else
    return clib_error_return (0, "expected `suspend' or `resume'");

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_set_context_delivery_command, static) = {
  .path = "set cilium srv6 context delivery",
  .short_help = "set cilium srv6 context delivery <suspend|resume>",
  .function = cilium_srv6_set_context_delivery_command_fn,
};

/* ------------------------------------------------------------------ */
/* End.Cilium local SID / SR domain node set (C8-b)                    */
/* ------------------------------------------------------------------ */

/* 06 §4: a VPP-side view usable for first-line investigation while the
 * agent is down. */
static clib_error_t *
cilium_srv6_show_endcilium_command_fn (vlib_main_t *vm, unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  u32 i;

  if (!em->initialised)
    return clib_error_return (0, "End.Cilium is not initialised");

  vlib_cli_output (vm, "locator             : %s", em->locator_set ? "set" : "NOT SET");
  if (em->locator_set)
    {
      vlib_cli_output (vm, "  local SID         : %U/%u (uN_B 0x%04x, uC 0x%04x)",
		       format_ip6_address, &em->localsid,
		       (u32) CILIUM_SRV6_LOCALSID_PREFIX_LEN, (u32) em->un_node, (u32) em->uc);
      vlib_cli_output (vm, "  FIB               : table %u, fib-index %u, entry %s", em->table_id,
		       em->fib_index, em->localsid_installed ? "installed" : "REMOVED");
    }
  vlib_cli_output (vm, "delivery            : %s (%llu suspend%s, %llu local SID install%s)",
		   em->delivery_suspended ? "SUSPENDED (03 §1.1 fail-closed ladder)" : "enabled",
		   em->n_delivery_suspends, em->n_delivery_suspends == 1 ? "" : "s",
		   em->n_localsid_installs, em->n_localsid_installs == 1 ? "" : "s");
  vlib_cli_output (vm, "guard coverage      : %s",
		   cilium_srv6_guard_coverage_complete (cm) ? "COMPLETE" : "INCOMPLETE");
  vlib_cli_output (vm, "conntrack hook (C10): %s",
		   cilium_srv6_ct_create_hook ? "registered" : "not registered (skipped)");
  vlib_cli_output (vm, "");

  vlib_cli_output (vm, "SR domain node set  : %u/%u prefix%s%s", em->n_sr_domain,
		   (u32) CILIUM_SRV6_SR_DOMAIN_MAX_PREFIXES, em->n_sr_domain == 1 ? "" : "es",
		   em->n_sr_domain == 0 ? " — every packet drops as DROP_UNTRUSTED_SOURCE" : "");

  for (i = 0; i < em->n_sr_domain; i++)
    vlib_cli_output (vm, "  %U", format_cilium_srv6_sr_domain, em->sr_domain + i);

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_endcilium_command, static) = {
  .path = "show cilium srv6 end-cilium",
  .short_help = "show cilium srv6 end-cilium",
  .function = cilium_srv6_show_endcilium_command_fn,
};

static clib_error_t *
cilium_srv6_set_sr_domain_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  ip6_address_t prefix;
  u32 len = ~0;
  u8 is_add = 1;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected a prefix");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U/%u", unformat_ip6_address, &prefix, &len))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (len == (u32) ~0 || len > 128)
    {
      error = clib_error_return (0, "expected <prefix>/<len>");
      goto done;
    }

  rv = cilium_srv6_sr_domain_prefix_add_del (&prefix, (u8) len, is_add);
  if (rv)
    error = clib_error_return (0, "rejected (%d)", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (cilium_srv6_set_sr_domain_command, static) = {
  .path = "set cilium srv6 sr-domain",
  .short_help = "set cilium srv6 sr-domain <prefix>/<len> [del]",
  .function = cilium_srv6_set_sr_domain_command_fn,
};

static clib_error_t *
cilium_srv6_set_uc_locator_command_fn (vlib_main_t *vm, unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = 0;
  u32 un_node = ~0;
  u32 uc = ~0;
  u32 table_id = 0;
  u8 is_add = 1;
  int rv;

  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected un-node and uc");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "un-node 0x%x", &un_node))
	;
      else if (unformat (line_input, "un-node %u", &un_node))
	;
      else if (unformat (line_input, "uc 0x%x", &uc))
	;
      else if (unformat (line_input, "uc %u", &uc))
	;
      else if (unformat (line_input, "table %u", &table_id))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'", format_unformat_error, line_input);
	  goto done;
	}
    }

  if (is_add && (un_node > 0xffff || uc > 0xffff))
    {
      error = clib_error_return (0, "expected un-node <0..65535> and uc <0..65535>");
      goto done;
    }

  rv = cilium_srv6_uc_locator_set (table_id, (u16) un_node, (u16) uc, is_add);
  if (rv)
    error = clib_error_return (0, "rejected (%d)", rv);

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (cilium_srv6_set_uc_locator_command, static) = {
  .path = "set cilium srv6 uc-locator",
  .short_help = "set cilium srv6 uc-locator un-node <n> uc <n> [table <id>] [del]",
  .function = cilium_srv6_set_uc_locator_command_fn,
};

/* ------------------------------------------------------------------ */
/* headend (C7, 02 §2 / §4 / §5)                                       */
/* ------------------------------------------------------------------ */

/*
 * 06 §4.2 lists `cilium-dbg srv6 program-cache` and `cilium-dbg srv6 paths`
 * as agent CLI; 06 §4 additionally asks for a VPP-side plugin CLI usable
 * while the agent is down. These are that view of the headend tables.
 */
static clib_error_t *
cilium_srv6_show_headend_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_policy_rev_t *r;
  u32 n_local = 0;
  u32 n_leased = 0;
  f64 now;
  u32 i;

  if (!hm->initialised)
    return clib_error_return (0, "headend tables not built yet");

  now = vlib_time_now (vm);

  for (i = 0; i < vec_len (hm->local_eps); i++)
    if (hm->local_eps[i].valid)
      n_local++;

  /* D-51: how many identities currently hold a usable lease. A drop to zero
     while entries remain is what a policy watcher outage looks like from
     here. */
  pool_foreach (r, hm->policy_rev)
    {
      if (r->identity != (u32) ~0 && r->lease_revision != CILIUM_SRV6_REV_INVALID &&
	  r->lease_valid_until > now)
	n_leased++;
    }

  vlib_cli_output (vm, "outer header (01 §1): %s", hm->configured ? "configured" : "NOT CONFIGURED "
								    "(cilium-srv6-encap drops "
								    "DROP_SRV6_NOT_READY)");
  if (hm->configured)
    vlib_cli_output (vm,
		     "  source %U, fib-index %u (table %u), hop-limit %u, "
		     "inner mtu %u, dscp copy %s",
		     format_ip6_address, &hm->node_address, hm->outer_fib_index, hm->outer_table_id,
		     (u32) hm->hop_limit, (u32) hm->inner_mtu, hm->copy_dscp ? "on" : "off");

  vlib_cli_output (vm,
		   "revisions: endpoint %llu, path %llu\n"
		   "PolicyLeaseTable: %u/%u identities, %u leased now, "
		   "install-time lease %.1f s, %llu renewals (D-51)",
		   hm->endpoint_revision, hm->path_revision, (u32) pool_elts (hm->policy_rev) - 1,
		   hm->policy_rev_capacity, n_leased, (f64) hm->allow_lease_ms * 1e-3,
		   hm->n_lease_extends);

  vlib_cli_output (vm, "LocalEndpointTable: %u endpoints", n_local);

  vlib_cli_output (vm,
		   "ProgramCache: %u/%u ALLOW, %u/%u negative "
		   "(installs %llu, deletes %llu, quota drops %llu, fair evictions %llu, "
		   "stale installs %llu)",
		   hm->n_programs[1], hm->program_capacity - hm->program_negative_capacity,
		   hm->n_programs[0], hm->program_negative_capacity, hm->n_program_installs,
		   hm->n_program_deletes, hm->n_program_quota_drops, hm->n_program_fair_evictions,
		   hm->n_program_stale_installs);

  /* D-61: the reservations of an open staging transaction hold pool slots but
     are not entries of the PathCache, so they are reported separately rather
     than counted as installed paths. */
  vlib_cli_output (vm,
		   "PathCache: %u/%u entries, %u retired awaiting the grace period, "
		   "%u staged in transaction 0x%016llx",
		   (u32) pool_elts (hm->paths) - hm->path_txn_reserved, hm->path_capacity,
		   vec_len (hm->path_pending), vec_len (hm->path_staged),
		   (unsigned long long) hm->path_txn_id);

  vlib_cli_output (vm,
		   "FragmentVerdictCache: %u/%u entries, timeout %.0f s "
		   "(evictions %llu, quota drops %llu, expired %llu, "
		   "IF-2 ALLOW refused for want of a lease %llu, "
		   "IF-2 refused for a punt_id conflict %llu)",
		   hm->n_frags, hm->frag_capacity, hm->frag_timeout, hm->n_frag_evictions,
		   hm->n_frag_quota_drops, hm->n_frag_gc, hm->n_frag_lease_rejects,
		   hm->n_frag_punt_id_conflicts);

  vlib_cli_output (vm, "conntrack hook (C10): %s, IF-3 punt transport: %s",
		   cilium_srv6_ct_lookup_hook ? "registered" :
					        "absent (every packet takes 02 §7.2 branch 3)",
		   cilium_srv6_punt_transport_registered () ? "registered" :
							      "absent (every punt fails closed)");

  for (i = 0; i < CILIUM_SRV6_PUNT_N_Q; i++)
    {
      const cilium_srv6_punt_queue_state_t *q = hm->punt_q + i;

      vlib_cli_output (vm,
		       "punt queue %-12U outstanding %u/%u (owner quota %u, identity quota %u)\n"
		       "    punted %llu, reinjected %llu, rejected %llu, expired %llu\n"
		       "    drops: global %llu, owner %llu, identity %llu, "
		       "no-token %llu, no-transport %llu",
		       format_cilium_srv6_punt_queue, i, q->n_outstanding, q->capacity,
		       q->owner_quota, q->identity_quota, q->n_punted, q->n_reinjected,
		       q->n_reinject_rejected, q->n_expired, q->n_drop_global, q->n_drop_owner,
		       q->n_drop_identity, q->n_drop_no_token, q->n_drop_no_transport);
    }

  /* Issue #90: a reinject whose echoed punt_id is not the one its token was
     issued with. Expected 0; a non-zero value means the agent is not echoing
     the punt metadata it received. */
  vlib_cli_output (vm, "IF-3 reinjects refused for a punt_id mismatch: %llu",
		   hm->n_reinject_punt_id_mismatch);

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_headend_command, static) = {
  .path = "show cilium srv6 headend",
  .short_help = "show cilium srv6 headend",
  .function = cilium_srv6_show_headend_command_fn,
};

static clib_error_t *
cilium_srv6_show_local_ep_command_fn (vlib_main_t *vm, unformat_input_t *input,
				      vlib_cli_command_t *cmd)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  vnet_main_t *vnm = vnet_get_main ();
  u32 i;

  if (!hm->initialised)
    return clib_error_return (0, "headend tables not built yet");

  for (i = 0; i < vec_len (hm->local_eps); i++)
    {
      const cilium_srv6_local_ep_t *e = hm->local_eps + i;
      u32 live;

      if (!e->valid)
	continue;

      live = (i < vec_len (cm->ifs)) ? cm->ifs[i].incarnation : (u32) ~0;

      vlib_cli_output (vm,
		       "%U: identity %u ip %U context %u owner %u\n"
		       "  incarnation %u (live %u)%s, policy revision %llu",
		       format_vnet_sw_if_index_name, vnm, i, e->identity, format_ip6_address, &e->ip,
		       e->local_context_id, e->owner_quota_class, e->if_incarnation, live,
		       (live == e->if_incarnation) ? "" : " STALE (D-31: will not resolve)",
		       cilium_srv6_policy_revision (hm, e->policy_rev_slot));
    }

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_local_ep_command, static) = {
  .path = "show cilium srv6 local-endpoints",
  .short_help = "show cilium srv6 local-endpoints",
  .function = cilium_srv6_show_local_ep_command_fn,
};

static clib_error_t *
cilium_srv6_show_paths_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_path_t *p;

  if (!hm->initialised)
    return clib_error_return (0, "headend tables not built yet");

  pool_foreach (p, hm->paths)
    {
      u16 learned = 0;

      /* D-61: a slot an open transaction reserved is not a PathCache entry.
	 Its handle is not usable and must not be shown as one. */
      if (p->state == CILIUM_SRV6_PATH_FREE)
	continue;

      if (p->mtu_index < hm->path_capacity && !pool_is_free_index (hm->path_mtus, p->mtu_index))
	learned = hm->path_mtus[p->mtu_index].effective_mtu;

      vlib_cli_output (vm,
		       "[%u gen %u] path-id 0x%016llx %s\n"
		       "  da %U service-sid %U srh %u bytes, %u shift states\n"
		       "  mtu: base %u, learned %u, effective %u",
		       (u32) (p - hm->paths), p->generation, p->path_id,
		       (p->state == CILIUM_SRV6_PATH_PUBLISHED) ? "published" : "RETIRED",
		       format_ip6_address, &p->da_template, format_ip6_address, &p->service_sid,
		       (u32) p->srh_len, (u32) p->n_shift_states, (u32) p->base_mtu,
		       (u32) learned, (u32) cilium_srv6_path_effective_mtu (hm, p));
    }

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_paths_command, static) = {
  .path = "show cilium srv6 paths",
  .short_help = "show cilium srv6 paths",
  .function = cilium_srv6_show_paths_command_fn,
};

static clib_error_t *
cilium_srv6_show_program_cache_command_fn (vlib_main_t *vm, unformat_input_t *input,
					   vlib_cli_command_t *cmd)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 filter_identity = ~0;
  u32 max = 64;
  u32 index, n = 0;
  f64 now;

  if (!hm->initialised)
    return clib_error_return (0, "headend tables not built yet");

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "identity %u", &filter_identity))
	    ;
	  else if (unformat (line_input, "max %u", &max))
	    ;
	  else
	    {
	      unformat_free (line_input);
	      return clib_error_return (0, "unknown input");
	    }
	}
      unformat_free (line_input);
    }

  now = vlib_time_now (vm);

  for (index = 0; index < hm->program_capacity && n < max; index++)
    {
      const cilium_srv6_program_t *e;
      ip6_address_t dst;
      f64 lease_left;
      int stale;

      if (pool_is_free_index (hm->programs, index))
	continue;

      e = hm->programs + index;

      if (!e->in_use)
	continue;

      if (filter_identity != (u32) ~0 && e->src_identity != filter_identity)
	continue;

      dst.as_u64[0] = e->key[0];
      dst.as_u64[1] = e->key[1];

      stale = !cilium_srv6_revisions_match (hm, e->policy_rev_slot, e->policy_revision,
					    e->endpoint_revision, e->path_revision);

      /* D-51: the lease belongs to the entry's dependency identity, not to
	 the entry, so it is read from the PolicyLeaseTable. */
      lease_left = (e->verdict == CILIUM_SRV6_VERDICT_ALLOW) ?
		     cilium_srv6_policy_lease_remaining (hm, e->policy_rev_slot, e->src_identity,
							 e->policy_revision, now) :
		     0.0;

      vlib_cli_output (
	vm,
	"[%u] identity %u -> %U proto %u l4-disc %u: %U%s\n"
	"  revisions policy %llu endpoint %llu path %llu%s\n"
	"  path %d gen %u, lease %.1f s, owner %u, %llu pkts %llu bytes",
	index, e->src_identity, format_ip6_address, &dst, (u32) ((e->key[2] >> 16) & 0xff),
	(u32) (e->key[2] & 0xffff), format_cilium_srv6_verdict, (u32) e->verdict,
	(e->verdict == CILIUM_SRV6_VERDICT_ALLOW && lease_left == 0.0) ? " (NO VALID LEASE)" : "",
	e->policy_revision, e->endpoint_revision, e->path_revision, stale ? " STALE" : "",
	(e->path_cache_index == (u32) ~0) ? -1 : (int) e->path_cache_index, e->path_generation,
	lease_left, e->owner_quota_class, e->packets, e->bytes);
      n++;
    }

  vlib_cli_output (vm, "%u entries shown (%u ALLOW, %u negative in the pool)", n,
		   hm->n_programs[1], hm->n_programs[0]);

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_program_cache_command, static) = {
  .path = "show cilium srv6 program-cache",
  .short_help = "show cilium srv6 program-cache [identity <n>] [max <n>]",
  .function = cilium_srv6_show_program_cache_command_fn,
};

/* ------------------------------------------------------------------ */
/* conntrack (C10, 02 §7)                                              */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_show_conntrack_command_fn (vlib_main_t *vm, unformat_input_t *input,
				       vlib_cli_command_t *cmd)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  u32 filter_context = ~0;
  u32 max = 64;
  u32 index, n = 0;
  f64 now;

  if (!ctm->initialised)
    return clib_error_return (0, "conntrack table not built yet");

  if (unformat_user (input, unformat_line_input, line_input))
    {
      while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
	{
	  if (unformat (line_input, "endpoint %u", &filter_context))
	    ;
	  else if (unformat (line_input, "max %u", &max))
	    ;
	  else
	    {
	      unformat_free (line_input);
	      return clib_error_return (0, "unknown input");
	    }
	}
      unformat_free (line_input);
    }

  now = vlib_time_now (vm);

  vlib_cli_output (vm,
		   "ConntrackTable: %u/%u UNVERIFIED (D-38 budget), %u/%u authorised\n"
		   "  created %llu/%llu, promotions %llu (rejected %llu), quota drops %llu,\n"
		   "  evictions %llu, timeouts %llu, invalidated %llu\n"
		   "  reply hits refused: incarnation %llu, revision %llu, lease %llu, "
		   "protocol state %llu\n"
		   "  hooks %s",
		   ctm->n_entries[CILIUM_SRV6_CT_BUDGET_UNVERIFIED], ctm->unverified_capacity,
		   ctm->n_entries[CILIUM_SRV6_CT_BUDGET_VERIFIED],
		   ctm->capacity - ctm->unverified_capacity,
		   ctm->n_created[CILIUM_SRV6_CT_BUDGET_UNVERIFIED],
		   ctm->n_created[CILIUM_SRV6_CT_BUDGET_VERIFIED], ctm->n_verified,
		   ctm->n_verify_rejected, ctm->n_quota_drops, ctm->n_evictions, ctm->n_gc,
		   ctm->n_invalidated, ctm->n_incarnation_mismatch, ctm->n_revision_mismatch,
		   ctm->n_lease_expired, ctm->n_proto_state_denied,
		   cilium_srv6_ct_lookup_hook ? "registered" : "absent");

  for (index = 0; index < ctm->capacity && n < max; index++)
    {
      const cilium_srv6_ct_entry_t *e;
      ip6_address_t src, dst;
      int verified;

      if (pool_is_free_index (ctm->entries, index))
	continue;

      e = ctm->entries + index;

      if (e->state == CILIUM_SRV6_CT_STATE_INVALID)
	continue;

      if (filter_context != (u32) ~0 && e->local_context_id != filter_context)
	continue;

      src.as_u64[0] = e->key[0];
      src.as_u64[1] = e->key[1];
      dst.as_u64[0] = e->key[2];
      dst.as_u64[1] = e->key[3];
      verified = (e->flags & CILIUM_SRV6_CT_F_VERIFIED) ? 1 : 0;

      vlib_cli_output (
	vm,
	"[%u] %U:%u -> %U:%u proto %u (%U)\n"
	"  state %U, tcp 0x%02x, endpoint context %u identity %u\n"
	"  peer identity %u, revision %llu%s, lease %.1f s, path %d gen %u\n"
	"  idle %.1f s, own %llu pkts %llu bytes, peer %llu pkts %llu bytes",
	index, format_ip6_address, &src, (u32) ((e->key[4] >> 16) & 0xffff), format_ip6_address,
	&dst, (u32) (e->key[4] & 0xffff), (u32) e->proto, format_cilium_srv6_ct_direction,
	(u32) ((e->flags & CILIUM_SRV6_CT_F_REPLY) ? CILIUM_SRV6_CT_DIR_REPLY :
						     CILIUM_SRV6_CT_DIR_FORWARD),
	format_cilium_srv6_ct_state, (u32) e->state, (u32) e->tcp, e->local_context_id,
	e->local_endpoint_identity, e->remote_identity, e->verified_revision,
	(verified && e->verified_revision == cilium_srv6_policy_revision_of (hm, e->policy_rev_slot,
									     e->remote_identity)) ?
	  "" :
	  " STALE",
	verified ? cilium_srv6_policy_lease_remaining (hm, e->policy_rev_slot, e->remote_identity,
						       e->verified_revision, now) :
		   0.0,
	(e->path_cache_index == (u32) ~0) ? -1 : (int) e->path_cache_index, e->path_generation,
	now - e->last_seen, e->pkts[0], e->bytes[0], e->pkts[1], e->bytes[1]);
      n++;
    }

  vlib_cli_output (vm, "%u entries shown", n);

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_conntrack_command, static) = {
  .path = "show cilium srv6 conntrack",
  .short_help = "show cilium srv6 conntrack [endpoint <local-context-id>] [max <n>]",
  .function = cilium_srv6_show_conntrack_command_fn,
};
