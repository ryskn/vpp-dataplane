/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — infrastructure guard / ACL (C8-a),
 * VPP binary API handlers (IF-2, design/detail/03 §7).
 *
 * Per D-27 / 00 §4.1 every field is validated before any state is touched
 * and every rejection is side-effect free.
 */

#include <stdbool.h>

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/interface.h>
#include <vnet/plugin/plugin.h>
#include <vnet/ip/ip_types_api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_ifbind.h>
#include <cilium_srv6/cilium_srv6_context.h>
#include <cilium_srv6/cilium_srv6_endcilium.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_ct.h>
#include <cilium_srv6/cilium_srv6_counters.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>
#include <cilium_srv6/cilium_srv6.api_types.h>

#define REPLY_MSG_ID_BASE cilium_srv6_main.msg_id_base
#include <vlibapi/api_helper_macros.h>

/* Wire enum → internal trust value. Unknown values are rejected. */
static int
cilium_srv6_trust_decode (vl_api_srv6_acl_trust_t in, u8 *out)
{
  switch (in)
    {
    case SRV6_ACL_TRUST_API_QUARANTINED:
      *out = CILIUM_SRV6_TRUST_QUARANTINED;
      return 0;
    case SRV6_ACL_TRUST_API_UNTRUSTED:
      *out = CILIUM_SRV6_TRUST_UNTRUSTED;
      return 0;
    case SRV6_ACL_TRUST_API_TRUSTED_FABRIC:
      *out = CILIUM_SRV6_TRUST_TRUSTED_FABRIC;
      return 0;
    default:
      return -1;
    }
}

static vl_api_srv6_acl_trust_t
cilium_srv6_trust_encode (u8 in)
{
  switch (in)
    {
    case CILIUM_SRV6_TRUST_UNTRUSTED:
      return SRV6_ACL_TRUST_API_UNTRUSTED;
    case CILIUM_SRV6_TRUST_TRUSTED_FABRIC:
      return SRV6_ACL_TRUST_API_TRUSTED_FABRIC;
    default:
      return SRV6_ACL_TRUST_API_QUARANTINED;
    }
}

static void
vl_api_srv6_acl_interface_set_t_handler (vl_api_srv6_acl_interface_set_t *mp)
{
  vl_api_srv6_acl_interface_set_reply_t *rmp;
  u8 trust;
  int rv;

  VALIDATE_SW_IF_INDEX_END (mp);

  if (cilium_srv6_trust_decode (mp->trust, &trust))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  rv = cilium_srv6_acl_interface_set (mp->sw_if_index, mp->if_incarnation, trust);

reply:
  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO_END (VL_API_SRV6_ACL_INTERFACE_SET_REPLY);
}

static void
send_srv6_acl_details (u32 sw_if_index, vl_api_registration_t *rp, u32 context)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  cilium_srv6_guard_if_t *e = vec_elt_at_index (cm->ifs, sw_if_index);
  vl_api_srv6_acl_details_t *rmp;

  REPLY_MACRO_DETAILS4_END (
    VL_API_SRV6_ACL_DETAILS, rp, context, ({
      rmp->sw_if_index = sw_if_index;
      rmp->if_incarnation = e->incarnation;
      rmp->trust = cilium_srv6_trust_encode (e->trust);
      rmp->guard_installed = e->guard_installed ? true : false;
      rmp->trusted_fabric_promotable = e->promotable ? true : false;
      rmp->quarantine_hold_remaining_ms = cilium_srv6_quarantine_hold_remaining_ms (e);
      rmp->withdraw_delay_remaining_ms = cilium_srv6_withdraw_delay_remaining_ms (e);
      rmp->guard_ready = cilium_srv6_guard_coverage_complete (cm);
      rmp->deadman_active = cm->deadman_active ? true : false;
      rmp->context_install_blocked = cilium_srv6_guard_context_install_allowed () ? false : true;
      rmp->n_quarantined_interfaces = cm->n_quarantined;
      rmp->deadman_activations = cm->deadman_activations;
    }));
}

static void
vl_api_srv6_acl_dump_t_handler (vl_api_srv6_acl_dump_t *mp)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  vl_api_registration_t *rp;
  u32 i;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0)
    return;

  if (mp->sw_if_index == (u32) ~0)
    {
      for (i = 0; i < vec_len (cm->ifs); i++)
	{
	  if (!cm->ifs[i].valid)
	    continue;
	  send_srv6_acl_details (i, rp, mp->context);
	}
      return;
    }

  if (mp->sw_if_index >= vec_len (cm->ifs) || !cm->ifs[mp->sw_if_index].valid)
    return;

  send_srv6_acl_details (mp->sw_if_index, rp, mp->context);
}

static void
vl_api_srv6_agent_keepalive_t_handler (vl_api_srv6_agent_keepalive_t *mp)
{
  vl_api_srv6_agent_keepalive_reply_t *rmp;
  int rv = 0;

  cilium_srv6_agent_keepalive (mp->client_index);

  REPLY_MACRO_END (VL_API_SRV6_AGENT_KEEPALIVE_REPLY);
}

/*
 * D-72: report the identity of this plugin instance.
 *
 * Read-only, and deliberately answered from the guard main rather than from
 * any per-feature state: the identity names the plugin initialisation, which
 * is the lifetime shared by every table the plugin owns, so answering it out
 * of one feature's state would let a partially initialised plugin report an
 * identity for tables that do not exist yet.
 *
 * `initialised` is the gate for exactly that reason. Before init completes
 * there is no drawn identity, and returning the zero value would be
 * indistinguishable from a real one - which is the single failure this message
 * exists to prevent, since the agent's whole recovery decision is an equality
 * test on it.
 */
static void
vl_api_srv6_instance_get_t_handler (vl_api_srv6_instance_get_t *mp)
{
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  vl_api_srv6_instance_get_reply_t *rmp;
  int rv = 0;

  if (!cm->initialised)
    rv = VNET_API_ERROR_INIT_FAILED;

  REPLY_MACRO2_END (VL_API_SRV6_INSTANCE_GET_REPLY, ({
		      /* REPLY_MACRO2_END does not zero the allocated reply, so
			 the refusal path has to write the field too rather
			 than leave whatever the message buffer held. */
		      if (rv == 0)
			clib_memcpy (rmp->plugin_instance_id, cm->plugin_instance_id,
				     CILIUM_SRV6_INSTANCE_ID_LEN);
		      else
			clib_memset (rmp->plugin_instance_id, 0, CILIUM_SRV6_INSTANCE_ID_LEN);
		    }));
}

/* ------------------------------------------------------------------ */
/* EndpointContextTable / tombstone store (C8-c, 03 §2 / §7)           */
/* ------------------------------------------------------------------ */

static vl_api_srv6_context_state_t
cilium_srv6_context_state_encode (u8 in)
{
  switch (in)
    {
    case CILIUM_SRV6_CONTEXT_ACTIVE:
      return SRV6_CONTEXT_STATE_API_ACTIVE;
    case CILIUM_SRV6_CONTEXT_SUSPENDED:
      return SRV6_CONTEXT_STATE_API_SUSPENDED;
    default:
      return SRV6_CONTEXT_STATE_API_INVALID;
    }
}

static void
vl_api_srv6_context_add_t_handler (vl_api_srv6_context_add_t *mp)
{
  vl_api_srv6_context_add_reply_t *rmp;
  ip6_address_t endpoint_ip;
  int rv;

  VALIDATE_SW_IF_INDEX_END (mp);

  ip6_address_decode (mp->endpoint_ip, &endpoint_ip);

  rv = cilium_srv6_context_add (mp->context_id, &endpoint_ip, mp->sw_if_index,
				mp->owner_quota_class);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO_END (VL_API_SRV6_CONTEXT_ADD_REPLY);
}

static void
vl_api_srv6_context_invalidate_t_handler (vl_api_srv6_context_invalidate_t *mp)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vl_api_srv6_context_invalidate_reply_t *rmp;
  u8 recorded = 0;
  int rv;

  rv = cilium_srv6_context_invalidate (mp->context_id, &recorded);

  REPLY_MACRO2_END (VL_API_SRV6_CONTEXT_INVALIDATE_REPLY, ({
		      rmp->tombstone_recorded = recorded ? true : false;
		      rmp->grace_period_ms = (u32) (cxm->grace_period * 1e3);
		    }));
}

static void
vl_api_srv6_context_gc_t_handler (vl_api_srv6_context_gc_t *mp)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vl_api_srv6_context_gc_reply_t *rmp;
  u32 n_reclaimed = 0;
  u32 n_remaining = 0;
  int rv;

  rv = cilium_srv6_context_gc (mp->retention_seconds, mp->max_entries, &n_reclaimed, &n_remaining);

  REPLY_MACRO2_END (
    VL_API_SRV6_CONTEXT_GC_REPLY, ({
      rmp->n_reclaimed = n_reclaimed;
      rmp->n_remaining = n_remaining;
      /* `more` means the per-call bound stopped the walk while the oldest
	 remaining record is still past retention. */
      rmp->more = false;
      if (rv == 0 && cxm->initialised && cxm->ts_age_head != (u32) ~0)
	{
	  const cilium_srv6_tombstone_t *t =
	    pool_elt_at_index (cxm->tombstones, cxm->ts_age_head);
	  f64 age = vlib_time_now (vlib_get_main ()) - t->invalidated_at;
	  f64 retention = clib_max (mp->retention_seconds, cxm->tombstone_retention);

	  rmp->more = (age > retention) ? true : false;
	}
    }));
}

static void
send_srv6_context_details (const cilium_srv6_context_entry_t *e, u32 grace_remaining_ms,
			   vl_api_registration_t *rp, u32 context)
{
  vl_api_srv6_context_details_t *rmp;

  REPLY_MACRO_DETAILS4_END (VL_API_SRV6_CONTEXT_DETAILS, rp, context, ({
			      rmp->context_id = e->context_id;
			      rmp->state = cilium_srv6_context_state_encode (e->state);
			      rmp->entry_generation = e->entry_generation;
			      ip6_address_encode (&e->endpoint_ip, rmp->endpoint_ip);
			      rmp->sw_if_index = e->tx_sw_if_index;
			      rmp->dpo_index = e->dpo_index;
			      rmp->owner_quota_class = e->owner_quota_class;
			      rmp->allocated_at = e->allocated_at;
			      rmp->invalidated_at = 0.0;
			      rmp->grace_remaining_ms = grace_remaining_ms;
			      rmp->packets = e->pkts;
			      rmp->bytes = e->bytes;
			    }));
}

static void
send_srv6_context_tombstone_details (const cilium_srv6_tombstone_t *t, vl_api_registration_t *rp,
				     u32 context)
{
  vl_api_srv6_context_details_t *rmp;

  REPLY_MACRO_DETAILS4_END (VL_API_SRV6_CONTEXT_DETAILS, rp, context, ({
			      rmp->context_id = t->context_id;
			      rmp->state = SRV6_CONTEXT_STATE_API_TOMBSTONE;
			      rmp->entry_generation = 0;
			      clib_memset (rmp->endpoint_ip, 0, sizeof (rmp->endpoint_ip));
			      rmp->sw_if_index = ~0;
			      rmp->dpo_index = ~0;
			      rmp->owner_quota_class = t->owner_quota_class;
			      rmp->allocated_at = 0.0;
			      rmp->invalidated_at = t->invalidated_at;
			      rmp->grace_remaining_ms = 0;
			      rmp->packets = 0;
			      rmp->bytes = 0;
			    }));
}

static void
vl_api_srv6_context_dump_t_handler (vl_api_srv6_context_dump_t *mp)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  cilium_srv6_context_entry_t *e;
  vl_api_registration_t *rp;
  f64 now;
  u32 index;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0 || !cxm->initialised)
    return;

  now = vlib_time_now (vlib_get_main ());

  pool_foreach (e, cxm->entries)
    {
      if (mp->context_id != (u32) ~0 && e->context_id != mp->context_id)
	continue;

      send_srv6_context_details (e, cilium_srv6_grace_remaining_ms (e->context_id, now), rp,
				 mp->context);
    }

  /* Tombstones oldest first (06 §4.1 keeps them queryable for the retention
     period so that a stale drop can be correlated). */
  for (index = cxm->ts_age_head; index != (u32) ~0;)
    {
      const cilium_srv6_tombstone_t *t = pool_elt_at_index (cxm->tombstones, index);

      if (mp->context_id == (u32) ~0 || t->context_id == mp->context_id)
	send_srv6_context_tombstone_details (t, rp, mp->context);

      index = t->age_next;
    }
}

static void
vl_api_srv6_context_capacity_get_t_handler (vl_api_srv6_context_capacity_get_t *mp)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vl_api_srv6_context_capacity_get_reply_t *rmp;
  u32 n_owners;
  int rv = 0;

  if (!cxm->initialised)
    rv = VNET_API_ERROR_INIT_FAILED;

  n_owners = (u32) pool_elts (cxm->ts_owners);
  if (n_owners < 1)
    n_owners = 1;

  REPLY_MACRO2_END (
    VL_API_SRV6_CONTEXT_CAPACITY_GET_REPLY, ({
      rmp->active_capacity = cxm->active_capacity;
      rmp->n_active = cxm->n_active;
      rmp->n_suspended = cxm->n_suspended;
      rmp->n_active_reserved = cilium_srv6_context_n_grace_pending ();
      rmp->tombstone_capacity = cxm->tombstone_capacity;
      rmp->n_tombstones = cxm->initialised ? (u32) pool_elts (cxm->tombstones) : 0;
      rmp->tombstone_retention_seconds = cxm->tombstone_retention;
      rmp->tombstone_soft_quota = clib_max (1, cxm->tombstone_capacity / n_owners);
      rmp->capacity_rejections = cxm->n_capacity_rejections;
      rmp->install_blocked = cxm->n_install_blocked;
      rmp->tombstone_evictions = cxm->n_tombstone_evictions;
      rmp->tombstone_record_failures =
	cxm->n_tombstone_record_failures_full + cxm->n_tombstone_record_failures_quota;
      rmp->tombstone_gc_reclaimed = cxm->n_tombstone_gc_reclaimed;
      rmp->grace_completions = cxm->n_grace_completions;
      rmp->grace_next_seq = cxm->grace_next_seq;
      rmp->grace_oldest_seq = cilium_srv6_grace_log_oldest_seq ();
    }));
}

static void
send_srv6_context_grace_details (const cilium_srv6_grace_log_t *g, vl_api_registration_t *rp,
				 u32 context)
{
  vl_api_srv6_context_grace_details_t *rmp;

  REPLY_MACRO_DETAILS4_END (VL_API_SRV6_CONTEXT_GRACE_DETAILS, rp, context, ({
			      rmp->seq = g->seq;
			      rmp->context_id = g->context_id;
			      rmp->released_at = g->released_at;
			    }));
}

static void
vl_api_srv6_context_grace_dump_t_handler (vl_api_srv6_context_grace_dump_t *mp)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vl_api_registration_t *rp;
  u64 seq, oldest;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0 || !cxm->initialised)
    return;

  oldest = cilium_srv6_grace_log_oldest_seq ();
  seq = clib_max (mp->since_seq, oldest);

  for (; seq < cxm->grace_next_seq; seq++)
    {
      const cilium_srv6_grace_log_t *g =
	cxm->grace_log + (seq & (u64) (cxm->grace_log_size - 1));

      /* Defensive: a wrap between the bound computation and the read. */
      if (g->seq != seq)
	continue;

      send_srv6_context_grace_details (g, rp, mp->context);
    }
}

/* ------------------------------------------------------------------ */
/* End.Cilium local SID / SR domain node set (C8-b, 03 §3 / §7)        */
/* ------------------------------------------------------------------ */

static void
vl_api_srv6_uc_locator_set_t_handler (vl_api_srv6_uc_locator_set_t *mp)
{
  vl_api_srv6_uc_locator_set_reply_t *rmp;
  int rv;

  rv = cilium_srv6_uc_locator_set (mp->table_id, mp->un_node, mp->uc, mp->is_add ? 1 : 0);

  REPLY_MACRO_END (VL_API_SRV6_UC_LOCATOR_SET_REPLY);
}

static void
vl_api_srv6_sr_domain_prefix_add_del_t_handler (vl_api_srv6_sr_domain_prefix_add_del_t *mp)
{
  vl_api_srv6_sr_domain_prefix_add_del_reply_t *rmp;
  ip6_address_t prefix;
  int rv;

  /* 00 §4.1: validate the declared length before it is used. */
  if (mp->prefix.len > 128)
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  ip6_address_decode (mp->prefix.address, &prefix);

  rv = cilium_srv6_sr_domain_prefix_add_del (&prefix, mp->prefix.len, mp->is_add ? 1 : 0);

reply:
  REPLY_MACRO_END (VL_API_SRV6_SR_DOMAIN_PREFIX_ADD_DEL_REPLY);
}

static void
send_srv6_sr_domain_details (const cilium_srv6_sr_domain_prefix_t *p, vl_api_registration_t *rp,
			     u32 context)
{
  vl_api_srv6_sr_domain_details_t *rmp;
  ip6_address_t a;

  a.as_u64[0] = p->addr[0];
  a.as_u64[1] = p->addr[1];

  REPLY_MACRO_DETAILS4_END (VL_API_SRV6_SR_DOMAIN_DETAILS, rp, context, ({
			      ip6_address_encode (&a, rmp->prefix.address);
			      rmp->prefix.len = p->len;
			    }));
}

static void
vl_api_srv6_sr_domain_dump_t_handler (vl_api_srv6_sr_domain_dump_t *mp)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  vl_api_registration_t *rp;
  u32 i;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0 || !em->initialised)
    return;

  for (i = 0; i < em->n_sr_domain; i++)
    send_srv6_sr_domain_details (em->sr_domain + i, rp, mp->context);
}

static void
vl_api_srv6_endcilium_status_get_t_handler (vl_api_srv6_endcilium_status_get_t *mp)
{
  cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  vl_api_srv6_endcilium_status_get_reply_t *rmp;
  int rv = 0;

  if (!em->initialised)
    rv = VNET_API_ERROR_INIT_FAILED;

  REPLY_MACRO2_END (VL_API_SRV6_ENDCILIUM_STATUS_GET_REPLY, ({
		      rmp->locator_set = em->locator_set ? true : false;
		      rmp->localsid_installed = em->localsid_installed ? true : false;
		      rmp->delivery_suspended = em->delivery_suspended ? true : false;
		      rmp->table_id = em->table_id;
		      rmp->un_node = em->un_node;
		      rmp->uc = em->uc;
		      ip6_address_encode (&em->localsid, rmp->localsid);
		      rmp->localsid_prefix_len = CILIUM_SRV6_LOCALSID_PREFIX_LEN;
		      rmp->n_sr_domain_prefixes = em->n_sr_domain;
		      rmp->delivery_suspends = em->n_delivery_suspends;
		      rmp->localsid_installs = em->n_localsid_installs;
		    }));
}

/* ------------------------------------------------------------------ */
/* headend tables (C7, 02 §2 / §4 / §8)                                */
/* ------------------------------------------------------------------ */

/* 00 §4.1: every count is bounded before it is used. */
#define CILIUM_SRV6_API_MAX_POLICY_REVISIONS 1024
/* Same bound for the other two D-83 namespaces. A publish that does not fit
   is split by the agent; the bound is what keeps one message's stack use and
   its barrier section bounded. */
#define CILIUM_SRV6_API_MAX_ENDPOINT_REVISIONS 1024
#define CILIUM_SRV6_API_MAX_PATH_REVISIONS     1024

static int
cilium_srv6_verdict_decode (vl_api_srv6_program_verdict_t in, u8 *out)
{
  switch (in)
    {
    case SRV6_PROGRAM_VERDICT_API_DENY:
      *out = CILIUM_SRV6_VERDICT_DENY;
      return 0;
    case SRV6_PROGRAM_VERDICT_API_ALLOW:
      *out = CILIUM_SRV6_VERDICT_ALLOW;
      return 0;
    default:
      return -1;
    }
}

static vl_api_srv6_program_verdict_t
cilium_srv6_verdict_encode (u8 in)
{
  return (in == CILIUM_SRV6_VERDICT_ALLOW) ? SRV6_PROGRAM_VERDICT_API_ALLOW :
					     SRV6_PROGRAM_VERDICT_API_DENY;
}

static void
vl_api_srv6_local_ep_add_del_t_handler (vl_api_srv6_local_ep_add_del_t *mp)
{
  vl_api_srv6_local_ep_add_del_reply_t *rmp;
  ip6_address_t ip;
  int rv;

  VALIDATE_SW_IF_INDEX_END (mp);

  ip6_address_decode (mp->ip, &ip);

  rv = cilium_srv6_local_ep_add_del (mp->sw_if_index, mp->if_incarnation, mp->identity, &ip,
				     mp->local_context_id, mp->owner_quota_class,
				     mp->is_add ? 1 : 0);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO_END (VL_API_SRV6_LOCAL_EP_ADD_DEL_REPLY);
}

static void
send_srv6_local_ep_details (u32 sw_if_index, const cilium_srv6_local_ep_t *e,
			    vl_api_registration_t *rp, u32 context)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vl_api_srv6_local_ep_details_t *rmp;

  REPLY_MACRO_DETAILS4_END (VL_API_SRV6_LOCAL_EP_DETAILS, rp, context, ({
			      rmp->sw_if_index = sw_if_index;
			      rmp->if_incarnation = e->if_incarnation;
			      rmp->identity = e->identity;
			      ip6_address_encode (&e->ip, rmp->ip);
			      rmp->local_context_id = e->local_context_id;
			      rmp->owner_quota_class = e->owner_quota_class;
			      rmp->policy_revision =
				cilium_srv6_policy_revision (hm, e->policy_rev_slot);
			    }));
}

static void
vl_api_srv6_local_ep_dump_t_handler (vl_api_srv6_local_ep_dump_t *mp)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vl_api_registration_t *rp;
  u32 i;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0 || !hm->initialised)
    return;

  if (mp->sw_if_index != (u32) ~0)
    {
      if (mp->sw_if_index >= vec_len (hm->local_eps) || !hm->local_eps[mp->sw_if_index].valid)
	return;

      send_srv6_local_ep_details (mp->sw_if_index, hm->local_eps + mp->sw_if_index, rp,
				  mp->context);
      return;
    }

  for (i = 0; i < vec_len (hm->local_eps); i++)
    {
      if (!hm->local_eps[i].valid)
	continue;

      send_srv6_local_ep_details (i, hm->local_eps + i, rp, mp->context);
    }
}

static void
vl_api_srv6_path_add_del_t_handler (vl_api_srv6_path_add_del_t *mp)
{
  vl_api_srv6_path_add_del_reply_t *rmp;
  ip6_address_t da, sid, shift[CILIUM_SRV6_PATH_MAX_SHIFT_STATES];
  u32 path_index = ~0, generation = 0;
  u32 i, n_shift;
  int rv;

  if (!mp->is_add)
    {
      rv = cilium_srv6_path_del (mp->path_index, mp->generation);
      goto reply;
    }

  /* 00 §4.1: bound both declared lengths before anything is copied. */
  if (mp->srh_len > CILIUM_SRV6_PATH_MAX_SRH_BYTES)
    {
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto reply;
    }

  if (mp->n_shift_states > CILIUM_SRV6_PATH_MAX_SHIFT_STATES)
    {
      rv = VNET_API_ERROR_INVALID_VALUE_3;
      goto reply;
    }

  n_shift = mp->n_shift_states;

  ip6_address_decode (mp->da_template, &da);
  ip6_address_decode (mp->service_sid, &sid);

  for (i = 0; i < n_shift; i++)
    ip6_address_decode (mp->shift_states[i], &shift[i]);

  rv = cilium_srv6_path_add (mp->path_id, &da, &sid, mp->base_mtu, mp->srh, mp->srh_len, shift,
			     n_shift, &path_index, &generation);

reply:
  REPLY_MACRO2_END (VL_API_SRV6_PATH_ADD_DEL_REPLY, ({
		      rmp->path_index = path_index;
		      rmp->generation = generation;
		    }));
}

/*
 * The staging transaction of D-61. The four handlers do nothing but decode:
 * the transaction state machine, the handle reservation and the barrier all
 * live in cilium_srv6_headend.c, so that a rejection here cannot leave a
 * half-applied transaction behind.
 */
static void
vl_api_srv6_path_txn_begin_t_handler (vl_api_srv6_path_txn_begin_t *mp)
{
  vl_api_srv6_path_txn_begin_reply_t *rmp;
  int rv;

  rv = cilium_srv6_path_txn_begin (mp->txn_id);

  REPLY_MACRO_END (VL_API_SRV6_PATH_TXN_BEGIN_REPLY);
}

static void
vl_api_srv6_path_txn_put_t_handler (vl_api_srv6_path_txn_put_t *mp)
{
  vl_api_srv6_path_txn_put_reply_t *rmp;
  cilium_srv6_path_spec_t spec;
  u32 path_index = ~0, generation = 0;
  u32 i;
  int rv;

  /* 00 §4.1: bound both declared lengths before anything is copied. */
  if (mp->srh_len > CILIUM_SRV6_PATH_MAX_SRH_BYTES)
    {
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto reply;
    }

  if (mp->n_shift_states > CILIUM_SRV6_PATH_MAX_SHIFT_STATES)
    {
      rv = VNET_API_ERROR_INVALID_VALUE_3;
      goto reply;
    }

  clib_memset (&spec, 0, sizeof (spec));

  spec.path_id = mp->path_id;
  ip6_address_decode (mp->da_template, &spec.da_template);
  ip6_address_decode (mp->service_sid, &spec.service_sid);
  spec.base_mtu = mp->base_mtu;
  spec.srh_len = mp->srh_len;
  spec.n_shift_states = mp->n_shift_states;

  if (mp->srh_len)
    clib_memcpy_fast (spec.srh_template, mp->srh, mp->srh_len);

  for (i = 0; i < mp->n_shift_states; i++)
    ip6_address_decode (mp->shift_states[i], &spec.expected_shift_states[i]);

  rv = cilium_srv6_path_txn_put (mp->txn_id, mp->client_path_id, &spec, &path_index, &generation);

reply:
  REPLY_MACRO2_END (VL_API_SRV6_PATH_TXN_PUT_REPLY, ({
		      rmp->path_index = path_index;
		      rmp->generation = generation;
		    }));
}

static void
vl_api_srv6_path_txn_commit_t_handler (vl_api_srv6_path_txn_commit_t *mp)
{
  vl_api_srv6_path_txn_commit_reply_t *rmp;
  int rv;

  rv = cilium_srv6_path_txn_commit (mp->txn_id);

  REPLY_MACRO_END (VL_API_SRV6_PATH_TXN_COMMIT_REPLY);
}

static void
vl_api_srv6_path_txn_abort_t_handler (vl_api_srv6_path_txn_abort_t *mp)
{
  vl_api_srv6_path_txn_abort_reply_t *rmp;
  int rv;

  rv = cilium_srv6_path_txn_abort (mp->txn_id);

  REPLY_MACRO_END (VL_API_SRV6_PATH_TXN_ABORT_REPLY);
}

static void
send_srv6_path_details (u32 path_index, const cilium_srv6_path_t *p, vl_api_registration_t *rp,
			u32 context)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vl_api_srv6_path_details_t *rmp;
  u16 learned = 0;

  if (p->mtu_index < hm->path_capacity && !pool_is_free_index (hm->path_mtus, p->mtu_index))
    learned = hm->path_mtus[p->mtu_index].effective_mtu;

  REPLY_MACRO_DETAILS4_END (VL_API_SRV6_PATH_DETAILS, rp, context, ({
			      rmp->path_index = path_index;
			      rmp->generation = p->generation;
			      rmp->path_id = p->path_id;
			      ip6_address_encode (&p->da_template, rmp->da_template);
			      ip6_address_encode (&p->service_sid, rmp->service_sid);
			      rmp->base_mtu = p->base_mtu;
			      rmp->learned_mtu = learned;
			      rmp->effective_mtu = cilium_srv6_path_effective_mtu (hm, p);
			      rmp->srh_len = p->srh_len;
			      rmp->n_shift_states = p->n_shift_states;
			    }));
}

static void
vl_api_srv6_path_dump_t_handler (vl_api_srv6_path_dump_t *mp)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vl_api_registration_t *rp;
  cilium_srv6_path_t *p;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0 || !hm->initialised)
    return;

  /*
   * D-61: a slot held by an open staging transaction is allocated out of the
   * pool but is not part of the PathCache — its handle is reserved and must
   * not be observable anywhere before the commit. The state filter is what
   * keeps it out of this dump; published and retired entries are reported as
   * before.
   */
  if (mp->path_index != (u32) ~0)
    {
      if (mp->path_index >= hm->path_capacity || pool_is_free_index (hm->paths, mp->path_index) ||
	  hm->paths[mp->path_index].state == CILIUM_SRV6_PATH_FREE)
	return;

      send_srv6_path_details (mp->path_index, hm->paths + mp->path_index, rp, mp->context);
      return;
    }

  pool_foreach (p, hm->paths)
    {
      if (p->state == CILIUM_SRV6_PATH_FREE)
	continue;

      send_srv6_path_details ((u32) (p - hm->paths), p, rp, mp->context);
    }
}

static void
vl_api_srv6_program_add_del_t_handler (vl_api_srv6_program_add_del_t *mp)
{
  vl_api_srv6_program_add_del_reply_t *rmp;
  ip6_address_t dst;
  u8 verdict;
  int rv;

  if (cilium_srv6_verdict_decode (mp->verdict, &verdict))
    {
      rv = VNET_API_ERROR_INVALID_VALUE_2;
      goto reply;
    }

  ip6_address_decode (mp->dst, &dst);

  rv = cilium_srv6_program_add_del (mp->src_identity, &dst, mp->proto, mp->l4_discriminator,
				    verdict, mp->policy_revision, mp->endpoint_revision,
				    mp->path_revision, mp->path_cache_index, mp->path_generation,
				    mp->owner_quota_class, mp->is_add ? 1 : 0);

reply:
  REPLY_MACRO_END (VL_API_SRV6_PROGRAM_ADD_DEL_REPLY);
}

static void
send_srv6_program_details (u32 index, const cilium_srv6_program_t *e, f64 now,
			   vl_api_registration_t *rp, u32 context)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vl_api_srv6_program_details_t *rmp;
  ip6_address_t dst;
  u32 lease_ms = 0;
  int stale;

  dst.as_u64[0] = e->key[0];
  dst.as_u64[1] = e->key[1];

  stale =
    !cilium_srv6_revisions_match (hm, e->policy_rev_slot, e->policy_revision, e->endpoint_rev_slot,
				  e->endpoint_revision, e->path_cache_index, e->path_revision);

  /* D-51: the lease of the entry's dependency pair, read from the
     PolicyLeaseTable rather than from the entry. */
  if (e->verdict == CILIUM_SRV6_VERDICT_ALLOW)
    lease_ms = (u32) (cilium_srv6_policy_lease_remaining (hm, e->policy_rev_slot, e->src_identity,
							  e->policy_revision, now) *
		      1e3);

  REPLY_MACRO_DETAILS4_END (VL_API_SRV6_PROGRAM_DETAILS, rp, context, ({
			      rmp->program_index = index;
			      rmp->src_identity = e->src_identity;
			      ip6_address_encode (&dst, rmp->dst);
			      rmp->proto = (u8) ((e->key[2] >> 16) & 0xff);
			      rmp->l4_discriminator = (u16) (e->key[2] & 0xffff);
			      rmp->verdict = cilium_srv6_verdict_encode (e->verdict);
			      rmp->policy_revision = e->policy_revision;
			      rmp->endpoint_revision = e->endpoint_revision;
			      rmp->path_revision = e->path_revision;
			      rmp->path_cache_index = e->path_cache_index;
			      rmp->path_generation = e->path_generation;
			      rmp->lease_remaining_ms = lease_ms;
			      rmp->owner_quota_class = e->owner_quota_class;
			      rmp->stale = stale ? true : false;
			      rmp->packets = e->packets;
			      rmp->bytes = e->bytes;
			    }));
}

static void
vl_api_srv6_program_dump_t_handler (vl_api_srv6_program_dump_t *mp)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vl_api_registration_t *rp;
  u32 index, n_sent = 0;
  u32 max_entries;
  f64 now;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0 || !hm->initialised)
    return;

  max_entries = mp->max_entries ? mp->max_entries : hm->program_capacity;
  now = vlib_time_now (vlib_get_main ());

  for (index = mp->cursor; index < hm->program_capacity && n_sent < max_entries; index++)
    {
      const cilium_srv6_program_t *e;

      if (pool_is_free_index (hm->programs, index))
	continue;

      e = hm->programs + index;

      if (!e->in_use)
	continue;

      if (mp->src_identity != (u32) ~0 && e->src_identity != mp->src_identity)
	continue;

      send_srv6_program_details (index, e, now, rp, mp->context);
      n_sent++;
    }
}

/*
 * D-83: one handler per revision namespace. The key type is explicit on the
 * wire, so no handler has to disambiguate a union, and each one applies its
 * whole message or none of it.
 */
static void
vl_api_srv6_policy_revision_publish_t_handler (vl_api_srv6_policy_revision_publish_t *mp)
{
  vl_api_srv6_policy_revision_publish_reply_t *rmp;
  u32 identities[CILIUM_SRV6_API_MAX_POLICY_REVISIONS];
  u64 revisions[CILIUM_SRV6_API_MAX_POLICY_REVISIONS];
  u32 i, n;
  int rv;

  /* 00 §4.1: the declared count is validated before it is used. */
  if (mp->n_policy > CILIUM_SRV6_API_MAX_POLICY_REVISIONS)
    {
      rv = VNET_API_ERROR_LIMIT_EXCEEDED;
      goto reply;
    }

  n = mp->n_policy;

  for (i = 0; i < n; i++)
    {
      identities[i] = mp->policy[i].identity;
      revisions[i] = mp->policy[i].revision;
    }

  rv = cilium_srv6_policy_revision_publish (identities, revisions, n);

reply:
  REPLY_MACRO_END (VL_API_SRV6_POLICY_REVISION_PUBLISH_REPLY);
}

static void
vl_api_srv6_endpoint_revision_publish_t_handler (vl_api_srv6_endpoint_revision_publish_t *mp)
{
  vl_api_srv6_endpoint_revision_publish_reply_t *rmp;
  ip6_address_t dsts[CILIUM_SRV6_API_MAX_ENDPOINT_REVISIONS];
  u64 revisions[CILIUM_SRV6_API_MAX_ENDPOINT_REVISIONS];
  u32 i, n;
  int rv;

  if (mp->n_endpoint > CILIUM_SRV6_API_MAX_ENDPOINT_REVISIONS)
    {
      rv = VNET_API_ERROR_LIMIT_EXCEEDED;
      goto reply;
    }

  n = mp->n_endpoint;

  for (i = 0; i < n; i++)
    {
      ip6_address_decode (mp->endpoint[i].dst, &dsts[i]);
      revisions[i] = mp->endpoint[i].revision;
    }

  rv = cilium_srv6_endpoint_revision_publish (dsts, revisions, n);

reply:
  REPLY_MACRO_END (VL_API_SRV6_ENDPOINT_REVISION_PUBLISH_REPLY);
}

static void
vl_api_srv6_path_revision_publish_t_handler (vl_api_srv6_path_revision_publish_t *mp)
{
  vl_api_srv6_path_revision_publish_reply_t *rmp;
  u32 indices[CILIUM_SRV6_API_MAX_PATH_REVISIONS];
  u64 revisions[CILIUM_SRV6_API_MAX_PATH_REVISIONS];
  u32 i, n;
  int rv;

  if (mp->n_path > CILIUM_SRV6_API_MAX_PATH_REVISIONS)
    {
      rv = VNET_API_ERROR_LIMIT_EXCEEDED;
      goto reply;
    }

  n = mp->n_path;

  for (i = 0; i < n; i++)
    {
      indices[i] = mp->path[i].path_index;
      revisions[i] = mp->path[i].revision;
    }

  rv = cilium_srv6_path_revision_publish (indices, revisions, n);

reply:
  REPLY_MACRO_END (VL_API_SRV6_PATH_REVISION_PUBLISH_REPLY);
}

static void
vl_api_srv6_lease_extend_t_handler (vl_api_srv6_lease_extend_t *mp)
{
  vl_api_srv6_lease_extend_reply_t *rmp;
  u32 identities[CILIUM_SRV6_API_MAX_POLICY_REVISIONS];
  u64 revisions[CILIUM_SRV6_API_MAX_POLICY_REVISIONS];
  u32 n_updated = 0, n_skipped = 0;
  u32 i, n;
  int rv;

  /* 00 §4.1: the declared count is validated before it is used. Same bound as
     srv6_policy_revision_publish: both carry a (identity, revision) vector. */
  if (mp->n_policy > CILIUM_SRV6_API_MAX_POLICY_REVISIONS)
    {
      rv = VNET_API_ERROR_LIMIT_EXCEEDED;
      goto reply;
    }

  n = mp->n_policy;

  for (i = 0; i < n; i++)
    {
      identities[i] = mp->policy[i].identity;
      revisions[i] = mp->policy[i].revision;
    }

  rv = cilium_srv6_lease_extend (identities, revisions, n, mp->lease_ms, &n_updated, &n_skipped);

reply:
  REPLY_MACRO2_END (VL_API_SRV6_LEASE_EXTEND_REPLY, ({
		      rmp->n_updated = n_updated;
		      rmp->n_skipped = n_skipped;
		    }));
}

static void
vl_api_srv6_fragment_verdict_add_t_handler (vl_api_srv6_fragment_verdict_add_t *mp)
{
  vl_api_srv6_fragment_verdict_add_reply_t *rmp;
  ip6_address_t src, dst;
  u8 verdict;
  int rv;

  if (cilium_srv6_verdict_decode (mp->verdict, &verdict))
    {
      rv = VNET_API_ERROR_INVALID_VALUE;
      goto reply;
    }

  ip6_address_decode (mp->src, &src);
  ip6_address_decode (mp->dst, &dst);

  /*
   * The message carries the Fragment header Identification as a number
   * (autoendian has already put it in host order); the FragmentVerdictCache
   * key is built from the field as it appears in the packet, which is what
   * cilium-srv6-classify hands to cilium_srv6_frag_key(). Converting here
   * keeps the byte order question in the one place that owns the wire format.
   */
  rv = cilium_srv6_frag_verdict_add (&src, &dst, clib_host_to_net_u32 (mp->fragment_id),
				     mp->next_header, mp->sw_if_index, mp->if_incarnation,
				     mp->src_identity, verdict, mp->policy_revision,
				     mp->endpoint_revision, mp->path_revision, mp->path_cache_index,
				     mp->path_generation, mp->timeout_ms, mp->punt_id);

reply:
  REPLY_MACRO_END (VL_API_SRV6_FRAGMENT_VERDICT_ADD_REPLY);
}

static void
vl_api_srv6_headend_config_set_t_handler (vl_api_srv6_headend_config_set_t *mp)
{
  vl_api_srv6_headend_config_set_reply_t *rmp;
  ip6_address_t node_address;
  int rv;

  ip6_address_decode (mp->node_address, &node_address);

  rv = cilium_srv6_headend_config_set (&node_address, mp->outer_table_id, mp->inner_mtu,
				       mp->hop_limit, mp->copy_dscp ? 1 : 0);

  REPLY_MACRO_END (VL_API_SRV6_HEADEND_CONFIG_SET_REPLY);
}

static void
vl_api_srv6_headend_status_get_t_handler (vl_api_srv6_headend_status_get_t *mp)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vl_api_srv6_headend_status_get_reply_t *rmp;
  cilium_srv6_punt_transport_stats_t tp;
  u32 n_local = 0;
  u32 n_path_revisions = 0;
  u32 i;
  int rv = 0;

  if (!hm->initialised)
    rv = VNET_API_ERROR_INIT_FAILED;

  for (i = 0; i < vec_len (hm->local_eps); i++)
    if (hm->local_eps[i].valid)
      n_local++;

  /* D-83 PATH keys are dense by PathCache index, so the count is a scan of
     the array rather than a pool occupancy. It is a status message, read at
     the metrics scrape interval, not per packet. */
  for (i = 0; i < vec_len (hm->path_revs); i++)
    if (hm->path_revs[i] != CILIUM_SRV6_REV_ABSENT)
      n_path_revisions++;

  REPLY_MACRO2_END (
    VL_API_SRV6_HEADEND_STATUS_GET_REPLY, ({
      u32 qi;

      rmp->configured = hm->configured ? true : false;
      ip6_address_encode (&hm->node_address, rmp->node_address);
      rmp->outer_table_id = hm->outer_table_id;
      rmp->inner_mtu = hm->inner_mtu;
      rmp->hop_limit = hm->hop_limit;
      rmp->copy_dscp = hm->copy_dscp ? true : false;
      rmp->program_capacity = hm->program_capacity;
      rmp->program_negative_capacity = hm->program_negative_capacity;
      rmp->n_programs_allow = hm->n_programs[1];
      rmp->n_programs_negative = hm->n_programs[0];
      rmp->path_capacity = hm->path_capacity;
      /* D-61: the slots an open staging transaction reserved are not entries
	 of the PathCache, so path_cache_entries does not count them. */
      rmp->n_paths =
	hm->initialised ? (u32) pool_elts (hm->paths) - hm->path_txn_reserved : 0;
      rmp->frag_capacity = hm->frag_capacity;
      rmp->n_frags = hm->n_frags;
      rmp->n_local_endpoints = n_local;
      /* D-83: per-namespace key counts. Slot 0 of the ENDPOINT table is the
	 permanent sentinel and is not a published key, exactly as in the
	 POLICY table. */
      rmp->n_endpoint_revisions = hm->initialised ? (u32) pool_elts (hm->endpoint_rev) - 1 : 0;
      rmp->n_path_revisions = n_path_revisions;
      rmp->n_policy_revisions = hm->initialised ? (u32) pool_elts (hm->policy_rev) - 1 : 0;
      rmp->program_installs = hm->n_program_installs;
      rmp->program_deletes = hm->n_program_deletes;
      rmp->program_quota_drops = hm->n_program_quota_drops;
      rmp->program_fair_evictions = hm->n_program_fair_evictions;
      rmp->program_stale_installs = hm->n_program_stale_installs;
      rmp->program_missing_key_installs = hm->n_program_missing_key_installs;
      rmp->lease_extends = hm->n_lease_extends;
      rmp->revision_publishes = hm->n_revision_publishes;
      rmp->frag_evictions = hm->n_frag_evictions;
      rmp->frag_quota_drops = hm->n_frag_quota_drops;
      rmp->frag_gc = hm->n_frag_gc;
      rmp->punt_no_transport = 0;
      rmp->punt_queue_full = 0;
      rmp->punt_write_failed = 0;
      rmp->punt_released = 0;
      rmp->punt_reinjected = 0;
      rmp->punt_reinject_rejected = 0;

      for (qi = 0; qi < CILIUM_SRV6_PUNT_N_Q; qi++)
	{
	  const cilium_srv6_punt_queue_state_t *q = hm->punt_q + qi;

	  rmp->punt_outstanding[qi] = q->n_outstanding;
	  rmp->punt_punted[qi] = q->n_punted;
	  /* slowpath_drops_total: every refusal reason of this queue summed.
	     The split is in the CLI and, for the two transport ones, in the
	     dedicated fields below. */
	  rmp->punt_drops[qi] = q->n_drop_global + q->n_drop_owner + q->n_drop_identity +
				q->n_drop_no_token + q->n_drop_no_transport + q->n_drop_ring_full +
				q->n_drop_write_failed;
	  rmp->punt_no_transport += q->n_drop_no_transport;
	  rmp->punt_queue_full += q->n_drop_ring_full;
	  rmp->punt_write_failed += q->n_drop_write_failed;
	  rmp->punt_released += q->n_released;
	  rmp->punt_reinjected += q->n_reinjected;
	  rmp->punt_reinject_rejected += q->n_reinject_rejected;
	}

      /*
       * 02 §5.6.9 / 06 §3. The two rejection totals stay separate series
       * because they are not two outcomes of one event: one keeps the
       * connection and the other ends it, and summing them hides the quantity
       * an operator actually needs (how often IF-3 was torn down).
       */
      cilium_srv6_punt_transport_stats (&tp);

      rmp->if3_socket_configured = tp.configured ? true : false;
      rmp->if3_connected = tp.connected ? true : false;
      rmp->if3_connects = tp.n_connects;
      rmp->if3_disconnects = tp.n_disconnects;
      rmp->if3_frames_sent = tp.n_frames_sent;
      rmp->if3_bytes_sent = tp.n_bytes_sent;
      rmp->if3_frames_received = tp.n_frames_received;
      rmp->if3_message_rejections = tp.n_rejections[CILIUM_SRV6_IF3_ERR_VERSION] +
				    tp.n_rejections[CILIUM_SRV6_IF3_ERR_OPCODE] +
				    tp.n_rejections[CILIUM_SRV6_IF3_ERR_LENGTH] +
				    tp.n_rejections[CILIUM_SRV6_IF3_ERR_TRUNCATED];
      rmp->if3_frame_drops =
	tp.n_rejections[CILIUM_SRV6_IF3_ERR_FIELD] + tp.n_rejections[CILIUM_SRV6_IF3_ERR_TOKEN];
      rmp->if3_unusable_token = tp.n_unknown_token;
      rmp->if3_encode_refused = tp.n_encode_refused;
      rmp->if3_queue_entries = tp.queue_entries;
      rmp->if3_queue_bytes = tp.queue_bytes;
      rmp->if3_queue_byte_cap = tp.queue_byte_cap;
      rmp->if3_queue_high_water_bytes = tp.queue_high_water_bytes;

      rmp->conntrack_registered = (cilium_srv6_ct_lookup_hook != 0) ? true : false;
      rmp->punt_transport_registered = cilium_srv6_punt_transport_registered () ? true : false;
    }));
}

/* ------------------------------------------------------------------ */
/* conntrack (C10, 02 §7, IF-2)                                        */
/* ------------------------------------------------------------------ */

static vl_api_srv6_ct_state_t
cilium_srv6_ct_state_encode (u8 in)
{
  switch (in)
    {
    case CILIUM_SRV6_CT_STATE_UNVERIFIED:
      return SRV6_CT_STATE_API_UNVERIFIED;
    case CILIUM_SRV6_CT_STATE_SYN_SEEN:
      return SRV6_CT_STATE_API_SYN_SEEN;
    case CILIUM_SRV6_CT_STATE_VERIFIED_ESTABLISHED:
      return SRV6_CT_STATE_API_VERIFIED_ESTABLISHED;
    case CILIUM_SRV6_CT_STATE_FIN_WAIT:
      return SRV6_CT_STATE_API_FIN_WAIT;
    case CILIUM_SRV6_CT_STATE_CLOSED:
      return SRV6_CT_STATE_API_CLOSED;
    default:
      return SRV6_CT_STATE_API_INVALID;
    }
}

static void
vl_api_srv6_ct_verify_t_handler (vl_api_srv6_ct_verify_t *mp)
{
  vl_api_srv6_ct_verify_reply_t *rmp;
  ip6_address_t src, dst;
  int rv;

  ip6_address_decode (mp->src, &src);
  ip6_address_decode (mp->dst, &dst);

  rv = cilium_srv6_ct_verify (&src, &dst, mp->proto, mp->sport, mp->dport, mp->sw_if_index,
			      mp->if_incarnation, mp->local_identity, mp->remote_identity,
			      mp->policy_revision, mp->path_cache_index, mp->path_generation);

  REPLY_MACRO_END (VL_API_SRV6_CT_VERIFY_REPLY);
}

static void
vl_api_srv6_ct_invalidate_t_handler (vl_api_srv6_ct_invalidate_t *mp)
{
  vl_api_srv6_ct_invalidate_reply_t *rmp;
  u32 n_invalidated = 0, next_cursor = 0;
  int rv;

  rv = cilium_srv6_ct_invalidate (mp->local_context_id, mp->cursor, mp->max_entries,
				  &n_invalidated, &next_cursor);

  REPLY_MACRO2_END (VL_API_SRV6_CT_INVALIDATE_REPLY, ({
		      rmp->n_invalidated = n_invalidated;
		      rmp->next_cursor = next_cursor;
		    }));
}

static void
vl_api_srv6_ct_status_get_t_handler (vl_api_srv6_ct_status_get_t *mp)
{
  const cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  vl_api_srv6_ct_status_get_reply_t *rmp;
  int rv = 0;

  if (!ctm->initialised)
    rv = VNET_API_ERROR_INIT_FAILED;

  REPLY_MACRO2_END (
    VL_API_SRV6_CT_STATUS_GET_REPLY, ({
      rmp->capacity = ctm->capacity;
      rmp->unverified_capacity = ctm->unverified_capacity;
      rmp->n_unverified = ctm->n_entries[CILIUM_SRV6_CT_BUDGET_UNVERIFIED];
      rmp->n_verified = ctm->n_entries[CILIUM_SRV6_CT_BUDGET_VERIFIED];
      rmp->created_unverified = ctm->n_created[CILIUM_SRV6_CT_BUDGET_UNVERIFIED];
      rmp->created_verified = ctm->n_created[CILIUM_SRV6_CT_BUDGET_VERIFIED];
      rmp->verified = ctm->n_verified;
      rmp->verify_rejected = ctm->n_verify_rejected;
      rmp->quota_drops = ctm->n_quota_drops;
      rmp->evictions = ctm->n_evictions;
      rmp->gc = ctm->n_gc;
      rmp->invalidated = ctm->n_invalidated;
      rmp->incarnation_mismatch = ctm->n_incarnation_mismatch;
      rmp->revision_mismatch = ctm->n_revision_mismatch;
      rmp->lease_expired = ctm->n_lease_expired;
      rmp->proto_state_denied = ctm->n_proto_state_denied;
      rmp->timeout_unverified = ctm->timeout_unverified;
      rmp->timeout_tcp_established = ctm->timeout_tcp_established;
      rmp->timeout_tcp_transient = ctm->timeout_tcp_transient;
      rmp->timeout_udp = ctm->timeout_udp;
      rmp->timeout_icmp6 = ctm->timeout_icmp6;
      rmp->registered = (cilium_srv6_ct_lookup_hook != 0) ? true : false;
    }));
}

static void
send_srv6_ct_details (u32 index, const cilium_srv6_ct_entry_t *e, f64 now,
		      vl_api_registration_t *rp, u32 context)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vl_api_srv6_ct_details_t *rmp;
  ip6_address_t src, dst;
  u32 lease_ms = 0;
  int verified = (e->flags & CILIUM_SRV6_CT_F_VERIFIED) ? 1 : 0;
  int stale;

  src.as_u64[0] = e->key[0];
  src.as_u64[1] = e->key[1];
  dst.as_u64[0] = e->key[2];
  dst.as_u64[1] = e->key[3];

  stale = !verified || e->verified_revision != cilium_srv6_policy_revision_of (
						 hm, e->policy_rev_slot, e->remote_identity);

  /* D-51: steps 3 and 4 of the 02 §7.2 judgement, read from the
     PolicyLeaseTable slot of the remote identity. */
  if (verified)
    lease_ms = (u32) (cilium_srv6_policy_lease_remaining (
			hm, e->policy_rev_slot, e->remote_identity, e->verified_revision, now) *
		      1e3);

  REPLY_MACRO_DETAILS4_END (
    VL_API_SRV6_CT_DETAILS, rp, context, ({
      rmp->entry_index = index;
      ip6_address_encode (&src, rmp->src);
      ip6_address_encode (&dst, rmp->dst);
      rmp->proto = e->proto;
      rmp->sport = (u16) ((e->key[4] >> 16) & 0xffff);
      rmp->dport = (u16) (e->key[4] & 0xffff);
      rmp->is_reply = (e->flags & CILIUM_SRV6_CT_F_REPLY) ? true : false;
      rmp->state = cilium_srv6_ct_state_encode (e->state);
      rmp->local_context_id = e->local_context_id;
      rmp->local_endpoint_identity = e->local_endpoint_identity;
      rmp->remote_identity = e->remote_identity;
      rmp->policy_revision = e->verified_revision;
      rmp->lease_remaining_ms = lease_ms;
      rmp->path_cache_index = e->path_cache_index;
      rmp->path_generation = e->path_generation;
      rmp->owner_quota_class = e->owner_quota_class;
      rmp->tcp_flags = e->tcp;
      rmp->verified = verified ? true : false;
      rmp->stale = stale ? true : false;
      rmp->age = now - e->last_seen;
      rmp->packets[0] = e->pkts[0];
      rmp->packets[1] = e->pkts[1];
      rmp->bytes[0] = e->bytes[0];
      rmp->bytes[1] = e->bytes[1];
    }));
}

static void
vl_api_srv6_ct_dump_t_handler (vl_api_srv6_ct_dump_t *mp)
{
  const cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  vl_api_registration_t *rp;
  u32 index, n_sent = 0;
  u32 max_entries;
  f64 now;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0 || !ctm->initialised)
    return;

  max_entries = mp->max_entries ? mp->max_entries : ctm->capacity;
  now = vlib_time_now (vlib_get_main ());

  for (index = mp->cursor; index < ctm->capacity && n_sent < max_entries; index++)
    {
      const cilium_srv6_ct_entry_t *e;

      if (pool_is_free_index (ctm->entries, index))
	continue;

      e = ctm->entries + index;

      if (e->state == CILIUM_SRV6_CT_STATE_INVALID)
	continue;

      if (mp->local_context_id != (u32) ~0 && e->local_context_id != mp->local_context_id)
	continue;

      send_srv6_ct_details (index, e, now, rp, mp->context);
      n_sent++;
    }
}

/*
 * ------------------------------------------------------------------
 * Drop reason counters (C5, 02 §8 srv6_counters_dump, 06 §2 / §3)
 * ------------------------------------------------------------------
 */

/*
 * Internal reason ↔ wire enum. The two spaces are kept separate on purpose:
 * the internal one has CILIUM_SRV6_DROP_UNSET at 0 so that a counter nobody
 * classified is detectable at init, the wire one has NOT_A_DROP at 0 so that
 * a zero-filled record reads as "not a drop" rather than as a reason.
 */
static vl_api_srv6_drop_reason_t
cilium_srv6_drop_reason_encode (u8 reason)
{
  switch (reason)
    {
#define _(sym, str, desc)                                                                          \
  case CILIUM_SRV6_DROP_##sym:                                                                     \
    return SRV6_DROP_REASON_API_##sym;
      foreach_cilium_srv6_drop_reason
#undef _
	default : return SRV6_DROP_REASON_API_NOT_A_DROP;
    }
}

/* Returns ~0 for a value outside the enum, which the caller rejects. */
static u32
cilium_srv6_drop_reason_decode (vl_api_srv6_drop_reason_t in)
{
  switch (in)
    {
#define _(sym, str, desc)                                                                          \
  case SRV6_DROP_REASON_API_##sym:                                                                 \
    return CILIUM_SRV6_DROP_##sym;
      foreach_cilium_srv6_drop_reason
#undef _
	default : return ~0;
    }
}

typedef struct
{
  vl_api_registration_t *rp;
  u32 context;
} cilium_srv6_counters_dump_ctx_t;

static void
send_srv6_counters_details (const cilium_srv6_counter_record_t *r, void *opaque)
{
  cilium_srv6_counters_dump_ctx_t *ctx = opaque;
  vl_api_registration_t *rp = ctx->rp;
  u32 context = ctx->context;
  vl_api_srv6_counters_details_t *rmp;

  REPLY_MACRO_DETAILS4_END (VL_API_SRV6_COUNTERS_DETAILS, rp, context, ({
			      rmp->reason = cilium_srv6_drop_reason_encode (r->reason);
			      rmp->severity = r->severity;
			      strncpy ((char *) rmp->node_name, r->node_name,
				       ARRAY_LEN (rmp->node_name) - 1);
			      strncpy ((char *) rmp->counter_name, r->counter_name,
				       ARRAY_LEN (rmp->counter_name) - 1);
			      rmp->value = r->value;
			    }));
}

static void
vl_api_srv6_counters_dump_t_handler (vl_api_srv6_counters_dump_t *mp)
{
  cilium_srv6_counters_dump_ctx_t ctx;
  u32 filter;

  ctx.rp = vl_api_client_index_to_registration (mp->client_index);
  if (ctx.rp == 0)
    return;
  ctx.context = mp->context;

  /*
   * 00 §4.1: validate before use, reject an unknown value without a side
   * effect. 0xff is the documented "every counter" sentinel; anything else
   * outside the enum returns an empty stream rather than being silently
   * coerced into a reason that happens to be in range.
   */
  if (mp->reason_filter == 0xff)
    filter = ~0;
  else
    {
      filter = cilium_srv6_drop_reason_decode (mp->reason_filter);
      if (filter == (u32) ~0)
	return;
    }

  cilium_srv6_counters_foreach (vlib_get_main (), filter, send_srv6_counters_details, &ctx);
}

/*
 * ------------------------------------------------------------------
 * CNI attachment binding table (D-68, 02 §8)
 * ------------------------------------------------------------------
 */

/*
 * Bound the identity before anything touches it.
 *
 * Two separate things are checked, and both have to be, because they bound
 * different attacks. The first is that the declared string length actually
 * fits inside the message that was received: a declared length is a number
 * the sender chose, and reading `length` bytes out of `buf` without comparing
 * them against the delivered message size is a read past the message. The
 * second is the table's own 255-byte bound, which is what keeps one API
 * message from turning into an unbounded allocation.
 *
 * Nothing is copied here. The identity is validated in place and passed to
 * the table as a pointer plus a length, so the handler performs no
 * allocation at all and there is no buffer whose size could disagree with
 * the length that was checked.
 *
 * Returns 0 and sets *id / *id_len when the identity is usable.
 */
static int
cilium_srv6_attachment_id_from_api (void *mp, vl_api_string_t *astr, const u8 **id, u32 *id_len)
{
  u32 len = vl_api_string_len (astr);
  u32 offset = (u32) ((u8 *) astr->buf - (u8 *) mp);

  if (len == 0 || len > CILIUM_SRV6_ATTACHMENT_ID_MAX)
    return VNET_API_ERROR_INVALID_VALUE;

  if (offset + len > vl_msg_api_max_length (mp))
    return VNET_API_ERROR_INVALID_VALUE;

  *id = astr->buf;
  *id_len = len;
  return 0;
}

static void
vl_api_srv6_if_attachment_add_del_t_handler (vl_api_srv6_if_attachment_add_del_t *mp)
{
  vl_api_srv6_if_attachment_add_del_reply_t *rmp;
  const u8 *id = 0;
  u32 id_len = 0;
  int rv;

  rv = cilium_srv6_attachment_id_from_api (mp, &mp->attachment_id, &id, &id_len);
  if (rv != 0)
    goto reply;

  /* No VALIDATE_SW_IF_INDEX here: the interface check that matters is the
     D-31 one the table performs against the guard's interface state, which
     also rejects an index VPP knows about but this plugin has not brought
     under guard control. A delete deliberately accepts an index whose
     interface is already gone (see the .api documentation). */
  rv = cilium_srv6_if_attachment_add_del (id, id_len, mp->sw_if_index, mp->if_incarnation,
					  mp->is_add ? 1 : 0);

reply:
  REPLY_MACRO_END (VL_API_SRV6_IF_ATTACHMENT_ADD_DEL_REPLY);
}

static void
send_srv6_if_attachment_details (const cilium_srv6_if_binding_t *b, vl_api_registration_t *rp,
				 u32 context)
{
  vl_api_srv6_if_attachment_details_t *rmp;
  u32 id_len = vec_len (b->attachment_id);

  REPLY_MACRO_DETAILS5_END (VL_API_SRV6_IF_ATTACHMENT_DETAILS, id_len, rp, context, ({
			      rmp->sw_if_index = b->sw_if_index;
			      rmp->if_incarnation = b->if_incarnation;
			      vl_api_vec_to_api_string (b->attachment_id, &rmp->attachment_id);
			    }));
}

static void
vl_api_srv6_if_attachment_dump_t_handler (vl_api_srv6_if_attachment_dump_t *mp)
{
  cilium_srv6_ifbind_main_t *bm = &cilium_srv6_ifbind_main;
  const cilium_srv6_if_binding_t *b;
  vl_api_registration_t *rp;

  rp = vl_api_client_index_to_registration (mp->client_index);
  if (rp == 0 || !bm->initialised)
    return;

  if (mp->sw_if_index != (u32) ~0)
    {
      b = cilium_srv6_ifbind_by_sw_if_index (mp->sw_if_index);
      if (b != 0)
	send_srv6_if_attachment_details (b, rp, mp->context);
      return;
    }

  pool_foreach (b, bm->bindings)
    {
      send_srv6_if_attachment_details (b, rp, mp->context);
    }
}

/* API definitions */
#include <vnet/format_fns.h>
#include <cilium_srv6/cilium_srv6.api.c>

clib_error_t *
cilium_srv6_plugin_api_hookup (vlib_main_t *vm)
{
  cilium_srv6_main.msg_id_base = setup_message_id_table ();
  return 0;
}

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Cilium SRv6 Endpoint Context — infrastructure guard/ACL, "
		 "Context tables, End.Cilium and endpoint delivery",
};
