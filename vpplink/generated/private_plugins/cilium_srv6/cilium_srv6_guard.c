/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — infrastructure guard / ACL (C8-a),
 * control plane: trust map, guard installation, interface lifecycle,
 * quarantine hysteresis and dead-man switch.
 *
 * design/detail/03-destination-dataplane.md §1.1
 * design/detail/00-overview.md §2 (D-9, D-24, D-31, D-35, D-44), §6
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/interface.h>
#include <vnet/interface_funcs.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
/* cilium_srv6_headend_classify_refresh(): accepting a classification is what
   decides whether the interface is on the 02 §1 headend path (item 191). */
#include <cilium_srv6/cilium_srv6_headend.h>

cilium_srv6_main_t cilium_srv6_main;

static vlib_log_class_t cilium_srv6_log_class;

#define CSG_LOG_ERR(fmt, ...)	 vlib_log_err (cilium_srv6_log_class, fmt, __VA_ARGS__)
#define CSG_LOG_NOTICE(fmt, ...) vlib_log_notice (cilium_srv6_log_class, fmt, __VA_ARGS__)

/*
 * The guard is a permanent ingress feature (03 §1.1: installed from plugin
 * init on every ingress / host-inject path, independent of the per-interface
 * ACL state and of the agent).
 */
#define CSG_ARC_NAME  "ip6-unicast"
#define CSG_NODE_NAME "cilium-srv6-guard"

/*
 * 03 §1.1 / D-31: promotion to TRUSTED_FABRIC is restricted to
 * physical/bond/uplink class interfaces, and the exclusion of the
 * tap/memif family is a VPP-side invariant.
 *
 * The device classes listed here are none of physical, bond or uplink:
 * each one terminates in a Pod, in the host kernel, or in a VM, i.e. on
 * the untrusted side of the trust boundary of 基本設計 §8.1. They must
 * therefore never be classifiable as SR domain fabric.
 *
 * The names are the `.name` fields of the corresponding VNET_DEVICE_CLASS
 * registrations in the VPP tree.
 */
static const char *cilium_srv6_non_fabric_dev_classes[] = {
  "virtio",	/* tapv2 / tun — VPP implements tap/tun on virtio */
  "tap",	/* legacy tap */
  "memif",	/* Pod / userspace dataplane attachment */
  "af-packet",	/* host kernel attachment (note: hyphen, not af_packet) */
  "vhost-user", /* VM attachment */
};

/* ------------------------------------------------------------------ */
/* SRV6_BLOCK constant (00 §6)                                         */
/* ------------------------------------------------------------------ */

static void
csg_set_block (cilium_srv6_main_t *cm, const ip6_address_t *a, u8 len)
{
  int i;

  if (len > 128)
    len = 128;

  cm->block = *a;
  cm->block_len = len;

  for (i = 0; i < 2; i++)
    {
      u32 bits = 0;

      if (len > (u32) (i * 64))
	{
	  bits = len - (u32) (i * 64);
	  if (bits > 64)
	    bits = 64;
	}

      cm->block_mask_u64[i] = bits ? clib_host_to_net_u64 (~(u64) 0 << (64 - bits)) : 0;
      cm->block_u64[i] = a->as_u64[i] & cm->block_mask_u64[i];
    }
}

/* ------------------------------------------------------------------ */
/* trust map                                                           */
/* ------------------------------------------------------------------ */

u8 *
format_cilium_srv6_trust (u8 *s, va_list *args)
{
  u32 trust = va_arg (*args, u32);

  switch (trust)
    {
    case CILIUM_SRV6_TRUST_QUARANTINED:
      return format (s, "QUARANTINED");
    case CILIUM_SRV6_TRUST_UNTRUSTED:
      return format (s, "UNTRUSTED");
    case CILIUM_SRV6_TRUST_TRUSTED_FABRIC:
      return format (s, "TRUSTED_FABRIC");
    default:
      return format (s, "INVALID(%u)", trust);
    }
}

static void
csg_account_trust (cilium_srv6_main_t *cm, u8 trust, int delta)
{
  switch (trust)
    {
    case CILIUM_SRV6_TRUST_QUARANTINED:
      cm->n_quarantined += delta;
      break;
    case CILIUM_SRV6_TRUST_UNTRUSTED:
      cm->n_untrusted += delta;
      break;
    case CILIUM_SRV6_TRUST_TRUSTED_FABRIC:
      cm->n_trusted_fabric += delta;
      break;
    default:
      break;
    }
}

/*
 * Apply a trust transition. Must be called with the worker barrier held.
 * Entering QUARANTINED (re)arms the D-44 minimum hold and the route
 * withdraw delay.
 */
static void
csg_set_trust (cilium_srv6_main_t *cm, cilium_srv6_guard_if_t *e, u8 trust, f64 now)
{
  if (e->trust == trust)
    return;

  csg_account_trust (cm, e->trust, -1);
  e->trust = trust;
  csg_account_trust (cm, trust, +1);

  if (trust == CILIUM_SRV6_TRUST_QUARANTINED)
    e->quarantined_at = now;
}

u32
cilium_srv6_quarantine_hold_remaining_ms (const cilium_srv6_guard_if_t *e)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  f64 elapsed, left;

  if (e->trust != CILIUM_SRV6_TRUST_QUARANTINED)
    return 0;

  elapsed = vlib_time_now (vlib_get_main ()) - e->quarantined_at;
  left = cm->quarantine_min_hold - elapsed;
  return left > 0.0 ? (u32) (left * 1e3) : 0;
}

u32
cilium_srv6_withdraw_delay_remaining_ms (const cilium_srv6_guard_if_t *e)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  f64 elapsed, left;

  if (e->trust != CILIUM_SRV6_TRUST_QUARANTINED)
    return 0;

  elapsed = vlib_time_now (vlib_get_main ()) - e->quarantined_at;
  left = cm->withdraw_delay - elapsed;
  return left > 0.0 ? (u32) (left * 1e3) : 0;
}

/* ------------------------------------------------------------------ */
/* interface classification / guard installation                       */
/* ------------------------------------------------------------------ */

/* 03 §1.1 / D-31 invariant: only physical/bond/uplink class interfaces may
 * become TRUSTED_FABRIC. Every device class in
 * cilium_srv6_non_fabric_dev_classes (tap family, memif, af-packet,
 * vhost-user) is rejected here, and an interface whose device class cannot
 * be determined is rejected as well (fail-safe). */
static u8
csg_interface_is_promotable (vnet_main_t *vnm, u32 sw_if_index)
{
  vnet_hw_interface_t *hi;
  vnet_device_class_t *dc;
  u32 i;

  hi = vnet_get_sup_hw_interface_api_visible_or_null (vnm, sw_if_index);
  if (hi == NULL)
    return 0;

  dc = vnet_get_device_class (vnm, hi->dev_class_index);
  if (dc == NULL || dc->name == NULL)
    return 0;

  for (i = 0; i < ARRAY_LEN (cilium_srv6_non_fabric_dev_classes); i++)
    if (0 == strcmp (dc->name, cilium_srv6_non_fabric_dev_classes[i]))
      return 0;

  return 1;
}

/* Install / remove the permanent guard feature on one interface. Returns 0
 * on success. Any failure leaves guard_installed == 0, which keeps guard
 * coverage incomplete and therefore SRv6 NOT_READY (03 §1.1). */
static int
csg_guard_feature_set (cilium_srv6_main_t *cm, u32 sw_if_index, int enable)
{
  cilium_srv6_guard_if_t *e = vec_elt_at_index (cm->ifs, sw_if_index);
  u8 want = enable ? 1 : 0;
  int rv;

  if (want == e->guard_installed)
    return 0;

  rv = vnet_feature_enable_disable (CSG_ARC_NAME, CSG_NODE_NAME, sw_if_index, enable, 0, 0);
  if (rv != 0)
    {
      CSG_LOG_ERR ("guard feature %s failed on sw_if_index %u: %d", enable ? "enable" : "disable",
		   sw_if_index, rv);
      return rv;
    }

  /* n_uncovered counts live interfaces that the guard is not on. */
  if (e->valid)
    {
      if (want)
	{
	  if (cm->n_uncovered > 0)
	    cm->n_uncovered--;
	}
      else
	cm->n_uncovered++;
    }

  e->guard_installed = want;
  return 0;
}

/*
 * Bring an interface under guard control. The entry starts QUARANTINED:
 * an interface the agent has not classified must never forward SID Block
 * traffic (03 §1.1 fail-safe), and a reused sw_if_index must not inherit
 * the previous interface's classification (D-31).
 */
static void
csg_interface_add (vlib_main_t *vm, vnet_main_t *vnm, u32 sw_if_index)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  cilium_srv6_guard_if_t *e;
  f64 now = vlib_time_now (vm);
  int taken;

  taken = cilium_srv6_barrier_acquire (vm);

  vec_validate_init_empty (cm->ifs, sw_if_index, (cilium_srv6_guard_if_t){ 0 });
  e = vec_elt_at_index (cm->ifs, sw_if_index);

  if (e->valid)
    {
      /* Should not happen; treat as a fresh incarnation anyway. */
      CSG_LOG_ERR ("sw_if_index %u added while still marked valid", sw_if_index);
    }
  else
    {
      cm->n_valid++;
      cm->n_uncovered++;
      csg_account_trust (cm, e->trust, +1);
    }

  e->valid = 1;
  e->incarnation = ++cm->next_incarnation;
  e->promotable = csg_interface_is_promotable (vnm, sw_if_index);
  csg_set_trust (cm, e, CILIUM_SRV6_TRUST_QUARANTINED, now);
  e->quarantined_at = now;

  csg_guard_feature_set (cm, sw_if_index, 1 /* enable */);

  cilium_srv6_barrier_release (vm, taken);
}

/*
 * D-31: drop the entry to QUARANTINED *before* the sw_if_index is released,
 * so that there is no window in which a new interface reusing the index is
 * treated as TRUSTED_FABRIC.
 */
static void
csg_interface_del (vlib_main_t *vm, u32 sw_if_index)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  cilium_srv6_guard_if_t *e;
  f64 now = vlib_time_now (vm);
  int taken;

  if (sw_if_index >= vec_len (cm->ifs))
    return;

  taken = cilium_srv6_barrier_acquire (vm);

  e = vec_elt_at_index (cm->ifs, sw_if_index);

  csg_set_trust (cm, e, CILIUM_SRV6_TRUST_QUARANTINED, now);

  csg_guard_feature_set (cm, sw_if_index, 0 /* disable */);

  if (e->valid)
    {
      cm->n_valid--;
      csg_account_trust (cm, e->trust, -1);
      if (!e->guard_installed && cm->n_uncovered > 0)
	cm->n_uncovered--;
    }

  e->valid = 0;
  e->promotable = 0;
  /* Keep trust == QUARANTINED and invalidate the incarnation so that an
   * in-flight agent write for the old interface lifetime is rejected. */
  e->incarnation = ~0;

  cilium_srv6_barrier_release (vm, taken);
}

static clib_error_t *
cilium_srv6_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  vlib_main_t *vm = vlib_get_main ();

  if (is_add)
    csg_interface_add (vm, vnm, sw_if_index);
  else
    csg_interface_del (vm, sw_if_index);

  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (cilium_srv6_sw_interface_add_del);

/* ------------------------------------------------------------------ */
/* API-facing operations                                               */
/* ------------------------------------------------------------------ */

/*
 * srv6_acl_interface_set (03 §7). Idempotent; every rejection path leaves
 * the trust map unchanged.
 */
int
cilium_srv6_acl_interface_set (u32 sw_if_index, u32 if_incarnation, u8 trust)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_guard_if_t *e;
  f64 now;
  int taken;
  int rv;

  if (trust >= CILIUM_SRV6_TRUST_N)
    return VNET_API_ERROR_INVALID_VALUE;

  if (sw_if_index >= vec_len (cm->ifs))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  e = vec_elt_at_index (cm->ifs, sw_if_index);

  if (!e->valid)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /* D-31: the trust map key is (sw_if_index, if_incarnation). */
  if (e->incarnation != if_incarnation)
    return VNET_API_ERROR_INVALID_VALUE_2;

  /* 03 §1.1 / D-31 invariant: only physical/bond/uplink class interfaces
   * may be promoted; Pod-, host- and VM-facing classes may not. */
  if (trust == CILIUM_SRV6_TRUST_TRUSTED_FABRIC && !e->promotable)
    {
      CSG_LOG_ERR ("refused TRUSTED_FABRIC promotion of sw_if_index %u "
		   "(device class is not a fabric class)",
		   sw_if_index);
      return VNET_API_ERROR_INVALID_INTERFACE;
    }

  /* D-44: quarantine has a minimum hold time. Leaving it early is refused
   * so that a flapping guard cannot drive BGP churn. The agent retries. */
  if (e->trust == CILIUM_SRV6_TRUST_QUARANTINED && trust != CILIUM_SRV6_TRUST_QUARANTINED &&
      cilium_srv6_quarantine_hold_remaining_ms (e) > 0)
    return VNET_API_ERROR_BUSY;

  /* D-35: while the dead-man switch is active the agent is presumed gone;
   * do not accept classifications that relax the quarantine. */
  if (cm->deadman_active && trust != CILIUM_SRV6_TRUST_QUARANTINED)
    return VNET_API_ERROR_FEATURE_DISABLED;

  now = vlib_time_now (vm);

  taken = cilium_srv6_barrier_acquire (vm);

  /* The guard is permanent; re-assert it in case a previous install failed,
   * so that coverage can recover without an interface event. A
   * classification that relaxes the quarantine is only accepted once the
   * guard is actually on the interface (03 §1.1: an interface must not be
   * treated as classified while the guard is off). */
  rv = csg_guard_feature_set (cm, sw_if_index, 1 /* enable */);
  if (rv != 0 && trust != CILIUM_SRV6_TRUST_QUARANTINED)
    {
      cilium_srv6_barrier_release (vm, taken);
      return rv;
    }

  csg_set_trust (cm, e, trust, now);

  /*
   * errata #34 item 191. `UNTRUSTED` is the only authoritative statement the
   * plugin has that an interface is Pod-facing (D-73 derives it from a
   * D-68/D-71 attachment binding), so it is here — not at the first
   * LocalEndpointTable write — that 02 §1's `pod-if -> guard -> classify`
   * becomes true of the interface. Before this call a Pod interface with no
   * endpoint carried the guard but not classify, and the guard passes
   * everything that is not SID Block destined, so those packets left the
   * ip6-unicast arc into ip6-lookup and were forwarded with no policy
   * evaluation at all (00 §2.20.1 invariant 2 forbids exactly that).
   *
   * A failure here does not reject the classification: it is already
   * committed above and, for a downgrade to QUARANTINED, must be (D-73:
   * trust removal is a fail-closed downgrade and is applied immediately).
   * The agent re-asserts the same classification on its next reconcile
   * (§2.15.4), which retries this; until then the log below is the record.
   */
  if (cilium_srv6_headend_classify_refresh (sw_if_index) != 0)
    CSG_LOG_ERR ("classify feature not brought in line with trust %U on "
		 "sw_if_index %u: the interface is not on the 02 §1 headend path",
		 format_cilium_srv6_trust, (u32) trust, sw_if_index);

  cilium_srv6_barrier_release (vm, taken);

  return 0;
}

/*
 * D-24 / D-35: contain immediately by moving interfaces to QUARANTINED.
 * This only changes classification; ACTIVE Context delivery is deliberately
 * not touched (D-35: stopping delivery would turn this mechanism into an
 * availability attack).
 *
 * `keep_fabric` leaves interfaces that are currently TRUSTED_FABRIC at their
 * classification. See cilium_srv6_quarantine_all_except_fabric().
 */
static void
csg_quarantine_all (const char *reason, int keep_fabric)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_guard_if_t *e;
  f64 now = vlib_time_now (vm);
  int taken;

  /*
   * Deliberately no cilium_srv6_headend_classify_refresh() here (item 191).
   * A bulk quarantine happens when the agent is presumed gone or has just
   * restarted, which is when removing classify from a Pod interface that has
   * no endpoint would hand its packets back to the plain IPv6 FIB. Leaving
   * the feature where it is keeps that interface fail-closed
   * (DROP_UNKNOWN_SOURCE_EP) and keeps a Pod that still has an endpoint
   * delivering, which is what D-35 requires. The next accepted
   * classification re-derives the state.
   */
  taken = cilium_srv6_barrier_acquire (vm);
  vec_foreach (e, cm->ifs)
    {
      if (keep_fabric && e->trust == CILIUM_SRV6_TRUST_TRUSTED_FABRIC)
	continue;
      csg_set_trust (cm, e, CILIUM_SRV6_TRUST_QUARANTINED, now);
    }
  cilium_srv6_barrier_release (vm, taken);

  CSG_LOG_NOTICE ("quarantined %s: %s",
		  keep_fabric ? "all interfaces except TRUSTED_FABRIC" : "all interfaces", reason);
}

/*
 * Quarantine every interface, TRUSTED_FABRIC included.
 *
 * Used where the previous classification itself has become untrustworthy and
 * the agent is known to be alive, so that a re-classification follows within
 * seconds (see cilium_srv6_agent_keepalive()).
 */
void
cilium_srv6_quarantine_all (const char *reason)
{
  csg_quarantine_all (reason, 0 /* keep_fabric */);
}

/*
 * Quarantine every interface that is not currently TRUSTED_FABRIC.
 *
 * This is the D-35 dead-man switch variant. D-35 requires that existing
 * ACTIVE delivery keeps working while the agent is gone, but the guard drops
 * SID Block destined packets on any interface that is not TRUSTED_FABRIC
 * (03 §1.1). Quarantining the fabric uplinks would therefore drop the
 * legitimate SRv6 traffic arriving from the SR domain and stop delivery,
 * which contradicts the D-35 retention clause and would make the dead-man
 * switch itself an availability attack (stall the agent, stop the node).
 *
 * Fabric classification is only ever granted by the agent to a promotable
 * device class (D-31), and every other interface — UNTRUSTED, already
 * QUARANTINED, or never classified — is quarantined as before, so the
 * injection paths the dead-man switch is meant to close stay closed.
 * New Context install is refused unconditionally while the switch is active
 * (cilium_srv6_guard_context_install_allowed()).
 */
void
cilium_srv6_quarantine_all_except_fabric (const char *reason)
{
  csg_quarantine_all (reason, 1 /* keep_fabric */);
}

/*
 * srv6_agent_keepalive (03 §7, D-35). A keepalive from a different API
 * client than the previous one means the agent restarted; the old
 * classification is not trusted across that boundary (D-27), so everything
 * is re-quarantined and must be re-classified.
 */
void
cilium_srv6_agent_keepalive (u32 client_index)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  int restarted;

  restarted = cm->keepalive_seen && cm->keepalive_client_index != client_index;

  cm->keepalive_last = vlib_time_now (vm);
  cm->keepalive_client_index = client_index;
  cm->keepalive_seen = 1;

  /* Deliberately the full variant, TRUSTED_FABRIC included, unlike the
   * dead-man switch path below. The agent is alive here — it just sent this
   * keepalive — so it re-classifies within seconds and the delivery gap is
   * short, while the classification inherited from the previous agent
   * incarnation is not trustworthy across a restart boundary (D-27). */
  if (restarted)
    cilium_srv6_quarantine_all ("agent API client changed (restart)");

  if (cm->deadman_active)
    {
      cm->deadman_active = 0;
      CSG_LOG_NOTICE ("dead-man switch cleared, agent keepalive resumed "
		      "(client_index %u)",
		      client_index);
    }
}

/* ------------------------------------------------------------------ */
/* dead-man switch process node (D-35)                                 */
/* ------------------------------------------------------------------ */

static uword
cilium_srv6_guard_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;

  while (1)
    {
      f64 now;

      vlib_process_wait_for_event_or_clock (vm, CILIUM_SRV6_GUARD_TICK_INTERVAL);
      (void) vlib_process_get_events (vm, 0);

      now = vlib_time_now (vm);

      if (!cm->deadman_active && (now - cm->keepalive_last) > cm->keepalive_timeout)
	{
	  cm->deadman_active = 1;
	  cm->deadman_activations++;
	  cilium_srv6_quarantine_all_except_fabric ("agent keepalive lapsed (D-35)");
	  CSG_LOG_ERR ("dead-man switch fired after %.1f s without an agent "
		       "keepalive: every interface except TRUSTED_FABRIC "
		       "QUARANTINED, new Context install refused, existing "
		       "ACTIVE delivery retained",
		       now - cm->keepalive_last);
	}
    }

  return 0;
}

VLIB_REGISTER_NODE (cilium_srv6_guard_process_node, static) = {
  .function = cilium_srv6_guard_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cilium-srv6-guard-process",
  .process_log2_n_stack_bytes = 16,
};

/* ------------------------------------------------------------------ */
/* startup configuration                                               */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_config (vlib_main_t *vm, unformat_input_t *input)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  ip6_address_t block;
  u8 *path = 0;
  u32 block_len;
  u32 bytes;
  f64 v;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "srv6-block %U/%u", unformat_ip6_address, &block, &block_len))
	{
	  /* LB = 32 (00 §6, D-60). Any other length makes the advertised SID
	     structure inconsistent with the SID, and the End.Cilium /64 local
	     SID of D-10 would be built from the wrong bits. */
	  if (block_len != CILIUM_SRV6_BLOCK_LEN)
	    return clib_error_return (0, "srv6-block prefix length must be /%u (LB=%u)",
				      CILIUM_SRV6_BLOCK_LEN, CILIUM_SRV6_BLOCK_LEN);
	  csg_set_block (cm, &block, (u8) block_len);
	  cm->block_configured = 1;
	}
      else if (unformat (input, "keepalive-timeout %f", &v) && v > 0.0)
	cm->keepalive_timeout = v;
      else if (unformat (input, "quarantine-min-hold %f", &v) && v >= 0.0)
	cm->quarantine_min_hold = v;
      else if (unformat (input, "withdraw-delay %f", &v) && v >= 0.0)
	cm->withdraw_delay = v;
      /* D-54 hardening option, default off. Only meaningful for deployments
	 that state that v1 does not support fragmentation: with D-50's L3
	 TUN attachment a Pod kernel can legitimately fragment before the
	 TUN, so enabling this drops conformant traffic. */
      else if (unformat (input, "untrusted-fragment-drop-all"))
	cm->untrusted_fragment_drop_all = 1;
      /*
       * IF-3 punt socket (D-27, `02` §5.6.6 and §5.6.9). The agent listens on
       * it and the plugin connects.
       *
       * A relative path is refused here rather than resolved against VPP's
       * working directory: that directory is not something the operator sets
       * in this file, so the same configuration would name different sockets
       * on different hosts. D-27 puts the socket in a 0700 directory whose
       * absolute path the agent owns.
       */
      else if (unformat (input, "punt-socket %s", &path))
	{
	  if (vec_len (path) == 0 || path[0] != '/')
	    {
	      vec_free (path);
	      return clib_error_return (0, "punt-socket must be an absolute path");
	    }
	  vec_free (cm->punt_socket_path);
	  vec_add1 (path, 0);
	  cm->punt_socket_path = path;
	  path = 0;
	}
      /* `00` §2.18.7: the punt queue is bounded twice, by entry count and by
	 a byte budget. The entry cap is the 4096 of `02` §5.2 and is not
	 configurable; this is the byte budget. */
      else if (unformat (input, "punt-queue-bytes %u", &bytes))
	{
	  if (bytes < CILIUM_SRV6_IF3_QUEUE_BYTES_MIN || bytes > CILIUM_SRV6_IF3_QUEUE_BYTES_MAX)
	    return clib_error_return (0, "punt-queue-bytes must be between %u and %u",
				      (u32) CILIUM_SRV6_IF3_QUEUE_BYTES_MIN,
				      (u32) CILIUM_SRV6_IF3_QUEUE_BYTES_MAX);
	  cm->punt_queue_bytes = bytes;
	}
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (cilium_srv6_config, "cilium-srv6");

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

/*
 * D-72: draw the plugin instance identity.
 *
 * The value is not a secret and carries no ordering. The one property it must
 * have is that a new plugin initialisation never reproduces the value a
 * previous one used, because that value is the agent's only evidence that the
 * dataplane tables it observed before a reconnect are still the same tables.
 *
 * /dev/urandom is the source, drawn the same way as the headend's flow entropy
 * seed and punt nonce. The fallback mixes the CPU cycle counter, the wall
 * clock and the process identity: none of those is unpredictable, but together
 * they do not repeat across restarts of this process on this node, which is
 * what is actually required here. The fallback is logged, because a deployment
 * in which /dev/urandom is unreadable inside the VPP container is a deployment
 * fault worth seeing.
 */
static void
csg_draw_instance_id (u8 *out)
{
  FILE *f = fopen ("/dev/urandom", "rb");
  u64 mix[2];
  int i;

  if (f != NULL)
    {
      size_t n = fread (out, 1, CILIUM_SRV6_INSTANCE_ID_LEN, f);
      fclose (f);
      if (n == CILIUM_SRV6_INSTANCE_ID_LEN)
	return;
    }

  mix[0] = clib_cpu_time_now () ^ (u64) unix_time_now_nsec ();
  mix[1] = ((u64) getpid () << 32) ^ (u64) (uword) out;
  for (i = 0; i < CILIUM_SRV6_INSTANCE_ID_LEN; i++)
    out[i] = (u8) (mix[i / 8] >> (8 * (i % 8)));

  CSG_LOG_ERR ("could not read /dev/urandom: the %u-byte D-72 plugin instance "
	       "identity is derived from local clock and process state instead",
	       (u32) CILIUM_SRV6_INSTANCE_ID_LEN);
}

static clib_error_t *
cilium_srv6_guard_init (vlib_main_t *vm)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  vnet_main_t *vnm = vnet_get_main ();
  vnet_interface_main_t *im = &vnm->interface_main;
  vnet_sw_interface_t *si;
  ip6_address_t block;
  clib_error_t *error;

  clib_memset (cm, 0, sizeof (*cm));

  cilium_srv6_log_class = vlib_log_register_class ("cilium-srv6", "guard");

  /*
   * D-72: drawn before anything else in init, so that no table this plugin
   * owns can exist without an identity naming the instance that owns it.
   */
  csg_draw_instance_id (cm->plugin_instance_id);

  /* D-60: fdbb:bb00::/32 is test-only and is not a production default. It is
     installed here only so that the block always has a known extent before the
     startup configuration is parsed; `block_configured` stays 0 until a
     `srv6-block` stanza sets it, and `show cilium-srv6` reports that. */
  clib_memset (&block, 0, sizeof (block));
  block.as_u8[0] = CILIUM_SRV6_BLOCK_TEST_DEFAULT_B0;
  block.as_u8[1] = CILIUM_SRV6_BLOCK_TEST_DEFAULT_B1;
  block.as_u8[2] = CILIUM_SRV6_BLOCK_TEST_DEFAULT_B2;
  block.as_u8[3] = CILIUM_SRV6_BLOCK_TEST_DEFAULT_B3;
  csg_set_block (cm, &block, CILIUM_SRV6_BLOCK_LEN);
  cm->block_configured = 0;

  cm->keepalive_timeout = CILIUM_SRV6_KEEPALIVE_TIMEOUT_DEFAULT;
  cm->quarantine_min_hold = CILIUM_SRV6_QUARANTINE_MIN_HOLD_DEFAULT;
  cm->withdraw_delay = CILIUM_SRV6_WITHDRAW_DELAY_DEFAULT;
  /* `00` §2.18.7. There is deliberately no default for `punt_socket_path`:
     see the note on the field. */
  cm->punt_queue_bytes = CILIUM_SRV6_IF3_QUEUE_BYTES_DEFAULT;

  /*
   * D-35: arm the dead-man switch from init. Until the agent has sent its
   * first keepalive the plugin behaves as if the agent were gone, which is
   * also the state every interface starts in (QUARANTINED).
   */
  cm->keepalive_last = vlib_time_now (vm);
  cm->keepalive_seen = 0;
  cm->keepalive_client_index = ~0;
  cm->deadman_active = 0;

  cm->process_node_index = cilium_srv6_guard_process_node.index;

  error = cilium_srv6_plugin_api_hookup (vm);
  if (error)
    return error;

  cm->initialised = 1;

  /*
   * Interfaces that already exist at plugin init time (the plugin is
   * loaded before interfaces are created in the normal case, but do not
   * depend on it).
   */
  pool_foreach (si, im->sw_interfaces)
    {
      csg_interface_add (vm, vnm, si->sw_if_index);
    }

  return 0;
}

/* The guard is installed as a feature during init, so the feature arcs must
 * already exist. Interface add/del callbacks are registered statically and
 * cover every interface created after this point. */
VLIB_INIT_FUNCTION (cilium_srv6_guard_init) = {
  .runs_after = VLIB_INITS ("vnet_feature_init", "vnet_interface_init"),
};
