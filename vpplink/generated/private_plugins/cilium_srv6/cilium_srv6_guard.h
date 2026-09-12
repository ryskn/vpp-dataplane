/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — infrastructure guard / ACL (C8-a).
 *
 * This is the only injection defence layer in v1 (D-7 removed the crypto
 * layer, D-9 made the ACL the sole barrier). It is installed from plugin
 * init on every ingress path and keeps working when the agent is gone.
 *
 * Design references:
 *   design/detail/03-destination-dataplane.md §1.1
 *   design/detail/00-overview.md §2 (D-9, D-24, D-31, D-32, D-35, D-44,
 *     D-54), §6
 *   design/detail/01-packet-format.md §3.1 (bounded parser limits)
 *   design/detail/06-observability.md §2, §3
 */

#ifndef __included_cilium_srv6_guard_h__
#define __included_cilium_srv6_guard_h__

#include <vlib/vlib.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>

/* The bounded header walk itself, and the verdict enum it produces, live in
   a vlib-free header so that they can be fuzzed as a pure function. */
#include <cilium_srv6/cilium_srv6_gparse.h>

/* The trust classification values (03 §1.1, D-31) and the predicate that
   decides which interfaces carry cilium-srv6-classify (errata #34 item 191)
   live in a vlib-free header for the same reason. */
#include <cilium_srv6/cilium_srv6_classify_scope.h>

/*
 * Worker barrier helpers shared by every control plane path of the plugin.
 *
 * Structural changes to any table the dataplane reads are made under the
 * worker barrier so that a packet in flight never observes a half-written
 * structure (D-12). Binary API handlers and interface add/del callbacks may
 * already run with the barrier held, process nodes do not, hence the
 * conditional acquire.
 */
static_always_inline int
cilium_srv6_barrier_acquire (vlib_main_t *vm)
{
  if (vlib_worker_thread_barrier_held ())
    return 0;
  vlib_worker_thread_barrier_sync (vm);
  return 1;
}

static_always_inline void
cilium_srv6_barrier_release (vlib_main_t *vm, int taken)
{
  if (taken)
    vlib_worker_thread_barrier_release (vm);
}

/*
 * 00 §6 common constants.
 *
 * SRV6_BLOCK is set from the VPP startup configuration
 * (`cilium-srv6 { srv6-block <prefix>/32 }`). Decision D-60 (00 §2.7):
 *
 *   SRV6_BLOCK is an explicitly configured, cluster-scoped /32 allocated for
 *   the SRv6 Endpoint Context domain. [...] fdbb:bb00::/32 remains test-only
 *   and is not a production default.
 *
 * The value below is therefore named TEST_DEFAULT, not DEFAULT: it exists so
 * that a plugin brought up without a startup configuration has a block whose
 * extent is known (a zero-length block would make the guard's `dst in
 * SRV6_BLOCK` comparison match every address and drop all traffic on every
 * interface it is installed on, and the guard is installed on every interface
 * as it appears). It is not a value any deployment may rely on.
 *
 * The plugin cannot prove the non-overlap invariant of 00 §6 invariant 3 by
 * itself - it needs the cluster's node addresses and PodCIDRs. C11 is the
 * authority for that proof (00 §2.7); until it succeeds the agent does not
 * install a local SID and advertises nothing, so the block configured here is
 * never used for delivery.
 *
 * `block_configured` records whether the value came from the configuration or
 * from the test default, so that `show cilium-srv6` can say so.
 */
#define CILIUM_SRV6_BLOCK_TEST_DEFAULT_B0  0xfd
#define CILIUM_SRV6_BLOCK_TEST_DEFAULT_B1  0xbb
#define CILIUM_SRV6_BLOCK_TEST_DEFAULT_B2  0xbb
#define CILIUM_SRV6_BLOCK_TEST_DEFAULT_B3  0x00

/* LB = 32 (00 §6, 05 §2.1 SID structure). SRV6_BLOCK is a /32 and nothing
   else: a shorter or longer prefix makes the Block(32) | uN_B(16) | uC(16)
   layout of 01 §2.3 untrue. */
#define CILIUM_SRV6_BLOCK_LEN 32

/* 01 §3.1 bounded parser limits (CILIUM_SRV6_GUARD_MAX_EH /
   CILIUM_SRV6_GUARD_MAX_EH_BYTES) live in cilium_srv6_gparse.h alongside the
   walk that enforces them. */

/* D-35 dead-man switch: agent keepalive lapse, default 30 s. */
#define CILIUM_SRV6_KEEPALIVE_TIMEOUT_DEFAULT 30.0

/* D-44 quarantine hysteresis: minimum hold 30 s, route withdraw delay 10 s. */
#define CILIUM_SRV6_QUARANTINE_MIN_HOLD_DEFAULT 30.0
#define CILIUM_SRV6_WITHDRAW_DELAY_DEFAULT	10.0

/* Interval at which the dead-man / hysteresis process node wakes up. */
#define CILIUM_SRV6_GUARD_TICK_INTERVAL 1.0

/*
 * D-72: length of the plugin instance identity, in bytes.
 *
 * 128 bits, drawn once per plugin initialisation. The agent compares two
 * observations of it for equality and nothing else: a different value means
 * every dataplane table this plugin owns was lost and the agent must run the
 * full recovery sequence; the same value means an IF-2 transport was merely
 * re-established. The width is chosen so that "two independently drawn
 * identities collide" is not a case the recovery logic has to consider, which
 * is what lets equality stand in for identity here.
 */
#define CILIUM_SRV6_INSTANCE_ID_LEN 16

/* The interface trust classification enum (03 §1.1, D-31) is defined in
 * cilium_srv6_classify_scope.h, included above, next to the predicate that
 * reads it. */

/*
 * Per-interface guard state. The dataplane reads only `trust`; every other
 * field is control plane. The key of the trust map is logically
 * (sw_if_index, incarnation) per D-31 — the vector index supplies
 * sw_if_index and `incarnation` is stored alongside so that a write
 * carrying a stale incarnation can be rejected.
 */
typedef struct
{
  /* hot path */
  u8 trust;

  /* control plane */
  u8 valid;	      /* interface currently exists */
  u8 guard_installed; /* cilium-srv6-guard on the ingress arc */
  /* cilium-srv6-classify on the ingress arc. Owned by the headend
     (cilium_srv6_headend_classify_refresh), kept here because it is
     per-interface-lifetime state that outlives any one local endpoint, and
     because vnet_feature_enable_disable() is reference counted and must not
     be called twice for the same state. */
  u8 classify_installed;
  u8 promotable; /* may become TRUSTED_FABRIC (D-31) */
  u32 incarnation;
  f64 quarantined_at; /* time of the last entry into QUARANTINED */
} cilium_srv6_guard_if_t;

typedef struct
{
  /* trust map, indexed by sw_if_index */
  cilium_srv6_guard_if_t *ifs;

  /*
   * Monotonically increasing incarnation source. sw_if_index values are
   * reused by VPP, incarnations are not, so (sw_if_index, incarnation)
   * identifies one interface lifetime (D-31).
   */
  u32 next_incarnation;

  /*
   * D-72 plugin instance identity, drawn once in cilium_srv6_guard_init and
   * never written again. It names *this* initialisation of the plugin, which
   * is the lifetime of every table the plugin owns.
   *
   * It is not the interface incarnation (that is per interface lifetime) and
   * it is not the IF-2 transport epoch (that is per connection, and the plugin
   * does not have a notion of it at all): a client that reconnects reads the
   * same value, a client that talks to a restarted VPP reads a different one.
   * Keeping the three apart is what stops "the socket came back" from being
   * read as "the tables are still there".
   */
  u8 plugin_instance_id[CILIUM_SRV6_INSTANCE_ID_LEN];

  /* SRV6_BLOCK (00 §6), pre-masked for the hot path comparison */
  ip6_address_t block;
  u8 block_len;
  /* D-60: set when the block came from the startup configuration rather than
     from the test default. Production deployments must configure it. */
  u8 block_configured;
  u64 block_u64[2];
  u64 block_mask_u64[2];

  /* D-35 dead-man switch */
  f64 keepalive_timeout;
  f64 keepalive_last;
  u32 keepalive_client_index;
  u8 keepalive_seen;
  u8 deadman_active;
  u64 deadman_activations;

  /* D-44 quarantine hysteresis */
  f64 quarantine_min_hold;
  f64 withdraw_delay;

  /*
   * D-54 hardening option, default off
   * (`cilium-srv6 { untrusted-fragment-drop-all }`).
   *
   * When set, any packet carrying an IPv6 Fragment header on an UNTRUSTED
   * ingress is dropped, offset and M bit included. This is for deployments
   * that state "v1 does not support fragmentation" — it is not the default
   * because D-50 made the Pod attachment an L3 TUN, and a Pod kernel may
   * legitimately fragment a large UDP datagram before the TUN, so an
   * unconditional fragment drop would break conformant traffic.
   */
  u8 untrusted_fragment_drop_all;

  /*
   * IF-3 punt socket (`cilium-srv6 { punt-socket <path> }`, D-27, `02`
   * §5.6.9). The agent listens on it and the plugin connects (`02` §5.6.6),
   * so this is the path the transport owner dials.
   *
   * A vec, NUL-terminated, or 0 when the operator did not configure one. It
   * has no default: the path is a deployment decision (the D-27 socket lives
   * in a 0700 directory the agent creates), and inventing one would make the
   * plugin dial a path nobody owns. With no path there is no transport, so
   * every punt fails closed and is counted in punt_no_transport — the same
   * disposition as an agent that is not running.
   *
   * A relative path is refused at startup rather than resolved against
   * whatever VPP's working directory happens to be.
   */
  u8 *punt_socket_path;

  /*
   * Byte budget of the IF-3 punt queue (`cilium-srv6 { punt-queue-bytes N }`,
   * `00` §2.18.7). The entry cap is fixed at the 4096 of `02` §5.2; this is
   * the second bound, and it exists because 4096 x 9216 B would reserve about
   * 38 MB for a queue whose entries are a few hundred bytes each.
   *
   * See CILIUM_SRV6_IF3_QUEUE_BYTES_* below for the default and the accepted
   * range.
   */
  u32 punt_queue_bytes;

  /* coverage accounting */
  u32 n_valid;
  u32 n_uncovered; /* valid interfaces without the guard installed */
  u32 n_quarantined;
  u32 n_untrusted;
  u32 n_trusted_fabric;

  u32 process_node_index;
  u16 msg_id_base;
  u8 initialised;
} cilium_srv6_main_t;

/*
 * Byte budget of the IF-3 punt queue (`00` §2.18.7). 8 MiB holds roughly
 * 8000 punts of a 1 KiB packet, i.e. more than the 4096 entry cap allows, and
 * about 1/5 of what the entry cap alone would have reserved.
 *
 * The minimum is set where a queue stops being one: below a handful of
 * maximum-size frames every burst overflows, which is a configuration mistake
 * rather than a tuning choice, so it is refused at startup instead of
 * producing a node that silently drops.
 */
#define CILIUM_SRV6_IF3_QUEUE_BYTES_DEFAULT (8u << 20)
#define CILIUM_SRV6_IF3_QUEUE_BYTES_MIN	    (64u << 10)
#define CILIUM_SRV6_IF3_QUEUE_BYTES_MAX	    (1u << 30)

extern cilium_srv6_main_t cilium_srv6_main;
extern vlib_node_registration_t cilium_srv6_guard_node;

/* cilium_srv6_guard_verdict_t is defined in cilium_srv6_gparse.h. */

/*
 * Hot path trust lookup (03 §1: one lookup, shared by every ingress).
 * An sw_if_index that has no entry is QUARANTINED — the fail-safe rule of
 * 03 §1.1. The vector is only ever grown under the worker barrier, so a
 * concurrent read of vec_len()/element is safe.
 */
static_always_inline u8
cilium_srv6_trust_get (const cilium_srv6_main_t *cm, u32 sw_if_index)
{
  if (PREDICT_FALSE (sw_if_index >= vec_len (cm->ifs)))
    return CILIUM_SRV6_TRUST_QUARANTINED;
  return cm->ifs[sw_if_index].trust;
}

/* dst ∈ SRV6_BLOCK (03 §1.1). */
static_always_inline int
cilium_srv6_addr_in_block (const cilium_srv6_main_t *cm, const ip6_address_t *a)
{
  return cilium_srv6_gparse_addr_in_block (cm->block_u64, cm->block_mask_u64, a);
}

/*
 * Guard coverage (03 §1.1): every live interface carries the guard.
 *
 * This is the guard-covered half of the D-58 READY invariant — "every packet
 * injection path reachable by an untrusted principal MUST either traverse the
 * guard or be administratively unavailable before local SID installation".
 * The administratively-unavailable half (untrusted workloads must not reach
 * the VPP Host Stack / session layer, and must not receive VPP API/session
 * attachment capability) is a deployment property that the plugin cannot
 * observe; it is checked against the deployment, not here.
 *
 * SRv6 must stay NOT_READY until this is true; a local SID must never be
 * installed while the guard is off.
 */
static_always_inline int
cilium_srv6_guard_coverage_complete (const cilium_srv6_main_t *cm)
{
  return cm->initialised && cm->n_uncovered == 0;
}

/*
 * Gate consulted by the Context install path (C8-b). New Context install
 * is refused while guard coverage is incomplete (03 §1.1) or while the
 * dead-man switch is active (D-35). Existing ACTIVE delivery is not
 * affected by this flag — see D-35 rationale.
 */
static_always_inline int
cilium_srv6_guard_context_install_allowed (void)
{
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  return cilium_srv6_guard_coverage_complete (cm) && !cm->deadman_active;
}

/* Control plane entry points (cilium_srv6_guard.c). */
int cilium_srv6_acl_interface_set (u32 sw_if_index, u32 if_incarnation, u8 trust);
void cilium_srv6_agent_keepalive (u32 client_index);
void cilium_srv6_quarantine_all (const char *reason);
void cilium_srv6_quarantine_all_except_fabric (const char *reason);
u8 *format_cilium_srv6_trust (u8 *s, va_list *args);
u32 cilium_srv6_quarantine_hold_remaining_ms (const cilium_srv6_guard_if_t *e);
u32 cilium_srv6_withdraw_delay_remaining_ms (const cilium_srv6_guard_if_t *e);

clib_error_t *cilium_srv6_plugin_api_hookup (vlib_main_t *vm);

#endif /* __included_cilium_srv6_guard_h__ */
