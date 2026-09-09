/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — conntrack state model (C10).
 *
 * The entry state, the direction and the TCP state machine of
 * design/detail/02-headend-dataplane.md §7, kept free of any vlib dependency
 * so that the transition rules are a pure function of {current state,
 * observed flags, direction, authorised} and can be exercised on their own —
 * the same rule cilium_srv6_hparse.h and cilium_srv6_parse.h follow for the
 * packet parsers.
 *
 * Design references:
 *   design/detail/02-headend-dataplane.md §7.1 (states), §7.2 (the allow
 *     conditions the state feeds)
 *   design/detail/00-overview.md §2 (D-19, D-38, D-45)
 */

#ifndef __included_cilium_srv6_ct_fsm_h__
#define __included_cilium_srv6_ct_fsm_h__

#include <vppinfra/clib.h>

/*
 * 02 §7.1:
 *
 *   state: UNVERIFIED            destination delivery created it (D-19)
 *        | VERIFIED_ESTABLISHED  re-authorised (reply) or ProgramCache
 *                                authorised (forward), and open
 *        | SYN_SEEN | FIN_WAIT | CLOSED   TCP state machine
 *
 * The design writes these as one enum, so they are one enum here. The
 * readings the implementation makes explicit:
 *
 *   - UNVERIFIED is an *authorisation* state and outranks the TCP states: an
 *     entry the destination created is UNVERIFIED whatever its TCP progress,
 *     which is carried in the separate progress bits instead. Only
 *     srv6_ct_verify leaves it (D-19).
 *   - VERIFIED_ESTABLISHED is the design's name for "authorised and open". A
 *     reply entry has to reach it when its re-authorisation succeeds, because
 *     the packet that triggered the punt is the TCP SYN-ACK: a promotion that
 *     stopped at SYN_SEEN would make the reinjected SYN-ACK punt again and
 *     the connection could never establish. "SYN-ACK と ACK を確認して
 *     VERIFIED_ESTABLISHED" is therefore implemented as: the handshake
 *     progress decides the timeout class (transient until both directions
 *     have acknowledged, established afterwards), not whether a packet may
 *     pass.
 *   - INVALID is 0 so that a zero-filled slot is never usable, matching the
 *     fail-safe convention of the Context table and the guard trust map.
 */
typedef enum
{
  CILIUM_SRV6_CT_STATE_INVALID = 0,
  CILIUM_SRV6_CT_STATE_UNVERIFIED = 1,
  CILIUM_SRV6_CT_STATE_SYN_SEEN = 2,
  CILIUM_SRV6_CT_STATE_VERIFIED_ESTABLISHED = 3,
  CILIUM_SRV6_CT_STATE_FIN_WAIT = 4,
  CILIUM_SRV6_CT_STATE_CLOSED = 5,
  CILIUM_SRV6_CT_N_STATE,
} cilium_srv6_ct_state_t;

/*
 * 02 §7.1 key component: "方向別 2 entry (forward/reply) を張る". FORWARD is
 * the direction a local endpoint originates in, REPLY the direction the
 * destination's delivery path pre-creates for the answer. Both entries of one
 * flow are keyed on the tuple as it appears on the wire in that direction, so
 * the reply entry of a flow A->B is keyed (B, A, dport, sport, REPLY) and
 * matches the reply packet directly.
 */
typedef enum
{
  CILIUM_SRV6_CT_DIR_FORWARD = 0,
  CILIUM_SRV6_CT_DIR_REPLY = 1,
} cilium_srv6_ct_dir_t;

/*
 * Entry flags.
 *
 * CILIUM_SRV6_CT_F_VERIFIED, not the state, decides which of the two D-38
 * budgets an entry belongs to and which timeout class it uses. The reason is
 * concurrency: the TCP state machine runs on workers without a lock, while
 * budget membership must only change under the lock. `state` may therefore
 * move (to CLOSED, say) on an unauthorised entry without the accounting
 * following it, and the entry stays in the UNVERIFIED budget, which is the
 * conservative direction.
 *
 * A forward entry is VERIFIED because the ProgramCache authorised the packet
 * that created it (02 §6 step 1); a reply entry only becomes VERIFIED through
 * srv6_ct_verify (02 §7.2, D-19).
 */
#define CILIUM_SRV6_CT_F_REPLY	  (1 << 0) /* direction, mirrors the key */
#define CILIUM_SRV6_CT_F_VERIFIED (1 << 1)

/*
 * TCP progress bits. "own" is the direction the entry is keyed in, "opp" the
 * opposite one: the delivery path refreshes both entries of a flow, so one
 * entry observes both directions and the handshake can be judged from either.
 */
#define CILIUM_SRV6_CT_TCP_SYN_OWN (1 << 0)
#define CILIUM_SRV6_CT_TCP_SYN_OPP (1 << 1)
#define CILIUM_SRV6_CT_TCP_ACK_OWN (1 << 2)
#define CILIUM_SRV6_CT_TCP_ACK_OPP (1 << 3)
#define CILIUM_SRV6_CT_TCP_FIN_OWN (1 << 4)
#define CILIUM_SRV6_CT_TCP_FIN_OPP (1 << 5)
#define CILIUM_SRV6_CT_TCP_RST	   (1 << 6)

/* TCP header control bits, read from byte 13 of the header. */
#define CILIUM_SRV6_CT_TH_FIN 0x01
#define CILIUM_SRV6_CT_TH_SYN 0x02
#define CILIUM_SRV6_CT_TH_RST 0x04
#define CILIUM_SRV6_CT_TH_ACK 0x10

/*
 * State of a TCP flow that is starting: 02 §7.1 "TCP は SYN 受信で SYN_SEEN".
 * A packet that is not a bare SYN belongs to a flow that is already running
 * (a mid-stream packet after a restart), and the entry starts open.
 */
static_always_inline u8
cilium_srv6_ct_initial_state (u8 proto_is_tcp, u8 th)
{
  if (proto_is_tcp && (th & CILIUM_SRV6_CT_TH_SYN) && !(th & CILIUM_SRV6_CT_TH_ACK))
    return CILIUM_SRV6_CT_STATE_SYN_SEEN;

  return CILIUM_SRV6_CT_STATE_VERIFIED_ESTABLISHED;
}

/*
 * Both directions have acknowledged, i.e. the handshake completed. This is
 * what selects the 8 h established timeout over the 30 s transient one
 * (02 §7.1).
 */
static_always_inline int
cilium_srv6_ct_tcp_handshake_done (u8 tcp)
{
  const u8 acked = CILIUM_SRV6_CT_TCP_ACK_OWN | CILIUM_SRV6_CT_TCP_ACK_OPP;

  return (tcp & acked) == acked;
}

/*
 * One step of the TCP state machine (02 §7.2).
 *
 * `th` is the packet's control bits, `own` says whether it travels in the
 * direction the entry is keyed in, and `verified` whether the entry has been
 * authorised (the ProgramCache for a forward entry, srv6_ct_verify for a
 * reply one).
 *
 * Rules:
 *   - progress bits always accumulate, in both directions;
 *   - a reset closes the flow whatever its authorisation state, which stops a
 *     later promotion of the entry (srv6_ct_verify refuses a CLOSED entry);
 *   - an unauthorised entry otherwise never changes state: D-19 requires the
 *     agent's re-authorisation to be the only way out of UNVERIFIED;
 *   - both FINs close, one FIN moves to FIN_WAIT, which 02 §7.2 still admits
 *     because the design excludes CLOSED and timeout, not a flow that is
 *     exchanging its close;
 *   - SYN_SEEN becomes established once both SYNs and an acknowledgement have
 *     been seen.
 */
static_always_inline void
cilium_srv6_ct_tcp_step (u8 *state, u8 *tcp, int verified, u8 th, int own)
{
  const u8 fin_both = CILIUM_SRV6_CT_TCP_FIN_OWN | CILIUM_SRV6_CT_TCP_FIN_OPP;
  const u8 syn_both = CILIUM_SRV6_CT_TCP_SYN_OWN | CILIUM_SRV6_CT_TCP_SYN_OPP;
  const u8 any_ack = CILIUM_SRV6_CT_TCP_ACK_OWN | CILIUM_SRV6_CT_TCP_ACK_OPP;
  u8 bits = *tcp;

  if (th & CILIUM_SRV6_CT_TH_SYN)
    bits |= own ? CILIUM_SRV6_CT_TCP_SYN_OWN : CILIUM_SRV6_CT_TCP_SYN_OPP;
  if (th & CILIUM_SRV6_CT_TH_ACK)
    bits |= own ? CILIUM_SRV6_CT_TCP_ACK_OWN : CILIUM_SRV6_CT_TCP_ACK_OPP;
  if (th & CILIUM_SRV6_CT_TH_FIN)
    bits |= own ? CILIUM_SRV6_CT_TCP_FIN_OWN : CILIUM_SRV6_CT_TCP_FIN_OPP;
  if (th & CILIUM_SRV6_CT_TH_RST)
    bits |= CILIUM_SRV6_CT_TCP_RST;

  *tcp = bits;

  if (bits & CILIUM_SRV6_CT_TCP_RST)
    {
      *state = CILIUM_SRV6_CT_STATE_CLOSED;
      return;
    }

  if (!verified)
    return;

  if ((bits & fin_both) == fin_both)
    *state = CILIUM_SRV6_CT_STATE_CLOSED;
  else if (bits & fin_both)
    *state = CILIUM_SRV6_CT_STATE_FIN_WAIT;
  else if (*state == CILIUM_SRV6_CT_STATE_SYN_SEEN && (bits & syn_both) == syn_both &&
	   (bits & any_ack))
    *state = CILIUM_SRV6_CT_STATE_VERIFIED_ESTABLISHED;
}

/*
 * 02 §7.2 branch 1, protocol state half: VERIFIED_ESTABLISHED is the state the
 * design names, and FIN_WAIT is admitted with it because it is only reachable
 * from VERIFIED_ESTABLISHED and "CLOSED/timeout 後は許可しない" excludes
 * neither the close exchange nor anything else that is still open.
 */
static_always_inline int
cilium_srv6_ct_state_admits_bypass (u8 state)
{
  return state == CILIUM_SRV6_CT_STATE_VERIFIED_ESTABLISHED ||
	 state == CILIUM_SRV6_CT_STATE_FIN_WAIT;
}

/*
 * "単なる 5-tuple 一致で ProgramCache を迂回しない" (02 §7.2). A TCP SYN
 * without ACK opens a connection in the forward direction by definition, so it
 * is never a reply, whatever entry happens to match its tuple. Without this,
 * an unsolicited packet delivered to this node earlier could have pre-created
 * a reply entry for a tuple a local endpoint later initiates, and the
 * connection's own first packet would be authorised against the policy of the
 * reverse direction.
 */
static_always_inline int
cilium_srv6_ct_opens_connection (u8 proto_is_tcp, u8 th)
{
  return proto_is_tcp && (th & CILIUM_SRV6_CT_TH_SYN) && !(th & CILIUM_SRV6_CT_TH_ACK);
}

#endif /* __included_cilium_srv6_ct_fsm_h__ */
