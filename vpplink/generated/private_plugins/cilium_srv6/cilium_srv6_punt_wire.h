/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — IF-3 wire format v2 (D-76, errata #34 item 152).
 *
 * design/detail/02-headend-dataplane.md §5.6 (byte tables, enums, worked
 *   example), §5.6.9 (this implementation)
 * design/detail/00-overview.md §2.18 (the normative clauses), §4.1 (validate
 *   version / opcode / length / counts before reading any field)
 *
 * The wire is defined by two documents that state one contract: `02` §5.6 and
 * `pkg/srv6ec/compiler/wire.go`. This header is the C serializer for it. It
 * is deliberately *not* a struct cast:
 *
 *   - no `sizeof` of any C type reaches the wire. The header lengths below
 *     are the wire constants of `02` §5.6, and every field is written to an
 *     explicit offset with an explicit width;
 *   - every integer is written big endian by hand (byte shifts), so the
 *     produced bytes do not depend on the host byte order, on struct padding,
 *     on a compiler's field ordering or on a `byte_order.h` configuration
 *     macro;
 *   - the plugin-internal handoff type (`cilium_srv6_punt_meta_t`) is an
 *     *input* to this file, never the thing that travels. `00` §2.18.1.
 *
 * Like the four parser headers it carries no vlib and no vnet dependency: it
 * is a pure function of bytes and can be compiled against the byte-level
 * stubs in test/fuzz/stub, which is what test/wire/ does when it checks the
 * three golden frames of `02` §5.6.7 byte for byte.
 *
 * Direction and roles (`02` §5.6.6): the agent listens on the D-27 punt
 * socket and the plugin connects. Punts travel plugin -> agent (opcodes
 * 1 / 2 / 3), reinject and release travel agent -> plugin (16 / 17), on the
 * same connection.
 */

#ifndef __included_cilium_srv6_punt_wire_h__
#define __included_cilium_srv6_punt_wire_h__

#include <vppinfra/clib.h>

/* ------------------------------------------------------------------ */
/* wire constants (02 §5.6.1, §5.6.2, §5.6.3)                          */
/* ------------------------------------------------------------------ */

/*
 * Version 2. Version 1 is not accepted in either direction: it never had a
 * working peer (`00` §2.18.1), and a v1 sender is rejected on the version
 * byte, which is a framing violation and closes the connection, so the
 * mismatch is loud rather than misread.
 */
#define CILIUM_SRV6_IF3_VERSION 2

/* Header lengths. These are the wire constants of 02 §5.6, not the sizeof of
   any structure on either end. */
#define CILIUM_SRV6_IF3_PUNT_HDR_LEN	 92
#define CILIUM_SRV6_IF3_REINJECT_HDR_LEN 36

/* 02 §5.6.2: packet_len <= 9216, so a punt frame is at most 9308 bytes and a
   reinject frame at most 9252. The transport bounds both before it reads a
   field (00 §4.1). */
#define CILIUM_SRV6_IF3_MAX_PACKET     9216
#define CILIUM_SRV6_IF3_MAX_PUNT_FRAME (CILIUM_SRV6_IF3_PUNT_HDR_LEN + CILIUM_SRV6_IF3_MAX_PACKET)
#define CILIUM_SRV6_IF3_MAX_REINJECT_FRAME                                                         \
  (CILIUM_SRV6_IF3_REINJECT_HDR_LEN + CILIUM_SRV6_IF3_MAX_PACKET)

/* The 16-byte one-shot capability of D-27, restated by D-76 §2.18.4. It is
   opaque: it encodes no slot index and nothing else the holder can act on. */
#define CILIUM_SRV6_IF3_TOKEN_LEN 16

/*
 * Opcodes. Punt opcodes are below 16 and reinject opcodes at or above it, so
 * a peer that echoes a frame back is rejected on the opcode instead of being
 * acted on. The punt opcode *is* the D-38 / D-43 queue: there is no separate
 * `queue` field, so the queue and the reason cannot disagree on the wire
 * (02 §5.6.1).
 */
#define CILIUM_SRV6_IF3_OP_PUNT_COMPILE	 1
#define CILIUM_SRV6_IF3_OP_PUNT_REAUTH	 2
#define CILIUM_SRV6_IF3_OP_PUNT_FRAGMENT 3
#define CILIUM_SRV6_IF3_OP_REINJECT	 16
#define CILIUM_SRV6_IF3_OP_RELEASE	 17

/*
 * 02 §5.6.4. These are the same five values as cilium_srv6_punt_reason_t; the
 * static assertions at the bottom of cilium_srv6_headend.h keep the two from
 * drifting apart. D-76 §2.18.3 forbids folding STALE_PATH into
 * STALE_REVISION: the two describe different invalidations and therefore
 * different recoveries.
 */
#define CILIUM_SRV6_IF3_CAUSE_MISS	     0
#define CILIUM_SRV6_IF3_CAUSE_STALE_REVISION 1
#define CILIUM_SRV6_IF3_CAUSE_LEASE_EXPIRED  2
#define CILIUM_SRV6_IF3_CAUSE_STALE_PATH     3
#define CILIUM_SRV6_IF3_CAUSE_REPLY_REAUTH   4
#define CILIUM_SRV6_IF3_N_CAUSE		     5

/*
 * 02 §5.6.5. Same values as cilium_srv6_frag_kind_t. ATOMIC is a distinct
 * wire value rather than being folded into NONE because the bounded parser of
 * `01` §3.1 distinguishes it, and D-76 §2.18.2 forbids the transport from
 * rewriting what the parser found.
 */
#define CILIUM_SRV6_IF3_FRAG_NONE      0
#define CILIUM_SRV6_IF3_FRAG_ATOMIC    1
#define CILIUM_SRV6_IF3_FRAG_FIRST     2
#define CILIUM_SRV6_IF3_FRAG_NON_FIRST 3
#define CILIUM_SRV6_IF3_N_FRAG_KIND    4

/*
 * The drop reasons a release may carry: the `06` §2 subset the headend slow
 * path can produce, matching pkg/srv6ec/compiler/reason.go. 0 is "not a
 * drop" and accompanies a reinject.
 */
#define CILIUM_SRV6_IF3_DROP_NONE		 0
#define CILIUM_SRV6_IF3_DROP_POLICY_DENIED	 1
#define CILIUM_SRV6_IF3_DROP_SLOWPATH_OVERFLOW	 2
#define CILIUM_SRV6_IF3_DROP_NO_REMOTE_ENDPOINT	 3
#define CILIUM_SRV6_IF3_DROP_IDENTITY_UNRESOLVED 4
#define CILIUM_SRV6_IF3_DROP_FRAGMENT_UNRESOLVED 5
#define CILIUM_SRV6_IF3_N_DROP_REASON		 6

/* ------------------------------------------------------------------ */
/* results                                                             */
/* ------------------------------------------------------------------ */

/*
 * Decode results, split exactly the way `00` §2.18.9 splits dispositions and
 * named after the closed `reason` label set of `06` §3.
 *
 *   framing   VERSION / OPCODE / LENGTH / TRUNCATED. After one of these the
 *             receiver no longer knows where this frame ends, so reading on
 *             would be guessing: close the connection and count
 *             ipc_message_rejections_total.
 *   semantic  FIELD / TOKEN. Detected inside a frame whose boundary was
 *             already validated, so exactly one frame is discarded, the
 *             stream continues, and ipc_frame_drops_total is counted.
 *
 * The asymmetry is the point: before D-76 every rejection closed the
 * connection, which let one odd frame disable the node's slow path
 * permanently — an attacker-inducible fail-stop, which is the failure mode
 * fail-closed exists to avoid (R-P16).
 */
typedef enum
{
  CILIUM_SRV6_IF3_OK = 0,
  CILIUM_SRV6_IF3_ERR_VERSION,
  CILIUM_SRV6_IF3_ERR_OPCODE,
  CILIUM_SRV6_IF3_ERR_LENGTH,
  CILIUM_SRV6_IF3_ERR_TRUNCATED,
  CILIUM_SRV6_IF3_ERR_FIELD,
  CILIUM_SRV6_IF3_ERR_TOKEN,
  CILIUM_SRV6_IF3_N_RESULT,
} cilium_srv6_if3_result_t;

static_always_inline int
cilium_srv6_if3_is_framing_error (cilium_srv6_if3_result_t r)
{
  return r >= CILIUM_SRV6_IF3_ERR_VERSION && r <= CILIUM_SRV6_IF3_ERR_TRUNCATED;
}

static_always_inline const char *
cilium_srv6_if3_result_name (cilium_srv6_if3_result_t r)
{
  switch (r)
    {
    case CILIUM_SRV6_IF3_OK:
      return "ok";
    case CILIUM_SRV6_IF3_ERR_VERSION:
      return "version";
    case CILIUM_SRV6_IF3_ERR_OPCODE:
      return "opcode";
    case CILIUM_SRV6_IF3_ERR_LENGTH:
      return "length";
    case CILIUM_SRV6_IF3_ERR_TRUNCATED:
      return "truncated";
    case CILIUM_SRV6_IF3_ERR_FIELD:
      return "field";
    case CILIUM_SRV6_IF3_ERR_TOKEN:
      return "token";
    default:
      return "invalid";
    }
}

/* ------------------------------------------------------------------ */
/* the values that travel                                              */
/* ------------------------------------------------------------------ */

/*
 * The wire view of a punt. Every field here is a value the headend classifier
 * already produced; the serializer never re-derives one from the packet
 * bytes (`00` §2.18.2). Integers are in host order in this structure and are
 * converted on write, so a caller never has to think about byte order.
 */
typedef struct
{
  u8 token[CILIUM_SRV6_IF3_TOKEN_LEN];
  u8 opcode;	       /* CILIUM_SRV6_IF3_OP_PUNT_*: the D-38 / D-43 queue */
  u8 cause;	       /* CILIUM_SRV6_IF3_CAUSE_* */
  u8 proto;	       /* upper layer protocol from the bounded parse */
  u8 frag_kind;	       /* CILIUM_SRV6_IF3_FRAG_* */
  u8 frag_next_header; /* Fragment header Next Header (01 §3.1) */
  u8 src_ip[16];
  u8 dst_ip[16];
  u16 l4_discriminator; /* D-41; 0 for a protocol that has none */
  u16 src_port;
  u16 dst_port;
  u32 src_identity;
  u32 rx_sw_if_index;
  u32 rx_if_incarnation;
  u32 fragment_id; /* host order Identification; 0 iff frag_kind == NONE */
  u64 punt_id;	   /* #90, never 0 */
} cilium_srv6_if3_punt_t;

/* The wire view of a reinject (opcode 16) or a release (opcode 17). */
typedef struct
{
  u8 token[CILIUM_SRV6_IF3_TOKEN_LEN];
  u8 opcode;
  u8 drop_reason; /* 0 on a reinject, 1..5 on a release */
  u64 punt_id;	  /* the punt's value on a reinject; 0 on a release */
  u32 packet_len;
  /* Points into the caller's frame buffer; nothing is copied. */
  const u8 *packet;
} cilium_srv6_if3_reinject_t;

/* ------------------------------------------------------------------ */
/* big endian primitives                                               */
/* ------------------------------------------------------------------ */

static_always_inline void
cilium_srv6_if3_put_u16 (u8 *p, u16 v)
{
  p[0] = (u8) (v >> 8);
  p[1] = (u8) v;
}

static_always_inline void
cilium_srv6_if3_put_u32 (u8 *p, u32 v)
{
  p[0] = (u8) (v >> 24);
  p[1] = (u8) (v >> 16);
  p[2] = (u8) (v >> 8);
  p[3] = (u8) v;
}

static_always_inline void
cilium_srv6_if3_put_u64 (u8 *p, u64 v)
{
  cilium_srv6_if3_put_u32 (p, (u32) (v >> 32));
  cilium_srv6_if3_put_u32 (p + 4, (u32) v);
}

static_always_inline u16
cilium_srv6_if3_get_u16 (const u8 *p)
{
  return (u16) (((u16) p[0] << 8) | (u16) p[1]);
}

static_always_inline u32
cilium_srv6_if3_get_u32 (const u8 *p)
{
  return ((u32) p[0] << 24) | ((u32) p[1] << 16) | ((u32) p[2] << 8) | (u32) p[3];
}

static_always_inline u64
cilium_srv6_if3_get_u64 (const u8 *p)
{
  return ((u64) cilium_srv6_if3_get_u32 (p) << 32) | (u64) cilium_srv6_if3_get_u32 (p + 4);
}

static_always_inline int
cilium_srv6_if3_token_is_zero (const u8 *token)
{
  int i;

  for (i = 0; i < CILIUM_SRV6_IF3_TOKEN_LEN; i++)
    if (token[i] != 0)
      return 0;
  return 1;
}

/* ------------------------------------------------------------------ */
/* frag_kind validity (02 §5.6.5)                                      */
/* ------------------------------------------------------------------ */

/*
 * The only two contradictions the frame can hold, stated once so that the
 * encoder and the decoder cannot drift apart:
 *
 *   (a) NONE means "no Fragment header", so a fragment_id or a
 *       frag_next_header next to it is a frame that disagrees with itself;
 *   (b) a fragment-class punt exists to compile a FragmentVerdictCache entry,
 *       whose key needs the Fragment header, so NONE contradicts opcode 3.
 *
 * Everything else is legal. In particular any frag_kind may appear on a
 * compile or a reply punt — a fragmented flow is re-authorised like any other
 * — and 0 is a legitimate fragment_id and a legitimate frag_next_header
 * (Hop-by-Hop) on a real fragment. The old inference "a non-fragment opcode
 * with fragment_id != 0 is fatal" is what made a reply reauthorization of a
 * fragmented flow kill the connection (00 §2.18.5).
 */
static_always_inline cilium_srv6_if3_result_t
cilium_srv6_if3_check_frag (u8 opcode, u8 frag_kind, u32 fragment_id, u8 frag_next_header)
{
  if (frag_kind >= CILIUM_SRV6_IF3_N_FRAG_KIND)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  if (frag_kind != CILIUM_SRV6_IF3_FRAG_NONE)
    return CILIUM_SRV6_IF3_OK;

  if (fragment_id != 0 || frag_next_header != 0)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  if (opcode == CILIUM_SRV6_IF3_OP_PUNT_FRAGMENT)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  return CILIUM_SRV6_IF3_OK;
}

/*
 * D-41, mirrored from pkg/srv6ec/compiler/key.go: only TCP, UDP and ICMPv6
 * have a discriminator, and every other protocol must carry 0. The agent
 * rejects a frame that breaks this with ErrField, so the plugin checks it
 * before sending rather than emitting frames the peer will drop.
 */
#define CILIUM_SRV6_IF3_PROTO_TCP   6
#define CILIUM_SRV6_IF3_PROTO_UDP   17
#define CILIUM_SRV6_IF3_PROTO_ICMP6 58

static_always_inline int
cilium_srv6_if3_discriminator_valid (u8 proto, u16 discriminator)
{
  switch (proto)
    {
    case CILIUM_SRV6_IF3_PROTO_TCP:
    case CILIUM_SRV6_IF3_PROTO_UDP:
    case CILIUM_SRV6_IF3_PROTO_ICMP6:
      return 1;
    default:
      return discriminator == 0;
    }
}

/* ------------------------------------------------------------------ */
/* punt frame encode (02 §5.6.2)                                       */
/* ------------------------------------------------------------------ */

/*
 * Write the 92-byte punt header for a frame carrying `packet_len` packet
 * bytes. `out` must have room for CILIUM_SRV6_IF3_PUNT_HDR_LEN bytes.
 *
 * Everything the agent's decoder refuses is refused here first, so that the
 * dataplane cannot spend a socket write on a frame the peer will drop and
 * then wait for a reinject that will never come. The offsets are the ones in
 * the `02` §5.6.2 table, written out literally.
 */
static_always_inline cilium_srv6_if3_result_t
cilium_srv6_if3_punt_encode (u8 *out, const cilium_srv6_if3_punt_t *p, u32 packet_len)
{
  cilium_srv6_if3_result_t rv;

  if (packet_len > CILIUM_SRV6_IF3_MAX_PACKET)
    return CILIUM_SRV6_IF3_ERR_LENGTH;

  if (p->opcode != CILIUM_SRV6_IF3_OP_PUNT_COMPILE && p->opcode != CILIUM_SRV6_IF3_OP_PUNT_REAUTH &&
      p->opcode != CILIUM_SRV6_IF3_OP_PUNT_FRAGMENT)
    return CILIUM_SRV6_IF3_ERR_OPCODE;

  if (cilium_srv6_if3_token_is_zero (p->token))
    return CILIUM_SRV6_IF3_ERR_TOKEN;

  if (p->punt_id == 0)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  if (p->cause >= CILIUM_SRV6_IF3_N_CAUSE)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  if (!cilium_srv6_if3_discriminator_valid (p->proto, p->l4_discriminator))
    return CILIUM_SRV6_IF3_ERR_FIELD;

  rv = cilium_srv6_if3_check_frag (p->opcode, p->frag_kind, p->fragment_id, p->frag_next_header);
  if (rv != CILIUM_SRV6_IF3_OK)
    return rv;

  clib_memset (out, 0, CILIUM_SRV6_IF3_PUNT_HDR_LEN);

  out[0] = CILIUM_SRV6_IF3_VERSION;
  out[1] = p->opcode;
  /* `length` is the *total* frame length, header included (02 §5.6.1). */
  cilium_srv6_if3_put_u16 (out + 2, (u16) (CILIUM_SRV6_IF3_PUNT_HDR_LEN + packet_len));
  clib_memcpy_fast (out + 4, p->token, CILIUM_SRV6_IF3_TOKEN_LEN);
  cilium_srv6_if3_put_u32 (out + 20, p->src_identity);
  cilium_srv6_if3_put_u32 (out + 24, p->rx_sw_if_index);
  cilium_srv6_if3_put_u32 (out + 28, p->rx_if_incarnation);
  clib_memcpy_fast (out + 32, p->src_ip, 16);
  clib_memcpy_fast (out + 48, p->dst_ip, 16);
  out[64] = p->proto;
  out[65] = p->cause;
  cilium_srv6_if3_put_u16 (out + 66, p->l4_discriminator);
  cilium_srv6_if3_put_u16 (out + 68, p->src_port);
  cilium_srv6_if3_put_u16 (out + 70, p->dst_port);
  cilium_srv6_if3_put_u32 (out + 72, p->fragment_id);
  out[76] = p->frag_next_header;
  out[77] = p->frag_kind;
  /* out[78..79] reserved, already zero. */
  cilium_srv6_if3_put_u32 (out + 80, packet_len);
  cilium_srv6_if3_put_u64 (out + 84, p->punt_id);

  return CILIUM_SRV6_IF3_OK;
}

/*
 * Decode a punt header. The plugin never receives one — it is the sender —
 * but the host-side test of test/wire/ round-trips through it, and having
 * one decoder written against the same offset table is what makes the golden
 * frames of `02` §5.6.7 a two-sided check rather than a restatement of the
 * encoder.
 */
static_always_inline cilium_srv6_if3_result_t
cilium_srv6_if3_punt_decode (const u8 *buf, u32 len, cilium_srv6_if3_punt_t *p, u32 *packet_len)
{
  u32 total, plen;
  cilium_srv6_if3_result_t rv;

  if (len < CILIUM_SRV6_IF3_PUNT_HDR_LEN)
    return CILIUM_SRV6_IF3_ERR_TRUNCATED;

  if (buf[0] != CILIUM_SRV6_IF3_VERSION)
    return CILIUM_SRV6_IF3_ERR_VERSION;

  if (buf[1] != CILIUM_SRV6_IF3_OP_PUNT_COMPILE && buf[1] != CILIUM_SRV6_IF3_OP_PUNT_REAUTH &&
      buf[1] != CILIUM_SRV6_IF3_OP_PUNT_FRAGMENT)
    return CILIUM_SRV6_IF3_ERR_OPCODE;

  total = cilium_srv6_if3_get_u16 (buf + 2);
  if (total < CILIUM_SRV6_IF3_PUNT_HDR_LEN || total > CILIUM_SRV6_IF3_MAX_PUNT_FRAME ||
      total != len)
    return CILIUM_SRV6_IF3_ERR_LENGTH;

  plen = cilium_srv6_if3_get_u32 (buf + 80);
  if (plen != total - CILIUM_SRV6_IF3_PUNT_HDR_LEN)
    return CILIUM_SRV6_IF3_ERR_LENGTH;

  if (buf[78] != 0 || buf[79] != 0)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  clib_memset (p, 0, sizeof (p[0]));
  p->opcode = buf[1];
  clib_memcpy_fast (p->token, buf + 4, CILIUM_SRV6_IF3_TOKEN_LEN);
  p->src_identity = cilium_srv6_if3_get_u32 (buf + 20);
  p->rx_sw_if_index = cilium_srv6_if3_get_u32 (buf + 24);
  p->rx_if_incarnation = cilium_srv6_if3_get_u32 (buf + 28);
  clib_memcpy_fast (p->src_ip, buf + 32, 16);
  clib_memcpy_fast (p->dst_ip, buf + 48, 16);
  p->proto = buf[64];
  p->cause = buf[65];
  p->l4_discriminator = cilium_srv6_if3_get_u16 (buf + 66);
  p->src_port = cilium_srv6_if3_get_u16 (buf + 68);
  p->dst_port = cilium_srv6_if3_get_u16 (buf + 70);
  p->fragment_id = cilium_srv6_if3_get_u32 (buf + 72);
  p->frag_next_header = buf[76];
  p->frag_kind = buf[77];
  p->punt_id = cilium_srv6_if3_get_u64 (buf + 84);

  if (cilium_srv6_if3_token_is_zero (p->token))
    return CILIUM_SRV6_IF3_ERR_TOKEN;

  if (p->punt_id == 0)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  if (p->cause >= CILIUM_SRV6_IF3_N_CAUSE)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  if (!cilium_srv6_if3_discriminator_valid (p->proto, p->l4_discriminator))
    return CILIUM_SRV6_IF3_ERR_FIELD;

  rv = cilium_srv6_if3_check_frag (p->opcode, p->frag_kind, p->fragment_id, p->frag_next_header);
  if (rv != CILIUM_SRV6_IF3_OK)
    return rv;

  if (packet_len)
    *packet_len = plen;

  return CILIUM_SRV6_IF3_OK;
}

/* ------------------------------------------------------------------ */
/* reinject / release frame decode (02 §5.6.3)                         */
/* ------------------------------------------------------------------ */

/*
 * Decode the agent -> plugin direction. `buf` must hold exactly one complete
 * frame of `len` bytes; the caller established that with
 * cilium_srv6_if3_frame_length() below.
 *
 * The check the plugin performs here is the one 00 §4.1 asks for: the frame
 * carries no metadata at all, so a peer cannot inject a packet together with
 * metadata of its choosing. The token is the whole authorisation, and
 * `punt_id` is checked by the redeemer against the value the dataplane
 * recorded rather than believed.
 *
 * `out->packet` points into `buf`; nothing is copied.
 */
static_always_inline cilium_srv6_if3_result_t
cilium_srv6_if3_reinject_decode (const u8 *buf, u32 len, cilium_srv6_if3_reinject_t *out)
{
  u32 total, plen;

  if (len < CILIUM_SRV6_IF3_REINJECT_HDR_LEN)
    return CILIUM_SRV6_IF3_ERR_TRUNCATED;

  if (buf[0] != CILIUM_SRV6_IF3_VERSION)
    return CILIUM_SRV6_IF3_ERR_VERSION;

  if (buf[1] != CILIUM_SRV6_IF3_OP_REINJECT && buf[1] != CILIUM_SRV6_IF3_OP_RELEASE)
    return CILIUM_SRV6_IF3_ERR_OPCODE;

  total = cilium_srv6_if3_get_u16 (buf + 2);
  if (total < CILIUM_SRV6_IF3_REINJECT_HDR_LEN || total > CILIUM_SRV6_IF3_MAX_REINJECT_FRAME ||
      total != len)
    return CILIUM_SRV6_IF3_ERR_LENGTH;

  plen = cilium_srv6_if3_get_u32 (buf + 24);
  if (plen != total - CILIUM_SRV6_IF3_REINJECT_HDR_LEN)
    return CILIUM_SRV6_IF3_ERR_LENGTH;

  if (buf[21] != 0 || buf[22] != 0 || buf[23] != 0)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  clib_memset (out, 0, sizeof (out[0]));
  out->opcode = buf[1];
  clib_memcpy_fast (out->token, buf + 4, CILIUM_SRV6_IF3_TOKEN_LEN);
  out->drop_reason = buf[20];
  out->packet_len = plen;
  out->punt_id = cilium_srv6_if3_get_u64 (buf + 28);
  out->packet = plen ? buf + CILIUM_SRV6_IF3_REINJECT_HDR_LEN : 0;

  if (cilium_srv6_if3_token_is_zero (out->token))
    return CILIUM_SRV6_IF3_ERR_TOKEN;

  if (out->drop_reason >= CILIUM_SRV6_IF3_N_DROP_REASON)
    return CILIUM_SRV6_IF3_ERR_FIELD;

  /*
   * The opcode and the drop reason must agree. This is an opcode-level
   * disagreement in the agent's decoder too (wire.go returns ErrOpcode), so
   * it closes the connection: a peer whose opcode and reason contradict each
   * other is not a peer whose framing can be trusted for the next frame.
   */
  if ((out->opcode == CILIUM_SRV6_IF3_OP_REINJECT) !=
      (out->drop_reason == CILIUM_SRV6_IF3_DROP_NONE))
    return CILIUM_SRV6_IF3_ERR_OPCODE;

  /* A release forwards nothing; a reinject without a packet reinjects
     nothing. Both are length statements about the frame. */
  if (out->drop_reason != CILIUM_SRV6_IF3_DROP_NONE && plen != 0)
    return CILIUM_SRV6_IF3_ERR_LENGTH;
  if (out->drop_reason == CILIUM_SRV6_IF3_DROP_NONE && plen == 0)
    return CILIUM_SRV6_IF3_ERR_LENGTH;

  /*
   * #90: a reinject that echoes no punt operation identity could never be
   * admitted past D-43, so it is refused here rather than consuming the token
   * and having the packet dropped at classify. A release forwards nothing, so
   * `punt_id` is 0 there and 02 §5.6.3 says the plugin must not use it — the
   * decoder therefore reports it as 0 and every consumer ignores it.
   */
  if (out->drop_reason == CILIUM_SRV6_IF3_DROP_NONE && out->punt_id == 0)
    return CILIUM_SRV6_IF3_ERR_FIELD;
  if (out->drop_reason != CILIUM_SRV6_IF3_DROP_NONE)
    out->punt_id = 0;

  return CILIUM_SRV6_IF3_OK;
}

/*
 * Encode a reinject or a release. The plugin never sends one; this exists so
 * that test/wire/ can build the golden release frame of `02` §5.6.7 and so
 * that the decoder above is checked against an independent writer.
 *
 * `out` must have room for CILIUM_SRV6_IF3_REINJECT_HDR_LEN bytes; the packet
 * (if any) is the caller's to append.
 */
static_always_inline cilium_srv6_if3_result_t
cilium_srv6_if3_reinject_encode (u8 *out, const cilium_srv6_if3_reinject_t *m)
{
  u64 punt_id = m->punt_id;

  if (m->packet_len > CILIUM_SRV6_IF3_MAX_PACKET)
    return CILIUM_SRV6_IF3_ERR_LENGTH;
  if (cilium_srv6_if3_token_is_zero (m->token))
    return CILIUM_SRV6_IF3_ERR_TOKEN;
  if (m->drop_reason >= CILIUM_SRV6_IF3_N_DROP_REASON)
    return CILIUM_SRV6_IF3_ERR_FIELD;
  if (m->drop_reason == CILIUM_SRV6_IF3_DROP_NONE && m->packet_len == 0)
    return CILIUM_SRV6_IF3_ERR_LENGTH;
  if (m->drop_reason != CILIUM_SRV6_IF3_DROP_NONE && m->packet_len != 0)
    return CILIUM_SRV6_IF3_ERR_LENGTH;

  clib_memset (out, 0, CILIUM_SRV6_IF3_REINJECT_HDR_LEN);
  out[0] = CILIUM_SRV6_IF3_VERSION;
  if (m->drop_reason == CILIUM_SRV6_IF3_DROP_NONE)
    {
      out[1] = CILIUM_SRV6_IF3_OP_REINJECT;
    }
  else
    {
      out[1] = CILIUM_SRV6_IF3_OP_RELEASE;
      /* A release answers a punt but forwards nothing, so there is no packet
	 to mark with the punt identity (02 §5.6.3). */
      punt_id = 0;
    }
  cilium_srv6_if3_put_u16 (out + 2, (u16) (CILIUM_SRV6_IF3_REINJECT_HDR_LEN + m->packet_len));
  clib_memcpy_fast (out + 4, m->token, CILIUM_SRV6_IF3_TOKEN_LEN);
  out[20] = m->drop_reason;
  /* out[21..23] reserved, already zero. */
  cilium_srv6_if3_put_u32 (out + 24, m->packet_len);
  cilium_srv6_if3_put_u64 (out + 28, punt_id);

  return CILIUM_SRV6_IF3_OK;
}

/*
 * Read the total length of a partially received frame, as the stream reader
 * needs it to know how much more to read. The version and the bound are
 * validated first so that a peer cannot make the reader wait for a frame that
 * would be rejected anyway.
 *
 * Every error this returns is a framing error by construction: it only looks
 * at the version and the length. `n` is how many header bytes are available;
 * fewer than 4 is not an error, it is "read more" — reported as
 * ERR_TRUNCATED with *out left at 0.
 *
 * The lower bound is the *reinject* header length, because this direction is
 * the only one the plugin reads.
 */
static_always_inline cilium_srv6_if3_result_t
cilium_srv6_if3_frame_length (const u8 *hdr, u32 n, u32 *out)
{
  u32 total;

  *out = 0;

  if (n < 4)
    return CILIUM_SRV6_IF3_ERR_TRUNCATED;

  if (hdr[0] != CILIUM_SRV6_IF3_VERSION)
    return CILIUM_SRV6_IF3_ERR_VERSION;

  total = cilium_srv6_if3_get_u16 (hdr + 2);
  if (total < CILIUM_SRV6_IF3_REINJECT_HDR_LEN || total > CILIUM_SRV6_IF3_MAX_REINJECT_FRAME)
    return CILIUM_SRV6_IF3_ERR_LENGTH;

  *out = total;
  return CILIUM_SRV6_IF3_OK;
}

/*
 * The token of a frame the transport has already framed, at the one offset
 * both directions share (02 §5.6.2 and §5.6.3 both put it at 4..20).
 *
 * The transport owner needs it on the failure path: a frame whose write was
 * interrupted must not be resent (00 §2.18.8), so its token is released
 * locally, and the only copy of that token left at that point is the bytes of
 * the frame itself.
 */
static_always_inline const u8 *
cilium_srv6_if3_frame_token (const u8 *frame)
{
  return frame + 4;
}

#endif /* __included_cilium_srv6_punt_wire_h__ */
