/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — PMTUD: ICMPv6 PTB validation (C7, #20).
 *
 * The part of 02 §9 that is a pure function of the received bytes and of the
 * immutable PathCache entry: the bounded parse of a transit-originated
 * ICMPv6 Packet Too Big, the RFC 9800 NEXT-C-SID shift-state reconstruction
 * that says whether the quoted (shifted) destination address is a state the
 * recorded path really passed through (D-16), and the MTU range arithmetic
 * of 02 §9. It is kept free of any vlib dependency for the same reason
 * cilium_srv6_parse.h and cilium_srv6_hparse.h are: so that it can be driven
 * against a malformed corpus on its own.
 *
 * Bounding rule, identical to the other two parsers. The caller supplies
 *
 *   avail      bytes readable from p0 in the first buffer, and
 *   chain_len  total length of the buffer chain,
 *
 * and the parser derives
 *
 *   bound = min(avail, 40 + payload length)
 *
 * as the first offset that must not be read. Every field access is preceded
 * by an explicit comparison against `bound`, so a declared length that runs
 * past the readable area is reported as malformed and never as a read.
 * Nothing outside [p0, p0 + bound) is dereferenced and the packet is never
 * written to.
 *
 * What this header deliberately does NOT do, because none of it is derivable
 * from the packet alone, is the three checks that actually make a PTB
 * trustworthy (D-36 and D-21). Those live in cilium_srv6_pmtud_node.c:
 *
 *   (a) the PTB was received on a TRUSTED_FABRIC interface,
 *   (b) its source address is in the SR domain node set,
 *   (c) the quoted packet matches a RecentTx record.
 *
 * Design references:
 *   design/detail/02-headend-dataplane.md §9 (PMTUD)
 *   design/detail/01-packet-format.md §2 (CSID container), §2.3 (final DA),
 *     §2.5 (appended Service SID), §5 (overhead), §7 (ICMPv6 PTB)
 *   design/detail/00-overview.md §2 (D-16, D-21, D-36)
 *   RFC 4443 §3.2 (PTB format and quote length), RFC 8200 (1280 minimum
 *     link MTU), RFC 9800 §9.4 (NEXT-C-SID / uN processing)
 */

#ifndef __included_cilium_srv6_pmtud_parse_h__
#define __included_cilium_srv6_pmtud_parse_h__

#include <vppinfra/clib.h>
#include <vppinfra/byte_order.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/srv6/sr_packet.h>

/*
 * Mirrors of the PathCache bounds of cilium_srv6_headend.h. They are repeated
 * rather than included so that this header stays vlib-free;
 * cilium_srv6_pmtud.h asserts that the two sets agree.
 */
#define CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES 8
#define CILIUM_SRV6_PMTUD_MAX_SEGMENTS	   8
#define CILIUM_SRV6_PMTUD_MAX_SRH_BYTES	   (8 + 16 * CILIUM_SRV6_PMTUD_MAX_SEGMENTS)

/* RFC 8200 minimum link MTU. 02 §9: below this a path is unusable. */
#define CILIUM_SRV6_PMTUD_MIN_MTU 1280

/*
 * 01 §7 / RFC 4443 §3.2: an ICMPv6 error must fit in 1280 bytes, so a
 * headend-originated PTB quotes at most 1280 - 40 (IPv6) - 8 (ICMPv6 type,
 * code, checksum, MTU) = 1232 bytes of the inner packet.
 */
#define CILIUM_SRV6_PMTUD_MAX_QUOTE 1232

/* Fixed part of an ICMPv6 PTB: type, code, checksum, MTU. */
#define CILIUM_SRV6_PMTUD_ICMP_LEN 8

/*
 * 01 §2 / 00 §6: the SR domain uses the RFC 9800 F3216 C-SID format, i.e. a
 * 32 bit Locator-Block followed by 16 bit C-SIDs. The shift reconstruction
 * below is only defined for that geometry and refuses any other, rather than
 * guessing a layout the design does not describe.
 */
#define CILIUM_SRV6_PMTUD_BLOCK_BITS 32
#define CILIUM_SRV6_PMTUD_CSID_BITS  16

typedef enum
{
  CILIUM_SRV6_PMTUD_PARSE_OK = 0,
  /* not an ICMPv6 Packet Too Big at all (wrong type/code/protocol) */
  CILIUM_SRV6_PMTUD_PARSE_NOT_PTB,
  /* length inconsistency, extension headers before the ICMPv6 header, or a
     quote too short to contain an IPv6 header */
  CILIUM_SRV6_PMTUD_PARSE_MALFORMED,
} cilium_srv6_pmtud_parse_result_t;

/*
 * Everything a PTB can contribute to the 02 §9 correlation. Addresses are
 * copied out rather than pointed at so that the caller never holds a pointer
 * into a packet it may forward or free.
 */
typedef struct
{
  /* MTU field of the ICMPv6 message, host order, verbatim (unvalidated). */
  u32 ptb_mtu;

  /* Source address of the PTB itself: the transit node that reports. */
  ip6_address_t reporter;

  /* Quoted outer header: the packet as that transit node saw it. */
  ip6_address_t quoted_src; /* must be this node (02 §9) */
  ip6_address_t quoted_dst; /* the shifted CSID container (D-16) */
  u32 quoted_flow_label;	/* 01 §4 entropy value */
  u32 quoted_outer_size;	/* 40 + quoted payload length */
  u8 quoted_next_header;	/* 41 (IPv6) or 43 (Routing) */
  u8 quoted_traffic_class;

  /* The quote is truncated at 1232 bytes, so the inner header is present
     only when it fit. 0 leaves inner_src/inner_dst undefined. */
  u8 has_inner;
  u8 has_srh;

  ip6_address_t inner_src;
  ip6_address_t inner_dst;

  /* Offset and length of the quoted SRH inside p0, valid when has_srh. */
  u32 srh_off;
  u32 srh_len;
} cilium_srv6_pmtud_ptb_t;

/*
 * The immutable half of a PathCache entry, copied out under no lock: the
 * shapes a packet of this path can present to a transit node. Copying it
 * keeps this header free of the PathCache type and makes the matcher a pure
 * function of its inputs.
 */
typedef struct
{
  ip6_address_t da_template;  /* 01 §2.1 / §2.2 as transmitted */
  ip6_address_t service_sid;  /* 01 §2.3 final DA / Service SID */
  ip6_address_t shift_states[CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES];
  u8 n_shift_states;
  u8 srh_len;			  /* 0 = no SRH */
  u8 pad[2];
  u8 srh[CILIUM_SRV6_PMTUD_MAX_SRH_BYTES];
} cilium_srv6_pmtud_path_shape_t;

/*
 * RFC 9800 §9.4 uN / NEXT-C-SID processing, F3216: the argument part of the
 * container is shifted left by one C-SID and the vacated low bits are zero
 * filled, so that the next C-SID becomes the active one.
 *
 *   before: Block(32) | C0(16) | C1(16) | ... | Cn
 *   after:  Block(32) | C1(16) | ... | Cn | 0(16)
 *
 * This is exactly the step that turns the 01 §2.1 DA into the 01 §2.3 final
 * DA after the transit uNs have been consumed, which is why the destination
 * address a transit node quotes cannot be recovered from `final_da` alone
 * (D-16).
 *
 * `in` and `out` may alias.
 */
static_always_inline void
cilium_srv6_pmtud_csid_shift (const ip6_address_t *in, ip6_address_t *out)
{
  const u32 lb = CILIUM_SRV6_PMTUD_BLOCK_BITS / 8; /* 4 */
  const u32 cs = CILIUM_SRV6_PMTUD_CSID_BITS / 8;  /* 2 */
  u8 tmp[16];

  /* Snapshot first so that `in` and `out` may be the same object. */
  clib_memcpy_fast (tmp, in->as_u8, 16);

  clib_memcpy_fast (out->as_u8, tmp, lb);
  clib_memcpy_fast (out->as_u8 + lb, tmp + lb + cs, 16 - lb - cs);
  clib_memset (out->as_u8 + 16 - cs, 0, cs);
}

/*
 * D-16: does `da` equal the destination address this path presented at some
 * point along its segment list?
 *
 * Three sources are consulted, all bounded:
 *
 *   1. the DA as transmitted (`da_template`), which is what the first transit
 *      node sees;
 *   2. `expected_shift_states`, precomputed by the reconciler (02 §4.4). This
 *      is authoritative and is the only source that covers the 01 §2.5 case
 *      where the Service SID is appended as an independent SRH segment, so
 *      the container chain does not converge on it;
 *   3. the chain derived here by repeated NEXT-C-SID shifts of `da_template`.
 *      The chain is only trusted when it terminates on `service_sid`, i.e.
 *      when it really is the F3216 container walk of 01 §2.1 -> §2.3. A chain
 *      that does not reach the Service SID within
 *      CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES steps describes a path this code
 *      cannot reconstruct, and contributes nothing rather than widening the
 *      accepted set.
 *
 * With an SRH the transit node that exhausts one container takes the next
 * segment from the Segment List, so the segments themselves are candidates
 * too (bounded by Last Entry).
 *
 * Returns 1 on a match. `state_out`, when not NULL, receives the number of
 * shifts that produced the match, which is only used for the packet trace.
 */
static_always_inline int
cilium_srv6_pmtud_da_match (const cilium_srv6_pmtud_path_shape_t *s, const ip6_address_t *da,
			    u32 *state_out)
{
  ip6_address_t cur, chain[CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES];
  u32 i, n_chain = 0;
  int reached_service_sid = 0;

  if (state_out)
    *state_out = 0;

  /* 1. as transmitted. */
  if (ip6_address_is_equal (da, &s->da_template))
    return 1;

  /* 2. reconciler-supplied states (02 §4.4). */
  for (i = 0; i < s->n_shift_states && i < CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES; i++)
    {
      if (ip6_address_is_equal (da, &s->shift_states[i]))
	{
	  if (state_out)
	    *state_out = i + 1;
	  return 1;
	}
    }

  /* 3. derived F3216 container walk, only trusted once it lands on the
     Service SID of 01 §2.3. */
  cur = s->da_template;
  for (i = 0; i < CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES; i++)
    {
      cilium_srv6_pmtud_csid_shift (&cur, &cur);
      chain[n_chain++] = cur;

      if (ip6_address_is_equal (&cur, &s->service_sid))
	{
	  reached_service_sid = 1;
	  break;
	}

      /* A fully drained container cannot shift any further; stop rather than
	 emitting the all-zero argument state repeatedly. */
      if (cur.as_u64[1] == 0 &&
	  (cur.as_u64[0] & clib_host_to_net_u64 (0x00000000ffffffffULL)) == 0)
	break;
    }

  if (reached_service_sid)
    {
      for (i = 0; i < n_chain; i++)
	{
	  if (ip6_address_is_equal (da, &chain[i]))
	    {
	      if (state_out)
		*state_out = i + 1;
	      return 1;
	    }
	}
    }

  /* 01 §2.4 / §2.5: with an SRH the next container comes from the Segment
     List, so each segment is a destination address this packet can carry.
     The template was validated at install time (csh_srh_template_ok), but the
     bound is recomputed here so that this function is safe on its own. */
  if (s->srh_len >= 8 && s->srh_len <= CILIUM_SRV6_PMTUD_MAX_SRH_BYTES)
    {
      /* RFC 8754 §4.1 field order: octet 3 is Segments Left and octet 4 is
	 Last Entry. In a Reduced SRH the two differ by one (D-62), so reading
	 the wrong one would count one segment too many; the bound below then
	 clamps it, but the value has to be the right field to begin with. */
      u32 n_seg = (u32) s->srh[4] + 1;
      u32 j;

      if (8 + 16 * n_seg > (u32) s->srh_len)
	n_seg = ((u32) s->srh_len - 8) / 16;

      for (j = 0; j < n_seg && j < CILIUM_SRV6_PMTUD_MAX_SEGMENTS; j++)
	{
	  ip6_address_t seg;

	  /* The segment list is only 4 byte aligned inside the template, so
	     it is copied out rather than aliased as an ip6_address_t. */
	  clib_memcpy_fast (seg.as_u8, s->srh + 8 + 16 * j, 16);

	  if (ip6_address_is_equal (da, &seg))
	    {
	      if (state_out)
		*state_out = CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES + j + 1;
	      return 1;
	    }
	}
    }

  return 0;
}

/*
 * Bounded parse of a received ICMPv6 Packet Too Big, starting at the outer
 * IPv6 header.
 *
 * The ICMPv6 checksum is NOT verified here: ip6-local validates it before
 * ip6-icmp-input dispatches by type (see the comment in VPP's icmp6.c,
 * "Checksum is already validated by ip6_local node"), so a PTB that reaches
 * this parser has already had its checksum accepted. 02 §9 requires the check
 * to happen, not for it to happen twice.
 *
 * Extension headers between the outer IPv6 header and the ICMPv6 header are
 * refused rather than walked. ip6-icmp-input itself reads the ICMPv6 header
 * at a fixed offset of 40 bytes, so a packet with extension headers would
 * already have been mis-dispatched; refusing it is the fail-closed reading.
 */
static_always_inline cilium_srv6_pmtud_parse_result_t
cilium_srv6_pmtud_parse_ptb (const u8 *p0, u32 avail, u64 chain_len, cilium_srv6_pmtud_ptb_t *r)
{
  const ip6_header_t *ip = (const ip6_header_t *) p0;
  const ip6_header_t *q;
  const icmp46_header_t *icmp;
  u64 declared;
  u32 bound, off, q_plen, q_off;
  u8 q_nh;

  clib_memset (r, 0, sizeof (*r));

  if (PREDICT_FALSE (avail < sizeof (ip6_header_t)))
    return CILIUM_SRV6_PMTUD_PARSE_MALFORMED;

  if (PREDICT_FALSE ((ip->ip_version_traffic_class_and_flow_label &
		      clib_host_to_net_u32 (0xf0000000)) != clib_host_to_net_u32 (0x60000000)))
    return CILIUM_SRV6_PMTUD_PARSE_MALFORMED;

  declared = (u64) sizeof (ip6_header_t) + (u64) clib_net_to_host_u16 (ip->payload_length);
  if (PREDICT_FALSE (declared > chain_len))
    return CILIUM_SRV6_PMTUD_PARSE_MALFORMED;

  bound = avail;
  if ((u64) bound > declared)
    bound = (u32) declared;

  if (PREDICT_FALSE (ip->protocol != IP_PROTOCOL_ICMP6))
    return CILIUM_SRV6_PMTUD_PARSE_NOT_PTB;

  off = sizeof (ip6_header_t);

  if (PREDICT_FALSE (off + CILIUM_SRV6_PMTUD_ICMP_LEN > bound))
    return CILIUM_SRV6_PMTUD_PARSE_MALFORMED;

  icmp = (const icmp46_header_t *) (p0 + off);

  if (PREDICT_FALSE (icmp->type != ICMP6_packet_too_big || icmp->code != 0))
    return CILIUM_SRV6_PMTUD_PARSE_NOT_PTB;

  r->reporter = ip->src_address;

  /* RFC 4443 §3.2: the MTU field occupies octets 4..7 of the ICMPv6 message.
     Assembled byte by byte so that the read needs no alignment assumption. */
  r->ptb_mtu = ((u32) p0[off + 4] << 24) | ((u32) p0[off + 5] << 16) |
	       ((u32) p0[off + 6] << 8) | (u32) p0[off + 7];

  /* RFC 4443 §3.2: the invoking packet follows the 8 byte ICMPv6 part. The
     quote has to contain at least a complete IPv6 header to be usable at
     all; anything shorter is not correlatable and is refused. */
  q_off = off + CILIUM_SRV6_PMTUD_ICMP_LEN;
  if (PREDICT_FALSE (q_off + sizeof (ip6_header_t) > bound))
    return CILIUM_SRV6_PMTUD_PARSE_MALFORMED;

  q = (const ip6_header_t *) (p0 + q_off);

  if (PREDICT_FALSE ((q->ip_version_traffic_class_and_flow_label &
		      clib_host_to_net_u32 (0xf0000000)) != clib_host_to_net_u32 (0x60000000)))
    return CILIUM_SRV6_PMTUD_PARSE_MALFORMED;

  r->quoted_src = q->src_address;
  r->quoted_dst = q->dst_address;
  r->quoted_flow_label =
    clib_net_to_host_u32 (q->ip_version_traffic_class_and_flow_label) & 0xfffff;
  r->quoted_traffic_class =
    (u8) ((clib_net_to_host_u32 (q->ip_version_traffic_class_and_flow_label) >> 20) & 0xff);

  q_plen = clib_net_to_host_u16 (q->payload_length);
  r->quoted_outer_size = (u32) sizeof (ip6_header_t) + q_plen;
  r->quoted_next_header = q->protocol;

  q_nh = q->protocol;
  off = q_off + sizeof (ip6_header_t);

  /*
   * 01 §2.4: the quote may continue into the SRH. It is optional — the
   * transit node only quotes what fits in 1280 bytes — so a truncated SRH is
   * reported as absent rather than as malformed.
   */
  if (q_nh == IP_PROTOCOL_IPV6_ROUTE)
    {
      u32 srh_len;

      if (off + 8 > bound)
	return CILIUM_SRV6_PMTUD_PARSE_OK;

      if (p0[off + 2] != ROUTING_HEADER_TYPE_SR)
	return CILIUM_SRV6_PMTUD_PARSE_MALFORMED;

      /* Hdr Ext Len is in 8 octet units and excludes the first 8 octets. */
      srh_len = ((u32) p0[off + 1] + 1) << 3;

      if (off + srh_len > bound)
	return CILIUM_SRV6_PMTUD_PARSE_OK;

      r->has_srh = 1;
      r->srh_off = off;
      r->srh_len = srh_len;

      q_nh = p0[off];
      off += srh_len;
    }

  if (q_nh != IP_PROTOCOL_IPV6)
    return CILIUM_SRV6_PMTUD_PARSE_OK;

  if (off + sizeof (ip6_header_t) > bound)
    return CILIUM_SRV6_PMTUD_PARSE_OK;

  {
    const ip6_header_t *inner = (const ip6_header_t *) (p0 + off);

    if ((inner->ip_version_traffic_class_and_flow_label &
	 clib_host_to_net_u32 (0xf0000000)) != clib_host_to_net_u32 (0x60000000))
      return CILIUM_SRV6_PMTUD_PARSE_MALFORMED;

    r->inner_src = inner->src_address;
    r->inner_dst = inner->dst_address;
    r->has_inner = 1;
  }

  return CILIUM_SRV6_PMTUD_PARSE_OK;
}

typedef enum
{
  /* usable inner MTU produced in *inner_mtu */
  CILIUM_SRV6_PMTUD_MTU_OK = 0,
  /* outside "1280 <= ptb_mtu < recorded_outer_size" (02 §9) */
  CILIUM_SRV6_PMTUD_MTU_OUT_OF_RANGE,
  /* in range, but the resulting inner MTU is below the IPv6 minimum: the
     path is unusable and must be failed closed (02 §9) */
  CILIUM_SRV6_PMTUD_MTU_PATH_UNUSABLE,
} cilium_srv6_pmtud_mtu_result_t;

/*
 * 02 §9: "1280 <= ptb_mtu < recorded_outer_size の場合だけ ...
 * effective_mtu = min(current, ptb_mtu - overhead) ... 結果が 1280 未満の
 * inner MTU になる path は unusable ... u16 underflow を起こさない".
 *
 * Every input is attacker-influenced, so the arithmetic is done in u32 and
 * each subtraction is guarded by the comparison that makes it non-negative:
 *
 *   ptb_mtu >= 1280 and overhead <= 40 + 136 = 176, so ptb_mtu - overhead
 *   cannot wrap; the result is < ptb_mtu <= 65535 and therefore fits u16.
 *
 * The upper bound on ptb_mtu is the ICMPv6 field being 32 bits wide: a
 * reported MTU that cannot be an IPv6 link MTU is out of range, not a
 * candidate to be truncated into u16.
 */
static_always_inline cilium_srv6_pmtud_mtu_result_t
cilium_srv6_pmtud_mtu_eval (u32 ptb_mtu, u32 recorded_outer_size, u32 overhead, u16 *inner_mtu)
{
  u32 inner;

  *inner_mtu = 0;

  if (ptb_mtu < CILIUM_SRV6_PMTUD_MIN_MTU || ptb_mtu > 0xffff)
    return CILIUM_SRV6_PMTUD_MTU_OUT_OF_RANGE;

  /* A PTB that does not shrink the packet we recorded is either a replay or
     a report for a packet we never sent. */
  if (ptb_mtu >= recorded_outer_size)
    return CILIUM_SRV6_PMTUD_MTU_OUT_OF_RANGE;

  /* Cannot happen for a validated SRH template, but the subtraction below
     must not depend on that. */
  if (overhead >= ptb_mtu)
    return CILIUM_SRV6_PMTUD_MTU_OUT_OF_RANGE;

  inner = ptb_mtu - overhead;

  if (inner < CILIUM_SRV6_PMTUD_MIN_MTU)
    return CILIUM_SRV6_PMTUD_MTU_PATH_UNUSABLE;

  *inner_mtu = (u16) inner;
  return CILIUM_SRV6_PMTUD_MTU_OK;
}

#endif /* __included_cilium_srv6_pmtud_parse_h__ */
