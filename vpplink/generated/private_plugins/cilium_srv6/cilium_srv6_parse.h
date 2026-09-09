/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — bounded destination parser (C8-b).
 *
 * The header/decapsulation part of cilium-end-cilium (03 §3), kept free of
 * any vlib dependency so that it is a pure function of the received bytes
 * and can be exercised against a malformed corpus on its own.
 *
 * Bounding rule. The caller supplies
 *
 *   avail      bytes readable from p0 in the first buffer, and
 *   chain_len  total length of the buffer chain,
 *
 * and the parser derives
 *
 *   bound = min(avail, 40 + outer payload length)
 *
 * as the first offset that must not be read. Every field access is
 * preceded by an explicit comparison against `bound`, so a declared length
 * that runs past the readable area is reported as a length inconsistency
 * and never as a read. Nothing outside [p0, p0 + bound) is dereferenced.
 *
 * The parser never writes to the packet: it reports how many bytes the
 * caller must remove, so the buffer is only advanced once the packet has
 * been fully accepted.
 *
 * Design references:
 *   design/detail/01-packet-format.md §3 (inner packet), §3.1 (bounded
 *     extension header rules), §3.2 (destination length validation)
 *   design/detail/03-destination-dataplane.md §3, §5
 *   design/detail/00-overview.md §2 (D-18, D-28)
 */

#ifndef __included_cilium_srv6_parse_h__
#define __included_cilium_srv6_parse_h__

#include <vppinfra/clib.h>
#include <vppinfra/byte_order.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/srv6/sr_packet.h>

/* 01 §3.1 bounded parser limits, applied to the inner packet. */
#define CILIUM_SRV6_INNER_MAX_EH       8
#define CILIUM_SRV6_INNER_MAX_EH_BYTES 256

/* Bound on the SRH TLV walk (01 §3.2 "TLV 境界"). */
#define CILIUM_SRV6_SRH_MAX_TLV 8

/*
 * SRH fixed part: Next Header, Hdr Ext Len, Routing Type, Segments Left,
 * Last Entry, Flags, Tag. Used as an explicit byte count so that the parser
 * bounds do not depend on struct layout.
 */
#define CILIUM_SRV6_SRH_FIXED_LEN 8

STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_sr_header_t, segments) == CILIUM_SRV6_SRH_FIXED_LEN,
	       "SRH fixed part is not 8 bytes");

typedef enum
{
  CILIUM_SRV6_PARSE_OK = 0,
  /* outer length, Next Header, or SRH field/bound violation */
  CILIUM_SRV6_PARSE_MALFORMED_OUTER,
  /* inner too short, not IPv6, length inconsistent, or EH chain outside
     the 01 §3.1 limits */
  CILIUM_SRV6_PARSE_MALFORMED_INNER,
  /* inner destination is not the Context's endpoint address */
  CILIUM_SRV6_PARSE_IP_MISMATCH,
} cilium_srv6_parse_result_t;

/*
 * Bounded extension-header walk over the inner packet (01 §3.1: at most 8
 * headers and 256 bytes of extension headers; a length inconsistency, a
 * duplicate Fragment header, an unknown Routing Type and an overrun are all
 * DROP_MALFORMED_INNER).
 *
 * `off` is the offset of the inner IPv6 header and `bound` the first offset
 * that must not be read. The caller guarantees off + 40 <= bound.
 */
static_always_inline int
cilium_srv6_inner_chain_ok (const u8 *p0, u32 off, u32 bound)
{
  const ip6_header_t *inner = (const ip6_header_t *) (p0 + off);
  u32 eh_bytes = 0;
  u32 n_hdr;
  u8 nh = inner->protocol;
  u8 seen_frag = 0;

  off += sizeof (ip6_header_t);

  for (n_hdr = 0; n_hdr < CILIUM_SRV6_INNER_MAX_EH; n_hdr++)
    {
      u32 hlen;

      switch (nh)
	{
	case IP_PROTOCOL_IPV6_ROUTE:
	  {
	    const ip6_ext_header_t *eh;

	    /* Routing Type lives at offset 2, so the whole fixed part has to
	       be readable before either field is touched. */
	    if (off + CILIUM_SRV6_SRH_FIXED_LEN > bound)
	      return 0;

	    eh = (const ip6_ext_header_t *) (p0 + off);

	    /* 01 §3.1: an unknown Routing Type is malformed. */
	    if (p0[off + 2] != ROUTING_HEADER_TYPE_SR)
	      return 0;

	    hlen = ((u32) eh->n_data_u64s + 1) << 3;
	    if (off + hlen > bound)
	      return 0;

	    eh_bytes += hlen;
	    if (eh_bytes > CILIUM_SRV6_INNER_MAX_EH_BYTES)
	      return 0;

	    nh = eh->next_hdr;
	    off += hlen;
	    break;
	  }

	case IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS:
	case IP_PROTOCOL_IP6_DESTINATION_OPTIONS:
	case IP_PROTOCOL_MOBILITY:
	case IP_PROTOCOL_HIP:
	case IP_PROTOCOL_SHIM6:
	case IP_PROTOCOL_IPSEC_AH:
	  {
	    const ip6_ext_header_t *eh;

	    if (off + sizeof (ip6_ext_header_t) > bound)
	      return 0;

	    eh = (const ip6_ext_header_t *) (p0 + off);

	    /* AH is measured in 4 byte units and excludes 8 bytes; every
	       other extension header is measured in 8 byte units and
	       excludes the first 8 bytes. */
	    hlen = (nh == IP_PROTOCOL_IPSEC_AH) ? (((u32) eh->n_data_u64s + 2) << 2) :
						  (((u32) eh->n_data_u64s + 1) << 3);

	    if (hlen < sizeof (ip6_ext_header_t) || off + hlen > bound)
	      return 0;

	    eh_bytes += hlen;
	    if (eh_bytes > CILIUM_SRV6_INNER_MAX_EH_BYTES)
	      return 0;

	    nh = eh->next_hdr;
	    off += hlen;
	    break;
	  }

	case IP_PROTOCOL_IPV6_FRAGMENTATION:
	  {
	    const ip6_frag_hdr_t *fh;

	    if (off + sizeof (ip6_frag_hdr_t) > bound)
	      return 0;

	    /* 01 §3.1: a duplicate Fragment header is malformed. */
	    if (seen_frag)
	      return 0;
	    seen_frag = 1;

	    eh_bytes += sizeof (ip6_frag_hdr_t);
	    if (eh_bytes > CILIUM_SRV6_INNER_MAX_EH_BYTES)
	      return 0;

	    fh = (const ip6_frag_hdr_t *) (p0 + off);

	    /* A non-first fragment carries payload, not a header chain. */
	    if (ip6_frag_hdr_offset (fh) != 0)
	      return 1;

	    nh = fh->next_hdr;
	    off += sizeof (ip6_frag_hdr_t);
	    break;
	  }

	default:
	  /* Upper layer protocol: end of the extension header chain. */
	  return 1;
	}
    }

  /* 01 §3.1: more than CILIUM_SRV6_INNER_MAX_EH headers. */
  return 0;
}

/*
 * SRH validation of 01 §3.2 and D-28. `off` is the offset of the SRH and
 * `bound` the first offset that must not be read. On success *srh_len holds
 * the validated SRH length in bytes.
 */
static_always_inline int
cilium_srv6_srh_ok (const u8 *p0, u32 off, u32 bound, u32 *srh_len)
{
  const ip6_sr_header_t *srh;
  u32 len, seg_bytes, tlv_off, srh_end, n_tlv;

  if (off + CILIUM_SRV6_SRH_FIXED_LEN > bound)
    return 0;

  srh = (const ip6_sr_header_t *) (p0 + off);

  if (srh->type != ROUTING_HEADER_TYPE_SR)
    return 0;

  /* Hdr Ext Len is in 8 octet units and excludes the first 8 octets. */
  len = ((u32) srh->length + 1) << 3;
  if (off + len > bound)
    return 0;

  /*
   * D-28: the SRH is only removed at the end of the segment list. A packet
   * that still has segments to visit must not be decapsulated here, because
   * that would skip the remaining path processing.
   */
  if (srh->segments_left != 0)
    return 0;

  /*
   * Last Entry is the zero based index of the last segment, so the segment
   * list occupies (last_entry + 1) * 16 bytes right after the fixed part
   * and has to fit inside the SRH. RFC 8754 requires at least one segment,
   * so an SRH with no room for Segment List[0] is malformed.
   */
  seg_bytes = ((u32) srh->last_entry + 1) << 4;
  if (CILIUM_SRV6_SRH_FIXED_LEN + seg_bytes > len)
    return 0;

  /* Optional TLVs fill the rest of the SRH exactly (RFC 8754 §2.1). */
  srh_end = off + len;
  tlv_off = off + CILIUM_SRV6_SRH_FIXED_LEN + seg_bytes;

  for (n_tlv = 0; tlv_off < srh_end; n_tlv++)
    {
      u32 tlv_len;

      if (n_tlv >= CILIUM_SRV6_SRH_MAX_TLV)
	return 0;

      /* Pad1 is a single octet with neither a length nor a value. */
      if (p0[tlv_off] == 0)
	{
	  tlv_off += 1;
	  continue;
	}

      if (tlv_off + 2 > srh_end)
	return 0;

      tlv_len = 2 + (u32) p0[tlv_off + 1];
      if (tlv_off + tlv_len > srh_end)
	return 0;

      tlv_off += tlv_len;
    }

  if (tlv_off != srh_end)
    return 0;

  /* 01 §3.2: the SRH must be followed by the inner IPv6 packet. */
  if (srh->protocol != IP_PROTOCOL_IPV6)
    return 0;

  *srh_len = len;
  return 1;
}

/*
 * The header part of 03 §3, from the outer length check to the inner
 * destination comparison.
 *
 * On CILIUM_SRV6_PARSE_OK, *decap_len is the number of leading bytes the
 * caller must remove (outer IPv6 header plus SRH, if any) and *has_srh
 * records whether an SRH was present.
 */
static_always_inline cilium_srv6_parse_result_t
cilium_srv6_parse_outer (const u8 *p0, u32 avail, u64 chain_len, const ip6_address_t *endpoint_ip,
			 u32 *decap_len, u8 *has_srh)
{
  const ip6_header_t *ip = (const ip6_header_t *) p0;
  const ip6_header_t *inner;
  u64 declared;
  u32 bound, off, inner_bound, inner_len, inner_plen, srh_len;
  u8 nh;

  *decap_len = 0;
  *has_srh = 0;

  if (PREDICT_FALSE (avail < sizeof (ip6_header_t)))
    return CILIUM_SRV6_PARSE_MALFORMED_OUTER;

  /* 01 §3.2: the declared outer length is checked against the buffer chain
     before anything past the outer IPv6 header is looked at. */
  declared = (u64) sizeof (ip6_header_t) + (u64) clib_net_to_host_u16 (ip->payload_length);
  if (PREDICT_FALSE (declared > chain_len))
    return CILIUM_SRV6_PARSE_MALFORMED_OUTER;

  bound = avail;
  if ((u64) bound > declared)
    bound = (u32) declared;

  off = sizeof (ip6_header_t);
  nh = ip->protocol;

  if (nh == IP_PROTOCOL_IPV6_ROUTE)
    {
      if (PREDICT_FALSE (!cilium_srv6_srh_ok (p0, off, bound, &srh_len)))
	return CILIUM_SRV6_PARSE_MALFORMED_OUTER;

      *has_srh = 1;
      off += srh_len;
    }
  else if (PREDICT_FALSE (nh != IP_PROTOCOL_IPV6))
    {
      return CILIUM_SRV6_PARSE_MALFORMED_OUTER;
    }

  /*
   * 01 §3 / 03 §5: this is the one place that assumes the bytes after the
   * outer headers are an inner IPv6 header. A future decrypt step or
   * authorization shim (01 §6) is inserted here and nowhere else.
   */
  inner_len = (u32) declared - off;

  if (PREDICT_FALSE (inner_len < sizeof (ip6_header_t)))
    return CILIUM_SRV6_PARSE_MALFORMED_INNER;

  /* The inner header itself must be readable in the first buffer; a chain
     that splits the L3 headers is refused rather than walked. */
  if (PREDICT_FALSE (off + sizeof (ip6_header_t) > bound))
    return CILIUM_SRV6_PARSE_MALFORMED_INNER;

  inner = (const ip6_header_t *) (p0 + off);

  if (PREDICT_FALSE ((inner->ip_version_traffic_class_and_flow_label &
		      clib_host_to_net_u32 (0xf0000000)) != clib_host_to_net_u32 (0x60000000)))
    return CILIUM_SRV6_PARSE_MALFORMED_INNER;

  /* The inner packet has to fit in what the outer header declared. */
  inner_plen = clib_net_to_host_u16 (inner->payload_length);
  if (PREDICT_FALSE (sizeof (ip6_header_t) + inner_plen > inner_len))
    return CILIUM_SRV6_PARSE_MALFORMED_INNER;

  inner_bound = off + (u32) sizeof (ip6_header_t) + inner_plen;
  if (inner_bound > bound)
    inner_bound = bound;

  if (PREDICT_FALSE (!cilium_srv6_inner_chain_ok (p0, off, inner_bound)))
    return CILIUM_SRV6_PARSE_MALFORMED_INNER;

  /*
   * 04 §4 defence line (4): the last check that a stale route or a state
   * inconsistency cannot deliver a packet to the wrong Pod.
   */
  if (PREDICT_FALSE (!ip6_address_is_equal (&inner->dst_address, endpoint_ip)))
    return CILIUM_SRV6_PARSE_IP_MISMATCH;

  *decap_len = off;
  return CILIUM_SRV6_PARSE_OK;
}

#endif /* __included_cilium_srv6_parse_h__ */
