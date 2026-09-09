/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — bounded headend parser (C7).
 *
 * The inner extension-header / fragment walk of cilium-srv6-classify
 * (02 §3, 01 §3.1), kept free of any vlib dependency so that it is a pure
 * function of the received bytes and can be exercised against a malformed
 * corpus on its own — the same rule cilium_srv6_parse.h follows for the
 * destination side.
 *
 * Bounding rule. The caller supplies
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
 * past the readable area is reported as a length inconsistency and never as
 * a read. Nothing outside [p0, p0 + bound) is dereferenced, and the parser
 * never writes to the packet.
 *
 * What it produces is the input of the two headend keys:
 *
 *   ProgramCache key       proto + l4_discriminator (D-41)
 *   FragmentVerdictCache   fragment id + next header (01 §3.1, D-43)
 *
 * plus the L4 ports that feed the flow entropy hash of 01 §4.
 *
 * Design references:
 *   design/detail/01-packet-format.md §3.1 (bounded EH/fragment rules),
 *     §4 (flow entropy input)
 *   design/detail/02-headend-dataplane.md §3 (cilium-srv6-classify)
 *   design/detail/00-overview.md §2 (D-18, D-41, D-43)
 */

#ifndef __included_cilium_srv6_hparse_h__
#define __included_cilium_srv6_hparse_h__

#include <vppinfra/clib.h>
#include <vppinfra/byte_order.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.h>

#include <cilium_srv6/cilium_srv6_parse.h>

/*
 * 01 §3.1 limits, shared with the destination parser: at most 8 extension
 * headers and 256 bytes of extension headers.
 */
#define CILIUM_SRV6_HPARSE_MAX_EH	CILIUM_SRV6_INNER_MAX_EH
#define CILIUM_SRV6_HPARSE_MAX_EH_BYTES CILIUM_SRV6_INNER_MAX_EH_BYTES

typedef enum
{
  CILIUM_SRV6_HPARSE_OK = 0,
  /* short, not IPv6, length inconsistent, duplicate Fragment header,
     unknown Routing Type, EH chain outside the 01 §3.1 limits, or a first
     fragment that does not carry its complete L4 header (RFC 8200 §4.5) —
     all DROP_MALFORMED_INNER */
  CILIUM_SRV6_HPARSE_MALFORMED,
} cilium_srv6_hparse_result_t;

/*
 * Fragment classification (01 §3.1 / D-43).
 *
 *   NONE       no Fragment header
 *   ATOMIC     Fragment header, offset 0 and M=0. "atomic fragment は通常
 *              packet として policy 評価する": treated exactly like NONE by
 *              every later stage, and deliberately not given a
 *              FragmentVerdictCache entry.
 *   FIRST      offset 0, M=1. Evaluated normally; the verdict is recorded in
 *              the FragmentVerdictCache.
 *   NON_FIRST  offset != 0. Carries payload, not a header chain, so no L4
 *              discriminator exists; only a FragmentVerdictCache hit can
 *              forward it.
 */
typedef enum
{
  CILIUM_SRV6_FRAG_NONE = 0,
  CILIUM_SRV6_FRAG_ATOMIC,
  CILIUM_SRV6_FRAG_FIRST,
  CILIUM_SRV6_FRAG_NON_FIRST,
} cilium_srv6_frag_kind_t;

typedef struct
{
  /* upper layer protocol, i.e. the ProgramCache key component. A non-first
     fragment has no upper layer header, so this is the Fragment header's
     Next Header for it. */
  u8 proto;
  u8 frag_kind; /* cilium_srv6_frag_kind_t */
  /*
   * The Fragment header's Next Header. This, not `proto`, is the
   * "next-header" component of the FragmentVerdictCache key and of the
   * fragment flow entropy hash (01 §3.1, §4): RFC 8200 puts per-fragment
   * extension headers *after* the Fragment header, so they appear only in
   * the first fragment. Walking through them would give the first and the
   * later fragments of one datagram different keys, and the later ones would
   * never match their own first fragment. 0 when not fragmented.
   */
  u8 frag_next_header;
  u8 pad;
  /* D-41: TCP/UDP dst port, ICMPv6 (type << 8) | code, anything else 0 */
  u16 l4_discriminator;
  u32 frag_id; /* network order Identification, 0 when not fragmented */
  u16 sport;   /* 01 §4 flow entropy input, 0 when there is no L4 header */
  u16 dport;
  /*
   * TCP control bits (byte 13 of the TCP header), the input of the conntrack
   * state machine of 02 §7.2: "TCP は SYN 受信で SYN_SEEN、SYN-ACK と ACK を
   * 確認して VERIFIED_ESTABLISHED とし、CLOSED/timeout 後は許可しない".
   * 0 for every other protocol. A TCP header too short to hold them is a
   * length inconsistency, which the walk below already reports as malformed.
   */
  u8 tcp_flags;
  u8 pad2[3];
} cilium_srv6_hparse_t;

/*
 * D-41. The discriminator is the one u16 that distinguishes flows of the
 * same (src identity, dst, proto) triple in the ProgramCache key. Rounding
 * non-TCP/UDP down to 0 would collapse ICMPv6 into a single all-ALLOW or
 * all-DENY entry, which is why ICMPv6 stores type/code instead.
 *
 * `off` is the offset of the upper layer header and `bound` the first offset
 * that must not be read. Returns 0 if the header is not fully readable.
 */
static_always_inline int
cilium_srv6_hparse_l4 (const u8 *p0, u32 off, u32 bound, u8 proto, cilium_srv6_hparse_t *r)
{
  switch (proto)
    {
    case IP_PROTOCOL_TCP:
    case IP_PROTOCOL_UDP:
      /* Source and destination port are the first four bytes of both. */
      if (off + 4 > bound)
	return 0;
      r->sport = clib_net_to_host_u16 (*(const u16 *) (p0 + off));
      r->dport = clib_net_to_host_u16 (*(const u16 *) (p0 + off + 2));
      r->l4_discriminator = r->dport;

      /*
       * The TCP control bits live at offset 13 and are only reported when
       * the whole fixed header prefix that contains them is readable. A
       * shorter one leaves them at 0, which makes the conntrack stage treat
       * the packet as carrying no protocol state: it is then evaluated by
       * the ProgramCache rather than by a conntrack entry (02 §7.2 branch 3),
       * which is the fail-closed side. The bound is not raised to 14 here so
       * that this parser keeps classifying exactly what it classified before
       * (02 §3 is not changed by C10).
       */
      if (proto == IP_PROTOCOL_TCP && off + 14 <= bound)
	r->tcp_flags = p0[off + 13];

      return 1;

    case IP_PROTOCOL_ICMP6:
      /* Type and code are the first two bytes. */
      if (off + 2 > bound)
	return 0;
      r->l4_discriminator = ((u16) p0[off] << 8) | (u16) p0[off + 1];
      return 1;

    default:
      /* 01 §3.1 / D-41: everything else keeps discriminator 0. No upper
	 layer bytes are read, so a protocol with no ports is not a length
	 violation. */
      r->l4_discriminator = 0;
      return 1;
    }
}

/*
 * Bounded walk over the inner packet the Pod sent (02 §3, 01 §3.1).
 *
 * `avail` is the number of bytes readable from p0 in the first buffer and
 * `chain_len` the total length of the buffer chain. On
 * CILIUM_SRV6_HPARSE_OK the result carries everything the later stages need;
 * the packet itself is left untouched.
 */
static_always_inline cilium_srv6_hparse_result_t
cilium_srv6_hparse (const u8 *p0, u32 avail, u64 chain_len, cilium_srv6_hparse_t *r)
{
  const ip6_header_t *ip = (const ip6_header_t *) p0;
  u64 declared;
  u32 bound, off, eh_bytes = 0, n_hdr;
  u8 nh;
  u8 seen_frag = 0;

  r->proto = 0;
  r->frag_kind = CILIUM_SRV6_FRAG_NONE;
  r->frag_next_header = 0;
  r->pad = 0;
  r->l4_discriminator = 0;
  r->frag_id = 0;
  r->sport = 0;
  r->dport = 0;
  r->tcp_flags = 0;
  r->pad2[0] = r->pad2[1] = r->pad2[2] = 0;

  if (PREDICT_FALSE (avail < sizeof (ip6_header_t)))
    return CILIUM_SRV6_HPARSE_MALFORMED;

  if (PREDICT_FALSE ((ip->ip_version_traffic_class_and_flow_label &
		      clib_host_to_net_u32 (0xf0000000)) != clib_host_to_net_u32 (0x60000000)))
    return CILIUM_SRV6_HPARSE_MALFORMED;

  /* The declared length is checked against the chain before anything past
     the IPv6 header is looked at. */
  declared = (u64) sizeof (ip6_header_t) + (u64) clib_net_to_host_u16 (ip->payload_length);
  if (PREDICT_FALSE (declared > chain_len))
    return CILIUM_SRV6_HPARSE_MALFORMED;

  bound = avail;
  if ((u64) bound > declared)
    bound = (u32) declared;

  off = sizeof (ip6_header_t);
  nh = ip->protocol;

  for (n_hdr = 0; n_hdr < CILIUM_SRV6_HPARSE_MAX_EH; n_hdr++)
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
	      return CILIUM_SRV6_HPARSE_MALFORMED;

	    eh = (const ip6_ext_header_t *) (p0 + off);

	    /* 01 §3.1: an unknown Routing Type is malformed. (A Pod has no
	       legitimate reason to send Routing Type 4 either — the guard
	       drops that on the untrusted ingress before classify runs.) */
	    if (p0[off + 2] != ROUTING_HEADER_TYPE_SR)
	      return CILIUM_SRV6_HPARSE_MALFORMED;

	    hlen = ((u32) eh->n_data_u64s + 1) << 3;
	    if (off + hlen > bound)
	      return CILIUM_SRV6_HPARSE_MALFORMED;

	    eh_bytes += hlen;
	    if (eh_bytes > CILIUM_SRV6_HPARSE_MAX_EH_BYTES)
	      return CILIUM_SRV6_HPARSE_MALFORMED;

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
	      return CILIUM_SRV6_HPARSE_MALFORMED;

	    eh = (const ip6_ext_header_t *) (p0 + off);

	    /* AH is measured in 4 byte units and excludes 8 bytes; every
	       other extension header is measured in 8 byte units and
	       excludes the first 8 bytes. */
	    hlen = (nh == IP_PROTOCOL_IPSEC_AH) ? (((u32) eh->n_data_u64s + 2) << 2) :
						  (((u32) eh->n_data_u64s + 1) << 3);

	    if (hlen < sizeof (ip6_ext_header_t) || off + hlen > bound)
	      return CILIUM_SRV6_HPARSE_MALFORMED;

	    eh_bytes += hlen;
	    if (eh_bytes > CILIUM_SRV6_HPARSE_MAX_EH_BYTES)
	      return CILIUM_SRV6_HPARSE_MALFORMED;

	    nh = eh->next_hdr;
	    off += hlen;
	    break;
	  }

	case IP_PROTOCOL_IPV6_FRAGMENTATION:
	  {
	    const ip6_frag_hdr_t *fh;

	    if (off + sizeof (ip6_frag_hdr_t) > bound)
	      return CILIUM_SRV6_HPARSE_MALFORMED;

	    /* 01 §3.1: a duplicate Fragment header is malformed. */
	    if (seen_frag)
	      return CILIUM_SRV6_HPARSE_MALFORMED;
	    seen_frag = 1;

	    eh_bytes += sizeof (ip6_frag_hdr_t);
	    if (eh_bytes > CILIUM_SRV6_HPARSE_MAX_EH_BYTES)
	      return CILIUM_SRV6_HPARSE_MALFORMED;

	    fh = (const ip6_frag_hdr_t *) (p0 + off);
	    r->frag_id = fh->identification;
	    /* 01 §3.1 "(src, dst, fragment-id, next-header)": the key component
	       every fragment of the datagram carries identically. */
	    r->frag_next_header = fh->next_hdr;

	    if (ip6_frag_hdr_offset (fh) != 0)
	      {
		/*
		 * D-43: a non-first fragment carries payload, not a header
		 * chain, so there is nothing further to walk and no L4
		 * discriminator to derive.
		 */
		r->frag_kind = CILIUM_SRV6_FRAG_NON_FIRST;
		r->proto = fh->next_hdr;
		r->l4_discriminator = 0;
		return CILIUM_SRV6_HPARSE_OK;
	      }

	    /* offset == 0: first fragment if more fragments follow, an atomic
	       fragment otherwise. Both continue through the chain. */
	    r->frag_kind =
	      ip6_frag_hdr_more (fh) ? CILIUM_SRV6_FRAG_FIRST : CILIUM_SRV6_FRAG_ATOMIC;

	    nh = fh->next_hdr;
	    off += sizeof (ip6_frag_hdr_t);
	    break;
	  }

	default:
	  /* Upper layer protocol: end of the extension header chain. */
	  r->proto = nh;

	  if (PREDICT_FALSE (!cilium_srv6_hparse_l4 (p0, off, bound, nh, r)))
	    {
	      /*
	       * RFC 8200 §4.5 requires the first fragment to carry the whole
	       * header chain, and 01 §3.1 only evaluates a first fragment
	       * "L4 header を完全に含む場合だけ". A packet whose declared
	       * length stops inside its own L4 header is malformed either
	       * way, so both cases fail closed here rather than being
	       * evaluated with a guessed discriminator.
	       */
	      return CILIUM_SRV6_HPARSE_MALFORMED;
	    }

	  return CILIUM_SRV6_HPARSE_OK;
	}
    }

  /* 01 §3.1: more than CILIUM_SRV6_HPARSE_MAX_EH headers. */
  return CILIUM_SRV6_HPARSE_MALFORMED;
}

#endif /* __included_cilium_srv6_hparse_h__ */
