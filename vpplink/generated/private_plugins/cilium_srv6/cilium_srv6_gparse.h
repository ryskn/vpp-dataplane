/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — bounded guard parser (C8-a).
 *
 * The header-inspection part of cilium-srv6-guard (03 §1.1), kept free of
 * any vlib dependency so that it is a pure function of the received bytes
 * and can be exercised against a malformed corpus on its own, the way
 * cilium_srv6_parse.h is for the destination parser.
 *
 * Bounding rule, identical to cilium_srv6_parse.h. The caller supplies
 * `avail`, the number of bytes readable from the outer IPv6 header in the
 * first buffer, and the parser derives
 *
 *   bound = min(avail, 40 + outer payload length)
 *
 * as the first offset that must not be read. Every field access is preceded
 * by an explicit comparison against `bound`; nothing outside [ip, ip+bound)
 * is ever dereferenced.
 *
 * ------------------------------------------------------------------
 * Fragment rules (D-54)
 * ------------------------------------------------------------------
 *
 * The security invariant this parser implements:
 *
 *   Every security-relevant IPv6 header of a fragmented packet received
 *   from an UNTRUSTED ingress MUST be completely inspectable in the
 *   offset-zero fragment. Otherwise the offset-zero fragment MUST be
 *   dropped.
 *
 * The four branches, in the order the walk decides them:
 *
 *   no Fragment header      bounded walk, as for any other packet
 *   atomic (off 0, M 0)     RFC 6946: processed as a non-fragmented
 *                           packet, i.e. the same bounded walk; a failure
 *                           is an ordinary DROP_MALFORMED_INNER
 *   first  (off 0, M 1)     bounded walk; *any* inspection failure —
 *                           a header that crosses the fragment boundary,
 *                           the 01 §3.1 parse budget, a malformed length,
 *                           or a chain that does not terminate inside this
 *                           fragment — is DROP_UNINSPECTABLE_FRAGMENT
 *   non-first (off != 0)    PASS. The outer destination check has already
 *                           been applied, and RFC 8200's reassembly
 *                           invariant means a non-first fragment cannot by
 *                           itself change the header semantics of the
 *                           reassembled packet: RFC 7112 puts the whole
 *                           IPv6 Header Chain — including the inner IPv6
 *                           header of an IPv6-in-IPv6 packet, which
 *                           terminates the chain as an Upper-Layer Header,
 *                           and including any Routing header, which is a
 *                           Per-Fragment header — in the offset-zero
 *                           fragment. A SID Block byte pattern sitting in
 *                           a non-first fragment is payload, and payload
 *                           is not promoted to a header by reassembly.
 *
 * The parser therefore does not need per-datagram state: the offset-zero
 * fragment alone decides, and dropping it prevents reassembly at the
 * destination.
 *
 * Design references:
 *   design/detail/03-destination-dataplane.md §1.1 (guard match/action,
 *     fragment branch table)
 *   design/detail/00-overview.md §2 (D-9, D-31, D-32, D-54)
 *   design/detail/01-packet-format.md §3.1 (bounded parser limits,
 *     duplicate Fragment header)
 *   RFC 8200 §4.5, RFC 7112, RFC 6946, RFC 8754 §5.1
 */

#ifndef __included_cilium_srv6_gparse_h__
#define __included_cilium_srv6_gparse_h__

#include <vppinfra/clib.h>
#include <vppinfra/byte_order.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.h>

/* 01 §3.1 bounded parser limits: at most 8 headers, 256 bytes total. */
#define CILIUM_SRV6_GUARD_MAX_EH       8
#define CILIUM_SRV6_GUARD_MAX_EH_BYTES 256

/* Verdicts produced by the guard dataplane, kept for packet trace (06 §6). */
typedef enum
{
  CILIUM_SRV6_GUARD_PASS = 0,
  CILIUM_SRV6_GUARD_PASS_NON_FIRST_FRAGMENT,
  CILIUM_SRV6_GUARD_DROP_BLOCK_DA,
  CILIUM_SRV6_GUARD_DROP_ROUTING_HDR,
  CILIUM_SRV6_GUARD_DROP_INNER_BLOCK_DA,
  CILIUM_SRV6_GUARD_DROP_QUARANTINED,
  CILIUM_SRV6_GUARD_DROP_MALFORMED,
  /* D-54: an offset-zero fragment whose security-relevant header chain is
     not completely visible inside that fragment, so the guard could not
     verify it (fail-closed). Kept apart from DROP_MALFORMED so that a
     possible evasion attempt is not averaged into the ordinary
     malformed-packet counter. */
  CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT,
  /* D-54 hardening option, default off: the deployment declares that an
     UNTRUSTED ingress carries no fragments at all. A configured refusal,
     not a failed inspection, so #64 gives it its own drop reason. */
  CILIUM_SRV6_GUARD_DROP_FRAGMENT_NOT_PERMITTED,
  CILIUM_SRV6_GUARD_N_VERDICT,
} cilium_srv6_guard_verdict_t;

/*
 * Where the walk stands with respect to the Fragment header. This is the
 * D-54 branch, carried as state because the classification of a later
 * failure depends on it.
 *
 * It intentionally does not reuse the headend's cilium_srv6_frag_kind_t
 * (cilium_srv6_hparse.h): that one is the D-43 fragment ordering key of
 * cilium-srv6-classify and carries a NON_FIRST value, whereas the guard
 * returns on a non-first fragment before there is any state to keep. Sharing
 * the type would couple the guard to the headend parser for no gain.
 *
 * CILIUM_SRV6_GFRAG_ATOMIC is deliberately *not* distinguished from
 * CILIUM_SRV6_GFRAG_NONE in the failure classification: RFC 6946 requires an
 * atomic fragment to be processed as a non-fragmented packet, so a failure
 * on one is an ordinary malformed packet and not an inspectability failure.
 * It is a separate value only so that the duplicate-Fragment-header rule of
 * 01 §3.1 can still see that a Fragment header was already parsed.
 */
typedef enum
{
  CILIUM_SRV6_GFRAG_NONE = 0,
  CILIUM_SRV6_GFRAG_ATOMIC,
  CILIUM_SRV6_GFRAG_FIRST,
} cilium_srv6_gfrag_state_t;

/* dst ∈ SRV6_BLOCK (03 §1.1). `block` is the prefix with its host bits
   already masked off and `mask` the prefix mask, both in network order. */
static_always_inline int
cilium_srv6_gparse_addr_in_block (const u64 block[2], const u64 mask[2], const ip6_address_t *a)
{
  u64 d0 = (a->as_u64[0] ^ block[0]) & mask[0];
  u64 d1 = (a->as_u64[1] ^ block[1]) & mask[1];
  return (d0 | d1) == 0;
}

/*
 * Classify an inspection failure. On a first fragment (offset 0, M 1) every
 * failure means the same thing — the security-relevant header chain is not
 * completely visible inside the offset-zero fragment — and the invariant
 * requires the fragment to be dropped. Everywhere else the failure is an
 * ordinary bounded-parser rejection.
 */
static_always_inline cilium_srv6_guard_verdict_t
cilium_srv6_gparse_failure (cilium_srv6_gfrag_state_t fs)
{
  return (fs == CILIUM_SRV6_GFRAG_FIRST) ? CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT :
					   CILIUM_SRV6_GUARD_DROP_MALFORMED;
}

/*
 * Bounded extension-header walk over an UNTRUSTED ingress packet.
 *
 * `avail` is the number of bytes readable from `ip` inside the first
 * buffer. `fragment_drop_all` is the D-54 hardening option.
 *
 * The outer destination and an outer Routing header are decided by the
 * caller before this walk starts (one comparison each, 03 §1.1).
 */
static_always_inline cilium_srv6_guard_verdict_t
cilium_srv6_guard_scan_untrusted (const u64 block[2], const u64 mask[2], u8 fragment_drop_all,
				  const ip6_header_t *ip, u32 avail)
{
  const u8 *p0 = (const u8 *) ip;
  u32 plen = clib_net_to_host_u16 (ip->payload_length);
  u64 declared = (u64) sizeof (ip6_header_t) + (u64) plen;
  u32 bound = avail;
  u32 off = sizeof (ip6_header_t);
  u32 eh_bytes = 0;
  u32 n_hdr;
  u8 nh = ip->protocol;
  cilium_srv6_gfrag_state_t fs = CILIUM_SRV6_GFRAG_NONE;

  /* Never read past either the declared packet end or the readable area. */
  if (declared < (u64) bound)
    bound = (u32) declared;

  for (n_hdr = 0; n_hdr < CILIUM_SRV6_GUARD_MAX_EH; n_hdr++)
    {
      u32 hlen;

      switch (nh)
	{
	case IP_PROTOCOL_IPV6_ROUTE:
	  /* D-32: unconditional drop on untrusted ingress. v1 gives a Pod no
	     legitimate reason to send an SRH. Unconditional means it does not
	     depend on the header being readable, so there is no bound check
	     and no fragment-dependent classification here: the Next Header
	     value alone is the violation. RFC 7112 puts a Routing header in
	     the Per-Fragment headers, so a fragmented packet carrying one
	     reaches this arm on its offset-zero fragment. */
	  return CILIUM_SRV6_GUARD_DROP_ROUTING_HDR;

	case IP_PROTOCOL_IPV6:
	  /* First level of encapsulation: check the inner destination
	     (03 §1.1 "1 段目 inner の DA"). RFC 8200 counts this header as an
	     Upper-Layer Header, so RFC 7112 requires it to be inside the
	     offset-zero fragment in full; a fragment that truncates it is
	     exactly what the D-54 invariant refuses. */
	  {
	    const ip6_header_t *inner;

	    if (off + sizeof (ip6_header_t) > bound)
	      return cilium_srv6_gparse_failure (fs);

	    inner = (const ip6_header_t *) (p0 + off);

	    if ((inner->ip_version_traffic_class_and_flow_label &
		 clib_host_to_net_u32 (0xf0000000)) != clib_host_to_net_u32 (0x60000000))
	      return cilium_srv6_gparse_failure (fs);

	    if (cilium_srv6_gparse_addr_in_block (block, mask, &inner->dst_address))
	      return CILIUM_SRV6_GUARD_DROP_INNER_BLOCK_DA;

	    return CILIUM_SRV6_GUARD_PASS;
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
	      return cilium_srv6_gparse_failure (fs);

	    eh = (const ip6_ext_header_t *) (p0 + off);

	    /* AH is measured in 4 byte units and excludes 8 bytes; every
	       other extension header is measured in 8 byte units and
	       excludes the first 8 bytes. */
	    hlen = (nh == IP_PROTOCOL_IPSEC_AH) ? (((u32) eh->n_data_u64s + 2) << 2) :
						  (((u32) eh->n_data_u64s + 1) << 3);

	    if (hlen < sizeof (ip6_ext_header_t) || off + hlen > bound)
	      return cilium_srv6_gparse_failure (fs);

	    eh_bytes += hlen;
	    if (eh_bytes > CILIUM_SRV6_GUARD_MAX_EH_BYTES)
	      return cilium_srv6_gparse_failure (fs);

	    nh = eh->next_hdr;
	    off += hlen;
	    break;
	  }

	case IP_PROTOCOL_IPV6_FRAGMENTATION:
	  {
	    const ip6_frag_hdr_t *fh;

	    /* D-54 hardening option (default off). The Next Header value is
	       the whole condition: a deployment that declares fragmentation
	       unsupported does not need the header to be readable. Counted on
	       its own reason and counter, DROP_FRAGMENT_NOT_PERMITTED (#64),
	       so that the drops it produces — which include perfectly
	       conformant fragments of any kind, atomic, first or non-first —
	       are never read as evasion attempts. */
	    if (PREDICT_FALSE (fragment_drop_all))
	      return CILIUM_SRV6_GUARD_DROP_FRAGMENT_NOT_PERMITTED;

	    if (off + sizeof (ip6_frag_hdr_t) > bound)
	      return cilium_srv6_gparse_failure (fs);

	    /* 01 §3.1: a duplicate Fragment header is malformed. `fs` still
	       describes the first one, which is what classifies the drop. */
	    if (fs != CILIUM_SRV6_GFRAG_NONE)
	      return cilium_srv6_gparse_failure (fs);

	    eh_bytes += sizeof (ip6_frag_hdr_t);
	    if (eh_bytes > CILIUM_SRV6_GUARD_MAX_EH_BYTES)
	      return cilium_srv6_gparse_failure (fs);

	    fh = (const ip6_frag_hdr_t *) (p0 + off);

	    /* D-54, non-first branch: nothing in this fragment can change the
	       header semantics of the reassembled packet, and the outer
	       destination check has already been applied. */
	    if (ip6_frag_hdr_offset (fh) != 0)
	      return CILIUM_SRV6_GUARD_PASS_NON_FIRST_FRAGMENT;

	    /* offset 0: atomic (M 0, RFC 6946) or first (M 1, RFC 7112). Both
	       continue the walk; they differ only in how a later failure is
	       classified. */
	    fs = ip6_frag_hdr_more (fh) ? CILIUM_SRV6_GFRAG_FIRST : CILIUM_SRV6_GFRAG_ATOMIC;

	    nh = fh->next_hdr;
	    off += sizeof (ip6_frag_hdr_t);
	    break;
	  }

	default:
	  /* Upper layer protocol: RFC 8200 ends the IPv6 Header Chain here,
	     so there is no further SRv6 structure to inspect.

	     On a first fragment RFC 7112 additionally requires the chain to
	     be complete inside the offset-zero fragment, so the upper-layer
	     header must at least begin before `bound`. `off == bound` means
	     the chain ended exactly at the fragment boundary and the
	     upper-layer header lives entirely in a later fragment: the
	     offset-zero fragment does not determine the chain on its own, and
	     the D-54 invariant refuses it. Without this check a truncated
	     offset-zero fragment would be passed as if it had been
	     inspected, which is the hole D-54 closes. */
	  if (PREDICT_FALSE (fs == CILIUM_SRV6_GFRAG_FIRST && off >= bound))
	    return CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT;
	  return CILIUM_SRV6_GUARD_PASS;
	}
    }

  /* 01 §3.1: more than CILIUM_SRV6_GUARD_MAX_EH headers. Fail closed, or a
     long header chain could be used to hide an SRH from the guard. */
  return cilium_srv6_gparse_failure (fs);
}

#endif /* __included_cilium_srv6_gparse_h__ */
