/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Fuzz target: cilium_srv6_parse_outer() and the two functions it calls
 * (cilium_srv6_parse.h).
 *
 * Responsibility of this target: the destination-side bounded parser of
 * cilium-end-cilium — outer length validation, SRH validation including the
 * D-28 segments-left rule and the RFC 8754 §2.1 TLV walk, the inner header
 * chain of 01 §3.1, and the 04 §4 defence line (4) destination comparison.
 * A crash here is a destination-dataplane bug.
 *
 * Post-conditions, from the malformed-corpus run recorded in PR #33 plus the
 * decap-length properties the caller depends on before it advances the
 * buffer:
 *
 *   P1  the result is a defined enum value
 *   P2  the result and both outputs are deterministic
 *   P3  every non-OK result leaves *decap_len at 0, so a caller that
 *       forgets to branch on the result cannot advance the buffer by a
 *       stale value
 *   P4  on OK the decapsulation length is inside every bound the caller
 *       relies on: 40 <= decap, decap + 40 <= avail, decap + 40 <= chain_len
 *   P5  on OK the decapsulation length is consistent with has_srh: exactly
 *       40 without an SRH, and 40 + a positive multiple of 8 with one
 *   P6  on OK the octets the caller will treat as the inner IPv6 header
 *       really are one, and its destination really is the endpoint address.
 *       Checked against the raw octets rather than through the parser's own
 *       comparison, because this is defence line (4): a stale route must not
 *       be able to deliver a packet to the wrong Pod.
 *   P7  on OK the outer declared length fits the buffer chain, recomputed
 *       from the octet stream
 */

#include "cilium_fuzz.h"

#include <cilium_srv6/cilium_srv6_parse.h>

const char *const cilium_fuzz_target_name = "fuzz_end_cilium_parser";

/* Indexed by cilium_srv6_parse_result_t. */
const char *const cilium_fuzz_outcome_name[] = { "PARSE_OK", "MALFORMED_OUTER", "MALFORMED_INNER",
						 "IP_MISMATCH", NULL };

const unsigned char cilium_fuzz_outcome_required[] = { 1, 1, 1, 1 };

/*
 * The Context's endpoint address. Fixed so that a corpus file means the same
 * thing on every run; the generators build packets that both match and miss
 * it, which is what makes IP_MISMATCH reachable.
 */
static ip6_address_t endpoint;

/* Exposed so that the generator builds inner packets addressed to it. */
const u8 *cilium_fuzz_endpoint_bytes (void);

static void
endpoint_init (void)
{
  memset (&endpoint, 0, sizeof (endpoint));
  endpoint.as_u8[0] = 0xfd;
  endpoint.as_u8[1] = 0xbb;
  endpoint.as_u8[2] = 0xbb;
  endpoint.as_u8[15] = 0x0b;
}

const u8 *
cilium_fuzz_endpoint_bytes (void)
{
  static int inited;

  if (!inited)
    {
      endpoint_init ();
      inited = 1;
    }
  return endpoint.as_u8;
}

void
cilium_fuzz_one (const uint8_t *data, size_t size)
{
  cilium_fuzz_input_t in;
  cilium_srv6_parse_result_t r, r2;
  u32 decap = 0xdeadbeef, decap2 = 0xdeadbeef;
  u8 has_srh = 0xff, has_srh2 = 0xff;

  (void) cilium_fuzz_endpoint_bytes ();

  if (!cilium_fuzz_input_decode (data, size, &in))
    return;

  r = cilium_srv6_parse_outer (in.pkt, in.avail, in.chain_len, &endpoint, &decap, &has_srh);
  r2 = cilium_srv6_parse_outer (in.pkt, in.avail, in.chain_len, &endpoint, &decap2, &has_srh2);

  /* P1 */
  CILIUM_FUZZ_ASSERT (r == CILIUM_SRV6_PARSE_OK || r == CILIUM_SRV6_PARSE_MALFORMED_OUTER ||
			r == CILIUM_SRV6_PARSE_MALFORMED_INNER ||
			r == CILIUM_SRV6_PARSE_IP_MISMATCH,
		      "result=%d avail=%u", (int) r, in.avail);
  /* P2 */
  CILIUM_FUZZ_ASSERT (r == r2 && decap == decap2 && has_srh == has_srh2,
		      "non-deterministic: %d/%u/%u vs %d/%u/%u", (int) r, decap, has_srh, (int) r2,
		      decap2, has_srh2);

  CILIUM_FUZZ_ASSERT (has_srh <= 1, "has_srh=%u", has_srh);

  if (r != CILIUM_SRV6_PARSE_OK)
    {
      /* P3 */
      CILIUM_FUZZ_ASSERT (decap == 0, "result=%d left decap_len=%u", (int) r, decap);
    }
  else
    {
      u64 declared;

      /* P4 */
      CILIUM_FUZZ_ASSERT (decap >= sizeof (ip6_header_t), "decap=%u", decap);
      CILIUM_FUZZ_ASSERT ((u64) decap + sizeof (ip6_header_t) <= (u64) in.avail,
			  "decap=%u avail=%u", decap, in.avail);
      CILIUM_FUZZ_ASSERT ((u64) decap + sizeof (ip6_header_t) <= in.chain_len,
			  "decap=%u chain_len=%llu", decap,
			  (unsigned long long) in.chain_len);

      /* P5 */
      if (has_srh == 0)
	CILIUM_FUZZ_ASSERT (decap == sizeof (ip6_header_t), "decap=%u without SRH", decap);
      else
	{
	  u32 srh_len = decap - (u32) sizeof (ip6_header_t);

	  CILIUM_FUZZ_ASSERT (srh_len >= CILIUM_SRV6_SRH_FIXED_LEN && (srh_len % 8) == 0,
			      "srh_len=%u", srh_len);
	  /* The SRH the parser accepted must be Routing Type 4 and must be
	     followed by IPv6, read straight out of the octets. */
	  CILIUM_FUZZ_ASSERT (in.pkt[6] == IP_PROTOCOL_IPV6_ROUTE, "outer nh=%u", in.pkt[6]);
	  CILIUM_FUZZ_ASSERT (in.pkt[40 + 2] == ROUTING_HEADER_TYPE_SR, "routing type=%u",
			      in.pkt[40 + 2]);
	  CILIUM_FUZZ_ASSERT (in.pkt[40] == IP_PROTOCOL_IPV6, "srh nh=%u", in.pkt[40]);
	  CILIUM_FUZZ_ASSERT (in.pkt[40 + 3] == 0, "D-28: segments_left=%u", in.pkt[40 + 3]);
	}

      /* P6: defence line (4), checked against the raw octets. */
      CILIUM_FUZZ_ASSERT ((in.pkt[decap] >> 4) == 6, "inner version nibble=%u",
			  in.pkt[decap] >> 4);
      CILIUM_FUZZ_ASSERT (memcmp (in.pkt + decap + 24, endpoint.as_u8, 16) == 0,
			  "inner destination is not the endpoint address");

      /* P7 */
      declared = (u64) sizeof (ip6_header_t) + (((u64) in.pkt[4] << 8) | in.pkt[5]);
      CILIUM_FUZZ_ASSERT (declared <= in.chain_len, "declared=%llu chain_len=%llu",
			  (unsigned long long) declared, (unsigned long long) in.chain_len);
      CILIUM_FUZZ_ASSERT ((u64) decap + sizeof (ip6_header_t) <= declared,
			  "decap=%u declared=%llu", decap, (unsigned long long) declared);
    }

  cilium_fuzz_record ((unsigned) r);
  cilium_fuzz_input_free (&in);
}
