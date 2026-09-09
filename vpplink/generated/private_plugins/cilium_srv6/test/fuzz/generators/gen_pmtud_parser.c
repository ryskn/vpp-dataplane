/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Deterministic input matrix for fuzz_pmtud_parser.
 *
 * The shapes follow the structure of an ICMPv6 error as RFC 4443 §3.2
 * defines it and as 02 §9 consumes it:
 *
 *   outer IPv6 -> ICMPv6 (type, code) -> MTU -> quoted packet
 *
 * and vary each stage independently:
 *
 *   1  the ICMPv6 type and code, so that NOT_PTB is reached by construction
 *      and not only by the fuzzer stumbling on a non-2 type
 *   2  extension headers between the outer header and the ICMPv6 header,
 *      which the parser refuses rather than walks
 *   3  the quote: absent, truncated inside the quoted IPv6 header, complete,
 *      continuing into an SRH of every length, and continuing into the inner
 *      header. The truncation points matter because 02 §9 treats a truncated
 *      SRH as absent rather than as malformed, and that distinction is the
 *      one an attacker would try to move.
 *   4  the reported MTU across the 02 §9 range boundaries: below 1280, at
 *      1280, just below the recorded outer size, at it, above it, and the
 *      full-width values that must not be truncated into u16
 */

#include "gen_common.h"

#define NH_TCP	  6
#define NH_IPV6	  41
#define NH_ROUTE  43
#define NH_FRAG	  44
#define NH_ICMP6  58
#define NH_DSTOPT 60

#define ICMP6_PTB 2

/* Append the ICMPv6 fixed part plus the 32 bit MTU of RFC 4443 §3.2. */
static void
put_icmp6 (gen_pkt_t *p, uint8_t type, uint8_t code, uint32_t mtu)
{
  uint8_t *q = gen_alloc (p, 8);

  if (q == NULL)
    return;
  q[0] = type;
  q[1] = code;
  q[2] = 0;
  q[3] = 0;
  q[4] = (uint8_t) (mtu >> 24);
  q[5] = (uint8_t) (mtu >> 16);
  q[6] = (uint8_t) (mtu >> 8);
  q[7] = (uint8_t) mtu;
}

/* Truncate a built packet to `len` octets. The parser must treat a quote cut
   short as "no more quote", not as a reason to read on. */
static void
truncate_to (gen_pkt_t *p, uint32_t len)
{
  if (len < p->len)
    p->len = len;
}

void
cilium_fuzz_generate (int full)
{
  static const uint32_t mtus[] = { 0,	    1,	    1279,   1280,   1281,  1400,
				   1500,    9000,   0xffff, 0x10000, 0xfffffffful };
  static const uint8_t types[] = { 1, 2, 3, 4, 128, 129, 0, 255 };
  static const uint8_t codes[] = { 0, 1, 255 };
  cilium_fuzz_rng_t rng;
  gen_pkt_t p, base;
  size_t ti, ci, mi;
  int seg, with_srh, with_inner, i;
  uint32_t cut;
  unsigned long trial, n_random;

  /* 1. ICMPv6 type and code. */
  for (ti = 0; ti < sizeof (types) / sizeof (types[0]); ti++)
    for (ci = 0; ci < sizeof (codes) / sizeof (codes[0]); ci++)
      {
	if (!full && types[ti] != ICMP6_PTB && ci > 0)
	  continue;

	gen_reset (&p);
	gen_ip6 (&p, NH_ICMP6, 0);
	put_icmp6 (&p, types[ti], codes[ci], 1400);
	gen_ip6 (&p, NH_IPV6, 60); /* the quoted outer header */
	gen_ip6 (&p, NH_TCP, 20);  /* the quoted inner header */
	gen_tcp (&p, 1000, 80, 0x10);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);
      }

  /* 2. an outer Next Header that is not ICMPv6, and extension headers in
     front of the ICMPv6 header, which the parser refuses. */
  for (i = 0; i < 4; i++)
    {
      static const uint8_t nhs[4] = { NH_TCP, NH_DSTOPT, NH_FRAG, NH_ROUTE };

      gen_reset (&p);
      gen_ip6 (&p, nhs[i], 0);
      if (nhs[i] == NH_DSTOPT)
	gen_eh (&p, NH_ICMP6, 0);
      else if (nhs[i] == NH_FRAG)
	gen_frag (&p, NH_ICMP6, 0, 0, 7);
      else if (nhs[i] == NH_ROUTE)
	gen_srh (&p, NH_ICMP6, 1, 0, 0, 4);
      put_icmp6 (&p, ICMP6_PTB, 0, 1400);
      gen_ip6 (&p, NH_IPV6, 60);
      gen_ip6 (&p, NH_TCP, 20);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* 3. the quote, across the shapes 01 §2.4 describes. */
  for (with_srh = 0; with_srh <= 1; with_srh++)
    for (with_inner = 0; with_inner <= 1; with_inner++)
      for (seg = 1; seg <= (with_srh ? 4 : 1); seg++)
	for (mi = 0; mi < sizeof (mtus) / sizeof (mtus[0]); mi++)
	  {
	    if (!full && (mi & 1) && mtus[mi] != 1280 && mtus[mi] != 1400)
	      continue;

	    gen_reset (&base);
	    gen_ip6 (&base, NH_ICMP6, 0);
	    put_icmp6 (&base, ICMP6_PTB, 0, mtus[mi]);

	    /* quoted outer */
	    gen_ip6 (&base, with_srh ? NH_ROUTE : (with_inner ? NH_IPV6 : NH_TCP), 0);
	    if (with_srh)
	      gen_srh (&base, with_inner ? NH_IPV6 : NH_TCP, (uint8_t) seg, (uint8_t) (seg - 1), 0,
		       4);
	    if (with_inner)
	      gen_ip6 (&base, NH_TCP, 20);
	    gen_tcp (&base, 1000, 80, 0x10);

	    /* Declare a plausible length for the quoted outer header. */
	    base.b[48 + 4] = 0;
	    base.b[48 + 5] = 200;
	    gen_set_plen (&base, gen_true_plen (&base));
	    gen_sweep_plen (&base, full);

	    /* Every truncation of the quote, which is what a transit node
	       that only quotes 1232 octets produces. */
	    for (cut = 48; cut <= base.len; cut += (full ? 1 : 4))
	      {
		p = base;
		truncate_to (&p, cut);
		gen_set_plen (&p, gen_true_plen (&p));
		gen_sweep (&p, 0);
	      }
	  }

  /* 4. a quoted header whose version nibble is wrong, and an SRH with a
     Routing Type other than 4, both of which must be MALFORMED rather than
     a truncated-quote OK. */
  for (i = 0; i < 4; i++)
    {
      gen_reset (&p);
      gen_ip6 (&p, NH_ICMP6, 0);
      put_icmp6 (&p, ICMP6_PTB, 0, 1400);
      gen_ip6 (&p, i < 2 ? NH_ROUTE : NH_IPV6, 0);
      if (i < 2)
	gen_srh (&p, NH_IPV6, 1, 0, 0, i == 0 ? 4 : 3);
      gen_ip6 (&p, NH_TCP, 20);
      if (i == 2)
	p.b[88] = 0x40; /* quoted outer version nibble 4 */
      if (i == 3)
	p.b[p.len - 20 - 40] = 0x40; /* quoted inner version nibble 4 */
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* 5. single-octet corruption of a complete PTB. */
  gen_reset (&p);
  gen_ip6 (&p, NH_ICMP6, 0);
  put_icmp6 (&p, ICMP6_PTB, 0, 1400);
  gen_ip6 (&p, NH_ROUTE, 0);
  gen_srh (&p, NH_IPV6, 2, 1, 0, 4);
  gen_ip6 (&p, NH_TCP, 20);
  gen_tcp (&p, 1000, 80, 0x10);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_corrupt_all_octets (&p, full);

  /* 6. random octets and random corruption of a complete PTB. */
  cilium_fuzz_rng_init (&rng, 0x504d5455444d5458ull);
  n_random = full ? 600000ul : 40000ul;

  for (trial = 0; trial < n_random; trial++)
    {
      gen_pkt_t r;
      uint32_t len, j, n;

      len = cilium_fuzz_rnd (&rng) % 320;
      gen_reset (&r);
      r.len = len;
      for (j = 0; j < len; j++)
	r.b[j] = (uint8_t) cilium_fuzz_rnd (&rng);
      if (cilium_fuzz_rnd (&rng) & 1)
	{
	  r.b[0] = 0x60;
	  r.b[6] = NH_ICMP6;
	  if (len > 41)
	    r.b[40] = ICMP6_PTB;
	  if (len > 42)
	    r.b[41] = 0;
	}
      cilium_fuzz_run_packet (r.b, r.len, 0, (uint8_t) (cilium_fuzz_rnd (&rng) % 41),
			      (uint16_t) (cilium_fuzz_rnd (&rng) % 256));

      gen_reset (&r);
      gen_ip6 (&r, NH_ICMP6, 0);
      put_icmp6 (&r, ICMP6_PTB, 0, 1280 + cilium_fuzz_rnd (&rng) % 400);
      gen_ip6 (&r, (cilium_fuzz_rnd (&rng) & 1) ? NH_ROUTE : NH_IPV6, 0);
      if (r.b[48 + 6] == NH_ROUTE)
	gen_srh (&r, NH_IPV6, (uint8_t) (1 + cilium_fuzz_rnd (&rng) % 3), 0, 0, 4);
      gen_ip6 (&r, NH_TCP, 20);
      gen_tcp (&r, 1000, 80, 0x10);
      gen_set_plen (&r, gen_true_plen (&r));
      n = 1 + cilium_fuzz_rnd (&rng) % 6;
      for (j = 0; j < n; j++)
	r.b[cilium_fuzz_rnd (&rng) % r.len] = (uint8_t) cilium_fuzz_rnd (&rng);
      cilium_fuzz_run_packet (r.b, r.len, 0, 0, 0);
      cilium_fuzz_run_packet (r.b, r.len, 0, (uint8_t) (cilium_fuzz_rnd (&rng) % 41), 64);
      cilium_fuzz_run_packet (r.b, r.len, 0x80, 0, (uint16_t) (cilium_fuzz_rnd (&rng) % 512));
    }
}
