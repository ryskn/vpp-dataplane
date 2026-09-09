/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Deterministic input matrix for fuzz_guard_parser.
 *
 * The shapes are the ones the D-54 fragment rules are stated over, so that
 * the branch table of 03 §1.1 is covered by construction rather than by the
 * fuzzer happening to find it:
 *
 *   1  no Fragment header, with and without an inner IPv6 header whose
 *      destination is inside SRV6_BLOCK
 *   2  every (fragment offset, M) combination, directly, behind a
 *      Destination Options header, in front of a Routing header (the RFC
 *      7112 ordering violation, where the Routing drop must still win), and
 *      carrying an unassigned upper-layer Next Header
 *   3  duplicate Fragment header in both orders of (offset, M)
 *   4  the 01 §3.1 header-count budget, behind a first fragment
 *   5  the 01 §3.1 byte budget, behind a first fragment
 *   6  Authentication Header length arithmetic, behind a first fragment
 *   7  a zero-length extension header, which must not make the walk loop
 *   8  a random tail, seeded to a literal
 *
 * Each shape then goes through gen_sweep_plen(), which replays it at every
 * truncation point and with the declared payload length swept, because the
 * D-54 invariant is precisely about what happens when the readable area and
 * the declared length disagree.
 */

#include "gen_common.h"

#define NH_HOPOPT 0
#define NH_TCP	  6
#define NH_IPV6	  41
#define NH_ROUTE  43
#define NH_FRAG	  44
#define NH_AH	  51
#define NH_DSTOPT 60
#define NH_UNASSIGNED 253

static void
put_inner (gen_pkt_t *p, int in_block)
{
  uint8_t *q = gen_ip6 (p, NH_TCP, 20);

  if (q == NULL)
    return;
  if (in_block)
    {
      /* fdbb:bb00::/32 */
      q[24] = 0xfd;
      q[25] = 0xbb;
      q[26] = 0xbb;
      q[27] = 0x00;
    }
  else
    q[24] = 0x20;
}

void
cilium_fuzz_generate (int full)
{
  static const uint16_t offs[] = { 0, 1, 2, 1023, 8191 };
  cilium_fuzz_rng_t rng;
  gen_pkt_t p;
  int m, i, k;
  unsigned long trial, n_random;

  /* 1. no Fragment header */
  gen_reset (&p);
  gen_ip6 (&p, NH_TCP, 20);
  gen_tcp (&p, 1000, 80, 0x02);
  gen_sweep_plen (&p, full);

  for (i = 0; i <= 1; i++)
    {
      gen_reset (&p);
      gen_ip6 (&p, NH_IPV6, 60);
      put_inner (&p, i);
      gen_tcp (&p, 1000, 80, 0x02);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* 2. every (offset, M) combination in four positions */
  for (m = 0; m <= 1; m++)
    for (i = 0; i < (int) (sizeof (offs) / sizeof (offs[0])); i++)
      {
	gen_reset (&p);
	gen_ip6 (&p, NH_FRAG, 0);
	gen_frag (&p, NH_IPV6, offs[i], m, 0x11223344);
	put_inner (&p, 0);
	gen_tcp (&p, 1000, 80, 0x02);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);

	gen_reset (&p);
	gen_ip6 (&p, NH_FRAG, 0);
	gen_frag (&p, NH_TCP, offs[i], m, 0x11223344);
	gen_tcp (&p, 1000, 80, 0x12);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);

	gen_reset (&p);
	gen_ip6 (&p, NH_DSTOPT, 0);
	gen_eh (&p, NH_FRAG, 0);
	gen_frag (&p, NH_IPV6, offs[i], m, 0x11223344);
	put_inner (&p, 1);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);

	/* Fragment header carrying an unassigned upper-layer Next Header:
	   the chain terminates for the guard, and on a first fragment the
	   upper-layer header must still start inside the fragment. */
	gen_reset (&p);
	gen_ip6 (&p, NH_FRAG, 0);
	gen_frag (&p, NH_UNASSIGNED, offs[i], m, 0);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);

	/* Fragment header in front of a Routing header. RFC 7112 forbids the
	   ordering; the unconditional Routing drop of D-32 must still win. */
	gen_reset (&p);
	gen_ip6 (&p, NH_FRAG, 0);
	gen_frag (&p, NH_ROUTE, offs[i], m, 0);
	gen_srh (&p, NH_IPV6, 1, 0, 0, 4);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);

	/* A Routing header directly on the outer chain. */
	gen_reset (&p);
	gen_ip6 (&p, NH_ROUTE, 0);
	gen_srh (&p, NH_IPV6, 1, 0, 0, 4);
	put_inner (&p, 0);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);
      }

  /* 3. duplicate Fragment header */
  for (m = 0; m <= 1; m++)
    for (i = 0; i <= 1; i++)
      {
	gen_reset (&p);
	gen_ip6 (&p, NH_FRAG, 0);
	gen_frag (&p, NH_FRAG, 0, m, 1);
	gen_frag (&p, NH_IPV6, i ? 3 : 0, m, 1);
	put_inner (&p, 0);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);
      }

  /* 4. header-count budget: nine Destination Options behind a fragment */
  for (m = 0; m <= 1; m++)
    {
      gen_reset (&p);
      gen_ip6 (&p, NH_FRAG, 0);
      gen_frag (&p, NH_DSTOPT, 0, m, 2);
      for (i = 0; i < 9; i++)
	gen_eh (&p, i == 8 ? NH_TCP : NH_DSTOPT, 0);
      gen_tcp (&p, 1000, 80, 0x02);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* 5. byte budget: two 136 octet Destination Options, total 280 > 256 */
  for (m = 0; m <= 1; m++)
    {
      gen_reset (&p);
      gen_ip6 (&p, NH_FRAG, 0);
      gen_frag (&p, NH_DSTOPT, 0, m, 3);
      gen_eh (&p, NH_DSTOPT, 16);
      gen_eh (&p, NH_TCP, 16);
      gen_tcp (&p, 1000, 80, 0x02);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* 6. Authentication Header length arithmetic */
  for (m = 0; m <= 1; m++)
    for (k = 0; k <= 3; k++)
      {
	gen_reset (&p);
	gen_ip6 (&p, NH_FRAG, 0);
	gen_frag (&p, NH_AH, 0, m, 4);
	gen_ah (&p, NH_IPV6, (uint8_t) k);
	put_inner (&p, 0);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);
      }

  /* 7. zero-length extension header: hlen arithmetic must not loop */
  gen_reset (&p);
  gen_ip6 (&p, NH_FRAG, 0);
  gen_frag (&p, NH_DSTOPT, 0, 1, 5);
  gen_eh (&p, NH_TCP, 0);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_sweep_plen (&p, full);

  gen_reset (&p);
  gen_ip6 (&p, NH_HOPOPT, 0);
  gen_eh (&p, NH_TCP, 0);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_sweep_plen (&p, full);

  /* 8. single-octet corruption of a representative packet */
  gen_reset (&p);
  gen_ip6 (&p, NH_FRAG, 0);
  gen_frag (&p, NH_IPV6, 0, 1, 0x11223344);
  put_inner (&p, 0);
  gen_tcp (&p, 1000, 80, 0x02);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_corrupt_all_octets (&p, full);

  /* 9. random octets and random corruption, from a literal seed */
  cilium_fuzz_rng_init (&rng, 0x6754524147554152ull);
  n_random = full ? 1500000ul : 100000ul;

  for (trial = 0; trial < n_random; trial++)
    {
      gen_pkt_t r;
      uint32_t len = 40 + cilium_fuzz_rnd (&rng) % 200;
      uint32_t j;

      gen_reset (&r);
      r.len = len;
      for (j = 0; j < len; j++)
	r.b[j] = (uint8_t) cilium_fuzz_rnd (&rng);
      /* Keep the version nibble plausible half the time so that the walk is
	 reached rather than rejected on the first comparison. */
      if (cilium_fuzz_rnd (&rng) & 1)
	r.b[0] = 0x60;
      cilium_fuzz_run_packet (r.b, r.len, 0, (uint8_t) (cilium_fuzz_rnd (&rng) % 41),
			      (uint16_t) (cilium_fuzz_rnd (&rng) % 256));
      cilium_fuzz_run_packet (r.b, r.len, 0x80, 0, (uint16_t) (cilium_fuzz_rnd (&rng) % 512));
    }
}
