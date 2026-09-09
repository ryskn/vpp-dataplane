/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Deterministic input matrix for fuzz_headend_classify.
 *
 * This is the generator that replaces the 379k-input matrix of PR #56. The
 * matrix is the cross product that the two headend keys are defined over:
 *
 *   upper layer protocol  x  fragment classification  x  extension header
 *   chain prefix  x  L4 header truncation point
 *
 * evaluated at every truncation of the packet and with the declared payload
 * length swept, because the D-41 discriminator and the D-43 fragment key
 * both have to stay well defined when the declared length and the readable
 * area disagree. At level 1 the sweeps are exhaustive and the run is of the
 * same order as the recorded 379k; at level 0 they are sampled, which is
 * what keeps the PR gate in the minutes range.
 */

#include "gen_common.h"

#define NH_HOPOPT 0
#define NH_TCP	  6
#define NH_UDP	  17
#define NH_ROUTE  43
#define NH_FRAG	  44
#define NH_AH	  51
#define NH_ICMP6  58
#define NH_DSTOPT 60

/* Append the upper layer header for `proto`, truncated to `keep` octets when
   `keep` is smaller than the header. Truncation is the interesting case: 01
   §3.1 only evaluates a first fragment that carries its complete L4 header. */
static void
put_l4 (gen_pkt_t *p, uint8_t proto, uint32_t keep)
{
  gen_pkt_t tmp;
  uint32_t full_len;
  uint8_t *q;

  gen_reset (&tmp);
  switch (proto)
    {
    case NH_TCP:
      gen_tcp (&tmp, 4096, 443, 0x12);
      break;
    case NH_UDP:
      gen_udp (&tmp, 4096, 53);
      break;
    case NH_ICMP6:
      gen_icmp6 (&tmp, 128, 0);
      break;
    default:
      return;
    }

  full_len = tmp.len;
  if (keep < full_len)
    full_len = keep;

  q = gen_alloc (p, full_len);
  if (q == NULL)
    return;
  memcpy (q, tmp.b, full_len);
}

void
cilium_fuzz_generate (int full)
{
  static const uint8_t protos[] = { NH_TCP, NH_UDP, NH_ICMP6, 132 /* SCTP: no discriminator */ };
  static const uint8_t ehs[] = { NH_HOPOPT, NH_DSTOPT, 135, 139, 140, NH_AH };
  static const uint16_t frag_offs[] = { 0, 1, 8191 };
  cilium_fuzz_rng_t rng;
  gen_pkt_t p;
  size_t pi, ei;
  int m, fi, chain, i;
  uint32_t keep;
  unsigned long trial, n_random;

  /* 1. protocol x fragment classification x L4 truncation. */
  for (pi = 0; pi < sizeof (protos) / sizeof (protos[0]); pi++)
    for (fi = -1; fi < (int) (sizeof (frag_offs) / sizeof (frag_offs[0])); fi++)
      for (m = 0; m <= 1; m++)
	{
	  static const uint32_t keeps[] = { 0, 1, 2, 3, 4, 13, 14, 20 };
	  size_t ki;

	  /* offset != 0 with M is the same non-first branch either way, so
	     only sweep M for the offset-zero cases. */
	  if (fi >= 0 && frag_offs[fi] != 0 && m == 1)
	    continue;

	  for (ki = 0; ki < sizeof (keeps) / sizeof (keeps[0]); ki++)
	    {
	      keep = keeps[ki];
	      if (!full && (ki & 1) && keep != 4 && keep != 14)
		continue;

	      gen_reset (&p);
	      if (fi < 0)
		{
		  gen_ip6 (&p, protos[pi], 0);
		}
	      else
		{
		  gen_ip6 (&p, NH_FRAG, 0);
		  gen_frag (&p, protos[pi], frag_offs[fi], m, 0xdeadbeef);
		}
	      put_l4 (&p, protos[pi], keep);
	      gen_set_plen (&p, gen_true_plen (&p));
	      gen_sweep_plen (&p, full);
	    }
	}

  /* 2. extension header prefixes, with and without a fragment behind them. */
  for (ei = 0; ei < sizeof (ehs) / sizeof (ehs[0]); ei++)
    for (chain = 0; chain <= 2; chain++)
      for (i = 0; i <= 3; i++)
	{
	  gen_reset (&p);
	  gen_ip6 (&p, ehs[ei], 0);
	  if (ehs[ei] == NH_AH)
	    gen_ah (&p, chain == 0 ? NH_TCP : NH_FRAG, (uint8_t) i);
	  else
	    gen_eh (&p, chain == 0 ? NH_TCP : NH_FRAG, (uint8_t) i);

	  if (chain != 0)
	    gen_frag (&p, NH_TCP, chain == 1 ? 0 : 9, 1, 0x1234);
	  put_l4 (&p, NH_TCP, 20);
	  gen_set_plen (&p, gen_true_plen (&p));
	  gen_sweep_plen (&p, full);
	}

  /* 3. duplicate Fragment header (01 §3.1) in every offset combination. */
  for (fi = 0; fi < (int) (sizeof (frag_offs) / sizeof (frag_offs[0])); fi++)
    for (m = 0; m <= 1; m++)
      {
	gen_reset (&p);
	gen_ip6 (&p, NH_FRAG, 0);
	gen_frag (&p, NH_FRAG, 0, m, 0x1111);
	gen_frag (&p, NH_TCP, frag_offs[fi], m, 0x2222);
	put_l4 (&p, NH_TCP, 20);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);
      }

  /* 4. the 01 §3.1 budgets. */
  gen_reset (&p);
  gen_ip6 (&p, NH_DSTOPT, 0);
  for (i = 0; i < 9; i++)
    gen_eh (&p, i == 8 ? NH_TCP : NH_DSTOPT, 0);
  put_l4 (&p, NH_TCP, 20);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_sweep_plen (&p, full);

  gen_reset (&p);
  gen_ip6 (&p, NH_DSTOPT, 0);
  gen_eh (&p, NH_DSTOPT, 16);
  gen_eh (&p, NH_TCP, 16);
  put_l4 (&p, NH_TCP, 20);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_sweep_plen (&p, full);

  /* 5. a Routing header in front of the classifier: Routing Type 4 is
     accepted by the walk (the guard has already dropped it on an untrusted
     ingress), any other type is malformed. */
  for (i = 0; i < 4; i++)
    {
      static const uint8_t rtypes[4] = { 4, 0, 3, 255 };

      gen_reset (&p);
      gen_ip6 (&p, NH_ROUTE, 0);
      gen_srh (&p, NH_TCP, 1, 0, 0, rtypes[i]);
      put_l4 (&p, NH_TCP, 20);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* 6. a zero-length extension header. */
  gen_reset (&p);
  gen_ip6 (&p, NH_HOPOPT, 0);
  gen_eh (&p, NH_UDP, 0);
  put_l4 (&p, NH_UDP, 8);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_sweep_plen (&p, full);

  /* 7. single-octet corruption of a first fragment carrying TCP. */
  gen_reset (&p);
  gen_ip6 (&p, NH_FRAG, 0);
  gen_frag (&p, NH_TCP, 0, 1, 0xdeadbeef);
  put_l4 (&p, NH_TCP, 20);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_corrupt_all_octets (&p, full);

  /* 8. random octets and random corruption. */
  cilium_fuzz_rng_init (&rng, 0x4845414445434c53ull);
  n_random = full ? 1500000ul : 100000ul;

  for (trial = 0; trial < n_random; trial++)
    {
      gen_pkt_t r;
      uint32_t len, j, n;

      len = cilium_fuzz_rnd (&rng) % 260;
      gen_reset (&r);
      r.len = len;
      for (j = 0; j < len; j++)
	r.b[j] = (uint8_t) cilium_fuzz_rnd (&rng);
      if (cilium_fuzz_rnd (&rng) & 1)
	r.b[0] = 0x60;
      cilium_fuzz_run_packet (r.b, r.len, 0, (uint8_t) (cilium_fuzz_rnd (&rng) % 41),
			      (uint16_t) (cilium_fuzz_rnd (&rng) % 256));

      gen_reset (&r);
      gen_ip6 (&r, NH_FRAG, 0);
      gen_frag (&r, protos[cilium_fuzz_rnd (&rng) % 4],
		(uint16_t) (cilium_fuzz_rnd (&rng) % 3 ? 0 : 17), (int) (cilium_fuzz_rnd (&rng) & 1),
		cilium_fuzz_rnd (&rng));
      put_l4 (&r, NH_TCP, 20);
      gen_set_plen (&r, gen_true_plen (&r));
      n = 1 + cilium_fuzz_rnd (&rng) % 5;
      for (j = 0; j < n; j++)
	r.b[cilium_fuzz_rnd (&rng) % r.len] = (uint8_t) cilium_fuzz_rnd (&rng);
      cilium_fuzz_run_packet (r.b, r.len, 0, 0, 0);
      cilium_fuzz_run_packet (r.b, r.len, 0, (uint8_t) (cilium_fuzz_rnd (&rng) % 41), 64);
      cilium_fuzz_run_packet (r.b, r.len, 0x80, 0, (uint16_t) (cilium_fuzz_rnd (&rng) % 512));
    }
}
