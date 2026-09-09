/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Deterministic input matrix for fuzz_end_cilium_parser.
 *
 * The shapes cover the three validation stages of cilium_srv6_parse_outer():
 *
 *   1  outer length validation against the buffer chain (01 §3.2)
 *   2  the SRH: Routing Type, the Hdr Ext Len arithmetic, the D-28
 *      segments-left rule, the RFC 8754 §2.1 segment list bound and the TLV
 *      walk with Pad1, PadN and a TLV that overruns the SRH end
 *   3  the inner packet: version, declared length, the 01 §3.1 extension
 *      header budget, the duplicate Fragment header rule, and the 04 §4
 *      defence line (4) destination comparison — built both matching and
 *      not matching the endpoint address, so IP_MISMATCH is reached by
 *      construction
 */

#include "gen_common.h"

#define NH_HOPOPT 0
#define NH_TCP	  6
#define NH_UDP	  17
#define NH_IPV6	  41
#define NH_ROUTE  43
#define NH_FRAG	  44
#define NH_AH	  51
#define NH_DSTOPT 60

/* Defined by harness/fuzz_end_cilium_parser.c. */
extern const uint8_t *cilium_fuzz_endpoint_bytes (void);

/* Inner IPv6 header addressed to the endpoint, or deliberately not. */
static void
put_inner (gen_pkt_t *p, uint8_t nh, uint16_t plen, int to_endpoint)
{
  uint8_t *q = gen_ip6 (p, nh, plen);

  if (q == NULL)
    return;
  if (to_endpoint)
    memcpy (q + 24, cilium_fuzz_endpoint_bytes (), 16);
  else
    q[24] = 0x20;
}

void
cilium_fuzz_generate (int full)
{
  cilium_fuzz_rng_t rng;
  gen_pkt_t p;
  int to_ep, with_srh, i;
  unsigned seg, tlv, sl;
  unsigned long trial, n_random;

  /* 1. the well-formed shapes, with and without an SRH, addressed to the
     endpoint and not. */
  for (to_ep = 0; to_ep <= 1; to_ep++)
    for (with_srh = 0; with_srh <= 1; with_srh++)
      for (seg = 1; seg <= 3; seg++)
	for (tlv = 0; tlv <= 16; tlv += 8)
	  {
	    gen_reset (&p);
	    gen_ip6 (&p, with_srh ? NH_ROUTE : NH_IPV6, 0);
	    if (with_srh)
	      gen_srh (&p, NH_IPV6, (uint8_t) seg, 0, tlv, 4);
	    put_inner (&p, NH_TCP, 20, to_ep);
	    gen_tcp (&p, 1000, 80, 0x02);
	    gen_set_plen (&p, gen_true_plen (&p));
	    gen_sweep_plen (&p, full);
	  }

  /* 2. SRH variations that must be refused. */
  for (sl = 0; sl <= 2; sl++)
    for (i = 0; i < 4; i++)
      {
	static const uint8_t rtypes[4] = { 4, 0, 3, 255 };

	gen_reset (&p);
	gen_ip6 (&p, NH_ROUTE, 0);
	/* D-28: any non-zero Segments Left must be refused, because the SRH
	   is only removed at the end of the segment list. */
	gen_srh (&p, NH_IPV6, 2, (uint8_t) sl, 8, rtypes[i]);
	put_inner (&p, NH_TCP, 20, 1);
	gen_tcp (&p, 1000, 80, 0x02);
	gen_set_plen (&p, gen_true_plen (&p));
	gen_sweep_plen (&p, full);
      }

  /* An SRH whose Last Entry claims more segments than the header can hold,
     and one whose Next Header is not IPv6. */
  for (i = 0; i <= 1; i++)
    {
      uint8_t *srh;

      gen_reset (&p);
      gen_ip6 (&p, NH_ROUTE, 0);
      srh = gen_srh (&p, i ? NH_TCP : NH_IPV6, 1, 0, 8, 4);
      if (srh && i == 0)
	srh[4] = 15; /* Last Entry = 15 -> 256 octets of segment list */
      put_inner (&p, NH_TCP, 20, 1);
      gen_tcp (&p, 1000, 80, 0x02);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* TLV walk: Pad1 runs, a PadN that ends exactly on the SRH end, and a PadN
     whose declared length runs past it. */
  for (i = 0; i < 6; i++)
    {
      uint8_t *srh;

      gen_reset (&p);
      gen_ip6 (&p, NH_ROUTE, 0);
      srh = gen_srh (&p, NH_IPV6, 1, 0, 16, 4);
      if (srh)
	{
	  uint8_t *t = srh + 8 + 16;

	  memset (t, 0, 16);
	  switch (i)
	    {
	    case 0:
	      break; /* sixteen Pad1 */
	    case 1:
	      t[0] = 4;
	      t[1] = 14;
	      break; /* one exact PadN */
	    case 2:
	      t[0] = 4;
	      t[1] = 255;
	      break; /* PadN past the SRH end */
	    case 3:
	      t[0] = 4;
	      t[1] = 0;
	      t[2] = 4;
	      t[3] = 0;
	      t[4] = 4;
	      t[5] = 0;
	      t[6] = 4;
	      t[7] = 0;
	      t[8] = 4;
	      t[9] = 0;
	      t[10] = 4;
	      t[11] = 0;
	      t[12] = 4;
	      t[13] = 0;
	      t[14] = 4;
	      t[15] = 0;
	      break; /* eight TLVs: exactly the walk budget */
	    case 4:
	      memset (t, 0, 15);
	      t[15] = 1; /* a TLV with no room for its length octet */
	      break;
	    case 5:
	      t[0] = 128;
	      t[1] = 14;
	      break; /* HMAC-shaped TLV filling the space */
	    }
	}
      put_inner (&p, NH_TCP, 20, 1);
      gen_tcp (&p, 1000, 80, 0x02);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* 3. inner extension header chains. */
  for (to_ep = 0; to_ep <= 1; to_ep++)
    {
      /* Every extension header type the walk accepts. */
      static const uint8_t ehs[] = { NH_HOPOPT, NH_DSTOPT, 135, 139, 140 };
      size_t e;

      for (e = 0; e < sizeof (ehs) / sizeof (ehs[0]); e++)
	{
	  gen_reset (&p);
	  gen_ip6 (&p, NH_IPV6, 0);
	  put_inner (&p, ehs[e], 0, to_ep);
	  gen_eh (&p, NH_UDP, 1);
	  gen_udp (&p, 1000, 53);
	  p.b[40 + 4] = (uint8_t) ((p.len - 80) >> 8);
	  p.b[40 + 5] = (uint8_t) (p.len - 80);
	  gen_set_plen (&p, gen_true_plen (&p));
	  gen_sweep_plen (&p, full);
	}

      /* Authentication Header, whose length is in 4 octet units. */
      for (i = 0; i <= 3; i++)
	{
	  gen_reset (&p);
	  gen_ip6 (&p, NH_IPV6, 0);
	  put_inner (&p, NH_AH, 0, to_ep);
	  gen_ah (&p, NH_TCP, (uint8_t) i);
	  gen_tcp (&p, 1000, 80, 0x02);
	  p.b[40 + 4] = (uint8_t) ((p.len - 80) >> 8);
	  p.b[40 + 5] = (uint8_t) (p.len - 80);
	  gen_set_plen (&p, gen_true_plen (&p));
	  gen_sweep_plen (&p, full);
	}

      /* Fragment header, including the duplicate that 01 §3.1 refuses. */
      for (i = 0; i <= 3; i++)
	{
	  gen_reset (&p);
	  gen_ip6 (&p, NH_IPV6, 0);
	  put_inner (&p, NH_FRAG, 0, to_ep);
	  gen_frag (&p, (i & 2) ? NH_FRAG : NH_TCP, (i & 1) ? 5 : 0, 1, 0x99);
	  if (i & 2)
	    gen_frag (&p, NH_TCP, 0, 0, 0x99);
	  gen_tcp (&p, 1000, 80, 0x02);
	  p.b[40 + 4] = (uint8_t) ((p.len - 80) >> 8);
	  p.b[40 + 5] = (uint8_t) (p.len - 80);
	  gen_set_plen (&p, gen_true_plen (&p));
	  gen_sweep_plen (&p, full);
	}

      /* The 01 §3.1 header-count budget: nine Destination Options. */
      gen_reset (&p);
      gen_ip6 (&p, NH_IPV6, 0);
      put_inner (&p, NH_DSTOPT, 0, to_ep);
      for (i = 0; i < 9; i++)
	gen_eh (&p, i == 8 ? NH_TCP : NH_DSTOPT, 0);
      gen_tcp (&p, 1000, 80, 0x02);
      p.b[40 + 4] = (uint8_t) ((p.len - 80) >> 8);
      p.b[40 + 5] = (uint8_t) (p.len - 80);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);

      /* The 01 §3.1 byte budget: 280 octets of extension headers. */
      gen_reset (&p);
      gen_ip6 (&p, NH_IPV6, 0);
      put_inner (&p, NH_DSTOPT, 0, to_ep);
      gen_eh (&p, NH_DSTOPT, 16);
      gen_eh (&p, NH_TCP, 16);
      gen_tcp (&p, 1000, 80, 0x02);
      p.b[40 + 4] = (uint8_t) ((p.len - 80) >> 8);
      p.b[40 + 5] = (uint8_t) (p.len - 80);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* An outer Next Header that is neither Routing nor IPv6. */
  for (i = 0; i < 4; i++)
    {
      static const uint8_t nhs[4] = { NH_TCP, NH_FRAG, NH_DSTOPT, 255 };

      gen_reset (&p);
      gen_ip6 (&p, nhs[i], 0);
      put_inner (&p, NH_TCP, 20, 1);
      gen_set_plen (&p, gen_true_plen (&p));
      gen_sweep_plen (&p, full);
    }

  /* 4. single-octet corruption of a representative accepted packet. */
  gen_reset (&p);
  gen_ip6 (&p, NH_ROUTE, 0);
  gen_srh (&p, NH_IPV6, 2, 0, 8, 4);
  put_inner (&p, NH_TCP, 20, 1);
  gen_tcp (&p, 1000, 80, 0x02);
  gen_set_plen (&p, gen_true_plen (&p));
  gen_corrupt_all_octets (&p, full);

  /* 5. random octets and random corruption of an accepted packet. */
  cilium_fuzz_rng_init (&rng, 0x454e44434c4d5031ull);
  n_random = full ? 1500000ul : 100000ul;

  for (trial = 0; trial < n_random; trial++)
    {
      gen_pkt_t r;
      uint32_t len, j, n;

      /* half raw noise ... */
      len = cilium_fuzz_rnd (&rng) % 300;
      gen_reset (&r);
      r.len = len;
      for (j = 0; j < len; j++)
	r.b[j] = (uint8_t) cilium_fuzz_rnd (&rng);
      if (cilium_fuzz_rnd (&rng) & 1)
	r.b[0] = 0x60;
      cilium_fuzz_run_packet (r.b, r.len, 0, (uint8_t) (cilium_fuzz_rnd (&rng) % 41),
			      (uint16_t) (cilium_fuzz_rnd (&rng) % 256));

      /* ... half a valid packet with a few octets stirred, which keeps the
	 parser deep inside the SRH and the inner chain. */
      gen_reset (&r);
      gen_ip6 (&r, (cilium_fuzz_rnd (&rng) & 1) ? NH_ROUTE : NH_IPV6, 0);
      if (r.b[6] == NH_ROUTE)
	gen_srh (&r, NH_IPV6, (uint8_t) (1 + cilium_fuzz_rnd (&rng) % 3), 0,
		 (cilium_fuzz_rnd (&rng) % 3) * 8, 4);
      put_inner (&r, NH_TCP, 20, (int) (cilium_fuzz_rnd (&rng) & 1));
      gen_tcp (&r, 1000, 80, 0x02);
      gen_set_plen (&r, gen_true_plen (&r));
      n = 1 + cilium_fuzz_rnd (&rng) % 6;
      for (j = 0; j < n; j++)
	r.b[cilium_fuzz_rnd (&rng) % r.len] = (uint8_t) cilium_fuzz_rnd (&rng);
      cilium_fuzz_run_packet (r.b, r.len, 0, 0, 0);
      cilium_fuzz_run_packet (r.b, r.len, 0, (uint8_t) (cilium_fuzz_rnd (&rng) % 41), 64);
      cilium_fuzz_run_packet (r.b, r.len, 0x80, 0, (uint16_t) (cilium_fuzz_rnd (&rng) % 512));
    }
}
