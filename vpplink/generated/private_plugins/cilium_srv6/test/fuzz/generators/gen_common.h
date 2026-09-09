/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Packet construction and sweep helpers shared by the four deterministic
 * generators.
 *
 * Why generators exist at all (Issue #67, 決定文):
 *
 *   "#56 の 379k 入力のような決定的に組合せ生成できる matrix は、379k
 *    ファイルを Git に置かず generator として収載し、毎回生成して走らせる
 *    (生成規則が deterministic ならそれ自体が deterministic corpus)"
 *
 * So nothing in here may depend on the clock, the host, the environment or
 * an unseeded RNG. The only randomness is cilium_fuzz_rnd(), a xorshift with
 * a literal seed, which produces the same sequence everywhere.
 *
 * Two levels:
 *
 *   level 0  the PR gate. Structural shapes, every truncation of the short
 *            ones, single-octet corruption, and a bounded random tail.
 *   level 1  the nightly gate. The same shapes with the full truncation and
 *            declared-length sweeps and a much longer random tail — the
 *            379k-class matrix.
 */

#ifndef __included_cilium_fuzz_gen_common_h__
#define __included_cilium_fuzz_gen_common_h__

#include "../harness/cilium_fuzz.h"

#define GEN_MAX_PKT 1600

typedef struct
{
  uint8_t b[GEN_MAX_PKT];
  uint32_t len;
} gen_pkt_t;

static inline void
gen_reset (gen_pkt_t *p)
{
  memset (p, 0, sizeof (*p));
}

static inline uint8_t *
gen_alloc (gen_pkt_t *p, uint32_t n)
{
  uint8_t *q;

  if (p->len + n > GEN_MAX_PKT)
    return NULL;
  q = p->b + p->len;
  p->len += n;
  return q;
}

/* Outer or inner IPv6 header. `plen` is written verbatim, so a generator can
   declare a length the packet does not have. */
static inline uint8_t *
gen_ip6 (gen_pkt_t *p, uint8_t nh, uint16_t plen)
{
  uint8_t *q = gen_alloc (p, 40);

  if (q == NULL)
    return NULL;
  memset (q, 0, 40);
  q[0] = 0x60;
  q[4] = (uint8_t) (plen >> 8);
  q[5] = (uint8_t) plen;
  q[6] = nh;
  q[7] = 64;
  return q;
}

/* Hop-by-hop / Destination Options / Mobility / HIP / Shim6 shaped header:
   (n_data_u64s + 1) * 8 octets. */
static inline uint8_t *
gen_eh (gen_pkt_t *p, uint8_t nh, uint8_t n_data_u64s)
{
  uint32_t n = ((uint32_t) n_data_u64s + 1) * 8;
  uint8_t *q = gen_alloc (p, n);

  if (q == NULL)
    return NULL;
  memset (q, 0, n);
  q[0] = nh;
  q[1] = n_data_u64s;
  return q;
}

/* Authentication Header: (n_data_u64s + 2) * 4 octets. */
static inline uint8_t *
gen_ah (gen_pkt_t *p, uint8_t nh, uint8_t n_data_u64s)
{
  uint32_t n = ((uint32_t) n_data_u64s + 2) * 4;
  uint8_t *q = gen_alloc (p, n);

  if (q == NULL)
    return NULL;
  memset (q, 0, n);
  q[0] = nh;
  q[1] = n_data_u64s;
  return q;
}

static inline uint8_t *
gen_frag (gen_pkt_t *p, uint8_t nh, uint16_t offset, int more, uint32_t id)
{
  uint16_t v = (uint16_t) ((offset << 3) | (more ? 1 : 0));
  uint8_t *q = gen_alloc (p, 8);

  if (q == NULL)
    return NULL;
  q[0] = nh;
  q[1] = 0;
  q[2] = (uint8_t) (v >> 8);
  q[3] = (uint8_t) v;
  q[4] = (uint8_t) (id >> 24);
  q[5] = (uint8_t) (id >> 16);
  q[6] = (uint8_t) (id >> 8);
  q[7] = (uint8_t) id;
  return q;
}

/*
 * RFC 8754 Segment Routing Header. `tlv_bytes` octets of TLV space are filled
 * with a single PadN so that the walk terminates exactly on the SRH end,
 * which is what cilium_srv6_srh_ok() requires.
 */
static inline uint8_t *
gen_srh (gen_pkt_t *p, uint8_t nh, uint8_t n_seg, uint8_t segments_left, uint32_t tlv_bytes,
	 uint8_t routing_type)
{
  uint32_t n = 8u + 16u * n_seg + tlv_bytes;
  uint8_t *q;

  if ((n % 8) != 0)
    return NULL;
  q = gen_alloc (p, n);
  if (q == NULL)
    return NULL;
  memset (q, 0, n);
  q[0] = nh;
  q[1] = (uint8_t) (n / 8 - 1);
  q[2] = routing_type;
  q[3] = segments_left;
  q[4] = (uint8_t) (n_seg ? n_seg - 1 : 0);

  if (tlv_bytes >= 2)
    {
      uint8_t *t = q + 8 + 16 * n_seg;
      t[0] = 4; /* PadN */
      t[1] = (uint8_t) (tlv_bytes - 2);
    }
  return q;
}

static inline void
gen_tcp (gen_pkt_t *p, uint16_t sport, uint16_t dport, uint8_t flags)
{
  uint8_t *q = gen_alloc (p, 20);

  if (q == NULL)
    return;
  memset (q, 0, 20);
  q[0] = (uint8_t) (sport >> 8);
  q[1] = (uint8_t) sport;
  q[2] = (uint8_t) (dport >> 8);
  q[3] = (uint8_t) dport;
  q[12] = 0x50;
  q[13] = flags;
}

static inline void
gen_udp (gen_pkt_t *p, uint16_t sport, uint16_t dport)
{
  uint8_t *q = gen_alloc (p, 8);

  if (q == NULL)
    return;
  memset (q, 0, 8);
  q[0] = (uint8_t) (sport >> 8);
  q[1] = (uint8_t) sport;
  q[2] = (uint8_t) (dport >> 8);
  q[3] = (uint8_t) dport;
}

static inline void
gen_icmp6 (gen_pkt_t *p, uint8_t type, uint8_t code)
{
  uint8_t *q = gen_alloc (p, 8);

  if (q == NULL)
    return;
  memset (q, 0, 8);
  q[0] = type;
  q[1] = code;
}

/* Rewrite the outer declared payload length after the packet is complete. */
static inline void
gen_set_plen (gen_pkt_t *p, uint16_t plen)
{
  if (p->len < 6)
    return;
  p->b[4] = (uint8_t) (plen >> 8);
  p->b[5] = (uint8_t) plen;
}

/* The honest declared length for a fully built packet. */
static inline uint16_t
gen_true_plen (const gen_pkt_t *p)
{
  return (uint16_t) (p->len > 40 ? p->len - 40 : 0);
}

/*
 * Run one packet through the framings that make the three inputs disagree.
 *
 * level 0 keeps a fixed, small set. level 1 sweeps every truncation point,
 * which is what turns a handful of shapes into a matrix of hundreds of
 * thousands of runs.
 */
static inline void
gen_sweep (const gen_pkt_t *p, int level)
{
  static const uint8_t cuts0[] = { 0, 1, 2, 8, 20, 40 };
  static const uint16_t extra0[] = { 0, 64 };
  uint32_t cut;
  size_t i, j;

  if (p->len == 0)
    return;

  for (i = 0; i < sizeof (extra0) / sizeof (extra0[0]); i++)
    {
      if (level == 0)
	{
	  for (j = 0; j < sizeof (cuts0) / sizeof (cuts0[0]); j++)
	    cilium_fuzz_run_packet (p->b, p->len, 0, cuts0[j], extra0[i]);
	}
      else
	{
	  for (cut = 0; cut <= p->len && cut <= 255; cut++)
	    cilium_fuzz_run_packet (p->b, p->len, 0, (uint8_t) cut, extra0[i]);
	}
    }

  /* chain_len below avail, which no caller may turn into a read. */
  cilium_fuzz_run_packet (p->b, p->len, 0x80, 0, 0);
  cilium_fuzz_run_packet (p->b, p->len, 0x80, 0, 40);
  cilium_fuzz_run_packet (p->b, p->len, 0x80, 0, (uint16_t) (p->len > 40 ? p->len - 1 : 0));
  cilium_fuzz_run_packet (p->b, p->len, 0x80, 0, 0xffff);
}

/*
 * The declared-length sweep: the same octets with every plausible lie about
 * how long the packet claims to be. This is where a parser that trusts
 * payload_length instead of min(avail, declared) is caught.
 */
static inline void
gen_sweep_plen (gen_pkt_t *p, int level)
{
  uint32_t l;
  uint16_t saved;

  if (p->len < 40)
    return;
  saved = (uint16_t) ((p->b[4] << 8) | p->b[5]);

  gen_sweep (p, level);

  if (level == 0)
    {
      static const uint16_t plens[] = { 0, 1, 7, 8, 40, 0xffff };
      size_t i;

      for (i = 0; i < sizeof (plens) / sizeof (plens[0]); i++)
	{
	  gen_set_plen (p, plens[i]);
	  gen_sweep (p, 0);
	}
      gen_set_plen (p, (uint16_t) (gen_true_plen (p) + 8));
      gen_sweep (p, 0);
    }
  else
    {
      for (l = 0; l + 40 <= (uint32_t) p->len + 16; l++)
	{
	  gen_set_plen (p, (uint16_t) l);
	  gen_sweep (p, 0);
	}
    }

  gen_set_plen (p, saved);
}

/* Single-octet corruption of every offset of one packet. */
static inline void
gen_corrupt_all_octets (const gen_pkt_t *p, int level)
{
  gen_pkt_t m;
  uint32_t off;
  unsigned v;
  unsigned step = level ? 1 : 17;

  for (off = 0; off < p->len; off++)
    for (v = 0; v < 256; v += step)
      {
	m = *p;
	m.b[off] = (uint8_t) v;
	cilium_fuzz_run_packet (m.b, m.len, 0, 0, 0);
	cilium_fuzz_run_packet (m.b, m.len, 0, 8, 64);
	if (level)
	  cilium_fuzz_run_packet (m.b, m.len, 0x80, 0, 40);
      }
}

#endif /* __included_cilium_fuzz_gen_common_h__ */
