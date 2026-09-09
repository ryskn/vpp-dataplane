/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Fuzz target: cilium_srv6_pmtud_parse_ptb(), cilium_srv6_pmtud_da_match(),
 * cilium_srv6_pmtud_csid_shift() and cilium_srv6_pmtud_mtu_eval()
 * (cilium_srv6_pmtud_parse.h).
 *
 * Responsibility of this target: everything about a received ICMPv6 Packet
 * Too Big that is a pure function of the octets and of the immutable half of
 * a PathCache entry (02 §9). The three checks that actually make a PTB
 * trustworthy — TRUSTED_FABRIC ingress, source in the SR domain node set,
 * and a matching RecentTx record — live in cilium_srv6_pmtud_node.c and are
 * deliberately out of scope here, so a PASS from this parser is not an
 * "accept": it is only "these octets are a syntactically usable PTB".
 *
 * Post-conditions, from the PTB validation work of PR #37 plus the D-21
 * arithmetic rules of 02 §9:
 *
 *   P1  the parse result is a defined enum value and is deterministic
 *   P2  a non-OK parse never reports an inner header, so a caller that
 *       branches only on has_inner cannot read fields the parser did not
 *       validate
 *   P3  on OK with has_srh the reported SRH window lies inside the readable
 *       area, is at least the 8 octet fixed part, and is a multiple of 8
 *   P4  on OK the quoted outer size is a possible IPv6 packet size
 *   P5  D-21 / 02 §9: mtu_eval never underflows. A non-OK verdict leaves the
 *       inner MTU at 0; an OK verdict yields exactly ptb_mtu - overhead, at
 *       least the RFC 8200 minimum of 1280 and inside u16 — the property the
 *       design calls out as "u16 underflow を起こさない"
 *   P6  da_match is reflexive on the transmitted destination address and
 *       deterministic, and any match it reports carries a state index inside
 *       the declared bounds
 *   P7  csid_shift produces the same result whether or not its arguments
 *       alias, which is what its contract promises the caller
 *
 * The PathCache shape fed to P6 is derived from the input and placed in its
 * own exact-size heap block, so a walk that runs off the end of the segment
 * list or of the shift-state array is an ASan failure and not a read of the
 * next struct field.
 */

#include "cilium_fuzz.h"

#include <cilium_srv6/cilium_srv6_pmtud_parse.h>

const char *const cilium_fuzz_target_name = "fuzz_pmtud_parser";

enum
{
  OUT_PARSE_OK = 0,
  OUT_PARSE_NOT_PTB,
  OUT_PARSE_MALFORMED,
  OUT_OK_WITH_SRH,
  OUT_OK_WITH_INNER,
  OUT_MTU_OK,
  OUT_MTU_OUT_OF_RANGE,
  OUT_MTU_PATH_UNUSABLE,
  OUT_DA_MATCH_DERIVED,
};

const char *const cilium_fuzz_outcome_name[] = {
  "PARSE_OK",	  "PARSE_NOT_PTB",     "PARSE_MALFORMED",     "OK_WITH_SRH",	  "OK_WITH_INNER",
  "MTU_OK",	  "MTU_OUT_OF_RANGE",  "MTU_PATH_UNUSABLE",  "DA_MATCH_DERIVED", NULL
};

const unsigned char cilium_fuzz_outcome_required[] = { 1, 1, 1, 1, 1, 1, 1, 1, 1 };

/* ------------------------------------------------------------------ */

static u32
fnv32 (const uint8_t *p, size_t n)
{
  u32 h = 2166136261u;
  size_t i;

  for (i = 0; i < n; i++)
    {
      h ^= p[i];
      h *= 16777619u;
    }
  return h;
}

/* Fill `dst` from the input, wrapping, so that the material is a function of
   the corpus file and a corpus file therefore reproduces exactly. */
static void
fill_from (u8 *dst, size_t n, const uint8_t *src, size_t src_n, size_t start)
{
  size_t i;

  for (i = 0; i < n; i++)
    dst[i] = src_n ? src[(start + i) % src_n] : 0;
}

static void
check_mtu (u32 ptb_mtu, u32 recorded, u32 overhead)
{
  u16 inner = 0xffff;
  cilium_srv6_pmtud_mtu_result_t m = cilium_srv6_pmtud_mtu_eval (ptb_mtu, recorded, overhead,
								 &inner);

  switch (m)
    {
    case CILIUM_SRV6_PMTUD_MTU_OK:
      CILIUM_FUZZ_ASSERT (inner >= CILIUM_SRV6_PMTUD_MIN_MTU, "inner_mtu=%u below 1280", inner);
      CILIUM_FUZZ_ASSERT (ptb_mtu >= CILIUM_SRV6_PMTUD_MIN_MTU && ptb_mtu <= 0xffff,
			  "ptb_mtu=%u accepted", ptb_mtu);
      CILIUM_FUZZ_ASSERT (ptb_mtu < recorded, "ptb_mtu=%u recorded=%u", ptb_mtu, recorded);
      CILIUM_FUZZ_ASSERT (overhead < ptb_mtu, "overhead=%u ptb_mtu=%u", overhead, ptb_mtu);
      CILIUM_FUZZ_ASSERT ((u32) inner == ptb_mtu - overhead, "inner=%u ptb=%u overhead=%u", inner,
			  ptb_mtu, overhead);
      cilium_fuzz_mark (OUT_MTU_OK);
      break;

    case CILIUM_SRV6_PMTUD_MTU_OUT_OF_RANGE:
      CILIUM_FUZZ_ASSERT (inner == 0, "out-of-range left inner_mtu=%u", inner);
      cilium_fuzz_mark (OUT_MTU_OUT_OF_RANGE);
      break;

    case CILIUM_SRV6_PMTUD_MTU_PATH_UNUSABLE:
      CILIUM_FUZZ_ASSERT (inner == 0, "unusable path left inner_mtu=%u", inner);
      /* The design fails this path closed rather than clamping, so the
	 subtraction must have been in range even though the result is not
	 usable. */
      CILIUM_FUZZ_ASSERT (overhead < ptb_mtu && ptb_mtu - overhead < CILIUM_SRV6_PMTUD_MIN_MTU,
			  "ptb=%u overhead=%u", ptb_mtu, overhead);
      cilium_fuzz_mark (OUT_MTU_PATH_UNUSABLE);
      break;

    default:
      CILIUM_FUZZ_ASSERT (0, "undefined mtu_eval result %d", (int) m);
    }
}

static void
check_da_match (const uint8_t *raw, size_t raw_size, const cilium_srv6_pmtud_ptb_t *ptb, u32 h)
{
  cilium_srv6_pmtud_path_shape_t *s;
  ip6_address_t probe, a, b, c;
  u32 st = 0xffffffff, st2 = 0xffffffff;
  int m, m2, i;

  /* Exact-size block: an over-read of shift_states[] or srh[] lands in ASan
     redzone rather than in the next field. */
  s = (cilium_srv6_pmtud_path_shape_t *) malloc (sizeof (*s));
  if (s == NULL)
    abort ();
  memset (s, 0, sizeof (*s));

  fill_from (s->da_template.as_u8, 16, raw, raw_size, 0);
  fill_from (s->service_sid.as_u8, 16, raw, raw_size, 7);
  for (i = 0; i < CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES; i++)
    fill_from (s->shift_states[i].as_u8, 16, raw, raw_size, (size_t) (3 + 5 * i));

  /* Deliberately allowed to exceed the array bound and the template bound:
     the function has to clamp both, and the exact-size block makes a failure
     to clamp observable. */
  s->n_shift_states = (u8) (h % (CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES + 3));
  s->srh_len = (u8) ((h >> 8) & 0xff);
  fill_from (s->srh, sizeof (s->srh), raw, raw_size, 11);

  /* P6: reflexive on the address as transmitted, and that is source 1, so
     the reported state is 0. */
  m = cilium_srv6_pmtud_da_match (s, &s->da_template, &st);
  CILIUM_FUZZ_ASSERT (m == 1 && st == 0, "da_match is not reflexive: m=%d st=%u", m, st);

  fill_from (probe.as_u8, 16, raw, raw_size, 2);
  m = cilium_srv6_pmtud_da_match (s, &probe, &st);
  m2 = cilium_srv6_pmtud_da_match (s, &probe, &st2);
  CILIUM_FUZZ_ASSERT (m == m2 && st == st2, "da_match is not deterministic");
  CILIUM_FUZZ_ASSERT (m == 0 || m == 1, "da_match returned %d", m);
  if (m)
    {
      CILIUM_FUZZ_ASSERT (st <= CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES +
			       CILIUM_SRV6_PMTUD_MAX_SEGMENTS,
			  "state index %u out of range", st);
      cilium_fuzz_mark (OUT_DA_MATCH_DERIVED);
    }

  /* The address a transit node actually quoted has to go through the same
     matcher, since that is how it is used in 02 §9. */
  (void) cilium_srv6_pmtud_da_match (s, &ptb->quoted_dst, NULL);

  /* P7: the contract says `in` and `out` may alias. */
  a = s->da_template;
  cilium_srv6_pmtud_csid_shift (&a, &b);
  c = a;
  cilium_srv6_pmtud_csid_shift (&c, &c);
  CILIUM_FUZZ_ASSERT (memcmp (b.as_u8, c.as_u8, 16) == 0,
		      "csid_shift differs when its arguments alias");

  free (s);
}

void
cilium_fuzz_one (const uint8_t *data, size_t size)
{
  cilium_fuzz_input_t in;
  cilium_srv6_pmtud_ptb_t r, r2;
  cilium_srv6_pmtud_parse_result_t res, res2;
  u32 h, overhead;

  if (!cilium_fuzz_input_decode (data, size, &in))
    return;

  memset (&r, 0xa5, sizeof (r));
  memset (&r2, 0x5a, sizeof (r2));

  res = cilium_srv6_pmtud_parse_ptb (in.pkt, in.avail, in.chain_len, &r);
  res2 = cilium_srv6_pmtud_parse_ptb (in.pkt, in.avail, in.chain_len, &r2);

  /* P1. The parser memsets the whole result at entry, so here the memcmp is
     over every octet including the padding. */
  CILIUM_FUZZ_ASSERT (res == CILIUM_SRV6_PMTUD_PARSE_OK || res == CILIUM_SRV6_PMTUD_PARSE_NOT_PTB ||
			res == CILIUM_SRV6_PMTUD_PARSE_MALFORMED,
		      "result=%d", (int) res);
  CILIUM_FUZZ_ASSERT (res == res2 && memcmp (&r, &r2, sizeof (r)) == 0,
		      "non-deterministic PTB parse");

  /* P2 */
  if (res != CILIUM_SRV6_PMTUD_PARSE_OK)
    CILIUM_FUZZ_ASSERT (r.has_inner == 0, "non-OK parse reported an inner header");

  if (res == CILIUM_SRV6_PMTUD_PARSE_OK)
    {
      CILIUM_FUZZ_ASSERT (r.has_srh <= 1 && r.has_inner <= 1, "has_srh=%u has_inner=%u", r.has_srh,
			  r.has_inner);

      /* P3 */
      if (r.has_srh)
	{
	  CILIUM_FUZZ_ASSERT (r.srh_len >= 8 && (r.srh_len % 8) == 0, "srh_len=%u", r.srh_len);
	  CILIUM_FUZZ_ASSERT (r.srh_off >= (u32) sizeof (ip6_header_t) +
					     CILIUM_SRV6_PMTUD_ICMP_LEN +
					     (u32) sizeof (ip6_header_t),
			      "srh_off=%u before the quoted header", r.srh_off);
	  CILIUM_FUZZ_ASSERT ((u64) r.srh_off + r.srh_len <= (u64) in.avail,
			      "srh window %u+%u past avail=%u", r.srh_off, r.srh_len, in.avail);
	  CILIUM_FUZZ_ASSERT (in.pkt[r.srh_off + 2] == ROUTING_HEADER_TYPE_SR,
			      "accepted routing type %u", in.pkt[r.srh_off + 2]);
	  cilium_fuzz_mark (OUT_OK_WITH_SRH);
	}

      /* P4 */
      CILIUM_FUZZ_ASSERT (r.quoted_outer_size >= sizeof (ip6_header_t) &&
			    r.quoted_outer_size <= (u32) sizeof (ip6_header_t) + 0xffff,
			  "quoted_outer_size=%u", r.quoted_outer_size);

      if (r.has_inner)
	cilium_fuzz_mark (OUT_OK_WITH_INNER);
    }

  cilium_fuzz_record ((unsigned) res);

  /* ---------------------------------------------------------------- */
  /* P5: the MTU arithmetic, driven both from the parsed PTB and from
     input-derived values, so that all three verdicts stay reachable. */

  h = fnv32 (in.raw, in.raw_size);
  overhead = 40 + 8 * (1 + (h % 9)); /* 48..112: an SRv6 encapsulation */

  check_mtu (r.ptb_mtu, r.quoted_outer_size, overhead);
  check_mtu (h, (h >> 8) & 0xffff, h & 0xff);
  check_mtu (CILIUM_SRV6_PMTUD_MIN_MTU + (h % 200), 1500, 40 + (h % 137));
  /* Pinned tuple, so that MTU_OK does not depend on the corpus reaching it by
     chance: 1280 - 0 is exactly the RFC 8200 minimum. */
  check_mtu (CILIUM_SRV6_PMTUD_MIN_MTU, CILIUM_SRV6_PMTUD_MIN_MTU + 1, 0);
  /* Pinned tuple for the boundary the design calls out: one octet of
     overhead below the minimum must be refused, not wrapped. */
  check_mtu (CILIUM_SRV6_PMTUD_MIN_MTU, CILIUM_SRV6_PMTUD_MIN_MTU + 1, 1);
  /* Pinned tuples where the overhead exceeds the reported MTU. Nothing a
     validated SRH template can produce, which is exactly why they have to be
     driven deliberately: this is the only shape in which the subtraction of
     02 §9 would wrap, so without them the D-21 guard is never exercised and
     removing it would go unnoticed. */
  check_mtu (CILIUM_SRV6_PMTUD_MIN_MTU, 60000, 2000);
  check_mtu (CILIUM_SRV6_PMTUD_MIN_MTU + (h % 200), 0xffff, 1300 + (h % 3000));

  /* ---------------------------------------------------------------- */
  /* P6, P7 */
  check_da_match (in.raw, in.raw_size, &r, h);

  cilium_fuzz_input_free (&in);
}
