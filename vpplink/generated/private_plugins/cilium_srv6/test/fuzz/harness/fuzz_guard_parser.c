/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Fuzz target: cilium_srv6_guard_scan_untrusted() (cilium_srv6_gparse.h).
 *
 * Responsibility of this target: the bounded header walk that decides what
 * an UNTRUSTED ingress packet is allowed to be (03 §1.1, D-9/D-31/D-32/D-54).
 * A crash here is a guard bug; it says nothing about the headend or the
 * destination parser, which have their own targets.
 *
 * The post-conditions are the ones PR #45 verified when D-54 was introduced,
 * moved here so that they are re-checked on every change rather than once:
 *
 *   P1  the verdict is a defined enum value
 *   P2  the verdict is deterministic
 *   P3  an independent byte-level reference model agrees. The model reads
 *       payload_length, n_data_u64s, the fragment offset and M straight out
 *       of the octet stream instead of through the VPP struct accessors, so
 *       a disagreement is a real difference and not a shared mistake about
 *       struct layout. It reads nothing outside [p, p + bound) either.
 *   P4  D-54: an offset-zero fragment with M=1 whose header chain is not
 *       complete inside that fragment yields DROP_UNINSPECTABLE_FRAGMENT and
 *       never any PASS
 *   P5  D-54: a Fragment header with offset != 0 yields
 *       PASS_NON_FIRST_FRAGMENT
 *   P6  with the hardening option on, PASS_NON_FIRST_FRAGMENT never occurs
 *       and a reachable Fragment header always yields
 *       DROP_FRAGMENT_NOT_PERMITTED
 *   P7  the D-54 counter split holds in both directions: an offset-zero M=1
 *       fragment never yields DROP_MALFORMED, and a packet that is not one
 *       never yields DROP_UNINSPECTABLE_FRAGMENT
 *
 * P4/P5/P7 are stated against a shape descriptor computed by a second,
 * separate walk, so they are not restatements of the verdict.
 */

#include "cilium_fuzz.h"

#include <cilium_srv6/cilium_srv6_gparse.h>

const char *const cilium_fuzz_target_name = "fuzz_guard_parser";

/* Indexed by cilium_srv6_guard_verdict_t. DROP_BLOCK_DA and DROP_QUARANTINED
   are decided by the caller (the outer destination lookup and the quarantine
   bit), not by this function, so they are listed for completeness and not
   required. */
const char *const cilium_fuzz_outcome_name[] = {
  "PASS",	       "PASS_NON_FIRST_FRAGMENT",	"DROP_BLOCK_DA",
  "DROP_ROUTING_HDR",  "DROP_INNER_BLOCK_DA",		"DROP_QUARANTINED",
  "DROP_MALFORMED",    "DROP_UNINSPECTABLE_FRAGMENT",	"DROP_FRAGMENT_NOT_PERMITTED",
  NULL
};

const unsigned char cilium_fuzz_outcome_required[] = { 1, 1, 0, 1, 1, 0, 1, 1, 1 };

/*
 * fdbb:bb00::/32, the SRV6_BLOCK placeholder of design/detail/00 §6. Fixed
 * rather than input-derived so that the reference model below is comparing
 * against the same configuration and a corpus file means the same thing on
 * every run.
 */
static u64 blk[2], msk[2];

static void
block_init (void)
{
  static const u8 a[16] = { 0xfd, 0xbb, 0xbb, 0x00 };

  memcpy (&blk[0], a, 8);
  memcpy (&blk[1], a + 8, 8);
  msk[0] = clib_host_to_net_u64 (0xffffffff00000000ull);
  msk[1] = 0;
  blk[0] &= msk[0];
  blk[1] &= msk[1];
}

/* ------------------------------------------------------------------ */
/* P3: byte-level reference model                                      */
/* ------------------------------------------------------------------ */

enum
{
  R_NONE = 0,
  R_ATOMIC,
  R_FIRST
};

static int
ref_fail (int fs)
{
  return fs == R_FIRST ? CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT :
			 CILIUM_SRV6_GUARD_DROP_MALFORMED;
}

static int
ref_in_block (const u8 *a)
{
  u64 x0, x1;
  memcpy (&x0, a, 8);
  memcpy (&x1, a + 8, 8);
  return (((x0 ^ blk[0]) & msk[0]) | ((x1 ^ blk[1]) & msk[1])) == 0;
}

static int
ref_is_eh (u8 nh)
{
  return nh == 0 || nh == 60 || nh == 135 || nh == 139 || nh == 140 || nh == 51;
}

static int
ref_scan (const u8 *p, unsigned avail, int drop_all)
{
  unsigned plen, bound, off = 40, eh_bytes = 0;
  unsigned long declared;
  int fs = R_NONE, i;
  u8 nh;

  plen = ((unsigned) p[4] << 8) | p[5];
  declared = 40ul + plen;
  bound = avail;
  if (declared < (unsigned long) bound)
    bound = (unsigned) declared;
  nh = p[6];

  for (i = 0; i < 8; i++)
    {
      unsigned hlen;

      if (nh == 43)
	return CILIUM_SRV6_GUARD_DROP_ROUTING_HDR;

      if (nh == 41)
	{
	  if (off + 40 > bound)
	    return ref_fail (fs);
	  if ((p[off] >> 4) != 6)
	    return ref_fail (fs);
	  if (ref_in_block (p + off + 24))
	    return CILIUM_SRV6_GUARD_DROP_INNER_BLOCK_DA;
	  return CILIUM_SRV6_GUARD_PASS;
	}

      if (ref_is_eh (nh))
	{
	  if (off + 2 > bound)
	    return ref_fail (fs);
	  hlen =
	    (nh == 51) ? (((unsigned) p[off + 1] + 2) << 2) : (((unsigned) p[off + 1] + 1) << 3);
	  if (hlen < 2 || off + hlen > bound)
	    return ref_fail (fs);
	  eh_bytes += hlen;
	  if (eh_bytes > 256)
	    return ref_fail (fs);
	  nh = p[off];
	  off += hlen;
	  continue;
	}

      if (nh == 44)
	{
	  unsigned fo;
	  int more;

	  if (drop_all)
	    return CILIUM_SRV6_GUARD_DROP_FRAGMENT_NOT_PERMITTED;
	  if (off + 8 > bound)
	    return ref_fail (fs);
	  if (fs != R_NONE)
	    return ref_fail (fs);
	  eh_bytes += 8;
	  if (eh_bytes > 256)
	    return ref_fail (fs);

	  fo = ((((unsigned) p[off + 2] << 8) | p[off + 3]) >> 3);
	  more = p[off + 3] & 1;
	  if (fo != 0)
	    return CILIUM_SRV6_GUARD_PASS_NON_FIRST_FRAGMENT;
	  fs = more ? R_FIRST : R_ATOMIC;
	  nh = p[off];
	  off += 8;
	  continue;
	}

      /* Upper layer header: RFC 8200 ends the header chain here. */
      if (fs == R_FIRST && off >= bound)
	return CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT;
      return CILIUM_SRV6_GUARD_PASS;
    }

  return ref_fail (fs);
}

/*
 * What kind of fragment does the chain reach, and does the chain terminate
 * inside the readable area? Computed by its own walk so that P4/P5/P7 are
 * checks and not tautologies.
 */
typedef struct
{
  int reaches_frag;   /* a Fragment header is reached by the walk */
  int frag_non_first; /* ... with offset != 0 */
  int frag_first;     /* ... with offset 0 and M=1 */
  int chain_complete; /* the chain terminates strictly inside bound */
  int routing_first;  /* a Routing header is reached before any of that */
} shape_t;

static void
ref_shape (const u8 *p, unsigned avail, shape_t *s)
{
  unsigned plen, bound, off = 40, eh_bytes = 0;
  unsigned long declared;
  int seen = 0, i;
  u8 nh;

  memset (s, 0, sizeof (*s));

  plen = ((unsigned) p[4] << 8) | p[5];
  declared = 40ul + plen;
  bound = avail;
  if (declared < (unsigned long) bound)
    bound = (unsigned) declared;
  nh = p[6];

  for (i = 0; i < 8; i++)
    {
      unsigned hlen;

      if (nh == 43)
	{
	  s->routing_first = 1;
	  return;
	}
      if (nh == 41)
	{
	  s->chain_complete = (off + 40 <= bound);
	  return;
	}
      if (ref_is_eh (nh))
	{
	  if (off + 2 > bound)
	    return;
	  hlen =
	    (nh == 51) ? (((unsigned) p[off + 1] + 2) << 2) : (((unsigned) p[off + 1] + 1) << 3);
	  if (hlen < 2 || off + hlen > bound)
	    return;
	  eh_bytes += hlen;
	  if (eh_bytes > 256)
	    return;
	  nh = p[off];
	  off += hlen;
	  continue;
	}
      if (nh == 44)
	{
	  unsigned fo;

	  if (off + 8 > bound || seen)
	    return;
	  eh_bytes += 8;
	  if (eh_bytes > 256)
	    return;
	  seen = 1;
	  s->reaches_frag = 1;
	  fo = ((((unsigned) p[off + 2] << 8) | p[off + 3]) >> 3);
	  if (fo != 0)
	    {
	      s->frag_non_first = 1;
	      return;
	    }
	  s->frag_first = (p[off + 3] & 1) != 0;
	  nh = p[off];
	  off += 8;
	  continue;
	}
      /* Upper layer header: the chain ends here and must start inside bound. */
      s->chain_complete = (off < bound);
      return;
    }
}

/* ------------------------------------------------------------------ */

void
cilium_fuzz_one (const uint8_t *data, size_t size)
{
  static int inited;
  cilium_fuzz_input_t in;
  shape_t sh;
  int v0, v0b, v1, r0, r1;

  if (!inited)
    {
      block_init ();
      inited = 1;
    }

  if (!cilium_fuzz_input_decode (data, size, &in))
    return;

  /* Contract of cilium_srv6_guard_scan_untrusted(): the caller has already
     read the outer header, so the outer 40 octets are readable. Inputs that
     do not satisfy it describe a caller bug, not a parser bug. */
  if (in.avail < sizeof (ip6_header_t))
    {
      cilium_fuzz_input_free (&in);
      return;
    }

  v0 = (int) cilium_srv6_guard_scan_untrusted (blk, msk, 0, (const ip6_header_t *) in.pkt,
					       in.avail);
  v0b = (int) cilium_srv6_guard_scan_untrusted (blk, msk, 0, (const ip6_header_t *) in.pkt,
						in.avail);
  v1 = (int) cilium_srv6_guard_scan_untrusted (blk, msk, 1, (const ip6_header_t *) in.pkt,
					       in.avail);
  r0 = ref_scan (in.pkt, in.avail, 0);
  r1 = ref_scan (in.pkt, in.avail, 1);
  ref_shape (in.pkt, in.avail, &sh);

  /* P1 */
  CILIUM_FUZZ_ASSERT (v0 >= 0 && v0 < CILIUM_SRV6_GUARD_N_VERDICT, "v0=%d avail=%u", v0, in.avail);
  CILIUM_FUZZ_ASSERT (v1 >= 0 && v1 < CILIUM_SRV6_GUARD_N_VERDICT, "v1=%d avail=%u", v1, in.avail);
  /* P2 */
  CILIUM_FUZZ_ASSERT (v0 == v0b, "non-deterministic verdict %d vs %d", v0, v0b);
  /* P3 */
  CILIUM_FUZZ_ASSERT (v0 == r0, "parser=%d reference=%d avail=%u", v0, r0, in.avail);
  CILIUM_FUZZ_ASSERT (v1 == r1, "hardened parser=%d reference=%d avail=%u", v1, r1, in.avail);

  /* P4. A Routing header anywhere in the chain is an unconditional drop that
     does not depend on the header being readable, so it wins over the
     inspectability rule; it is still a drop. */
  if (sh.routing_first)
    CILIUM_FUZZ_ASSERT (v0 == CILIUM_SRV6_GUARD_DROP_ROUTING_HDR, "v0=%d", v0);
  else if (sh.frag_first && !sh.chain_complete)
    {
      CILIUM_FUZZ_ASSERT (v0 == CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT, "v0=%d", v0);
      CILIUM_FUZZ_ASSERT (v0 != CILIUM_SRV6_GUARD_PASS, "v0=%d", v0);
      CILIUM_FUZZ_ASSERT (v0 != CILIUM_SRV6_GUARD_PASS_NON_FIRST_FRAGMENT, "v0=%d", v0);
    }
  /* P5 */
  if (sh.frag_non_first)
    CILIUM_FUZZ_ASSERT (v0 == CILIUM_SRV6_GUARD_PASS_NON_FIRST_FRAGMENT, "v0=%d", v0);
  /* P6 */
  CILIUM_FUZZ_ASSERT (v1 != CILIUM_SRV6_GUARD_PASS_NON_FIRST_FRAGMENT, "v1=%d", v1);
  if (sh.reaches_frag && !sh.routing_first)
    CILIUM_FUZZ_ASSERT (v1 == CILIUM_SRV6_GUARD_DROP_FRAGMENT_NOT_PERMITTED, "v1=%d", v1);
  /* P7 */
  if (!sh.frag_first)
    CILIUM_FUZZ_ASSERT (v0 != CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT, "v0=%d", v0);
  if (sh.frag_first)
    CILIUM_FUZZ_ASSERT (v0 != CILIUM_SRV6_GUARD_DROP_MALFORMED, "v0=%d", v0);

  cilium_fuzz_record ((unsigned) v0);
  if (v1 == CILIUM_SRV6_GUARD_DROP_FRAGMENT_NOT_PERMITTED)
    cilium_fuzz_mark (CILIUM_SRV6_GUARD_DROP_FRAGMENT_NOT_PERMITTED);

  cilium_fuzz_input_free (&in);
}
