/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Fuzz target: cilium_srv6_hparse() and cilium_srv6_hparse_l4()
 * (cilium_srv6_hparse.h).
 *
 * Responsibility of this target: the headend classifier's bounded walk over
 * the packet a Pod sent (02 §3, 01 §3.1). Its output is not a verdict but a
 * key: `proto` and `l4_discriminator` form the ProgramCache key (D-41), and
 * `frag_id` with `frag_next_header` form the FragmentVerdictCache key (D-43).
 * A crash here is a headend bug; a *wrong* key here is a policy-evaluation
 * bug, which is why the post-conditions below are mostly about the key and
 * not only about memory safety.
 *
 * Post-conditions, moved from the deterministic matrix run of PR #56:
 *
 *   P1  the result is a defined enum value
 *   P2  every named field of the result is identical across two runs whose
 *       destination structs were pre-filled with different values, so a
 *       field the parser fails to write is visible as non-determinism.
 *
 *       The comparison is field by field rather than a memcmp of the whole
 *       struct: cilium_srv6_hparse_t has a two octet alignment hole between
 *       l4_discriminator and frag_id that cilium_srv6_hparse() does not
 *       write. That is harmless as the struct is used today — the headend
 *       copies named fields into the ProgramCache and FragmentVerdictCache
 *       keys and never hashes the struct as raw octets — but it does mean
 *       "the struct is deterministic" is only true of its fields.
 *   P3  on OK the declared padding fields are zero, which is what makes the
 *       key components the headend does copy out well defined
 *   P4  on OK frag_kind is one of the four defined values
 *   P5  D-43: a non-first fragment has no upper-layer header, so it carries
 *       no discriminator, no ports and no TCP flags, and its `proto` is the
 *       Fragment header's Next Header
 *   P6  no Fragment header means no fragment key material
 *   P7  the discriminator agrees with D-41: the destination port for TCP and
 *       UDP, zero for everything that is neither TCP, UDP nor ICMPv6
 *   P8  TCP control bits are only ever reported for TCP
 *   P9  on OK the packet really was IPv6 and its declared length really did
 *       fit the buffer chain, recomputed from the octet stream
 */

#include "cilium_fuzz.h"

#include <cilium_srv6/cilium_srv6_hparse.h>

const char *const cilium_fuzz_target_name = "fuzz_headend_classify";

/*
 * The two-valued result enum would make a poor coverage signal on its own, so
 * the OK outcomes are split by fragment classification: those are the four
 * D-43 branches whose keys differ.
 */
enum
{
  OUT_MALFORMED = 0,
  OUT_OK_FRAG_NONE,
  OUT_OK_FRAG_ATOMIC,
  OUT_OK_FRAG_FIRST,
  OUT_OK_FRAG_NON_FIRST,
  OUT_OK_TCP_FLAGS,
};

const char *const cilium_fuzz_outcome_name[] = {
  "MALFORMED",	   "OK_FRAG_NONE",     "OK_FRAG_ATOMIC", "OK_FRAG_FIRST",
  "OK_FRAG_NON_FIRST", "OK_TCP_FLAGS_SEEN", NULL
};

const unsigned char cilium_fuzz_outcome_required[] = { 1, 1, 1, 1, 1, 1 };

/* Every named field of cilium_srv6_hparse_t. See P2 for why this is not a
   memcmp. Adding a field to the struct without adding it here weakens the
   determinism check, so the static assertion below pins the struct size. */
STATIC_ASSERT (sizeof (cilium_srv6_hparse_t) == 20,
	       "cilium_srv6_hparse_t changed shape; update the P2 field list");

static int
hparse_fields_equal (const cilium_srv6_hparse_t *a, const cilium_srv6_hparse_t *b)
{
  return a->proto == b->proto && a->frag_kind == b->frag_kind &&
	 a->frag_next_header == b->frag_next_header && a->pad == b->pad &&
	 a->l4_discriminator == b->l4_discriminator && a->frag_id == b->frag_id &&
	 a->sport == b->sport && a->dport == b->dport && a->tcp_flags == b->tcp_flags &&
	 a->pad2[0] == b->pad2[0] && a->pad2[1] == b->pad2[1] && a->pad2[2] == b->pad2[2];
}

void
cilium_fuzz_one (const uint8_t *data, size_t size)
{
  cilium_fuzz_input_t in;
  cilium_srv6_hparse_t r, r2;
  cilium_srv6_hparse_result_t res, res2;

  if (!cilium_fuzz_input_decode (data, size, &in))
    return;

  /* Poison the destination so that an unwritten field is visible as such
     rather than as a plausible zero. */
  memset (&r, 0xa5, sizeof (r));
  memset (&r2, 0x5a, sizeof (r2));

  res = cilium_srv6_hparse (in.pkt, in.avail, in.chain_len, &r);
  res2 = cilium_srv6_hparse (in.pkt, in.avail, in.chain_len, &r2);

  /* P1 */
  CILIUM_FUZZ_ASSERT (res == CILIUM_SRV6_HPARSE_OK || res == CILIUM_SRV6_HPARSE_MALFORMED,
		      "result=%d", (int) res);
  /* P2: the two runs started from different poison values, so an equal result
     also means no field was left uninitialised. */
  CILIUM_FUZZ_ASSERT (res == res2 && hparse_fields_equal (&r, &r2),
		      "non-deterministic classification");

  if (res != CILIUM_SRV6_HPARSE_OK)
    {
      cilium_fuzz_record (OUT_MALFORMED);
      cilium_fuzz_input_free (&in);
      return;
    }

  /* P3 */
  CILIUM_FUZZ_ASSERT (r.pad == 0 && r.pad2[0] == 0 && r.pad2[1] == 0 && r.pad2[2] == 0,
		      "cache key padding is not zero");

  /* P4 */
  CILIUM_FUZZ_ASSERT (r.frag_kind <= CILIUM_SRV6_FRAG_NON_FIRST, "frag_kind=%u", r.frag_kind);

  /* P5 */
  if (r.frag_kind == CILIUM_SRV6_FRAG_NON_FIRST)
    CILIUM_FUZZ_ASSERT (r.proto == r.frag_next_header && r.l4_discriminator == 0 &&
			  r.sport == 0 && r.dport == 0 && r.tcp_flags == 0,
			"non-first fragment carries L4 key material: proto=%u nh=%u disc=%u",
			r.proto, r.frag_next_header, r.l4_discriminator);

  /* P6 */
  if (r.frag_kind == CILIUM_SRV6_FRAG_NONE)
    CILIUM_FUZZ_ASSERT (r.frag_id == 0 && r.frag_next_header == 0,
			"unfragmented packet carries fragment key material");

  /* P7 */
  if (r.frag_kind != CILIUM_SRV6_FRAG_NON_FIRST)
    {
      if (r.proto == IP_PROTOCOL_TCP || r.proto == IP_PROTOCOL_UDP)
	CILIUM_FUZZ_ASSERT (r.l4_discriminator == r.dport, "disc=%u dport=%u",
			    r.l4_discriminator, r.dport);
      else if (r.proto != IP_PROTOCOL_ICMP6)
	CILIUM_FUZZ_ASSERT (r.l4_discriminator == 0 && r.sport == 0 && r.dport == 0,
			    "proto=%u carries port key material", r.proto);
    }

  /* P8 */
  if (r.proto != IP_PROTOCOL_TCP)
    CILIUM_FUZZ_ASSERT (r.tcp_flags == 0, "proto=%u carries TCP control bits", r.proto);

  /* P9 */
  {
    u64 declared = (u64) sizeof (ip6_header_t) + (((u64) in.pkt[4] << 8) | in.pkt[5]);

    CILIUM_FUZZ_ASSERT ((in.pkt[0] >> 4) == 6, "version nibble=%u", in.pkt[0] >> 4);
    CILIUM_FUZZ_ASSERT (declared <= in.chain_len, "declared=%llu chain_len=%llu",
			(unsigned long long) declared, (unsigned long long) in.chain_len);
  }

  cilium_fuzz_record ((unsigned) OUT_OK_FRAG_NONE + r.frag_kind);
  if (r.tcp_flags != 0)
    cilium_fuzz_mark (OUT_OK_TCP_FLAGS);

  cilium_fuzz_input_free (&in);
}
