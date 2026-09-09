/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Shared harness contract for the cilium_srv6 parser fuzz targets (#67).
 *
 * Every target is one translation unit in harness/ that defines
 *
 *   cilium_fuzz_target_name    the target's name, used in output
 *   cilium_fuzz_outcome_name   NULL-terminated list of outcome labels
 *   cilium_fuzz_one()          run one input and assert the post-conditions
 *
 * and one translation unit in generators/ that defines
 *
 *   cilium_fuzz_generate()     the deterministic input matrix
 *
 * The same object file is linked two ways (see build.sh):
 *
 *   replay      + harness/fuzz_main.c + generators/gen_<target>.c
 *   libFuzzer   + -fsanitize=fuzzer, entry point below
 *
 * so a harness that stops compiling, stops linking, or stops asserting is
 * caught by the blocking PR job rather than discovered at the next incident.
 *
 * ------------------------------------------------------------------
 * Input framing
 * ------------------------------------------------------------------
 *
 * A corpus file is not a bare packet. The parsers take three inputs — the
 * bytes, how many of them are readable in the first buffer (`avail`), and
 * how long the whole buffer chain is (`chain_len`) — and the interesting
 * bugs live in the disagreements between the three. So the last two are part
 * of the input, in a fixed 4 octet prefix:
 *
 *   octet 0   flags        bit 0  target option (guard: fragment_drop_all)
 *                          bit 7  chain_len is absolute, not relative
 *   octet 1   avail_cut    octets removed from the end of the packet to
 *                          form `avail`, saturating at the packet length
 *   octet 2-3 chain_extra  big endian
 *   octet 4+  packet       the bytes on the wire
 *
 * and
 *
 *   avail     = packet_len - min(avail_cut, packet_len)
 *   chain_len = (flags & 0x80) ? chain_extra : avail + chain_extra
 *
 * The absolute form is what produces chain_len < avail, which is the shape a
 * caller must never be able to turn into a read past the readable area.
 *
 * `avail` octets — not packet_len — are then copied into a heap block of
 * exactly `avail` octets. ASan poisons both sides of that block, so a single
 * octet read past the declared readable area is a hard failure rather than a
 * silent read of adjacent packet bytes. This is the property the fuzz gate
 * exists to hold: "bounded parser の全 deref が境界検査済み".
 */

#ifndef __included_cilium_fuzz_h__
#define __included_cilium_fuzz_h__

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CILIUM_FUZZ_PREFIX_LEN	 4
#define CILIUM_FUZZ_MAX_OUTCOMES 16

/* Upper bound on a corpus input. Large enough for the 1280 octet ICMPv6
   error of RFC 4443 §3.2 plus its framing, small enough that libFuzzer does
   not spend its budget growing inputs that no parser can reach into. */
#define CILIUM_FUZZ_MAX_INPUT 2048

/* Defined by harness/fuzz_<target>.c.
 *
 * cilium_fuzz_outcome_required[] is parallel to cilium_fuzz_outcome_name[]
 * and marks the outcomes the deterministic corpus must still be able to
 * reach. An outcome that stops being produced means the corpus stopped
 * covering that branch — usually because the parser changed — and the
 * blocking gate reports it rather than passing on a corpus that has quietly
 * become inert. */
extern const char *const cilium_fuzz_target_name;
extern const char *const cilium_fuzz_outcome_name[];
extern const unsigned char cilium_fuzz_outcome_required[];
extern void cilium_fuzz_one (const uint8_t *data, size_t size);

/* Defined by generators/gen_<target>.c. `full` selects the nightly matrix;
   both levels are deterministic. */
extern void cilium_fuzz_generate (int full);

/* Bookkeeping, defined in harness/fuzz_stats.c. The outcome counters are not
   decoration: a corpus that never reaches an outcome is a corpus that is not
   testing that branch, and fuzz_main.c fails the run when a label that the
   target declares required was never produced. */
extern unsigned long cilium_fuzz_n_runs;
extern unsigned long cilium_fuzz_outcome_count[CILIUM_FUZZ_MAX_OUTCOMES];

/* One run, one primary outcome. */
extern void cilium_fuzz_record (unsigned outcome);

/* An additional property of the same run (a second verdict produced with a
   different option, a secondary function's result). Counts the outcome
   without counting another run. */
extern void cilium_fuzz_mark (unsigned outcome);

/* A failed post-condition is a finding, not a diagnostic: abort so that the
   replay binary, libFuzzer and the CI job all see the same signal. */
#define CILIUM_FUZZ_ASSERT(cond, ...)                                         \
  do                                                                          \
    {                                                                         \
      if (!(cond))                                                            \
	{                                                                     \
	  fprintf (stderr, "%s:%d: post-condition failed: %s\n", __FILE__,    \
		   __LINE__, #cond);                                          \
	  fprintf (stderr, "  ");                                             \
	  fprintf (stderr, __VA_ARGS__);                                      \
	  fprintf (stderr, "\n");                                             \
	  abort ();                                                           \
	}                                                                     \
    }                                                                         \
  while (0)

/* The decoded framing of one input. `pkt` points into a heap block of
   exactly `avail` octets and is freed by cilium_fuzz_input_free(). */
typedef struct
{
  uint8_t *pkt;
  uint32_t avail;
  uint64_t chain_len;
  uint8_t flags;
  /* The undecoded input, still fully readable. Targets that need auxiliary
     material (the PMTUD path shape, for instance) take it from here rather
     than from `pkt`, so that reading it can never be mistaken for the parser
     reading past `avail`. */
  const uint8_t *raw;
  size_t raw_size;
} cilium_fuzz_input_t;

/* Returns 0 when the input is too short to carry the framing. */
static inline int
cilium_fuzz_input_decode (const uint8_t *data, size_t size, cilium_fuzz_input_t *in)
{
  uint32_t pkt_len, cut;
  uint16_t chain_extra;

  memset (in, 0, sizeof (*in));

  if (size < CILIUM_FUZZ_PREFIX_LEN || size > CILIUM_FUZZ_MAX_INPUT)
    return 0;

  in->flags = data[0];
  cut = data[1];
  chain_extra = (uint16_t) ((uint16_t) data[2] << 8 | data[3]);

  pkt_len = (uint32_t) (size - CILIUM_FUZZ_PREFIX_LEN);
  in->avail = cut >= pkt_len ? 0 : pkt_len - cut;

  in->chain_len =
    (in->flags & 0x80) ? (uint64_t) chain_extra : (uint64_t) in->avail + (uint64_t) chain_extra;

  /* Exact-size allocation. malloc(0) still yields a block with no readable
     octet under ASan, which is the correct model for avail == 0. */
  in->pkt = (uint8_t *) malloc (in->avail ? in->avail : 1);
  if (in->pkt == NULL)
    abort ();
  memcpy (in->pkt, data + CILIUM_FUZZ_PREFIX_LEN, in->avail);

  in->raw = data;
  in->raw_size = size;
  return 1;
}

static inline void
cilium_fuzz_input_free (cilium_fuzz_input_t *in)
{
  free (in->pkt);
  in->pkt = NULL;
}

/* Deterministic xorshift, so that a "random" generator level replays
   identically on every host and in every CI run. */
typedef struct
{
  uint64_t s;
} cilium_fuzz_rng_t;

static inline void
cilium_fuzz_rng_init (cilium_fuzz_rng_t *r, uint64_t seed)
{
  r->s = seed ? seed : 0x2026083100000001ull;
}

static inline uint32_t
cilium_fuzz_rnd (cilium_fuzz_rng_t *r)
{
  r->s ^= r->s << 13;
  r->s ^= r->s >> 7;
  r->s ^= r->s << 17;
  return (uint32_t) (r->s >> 11);
}

/* Build a framed input from a bare packet and run it. Used by the
   generators, which think in packets rather than in framing. */
static inline void
cilium_fuzz_run_packet (const uint8_t *pkt, uint32_t pkt_len, uint8_t flags, uint8_t avail_cut,
			uint16_t chain_extra)
{
  uint8_t buf[CILIUM_FUZZ_PREFIX_LEN + CILIUM_FUZZ_MAX_INPUT];

  if (pkt_len > CILIUM_FUZZ_MAX_INPUT - CILIUM_FUZZ_PREFIX_LEN)
    return;

  buf[0] = flags;
  buf[1] = avail_cut;
  buf[2] = (uint8_t) (chain_extra >> 8);
  buf[3] = (uint8_t) chain_extra;
  memcpy (buf + CILIUM_FUZZ_PREFIX_LEN, pkt, pkt_len);

  cilium_fuzz_one (buf, (size_t) pkt_len + CILIUM_FUZZ_PREFIX_LEN);
}

#endif /* __included_cilium_fuzz_h__ */
