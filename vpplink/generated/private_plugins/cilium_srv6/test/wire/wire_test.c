/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Host-side check of the IF-3 wire format v2 serializer
 * (cilium_srv6_punt_wire.h) against the golden frames of
 * design/detail/02-headend-dataplane.md §5.6.7, which are the frames
 * pkg/srv6ec/compiler/wire_test.go's TestGoldenFrames pins on the agent side.
 *
 * Why a standalone program rather than a VPP unit test: the whole point of
 * D-76 is that the two ends agree on *bytes*, and the bytes are a pure
 * function of the values the classifier produced. cilium_srv6_punt_wire.h
 * therefore carries no vlib and no vnet dependency, and this test compiles it
 * against the byte-level stubs of ../fuzz/stub — the same architectural
 * check Issue #67 applies to the parser headers. If the serializer starts
 * needing VPP state, this build stops working, and that break is the signal.
 *
 * The golden frames are written here as hex strings copied from `02` §5.6.7,
 * not as computed expectations, so a change to the encoder cannot quietly
 * move the expectation with it.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cilium_srv6/cilium_srv6_punt_wire.h>

static int failures;
static int checks;

static void
fail (const char *what, const char *detail)
{
  fprintf (stderr, "FAIL %s: %s\n", what, detail);
  failures++;
}

/* Decode a hex string, ignoring whitespace. Returns the byte count. */
static u32
unhex (const char *s, u8 *out, u32 cap)
{
  u32 n = 0;
  int hi = -1;

  for (; *s; s++)
    {
      int v;

      if (*s == ' ' || *s == '\n' || *s == '\t' || *s == '\r')
	continue;
      if (*s >= '0' && *s <= '9')
	v = *s - '0';
      else if (*s >= 'a' && *s <= 'f')
	v = *s - 'a' + 10;
      else if (*s >= 'A' && *s <= 'F')
	v = *s - 'A' + 10;
      else
	{
	  fprintf (stderr, "unhex: bad character '%c'\n", *s);
	  exit (2);
	}

      if (hi < 0)
	hi = v;
      else
	{
	  if (n >= cap)
	    {
	      fprintf (stderr, "unhex: more than %u bytes\n", cap);
	      exit (2);
	    }
	  out[n++] = (u8) ((hi << 4) | v);
	  hi = -1;
	}
    }

  if (hi >= 0)
    {
      fprintf (stderr, "unhex: odd number of hex digits\n");
      exit (2);
    }
  return n;
}

static void
expect_bytes (const char *what, const u8 *got, u32 got_len, const u8 *want, u32 want_len)
{
  u32 i;

  checks++;
  if (got_len != want_len)
    {
      char d[128];
      snprintf (d, sizeof (d), "length %u, want %u", got_len, want_len);
      fail (what, d);
      return;
    }
  for (i = 0; i < want_len; i++)
    if (got[i] != want[i])
      {
	char d[160];
	snprintf (d, sizeof (d), "byte %u is %02x, want %02x", i, got[i], want[i]);
	fail (what, d);
	return;
      }
  printf ("ok   %s (%u bytes)\n", what, want_len);
}

static void
expect_result (const char *what, cilium_srv6_if3_result_t got, cilium_srv6_if3_result_t want)
{
  checks++;
  if (got != want)
    {
      char d[160];
      snprintf (d, sizeof (d), "result %s, want %s", cilium_srv6_if3_result_name (got),
		cilium_srv6_if3_result_name (want));
      fail (what, d);
      return;
    }
  printf ("ok   %s (%s)\n", what, cilium_srv6_if3_result_name (want));
}

static void
expect_u64 (const char *what, u64 got, u64 want)
{
  checks++;
  if (got != want)
    {
      char d[160];
      snprintf (d, sizeof (d), "%llu, want %llu", (unsigned long long) got,
		(unsigned long long) want);
      fail (what, d);
      return;
    }
  printf ("ok   %s\n", what);
}

/* ------------------------------------------------------------------ */
/* 02 §5.6.7 golden frames                                             */
/* ------------------------------------------------------------------ */

/*
 * Shared values of the worked example: src_identity = 100,
 * rx_sw_if_index = 18, rx_if_incarnation = 7, src_ip = fd00:a::1,
 * dst_ip = fd00:b::1, proto = 6 (TCP), l4_discriminator = 443,
 * src_port = 54321, dst_port = 443, punt_id = 0x9e3779b97f4a7c15.
 */
static void
fill_common (cilium_srv6_if3_punt_t *p)
{
  static const u8 src[16] = { 0xfd, 0x00, 0x00, 0x0a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
  static const u8 dst[16] = { 0xfd, 0x00, 0x00, 0x0b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };

  memset (p, 0, sizeof (p[0]));
  p->src_identity = 100;
  p->rx_sw_if_index = 18;
  p->rx_if_incarnation = 7;
  memcpy (p->src_ip, src, 16);
  memcpy (p->dst_ip, dst, 16);
  p->proto = 6;
  p->l4_discriminator = 443;
  p->src_port = 54321;
  p->dst_port = 443;
  p->punt_id = 0x9e3779b97f4a7c15ULL;
}

/* (1) compile queue MISS punt, no Fragment header, packet = "punt". */
static const char *golden_compile_miss = "02 01 0060"
					 "000102030405060708090a0b0c0d0e0f"
					 "00000064 00000012 00000007"
					 "fd00000a000000000000000000000001"
					 "fd00000b000000000000000000000001"
					 "06 00 01bb"
					 "d431 01bb"
					 "00000000 00 00 0000"
					 "00000004 9e3779b97f4a7c15"
					 "70756e74";

/* (2) reply reauthorization REPLY_REAUTH punt of a first fragment. This is
   the frame v1 could not carry: a non-fragment opcode with fragment_id != 0
   made the old decoder return ErrField and the old transport close the
   connection (00 §2.18.5). */
static const char *golden_reauth_first_fragment = "02 02 0061"
						  "101112131415161718191a1b1c1d1e1f"
						  "00000064 00000012 00000007"
						  "fd00000a000000000000000000000001"
						  "fd00000b000000000000000000000001"
						  "06 04 01bb"
						  "d431 01bb"
						  "deadbeef 3c 02 0000"
						  "00000005 9e3779b97f4a7c15"
						  "7265706c79";

/* (3) release of a DENY: token 20..2f, drop_reason 1 (DROP_POLICY_DENIED),
   no packet, 36 bytes. */
static const char *golden_release_deny = "02 11 0024"
					 "202122232425262728292a2b2c2d2e2f"
					 "01 000000"
					 "00000000 0000000000000000";

static void
test_golden_compile_miss (void)
{
  u8 want[CILIUM_SRV6_IF3_MAX_PUNT_FRAME];
  u8 got[CILIUM_SRV6_IF3_MAX_PUNT_FRAME];
  cilium_srv6_if3_punt_t p, back;
  u32 want_len, plen;
  u32 i;
  cilium_srv6_if3_result_t rv;
  static const char packet[] = "punt";

  want_len = unhex (golden_compile_miss, want, sizeof (want));

  fill_common (&p);
  p.opcode = CILIUM_SRV6_IF3_OP_PUNT_COMPILE;
  p.cause = CILIUM_SRV6_IF3_CAUSE_MISS;
  p.frag_kind = CILIUM_SRV6_IF3_FRAG_NONE;
  for (i = 0; i < CILIUM_SRV6_IF3_TOKEN_LEN; i++)
    p.token[i] = (u8) i;

  rv = cilium_srv6_if3_punt_encode (got, &p, (u32) strlen (packet));
  expect_result ("golden(1) encode", rv, CILIUM_SRV6_IF3_OK);
  memcpy (got + CILIUM_SRV6_IF3_PUNT_HDR_LEN, packet, strlen (packet));

  expect_bytes ("golden(1) compile MISS punt", got,
		CILIUM_SRV6_IF3_PUNT_HDR_LEN + (u32) strlen (packet), want, want_len);

  rv = cilium_srv6_if3_punt_decode (want, want_len, &back, &plen);
  expect_result ("golden(1) decode", rv, CILIUM_SRV6_IF3_OK);
  expect_u64 ("golden(1) decoded punt_id", back.punt_id, 0x9e3779b97f4a7c15ULL);
  expect_u64 ("golden(1) decoded packet_len", plen, strlen (packet));
  expect_u64 ("golden(1) decoded src_identity", back.src_identity, 100);
  expect_u64 ("golden(1) decoded l4_discriminator", back.l4_discriminator, 443);
  expect_u64 ("golden(1) decoded frag_kind", back.frag_kind, CILIUM_SRV6_IF3_FRAG_NONE);
}

static void
test_golden_reauth_first_fragment (void)
{
  u8 want[CILIUM_SRV6_IF3_MAX_PUNT_FRAME];
  u8 got[CILIUM_SRV6_IF3_MAX_PUNT_FRAME];
  cilium_srv6_if3_punt_t p, back;
  u32 want_len, plen, i;
  cilium_srv6_if3_result_t rv;
  static const char packet[] = "reply";

  want_len = unhex (golden_reauth_first_fragment, want, sizeof (want));

  fill_common (&p);
  p.opcode = CILIUM_SRV6_IF3_OP_PUNT_REAUTH;
  p.cause = CILIUM_SRV6_IF3_CAUSE_REPLY_REAUTH;
  p.frag_kind = CILIUM_SRV6_IF3_FRAG_FIRST;
  p.fragment_id = 0xdeadbeef;
  p.frag_next_header = 60; /* Destination Options */
  for (i = 0; i < CILIUM_SRV6_IF3_TOKEN_LEN; i++)
    p.token[i] = (u8) (0x10 + i);

  rv = cilium_srv6_if3_punt_encode (got, &p, (u32) strlen (packet));
  expect_result ("golden(2) encode", rv, CILIUM_SRV6_IF3_OK);
  memcpy (got + CILIUM_SRV6_IF3_PUNT_HDR_LEN, packet, strlen (packet));

  expect_bytes ("golden(2) reply-reauth first-fragment punt", got,
		CILIUM_SRV6_IF3_PUNT_HDR_LEN + (u32) strlen (packet), want, want_len);

  /* The v1 regression: fragment metadata under a non-fragment opcode is a
     legitimate frame and must decode, not be rejected (00 §2.18.5). */
  rv = cilium_srv6_if3_punt_decode (want, want_len, &back, &plen);
  expect_result ("golden(2) decode", rv, CILIUM_SRV6_IF3_OK);
  expect_u64 ("golden(2) decoded fragment_id", back.fragment_id, 0xdeadbeefULL);
  expect_u64 ("golden(2) decoded frag_next_header", back.frag_next_header, 60);
  expect_u64 ("golden(2) decoded frag_kind", back.frag_kind, CILIUM_SRV6_IF3_FRAG_FIRST);
  expect_u64 ("golden(2) decoded cause", back.cause, CILIUM_SRV6_IF3_CAUSE_REPLY_REAUTH);
}

static void
test_golden_release (void)
{
  u8 want[64], got[CILIUM_SRV6_IF3_REINJECT_HDR_LEN];
  cilium_srv6_if3_reinject_t m, back;
  u32 want_len, i;
  cilium_srv6_if3_result_t rv;

  want_len = unhex (golden_release_deny, want, sizeof (want));

  memset (&m, 0, sizeof (m));
  for (i = 0; i < CILIUM_SRV6_IF3_TOKEN_LEN; i++)
    m.token[i] = (u8) (0x20 + i);
  m.drop_reason = CILIUM_SRV6_IF3_DROP_POLICY_DENIED;
  /* 02 §5.6.3: a release carries punt_id 0 whatever the caller holds. */
  m.punt_id = 0x1122334455667788ULL;

  rv = cilium_srv6_if3_reinject_encode (got, &m);
  expect_result ("golden(3) encode", rv, CILIUM_SRV6_IF3_OK);
  expect_bytes ("golden(3) DENY release", got, CILIUM_SRV6_IF3_REINJECT_HDR_LEN, want, want_len);

  rv = cilium_srv6_if3_reinject_decode (want, want_len, &back);
  expect_result ("golden(3) decode", rv, CILIUM_SRV6_IF3_OK);
  expect_u64 ("golden(3) decoded drop_reason", back.drop_reason,
	      CILIUM_SRV6_IF3_DROP_POLICY_DENIED);
  expect_u64 ("golden(3) decoded punt_id is ignored and zero", back.punt_id, 0);
  expect_u64 ("golden(3) decoded packet_len", back.packet_len, 0);
}

/* ------------------------------------------------------------------ */
/* reinject decode                                                     */
/* ------------------------------------------------------------------ */

static u32
build_reinject (u8 *out, const u8 *token, u64 punt_id, const u8 *packet, u32 packet_len)
{
  cilium_srv6_if3_reinject_t m;

  memset (&m, 0, sizeof (m));
  memcpy (m.token, token, CILIUM_SRV6_IF3_TOKEN_LEN);
  m.drop_reason = CILIUM_SRV6_IF3_DROP_NONE;
  m.punt_id = punt_id;
  m.packet_len = packet_len;

  if (cilium_srv6_if3_reinject_encode (out, &m) != CILIUM_SRV6_IF3_OK)
    {
      fprintf (stderr, "build_reinject: encoder refused a valid message\n");
      exit (2);
    }
  memcpy (out + CILIUM_SRV6_IF3_REINJECT_HDR_LEN, packet, packet_len);
  return CILIUM_SRV6_IF3_REINJECT_HDR_LEN + packet_len;
}

static void
test_reinject_roundtrip (void)
{
  u8 frame[CILIUM_SRV6_IF3_MAX_REINJECT_FRAME];
  u8 token[CILIUM_SRV6_IF3_TOKEN_LEN];
  static const u8 packet[] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x40 };
  cilium_srv6_if3_reinject_t m;
  u32 len, i, total;
  cilium_srv6_if3_result_t rv;

  for (i = 0; i < sizeof (token); i++)
    token[i] = (u8) (0xa0 + i);

  len = build_reinject (frame, token, 0x0102030405060708ULL, packet, sizeof (packet));

  rv = cilium_srv6_if3_frame_length (frame, 4, &total);
  expect_result ("reinject frame_length", rv, CILIUM_SRV6_IF3_OK);
  expect_u64 ("reinject frame_length value", total, len);

  rv = cilium_srv6_if3_reinject_decode (frame, len, &m);
  expect_result ("reinject decode", rv, CILIUM_SRV6_IF3_OK);
  expect_u64 ("reinject punt_id", m.punt_id, 0x0102030405060708ULL);
  expect_u64 ("reinject packet_len", m.packet_len, sizeof (packet));
  checks++;
  if (m.packet == 0 || memcmp (m.packet, packet, sizeof (packet)) != 0)
    fail ("reinject packet", "packet bytes differ");
  else
    printf ("ok   reinject packet\n");
  checks++;
  if (memcmp (m.token, token, sizeof (token)) != 0)
    fail ("reinject token", "token bytes differ");
  else
    printf ("ok   reinject token\n");
}

/* ------------------------------------------------------------------ */
/* rejections, and which of them close the connection (00 §2.18.9)     */
/* ------------------------------------------------------------------ */

static void
test_reinject_rejections (void)
{
  u8 frame[CILIUM_SRV6_IF3_MAX_REINJECT_FRAME];
  u8 token[CILIUM_SRV6_IF3_TOKEN_LEN];
  static const u8 packet[] = { 0x60, 0x00, 0x00, 0x00 };
  cilium_srv6_if3_reinject_t m;
  u32 len, i;

  for (i = 0; i < sizeof (token); i++)
    token[i] = (u8) (0xb0 + i);
  len = build_reinject (frame, token, 42, packet, sizeof (packet));

  {
    u8 bad[sizeof (frame)];
    memcpy (bad, frame, len);
    bad[0] = 1; /* the v1 version byte */
    expect_result ("v1 version is refused", cilium_srv6_if3_reinject_decode (bad, len, &m),
		   CILIUM_SRV6_IF3_ERR_VERSION);
  }
  {
    u8 bad[sizeof (frame)];
    memcpy (bad, frame, len);
    bad[1] = CILIUM_SRV6_IF3_OP_PUNT_COMPILE; /* wrong direction */
    expect_result ("a punt opcode from the agent is refused",
		   cilium_srv6_if3_reinject_decode (bad, len, &m), CILIUM_SRV6_IF3_ERR_OPCODE);
  }
  {
    u8 bad[sizeof (frame)];
    memcpy (bad, frame, len);
    bad[3] = (u8) (bad[3] + 1); /* length no longer describes the frame */
    expect_result ("an inconsistent length is refused",
		   cilium_srv6_if3_reinject_decode (bad, len, &m), CILIUM_SRV6_IF3_ERR_LENGTH);
  }
  {
    u8 bad[sizeof (frame)];
    memcpy (bad, frame, len);
    memset (bad + 4, 0, CILIUM_SRV6_IF3_TOKEN_LEN);
    expect_result ("an all-zero token is refused", cilium_srv6_if3_reinject_decode (bad, len, &m),
		   CILIUM_SRV6_IF3_ERR_TOKEN);
  }
  {
    u8 bad[sizeof (frame)];
    memcpy (bad, frame, len);
    bad[21] = 1; /* reserved */
    expect_result ("a non-zero reserved byte is refused",
		   cilium_srv6_if3_reinject_decode (bad, len, &m), CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    u8 bad[sizeof (frame)];
    memcpy (bad, frame, len);
    bad[20] = CILIUM_SRV6_IF3_DROP_POLICY_DENIED; /* reinject opcode, drop reason */
    expect_result ("opcode and drop reason must agree",
		   cilium_srv6_if3_reinject_decode (bad, len, &m), CILIUM_SRV6_IF3_ERR_OPCODE);
  }
  {
    u8 bad[sizeof (frame)];
    memcpy (bad, frame, len);
    bad[20] = CILIUM_SRV6_IF3_N_DROP_REASON; /* out of range */
    bad[1] = CILIUM_SRV6_IF3_OP_RELEASE;
    expect_result ("an unknown drop reason is refused",
		   cilium_srv6_if3_reinject_decode (bad, len, &m), CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    u8 bad[sizeof (frame)];
    memcpy (bad, frame, len);
    memset (bad + 28, 0, 8); /* punt_id 0 on a reinject */
    expect_result ("a zero punt_id on a reinject is refused",
		   cilium_srv6_if3_reinject_decode (bad, len, &m), CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    expect_result (
      "a short frame is truncated, not malformed",
      cilium_srv6_if3_reinject_decode (frame, CILIUM_SRV6_IF3_REINJECT_HDR_LEN - 1, &m),
      CILIUM_SRV6_IF3_ERR_TRUNCATED);
  }

  /* Dispositions: only the framing four close the connection. */
  checks++;
  if (!cilium_srv6_if3_is_framing_error (CILIUM_SRV6_IF3_ERR_VERSION) ||
      !cilium_srv6_if3_is_framing_error (CILIUM_SRV6_IF3_ERR_OPCODE) ||
      !cilium_srv6_if3_is_framing_error (CILIUM_SRV6_IF3_ERR_LENGTH) ||
      !cilium_srv6_if3_is_framing_error (CILIUM_SRV6_IF3_ERR_TRUNCATED) ||
      cilium_srv6_if3_is_framing_error (CILIUM_SRV6_IF3_ERR_FIELD) ||
      cilium_srv6_if3_is_framing_error (CILIUM_SRV6_IF3_ERR_TOKEN) ||
      cilium_srv6_if3_is_framing_error (CILIUM_SRV6_IF3_OK))
    fail ("error disposition", "the framing/semantic split of 00 §2.18.9 is wrong");
  else
    printf ("ok   error disposition (framing closes, semantic drops one frame)\n");
}

/* ------------------------------------------------------------------ */
/* punt encode rejections                                              */
/* ------------------------------------------------------------------ */

static void
test_punt_encode_rejections (void)
{
  u8 out[CILIUM_SRV6_IF3_PUNT_HDR_LEN];
  cilium_srv6_if3_punt_t p;
  u32 i;

  fill_common (&p);
  p.opcode = CILIUM_SRV6_IF3_OP_PUNT_COMPILE;
  for (i = 0; i < CILIUM_SRV6_IF3_TOKEN_LEN; i++)
    p.token[i] = 1;

  {
    cilium_srv6_if3_punt_t q = p;
    memset (q.token, 0, sizeof (q.token));
    expect_result ("refuse to encode a zero token", cilium_srv6_if3_punt_encode (out, &q, 0),
		   CILIUM_SRV6_IF3_ERR_TOKEN);
  }
  {
    cilium_srv6_if3_punt_t q = p;
    q.punt_id = 0;
    expect_result ("refuse to encode a zero punt_id", cilium_srv6_if3_punt_encode (out, &q, 0),
		   CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    cilium_srv6_if3_punt_t q = p;
    q.cause = CILIUM_SRV6_IF3_N_CAUSE;
    expect_result ("refuse an unknown cause", cilium_srv6_if3_punt_encode (out, &q, 0),
		   CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    cilium_srv6_if3_punt_t q = p;
    q.fragment_id = 1; /* with frag_kind NONE */
    expect_result ("refuse fragment_id under frag_kind none",
		   cilium_srv6_if3_punt_encode (out, &q, 0), CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    cilium_srv6_if3_punt_t q = p;
    q.frag_next_header = 60; /* with frag_kind NONE */
    expect_result ("refuse frag_next_header under frag_kind none",
		   cilium_srv6_if3_punt_encode (out, &q, 0), CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    cilium_srv6_if3_punt_t q = p;
    q.opcode = CILIUM_SRV6_IF3_OP_PUNT_FRAGMENT;
    q.frag_kind = CILIUM_SRV6_IF3_FRAG_NONE;
    expect_result ("refuse a fragment punt with frag_kind none",
		   cilium_srv6_if3_punt_encode (out, &q, 0), CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    /* An atomic fragment on the compile queue is legal, and it is exactly
       what the classifier must be able to report: folding ATOMIC into NONE
       would produce a frame whose fragment_id contradicts its frag_kind and
       the agent would drop every punt of an atomically fragmented flow. */
    cilium_srv6_if3_punt_t q = p;
    q.frag_kind = CILIUM_SRV6_IF3_FRAG_ATOMIC;
    q.fragment_id = 0x11223344;
    q.frag_next_header = 6;
    expect_result ("an atomic fragment on the compile queue is legal",
		   cilium_srv6_if3_punt_encode (out, &q, 0), CILIUM_SRV6_IF3_OK);
  }
  {
    /* A fragment whose Identification and Next Header are both 0 is legal
       once frag_kind says a Fragment header is present (RFC 8200 reserves
       neither value). */
    cilium_srv6_if3_punt_t q = p;
    q.opcode = CILIUM_SRV6_IF3_OP_PUNT_FRAGMENT;
    q.frag_kind = CILIUM_SRV6_IF3_FRAG_FIRST;
    q.fragment_id = 0;
    q.frag_next_header = 0;
    expect_result ("fragment_id 0 and frag_next_header 0 are legal on a real fragment",
		   cilium_srv6_if3_punt_encode (out, &q, 0), CILIUM_SRV6_IF3_OK);
  }
  {
    cilium_srv6_if3_punt_t q = p;
    q.proto = 132; /* SCTP: no D-41 discriminator */
    q.l4_discriminator = 80;
    expect_result ("a discriminator on a protocol that has none is refused",
		   cilium_srv6_if3_punt_encode (out, &q, 0), CILIUM_SRV6_IF3_ERR_FIELD);
  }
  {
    cilium_srv6_if3_punt_t q = p;
    expect_result ("a packet over MaxPuntPacket is refused",
		   cilium_srv6_if3_punt_encode (out, &q, CILIUM_SRV6_IF3_MAX_PACKET + 1),
		   CILIUM_SRV6_IF3_ERR_LENGTH);
  }
  {
    /* The largest legal frame still fits the u16 length field. */
    cilium_srv6_if3_punt_t q = p;
    expect_result ("the largest legal packet is accepted",
		   cilium_srv6_if3_punt_encode (out, &q, CILIUM_SRV6_IF3_MAX_PACKET),
		   CILIUM_SRV6_IF3_OK);
    checks++;
    if (cilium_srv6_if3_get_u16 (out + 2) != CILIUM_SRV6_IF3_MAX_PUNT_FRAME)
      fail ("largest frame length", "the length field is not the total frame length");
    else
      printf ("ok   largest frame length is the total frame length (%u)\n",
	      CILIUM_SRV6_IF3_MAX_PUNT_FRAME);
  }
}

/* ------------------------------------------------------------------ */
/* wire constants                                                      */
/* ------------------------------------------------------------------ */

static void
test_wire_constants (void)
{
  /* 02 §5.6: these are wire constants, not sizeof values, and the two ends
     agree on the numbers. A struct that happens to be 92 bytes is not what
     puts 92 here. */
  expect_u64 ("punt header length", CILIUM_SRV6_IF3_PUNT_HDR_LEN, 92);
  expect_u64 ("reinject header length", CILIUM_SRV6_IF3_REINJECT_HDR_LEN, 36);
  expect_u64 ("max punt frame", CILIUM_SRV6_IF3_MAX_PUNT_FRAME, 9308);
  expect_u64 ("max reinject frame", CILIUM_SRV6_IF3_MAX_REINJECT_FRAME, 9252);
  expect_u64 ("wire version", CILIUM_SRV6_IF3_VERSION, 2);
  expect_u64 ("token length", CILIUM_SRV6_IF3_TOKEN_LEN, 16);
}

int
main (void)
{
  test_wire_constants ();
  test_golden_compile_miss ();
  test_golden_reauth_first_fragment ();
  test_golden_release ();
  test_reinject_roundtrip ();
  test_reinject_rejections ();
  test_punt_encode_rejections ();

  printf ("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
