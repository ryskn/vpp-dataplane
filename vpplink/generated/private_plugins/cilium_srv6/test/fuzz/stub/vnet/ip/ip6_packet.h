/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Test-only stand-in for <vnet/ip/ip6_packet.h>.
 *
 * The real header includes <vlib/vlib.h> transitively, which is precisely
 * what the four cilium_srv6 parser headers must not need. This file supplies
 * the wire-format types they use and nothing else.
 *
 * Layout fidelity is the load-bearing property here: the parsers cast raw
 * packet bytes to these types, so a stub whose layout differs from VPP's
 * would fuzz a different program than the one that ships. Every type below
 * is transcribed field-for-field from vnet/ip/ip6_packet.h and pinned with a
 * STATIC_ASSERT on its size, and on the field offsets the parsers depend on.
 * The SIMD members of the real ip6_address_t union are omitted because no
 * parser reads them; the size assertion keeps the omission honest.
 */

#ifndef __included_cilium_srv6_fuzz_stub_ip6_packet_h__
#define __included_cilium_srv6_fuzz_stub_ip6_packet_h__

#include <vppinfra/clib.h>
#include <vppinfra/byte_order.h>

typedef union
{
  u8 as_u8[16];
  u16 as_u16[8];
  u32 as_u32[4];
  u64 as_u64[2];
  uword as_uword[16 / sizeof (uword)];
} __clib_packed ip6_address_t;

STATIC_ASSERT_SIZEOF (ip6_address_t, 16);

typedef struct
{
  /* 4 bit version, 8 bit traffic class and 20 bit flow label. */
  u32 ip_version_traffic_class_and_flow_label;

  /* Total packet length not including this header. */
  u16 payload_length;

  /* Protocol for next header. */
  u8 protocol;

  /* Hop limit decremented by router at each hop. */
  u8 hop_limit;

  ip6_address_t src_address, dst_address;
} ip6_header_t;

STATIC_ASSERT_SIZEOF (ip6_header_t, 40);
STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_header_t, payload_length) == 4,
	       "ip6_header_t.payload_length must sit at octet 4");
STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_header_t, protocol) == 6,
	       "ip6_header_t.protocol must sit at octet 6");
STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_header_t, src_address) == 8,
	       "ip6_header_t.src_address must sit at octet 8");
STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_header_t, dst_address) == 24,
	       "ip6_header_t.dst_address must sit at octet 24");

typedef CLIB_PACKED (struct {
  u8 next_hdr;
  /* Length of this header plus option data in 8 byte units. */
  u8 n_data_u64s;
}) ip6_ext_header_t;

STATIC_ASSERT_SIZEOF (ip6_ext_header_t, 2);

typedef CLIB_PACKED (struct {
  u8 next_hdr;
  u8 rsv;
  u16 fragment_offset_and_more;
  u32 identification;
}) ip6_frag_hdr_t;

STATIC_ASSERT_SIZEOF (ip6_frag_hdr_t, 8);
STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_frag_hdr_t, fragment_offset_and_more) == 2,
	       "ip6_frag_hdr_t offset/M field must sit at octet 2");
STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_frag_hdr_t, identification) == 4,
	       "ip6_frag_hdr_t.identification must sit at octet 4");

#define ip6_frag_hdr_offset(hdr)                                              \
  (clib_net_to_host_u16 ((hdr)->fragment_offset_and_more) >> 3)

#define ip6_frag_hdr_offset_bytes(hdr) (8 * ip6_frag_hdr_offset (hdr))

#define ip6_frag_hdr_more(hdr)                                                \
  (clib_net_to_host_u16 ((hdr)->fragment_offset_and_more) & 0x1)

#define ip6_frag_hdr_offset_and_more(offset, more)                            \
  clib_host_to_net_u16 (((offset) << 3) + !!(more))

#define ip6_ext_header_len(p)  ((((ip6_ext_header_t *) (p))->n_data_u64s + 1) << 3)
#define ip6_ext_authhdr_len(p) ((((ip6_ext_header_t *) (p))->n_data_u64s + 2) << 2)

always_inline uword
ip6_address_is_equal (const ip6_address_t *a, const ip6_address_t *b)
{
  int i;
  for (i = 0; i < (int) ARRAY_LEN (a->as_uword); i++)
    if (a->as_uword[i] != b->as_uword[i])
      return 0;
  return 1;
}

#endif /* __included_cilium_srv6_fuzz_stub_ip6_packet_h__ */
