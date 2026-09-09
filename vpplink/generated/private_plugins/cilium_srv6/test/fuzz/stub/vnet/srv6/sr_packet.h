/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Test-only stand-in for <vnet/srv6/sr_packet.h>: the RFC 8754 Segment
 * Routing Header, transcribed field-for-field from VPP so that the fuzzed
 * parser sees the layout that ships.
 *
 * cilium_srv6_parse.h contains
 *
 *   STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_sr_header_t, segments) == 8, ...)
 *
 * so the fixed-part layout below is checked by the production header itself
 * every time the fuzz build runs.
 */

#ifndef __included_cilium_srv6_fuzz_stub_sr_packet_h__
#define __included_cilium_srv6_fuzz_stub_sr_packet_h__

#include <vppinfra/clib.h>
#include <vnet/ip/ip6_packet.h>

#ifndef IP_PROTOCOL_IPV6_ROUTE
#define IP_PROTOCOL_IPV6_ROUTE 43
#endif

#define ROUTING_HEADER_TYPE_SR 4

typedef struct
{
  /* Protocol for next header. */
  u8 protocol;

  /* Length of routing header in 8 octet units, not including the first 8
     octets. */
  u8 length;

  /* Type of routing header; type 4 = segment routing. */
  u8 type;

  /* Next segment in the segment list. */
  u8 segments_left;

  /* Zero based index of the last element of the segment list. */
  u8 last_entry;

#define IP6_SR_HEADER_FLAG_PROTECTED (0x40)
#define IP6_SR_HEADER_FLAG_OAM	     (0x20)
#define IP6_SR_HEADER_FLAG_ALERT     (0x10)
#define IP6_SR_HEADER_FLAG_HMAC	     (0x80)

  u8 flags;
  u16 tag;

  /* The segment elts. */
  ip6_address_t segments[0];
} __attribute__ ((packed)) ip6_sr_header_t;

STATIC_ASSERT (STRUCT_OFFSET_OF (ip6_sr_header_t, segments) == 8,
	       "SRH fixed part must be 8 octets");

#endif /* __included_cilium_srv6_fuzz_stub_sr_packet_h__ */
