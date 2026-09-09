/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Test-only stand-in for <vnet/ip/icmp46_packet.h>: the four-octet ICMPv6
 * fixed header and the one message type cilium_srv6_pmtud_parse.h looks at.
 * RFC 4443 §3.2 Packet Too Big is type 2, code 0.
 */

#ifndef __included_cilium_srv6_fuzz_stub_icmp46_packet_h__
#define __included_cilium_srv6_fuzz_stub_icmp46_packet_h__

#include <vppinfra/clib.h>

typedef CLIB_PACKED (struct {
  u8 type;
  u8 code;
  /* IP checksum of icmp header plus data which follows. */
  u16 checksum;
}) icmp46_header_t;

STATIC_ASSERT_SIZEOF (icmp46_header_t, 4);

#define ICMP6_destination_unreachable 1
#define ICMP6_packet_too_big	      2
#define ICMP6_time_exceeded	      3
#define ICMP6_parameter_problem	      4

#endif /* __included_cilium_srv6_fuzz_stub_icmp46_packet_h__ */
