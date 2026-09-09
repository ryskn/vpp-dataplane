/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Test-only stand-in for <vnet/ip/ip_types.h>.
 *
 * Only the ip_protocol_t values the four cilium_srv6 parser headers switch
 * on, transcribed from vnet/ip/protocols.def. The numbers are IANA protocol
 * numbers, so they are stable; they are listed explicitly rather than
 * generated from the .def file to keep the stub free of any VPP path.
 */

#ifndef __included_cilium_srv6_fuzz_stub_ip_types_h__
#define __included_cilium_srv6_fuzz_stub_ip_types_h__

#include <vppinfra/clib.h>

typedef enum
{
  IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS = 0,
  IP_PROTOCOL_TCP = 6,
  IP_PROTOCOL_UDP = 17,
  IP_PROTOCOL_IPV6 = 41,
  IP_PROTOCOL_IPV6_ROUTE = 43,
  IP_PROTOCOL_IPV6_FRAGMENTATION = 44,
  IP_PROTOCOL_IPSEC_AH = 51,
  IP_PROTOCOL_ICMP6 = 58,
  IP_PROTOCOL_IP6_DESTINATION_OPTIONS = 60,
  IP_PROTOCOL_MOBILITY = 135,
  IP_PROTOCOL_HIP = 139,
  IP_PROTOCOL_SHIM6 = 140,
} ip_protocol_t;

#endif /* __included_cilium_srv6_fuzz_stub_ip_types_h__ */
