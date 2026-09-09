/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Test-only stand-in for <vppinfra/byte_order.h>. See stub/vppinfra/clib.h
 * for why this stub exists and why it must not grow beyond byte-level
 * primitives.
 *
 * The conversions are written with __builtin_bswap so that the behaviour is
 * identical on a little- and a big-endian host and does not depend on any
 * vppinfra configuration macro.
 */

#ifndef __included_cilium_srv6_fuzz_stub_byte_order_h__
#define __included_cilium_srv6_fuzz_stub_byte_order_h__

#include <vppinfra/clib.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define CILIUM_FUZZ_BIG_ENDIAN 1
#else
#define CILIUM_FUZZ_BIG_ENDIAN 0
#endif

static_always_inline u16
clib_byte_swap_u16 (u16 x)
{
  return CILIUM_FUZZ_BIG_ENDIAN ? x : __builtin_bswap16 (x);
}

static_always_inline u32
clib_byte_swap_u32 (u32 x)
{
  return CILIUM_FUZZ_BIG_ENDIAN ? x : __builtin_bswap32 (x);
}

static_always_inline u64
clib_byte_swap_u64 (u64 x)
{
  return CILIUM_FUZZ_BIG_ENDIAN ? x : __builtin_bswap64 (x);
}

#define clib_net_to_host_u16(x) clib_byte_swap_u16 (x)
#define clib_net_to_host_u32(x) clib_byte_swap_u32 (x)
#define clib_net_to_host_u64(x) clib_byte_swap_u64 (x)

#define clib_host_to_net_u16(x) clib_byte_swap_u16 (x)
#define clib_host_to_net_u32(x) clib_byte_swap_u32 (x)
#define clib_host_to_net_u64(x) clib_byte_swap_u64 (x)

#endif /* __included_cilium_srv6_fuzz_stub_byte_order_h__ */
