/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Test-only stand-in for <vppinfra/clib.h>.
 *
 * Scope: exactly the vppinfra surface the four cilium_srv6 parser headers
 * use, and nothing else. The point of this file is the fail-fast property
 * recorded in Issue #67: the parsers must stay a pure function of the
 * received bytes, so they must build and run without vlib, without vnet, and
 * without any VPP global state. If a parser starts using a vppinfra facility
 * that is not in this file, the fuzz build breaks, and that break is the
 * signal — do not widen this stub to make an architectural regression
 * compile. Add the symbol here only when it is genuinely a byte-level
 * primitive (byte order, memcpy, branch hints, static assertions).
 *
 * This file is never compiled into the plugin. It exists only on the
 * -I search path of vpp/plugins/cilium_srv6/test/fuzz/build.sh.
 */

#ifndef __included_cilium_srv6_fuzz_stub_clib_h__
#define __included_cilium_srv6_fuzz_stub_clib_h__

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t i8;
typedef int16_t i16;
typedef int32_t i32;
typedef int64_t i64;

typedef uintptr_t uword;
typedef intptr_t word;

/* Spelt with the reserved __always_inline__ form: `always_inline` is itself
   a macro here, so the plain attribute name would be rewritten inside its
   own expansion. */
#define always_inline	     static inline __attribute__ ((__always_inline__))
#define static_always_inline static inline __attribute__ ((__always_inline__))

#define PREDICT_FALSE(x) __builtin_expect ((long) (x), 0)
#define PREDICT_TRUE(x)	 __builtin_expect ((long) (x), 1)

#define CLIB_PACKED(x)	x __attribute__ ((packed))
#define __clib_packed	__attribute__ ((packed))
#define CLIB_UNUSED(x)	x __attribute__ ((unused))

#define ARRAY_LEN(a) (sizeof (a) / sizeof ((a)[0]))

#define STRUCT_OFFSET_OF(t, f) __builtin_offsetof (t, f)
#define STRUCT_SIZE_OF(t, f)   (sizeof (((t *) 0)->f))

#define _CILIUM_FUZZ_CAT2(a, b) a##b
#define _CILIUM_FUZZ_CAT(a, b)	_CILIUM_FUZZ_CAT2 (a, b)

/* Same spelling and same arity as the vppinfra macro, so that a
   STATIC_ASSERT in a parser header is checked here too. */
#define STATIC_ASSERT(truth, ...)                                             \
  typedef char _CILIUM_FUZZ_CAT (_static_assert_, __LINE__)[(truth) ? 1 : -1]

#define STATIC_ASSERT_SIZEOF(t, s) STATIC_ASSERT (sizeof (t) == (s), #t)

#define clib_memcpy_fast(d, s, n) memcpy ((d), (s), (n))
#define clib_memcpy(d, s, n)	  memcpy ((d), (s), (n))
#define clib_memset(d, c, n)	  memset ((d), (c), (n))
#define clib_memcmp(a, b, n)	  memcmp ((a), (b), (n))

#endif /* __included_cilium_srv6_fuzz_stub_clib_h__ */
