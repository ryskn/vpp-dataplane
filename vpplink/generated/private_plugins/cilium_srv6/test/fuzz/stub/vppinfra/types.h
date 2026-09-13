/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Test-only stand-in for <vppinfra/types.h>.
 *
 * In VPP this header defines the integer type names and <vppinfra/clib.h>
 * includes it. The stub is the other way round for no deeper reason than that
 * the stub clib.h came first and already defines them, so this file exists to
 * let a header that includes vppinfra/types.h directly - as
 * cilium_srv6_ifbind_rules.h and cilium_srv6_localep_rules.h do - build
 * against the stubs at all. It widens the stub surface by nothing.
 *
 * This file is never compiled into the plugin. It exists only on the
 * -I search path of the host-side checks under vpp/plugins/cilium_srv6/test.
 */

#ifndef __included_cilium_srv6_fuzz_stub_types_h__
#define __included_cilium_srv6_fuzz_stub_types_h__

#include <vppinfra/clib.h>

#endif /* __included_cilium_srv6_fuzz_stub_types_h__ */
