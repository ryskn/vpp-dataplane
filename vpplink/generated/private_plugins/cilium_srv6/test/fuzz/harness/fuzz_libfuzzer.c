/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * libFuzzer entry point, shared by all four targets. The coverage-guided run
 * and the deterministic replay run therefore exercise byte-for-byte the same
 * cilium_fuzz_one(), which is what makes a crash found by the nightly job
 * reproducible by committing its input to corpus/regression/.
 */

#include "cilium_fuzz.h"

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

int
LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  cilium_fuzz_one (data, size);
  return 0;
}
