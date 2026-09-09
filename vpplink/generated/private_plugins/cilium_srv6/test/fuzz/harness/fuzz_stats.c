/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Outcome bookkeeping shared by the replay and the libFuzzer link of every
 * target. Kept in its own translation unit so that both links get exactly
 * one definition of the counters.
 */

#include "cilium_fuzz.h"

unsigned long cilium_fuzz_n_runs;
unsigned long cilium_fuzz_outcome_count[CILIUM_FUZZ_MAX_OUTCOMES];

void
cilium_fuzz_record (unsigned outcome)
{
  CILIUM_FUZZ_ASSERT (outcome < CILIUM_FUZZ_MAX_OUTCOMES, "outcome=%u out of range", outcome);
  cilium_fuzz_n_runs++;
  cilium_fuzz_outcome_count[outcome]++;
}

void
cilium_fuzz_mark (unsigned outcome)
{
  CILIUM_FUZZ_ASSERT (outcome < CILIUM_FUZZ_MAX_OUTCOMES, "outcome=%u out of range", outcome);
  cilium_fuzz_outcome_count[outcome]++;
}
