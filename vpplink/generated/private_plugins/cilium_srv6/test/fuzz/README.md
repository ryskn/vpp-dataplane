# cilium_srv6 parser fuzz targets

Fuzz harnesses, corpora and generators for the four bounded parsers of the
SRv6 Endpoint Context dataplane. Introduced by Issue #67; the plan-level
description lives in `design/test/test-plan.md` §5.8.

```
test/fuzz/
  build.sh              build and run everything
  stub/                 minimal vlib-free stand-ins for the VPP headers
  harness/              one target per parser + the shared replay driver
  generators/           the deterministic input matrices
  corpus/seed/          coverage-guided starting points
  corpus/regression/    inputs that pin a decision, replayed on every PR
  mutants/              test-only mutations for the negative control
```

## Why this exists

From the decision recorded on Issue #67:

> Security-critical parser の fuzz harness、seed corpus、regression corpus を
> repository の一部として維持する。各 PR では、harness が standalone で
> build 可能であること、および ASan/UBSan 付きで deterministic regression
> corpus を全件通過することを必須の blocking test とする。
>
> Coverage-guided fuzzing は継続的探索として実施する。PR では固定時間の
> short fuzz を実施してよいが、security regression の主要な gate は
> deterministic corpus と sanitizer とする。長時間の coverage-guided fuzz は
> nightly で実施し、新しい crash/coverage-relevant input は minimize 後に
> repository corpus へ還元する。
>
> 過去 PR で記録された fuzz run 数は当時の verification evidence であり、
> その探索過程そのものを再現可能とみなさない。今回の infra 収載の目的は、
> 今後の parser 変更に対して同じ target と既知入力を継続的に再検証可能に
> することである。

So the number to look at is not "how many runs did we do". It is "does the
same set of inputs still produce the same verdicts, and does the harness
still notice when they do not".

## Targets

Each target owns one parser and therefore one failure domain. A crash names
the component that has to be fixed.

| target | parser | responsibility |
| --- | --- | --- |
| `fuzz_guard_parser` | `cilium_srv6_gparse.h` | untrusted ingress header walk (03 §1.1, D-9/D-31/D-32/D-54) |
| `fuzz_end_cilium_parser` | `cilium_srv6_parse.h` | destination outer/SRH/inner validation and defence line (4) (03 §3, D-18/D-28) |
| `fuzz_headend_classify` | `cilium_srv6_hparse.h` | headend key derivation (02 §3, D-41/D-43) |
| `fuzz_pmtud_parser` | `cilium_srv6_pmtud_parse.h` | ICMPv6 PTB parse, CSID shift reconstruction, MTU arithmetic (02 §9, D-16/D-21) |

The post-conditions each target asserts are documented at the top of its
`harness/fuzz_<target>.c`, with the design rule each one comes from.

## Running it

```sh
./build.sh check            # the blocking PR gate: build + corpus + generators
./build.sh mutants          # the negative control
./build.sh fuzz 60          # 60 s of libFuzzer per target
./build.sh fuzz-one fuzz_guard_parser 3600
./build.sh check-full       # the nightly generator level
```

`check` runs in a few seconds locally and exercises 200k–430k inputs per
target under AddressSanitizer and UndefinedBehaviorSanitizer, with
`-fno-sanitize-recover` so that a UBSan report fails the run rather than
printing.

Requires clang. libFuzzer mode additionally requires the compiler-rt fuzzer
runtime, which Homebrew clang and the Ubuntu `clang` package both ship;
Apple's `/usr/bin/clang` does not, so on macOS use
`CC=/opt/homebrew/opt/llvm/bin/clang`.

## The standalone build is itself a test

None of this links vlib, vnet or any VPP global state. The four parser
headers are compiled against the wire-format stubs in `stub/`, which supply
`ip6_header_t`, `ip6_ext_header_t`, `ip6_frag_hdr_t`, `ip6_sr_header_t`,
`icmp46_header_t`, the `IP_PROTOCOL_*` values and about a dozen vppinfra
primitives — nothing else.

That is deliberate. If a parser helper starts depending on vlib, this build
stops working, and the blocking PR job reports it. **Do not widen `stub/` to
make such a change compile.** The parsers are meant to be pure functions of
the received octets; a build failure here is a design question.

The stubs pin their own layout with `STATIC_ASSERT` on struct sizes and on
the field offsets the parsers index, and `cilium_srv6_parse.h` contributes
its own assertion that the SRH fixed part is 8 octets. A stub that drifted
from VPP's layout would fuzz a different program than the one that ships, so
the assertions are the thing keeping the exercise honest.

## Input framing

A corpus file is not a bare packet. The parsers take three inputs — the
octets, how many are readable in the first buffer (`avail`), and the length
of the whole buffer chain (`chain_len`) — and the interesting bugs live in
the disagreements between the three. The last two are part of the input, in
a fixed 4 octet prefix:

| octet | meaning |
| --- | --- |
| 0 | flags. bit 0 target option, bit 7 `chain_len` is absolute rather than relative |
| 1 | `avail_cut`: octets removed from the end of the packet to form `avail` |
| 2–3 | `chain_extra`, big endian |
| 4+ | the packet |

```
avail     = packet_len - min(avail_cut, packet_len)
chain_len = (flags & 0x80) ? chain_extra : avail + chain_extra
```

`avail` octets are then copied into a heap block of **exactly** `avail`
octets. ASan poisons both sides, so a single octet read past the declared
readable area is a hard failure rather than a silent read of adjacent packet
bytes. That is the property the whole gate exists to hold.

## Corpus

Three kinds of input, kept apart because they have different lifetimes.

**`corpus/seed/<target>/`** — starting points for the coverage-guided runs.
Small, mostly well-formed. A seed that stops being useful can be deleted.

**`corpus/regression/<target>/`** — inputs that pin a decision: a past bug, a
boundary, or a case the design calls out. Replayed on every PR. Each file has
a line in the directory's `MANIFEST.md` saying what it pins. **An input with
no MANIFEST line must not be added** — without it nobody can later judge
whether removing the file is safe.

**`generators/gen_<target>.c`** — the matrices that are cheaper to generate
than to store. The 379k-input matrix of PR #56 lives here rather than as 379k
files in Git, per the decision: a deterministic generation rule produces a
deterministic corpus. Nothing in a generator may depend on the clock, the
host or an unseeded RNG; the only randomness is a xorshift with a literal
seed. Two levels: `--generate` for the PR gate, `--generate-full` for
nightly.

### Outcome coverage

`--require-outcomes` fails the run when an outcome the target declares
required was never produced. A corpus that can no longer reach a branch has
stopped testing it, usually because the parser changed. The blocking gate
passes this flag, so that failure mode is visible rather than silent.

## Promoting nightly findings

The nightly job uploads the corpus it produced whether or not it found
anything. A nightly that ends with 0 findings and no artifact has produced
nothing to review.

**A new coverage-inducing input:**

1. Download the `srv6-fuzz-nightly-corpus-<target>` artifact.
2. Merge it against the committed corpus and keep only what adds coverage:
   ```sh
   ./build.sh build-fuzzer
   mkdir -p /tmp/merged
   ./build/<target>_libfuzzer -merge=1 /tmp/merged \
       corpus/seed/<target> corpus/regression/<target> <downloaded-dir>
   ```
   `-merge=1` writes into the first directory only the inputs that add
   coverage over the later ones.
3. Read what the survivors actually do — run them through the replay binary
   and look at which outcome each produces. An input worth committing is one
   you can describe in a MANIFEST line.
4. Commit it to `corpus/seed/<target>/` with that line.

**A crash:**

1. Minimize it, so that what lands in the tree is the smallest input that
   still reproduces:
   ```sh
   ./build/<target>_libfuzzer -minimize_crash=1 -runs=100000 crash-<target>-<hash>
   ```
2. Commit the minimized input to `corpus/regression/<target>/` with a
   MANIFEST line naming the rule it violates, not just "crash found on
   2026-09-01".
3. Fix the parser. The committed input is what stops the bug coming back.

Keep the unminimized original in the artifact until the fix has merged;
minimization can change which path the input takes.

## Negative control

`./build.sh mutants` answers "would this harness notice?" without editing a
production file. `mutants/mutate.sh` writes a mutated **copy** of a parser
header into a scratch include directory placed ahead of the plugin directory
on the include path; the harness, the corpus and the generators are
unchanged. Each mutation must make the run fail, with an ASan report, a UBSan
error, or a post-condition failure.

Two mutants per target, one of each kind:

- a memory-safety mutation — the parse bound follows the attacker-declared
  payload length instead of the readable area — which shows the exact-size
  allocation and ASan are wired up;
- a semantic mutation — the D-54 counter split, the D-28 segments-left rule,
  the D-43 non-first-fragment rule, or the D-21 MTU arithmetic — which shows
  the post-conditions are doing work of their own. Without this second kind,
  a harness that only allocated correctly would look healthy.

Run on harness addition, on infra change, and nightly.

A mutation is a literal substitution on an anchor string that must appear
exactly once. If a refactor moves the anchor, `mutate.sh` fails with "found
0" rather than silently producing an unmutated copy that would make the
control pass for the wrong reason. **Update the anchor; do not delete the
mutant.**

## Adding a target

1. Write `harness/fuzz_<name>.c` defining `cilium_fuzz_target_name`,
   `cilium_fuzz_outcome_name[]`, `cilium_fuzz_outcome_required[]` and
   `cilium_fuzz_one()`. Document each post-condition with the design rule it
   comes from — an assertion nobody can trace back to a rule is one nobody
   can correctly weaken later.
2. Write `generators/gen_<name>.c` defining `cilium_fuzz_generate(int full)`.
3. Add the target to `TARGETS` and `target_header()` in `build.sh`, and to
   the nightly matrix in `.github/workflows/srv6-fuzz.yml`.
4. Add two rows to `mutants/mutants.tsv` and their cases to `mutate.sh`, and
   check that both are detected before relying on the target.
5. Seed `corpus/seed/<name>/` and `corpus/regression/<name>/`, each with a
   `MANIFEST.md`.
