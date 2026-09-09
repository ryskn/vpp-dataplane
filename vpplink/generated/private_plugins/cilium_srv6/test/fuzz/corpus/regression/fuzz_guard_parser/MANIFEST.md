# Regression corpus — fuzz_guard_parser

Inputs that pin a decision. Each one is replayed on every PR, under
AddressSanitizer and UndefinedBehaviorSanitizer, and each one is here because
a specific rule of the design says what the parser must do with it — a past
bug, a boundary, or a case the specification calls out. Deleting a file here
removes a check; if a rule changes, change the description with it.

Every file uses the 4 octet framing of `harness/cilium_fuzz.h`
(flags, avail_cut, chain_extra, then the packet).

| file | what it pins |
| --- | --- |
| `001-d54-first-fragment-truncated-inner.bin` | D-54: the inner IPv6 header does not fit in the offset-zero fragment, so the fragment must be DROP_UNINSPECTABLE_FRAGMENT and never PASS |
| `002-d54-first-fragment-chain-ends-at-bound.bin` | D-54: the chain ends exactly at the fragment boundary, so the upper layer header lives entirely in a later fragment. off == bound must be refused |
| `003-d54-atomic-fragment-truncated.bin` | RFC 6946: an atomic fragment is an ordinary packet, so the same truncation is DROP_MALFORMED and not DROP_UNINSPECTABLE_FRAGMENT (the D-54 counter split) |
| `004-d54-non-first-fragment-passes.bin` | D-54: offset != 0 carries payload, not a header chain, so it passes on the outer destination check the caller already made |
| `005-rfc7112-fragment-before-routing.bin` | RFC 7112 forbids this ordering; the unconditional D-32 Routing drop must still win over the fragment classification |
| `006-routing-header-not-readable.bin` | D-32 is unconditional: a Routing Next Header is a drop even when the header itself is not readable, so no bound check may precede it |
| `007-duplicate-fragment-header.bin` | 01 §3.1: a duplicate Fragment header is malformed, classified by the first one |
| `008-nine-extension-headers.bin` | 01 §3.1 header count budget: nine headers must fail closed, or a long chain hides an SRH from the guard |
| `009-extension-header-byte-budget.bin` | 01 §3.1 byte budget: 272 octets of extension headers exceeds 256 |
| `010-zero-length-extension-header.bin` | the smallest extension header the walk accepts; hlen arithmetic must advance |
| `011-authentication-header-length.bin` | AH is measured in 4 octet units and excludes 8 octets, unlike every other extension header |
| `012-declared-length-past-readable-area.bin` | the declared payload length runs far past the first buffer: bound must follow the readable area, not the declaration |
| `013-readable-area-truncated-mid-inner.bin` | the inner destination is only half readable; the block comparison must not be made on octets that are not there |
| `014-chain-shorter-than-readable-area.bin` | a caller reporting a chain shorter than the first buffer must not produce a read past either |
| `015-inner-version-nibble-not-6.bin` | an inner header that is not IPv6 is a parse failure, not an accept |
| `016-mobility-hip-shim6-chain.bin` | the three less common extension header types the walk accepts |
