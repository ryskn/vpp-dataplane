# Regression corpus — fuzz_headend_classify

Inputs that pin a decision. Each one is replayed on every PR, under
AddressSanitizer and UndefinedBehaviorSanitizer, and each one is here because
a specific rule of the design says what the parser must do with it — a past
bug, a boundary, or a case the specification calls out. Deleting a file here
removes a check; if a rule changes, change the description with it.

Every file uses the 4 octet framing of `harness/cilium_fuzz.h`
(flags, avail_cut, chain_extra, then the packet).

| file | what it pins |
| --- | --- |
| `001-d43-non-first-has-no-discriminator.bin` | D-43: a non-first fragment carries payload, not a header chain, so it must have no L4 discriminator, no ports and no TCP flags — only a FragmentVerdictCache hit can forward it |
| `002-d43-atomic-is-an-ordinary-packet.bin` | 01 §3.1: an atomic fragment is evaluated as a normal packet and gets no FragmentVerdictCache entry |
| `003-first-fragment-truncated-l4.bin` | RFC 8200 §4.5 / 01 §3.1: a first fragment that does not carry its complete L4 header is malformed rather than evaluated with a guessed discriminator |
| `004-tcp-header-too-short-for-flags.bin` | 02 §7.2: a TCP header too short to hold the control bits leaves them 0, which sends the packet to the ProgramCache rather than to a conntrack entry |
| `005-tcp-header-exactly-holds-flags.bin` | the boundary of the previous case: 14 octets is the first length at which the control bits are reported |
| `006-fragment-then-per-fragment-extension-header.bin` | RFC 8200 puts per-fragment extension headers after the Fragment header, which is why frag_next_header and not proto is the FragmentVerdictCache key component |
| `007-duplicate-fragment-header.bin` | 01 §3.1: a duplicate Fragment header is malformed |
| `008-routing-type-4-accepted.bin` | the classifier accepts Routing Type 4; the guard has already dropped it on an untrusted ingress |
| `009-routing-type-other-malformed.bin` | 01 §3.1: any other Routing Type is malformed |
| `010-nine-extension-headers.bin` | 01 §3.1 header count budget |
| `011-extension-header-byte-budget.bin` | 01 §3.1 byte budget |
| `012-authentication-header-length.bin` | AH length arithmetic differs from every other extension header |
| `013-protocol-without-ports.bin` | D-41: a protocol that is neither TCP, UDP nor ICMPv6 keeps discriminator 0 and reads no upper layer octets, so it is not a length violation |
| `014-declared-length-exceeds-chain.bin` | the declared length is checked against the chain before the walk starts |
| `015-declared-length-past-readable-area.bin` | the chain is long enough for the declaration but the first buffer is not; bound must follow the readable area |
| `016-icmp6-two-octet-header.bin` | ICMPv6 needs only its type and code octets, which is the shortest L4 read the discriminator makes |
