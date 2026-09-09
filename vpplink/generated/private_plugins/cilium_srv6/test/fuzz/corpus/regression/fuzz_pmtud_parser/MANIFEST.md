# Regression corpus — fuzz_pmtud_parser

Inputs that pin a decision. Each one is replayed on every PR, under
AddressSanitizer and UndefinedBehaviorSanitizer, and each one is here because
a specific rule of the design says what the parser must do with it — a past
bug, a boundary, or a case the specification calls out. Deleting a file here
removes a check; if a rule changes, change the description with it.

Every file uses the 4 octet framing of `harness/cilium_fuzz.h`
(flags, avail_cut, chain_extra, then the packet).

| file | what it pins |
| --- | --- |
| `001-ptb-wrong-code.bin` | RFC 4443 §3.2: Packet Too Big is code 0; any other code is not a PTB |
| `002-extension-header-before-icmp6.bin` | ip6-icmp-input reads the ICMPv6 header at a fixed offset of 40, so a packet with extension headers in front of it is refused rather than walked |
| `003-quote-shorter-than-ipv6-header.bin` | a quote too short to hold an IPv6 header is not correlatable and is refused |
| `004-quote-truncated-inside-srh.bin` | 01 §2.4: a transit node only quotes what fits in 1280 octets, so a truncated SRH is reported as absent rather than as malformed |
| `005-quote-srh-wrong-routing-type.bin` | a readable quoted SRH with a Routing Type other than 4 is malformed, not absent |
| `006-quote-inner-version-nibble-not-6.bin` | the quoted inner header must be IPv6 |
| `007-ptb-mtu-below-minimum.bin` | 02 §9: below the RFC 8200 minimum link MTU of 1280 the report is out of range |
| `008-ptb-mtu-at-minimum.bin` | the boundary of the previous case |
| `009-ptb-mtu-full-width.bin` | D-21: an MTU that cannot be an IPv6 link MTU is out of range, never a value to truncate into u16 |
| `010-ptb-mtu-just-under-u16.bin` | the largest MTU the u16 store can hold |
| `011-icmp6-header-not-readable.bin` | the ICMPv6 fixed part plus MTU field must be complete before either is read |
| `012-declared-length-past-readable-area.bin` | bound must follow the readable area rather than the declared payload length |
| `013-declared-length-exceeds-chain.bin` | the declared length is checked against the chain first |
| `014-quoted-outer-length-full-width.bin` | the quoted outer size is attacker-controlled and feeds the 02 §9 range comparison |
| `015-not-icmp6-at-all.bin` | an outer protocol other than ICMPv6 is NOT_PTB, decided before any ICMPv6 field is read |
| `016-quote-srh-four-segments.bin` | the longest quoted SRH that still leaves the inner header inside a 1280 octet ICMPv6 error |
