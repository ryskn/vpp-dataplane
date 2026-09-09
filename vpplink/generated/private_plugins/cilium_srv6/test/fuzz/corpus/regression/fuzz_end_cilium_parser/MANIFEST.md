# Regression corpus — fuzz_end_cilium_parser

Inputs that pin a decision. Each one is replayed on every PR, under
AddressSanitizer and UndefinedBehaviorSanitizer, and each one is here because
a specific rule of the design says what the parser must do with it — a past
bug, a boundary, or a case the specification calls out. Deleting a file here
removes a check; if a rule changes, change the description with it.

Every file uses the 4 octet framing of `harness/cilium_fuzz.h`
(flags, avail_cut, chain_extra, then the packet).

| file | what it pins |
| --- | --- |
| `001-d28-srh-segments-left-nonzero.bin` | D-28: the SRH is only removed at the end of the segment list. A packet with segments still to visit must not be decapsulated here |
| `002-defence-line-4-wrong-endpoint.bin` | 04 §4 defence line (4): a stale route must not deliver a packet to the wrong Pod, so a mismatching inner destination is IP_MISMATCH and decap_len stays 0 |
| `003-srh-unknown-routing-type.bin` | 01 §3.1: a Routing Type other than 4 is malformed |
| `004-srh-last-entry-past-header-end.bin` | RFC 8754 §2.1: Last Entry claims 16 segments in a header that holds one |
| `005-srh-padn-past-header-end.bin` | a PadN whose declared length runs past the SRH end; the TLV walk must stop at the SRH boundary and not at the buffer boundary |
| `006-srh-tlv-length-octet-missing.bin` | a TLV whose type octet is the last octet of the SRH, so its length octet is outside |
| `007-srh-next-header-not-ipv6.bin` | 01 §3.2: the SRH must be followed by the inner IPv6 packet |
| `008-declared-length-exceeds-chain.bin` | 01 §3.2: the declared outer length is checked against the buffer chain before anything past the outer header is read |
| `009-inner-declared-longer-than-outer.bin` | the inner packet must fit in what the outer header declared |
| `010-inner-duplicate-fragment-header.bin` | 01 §3.1: a duplicate Fragment header in the inner chain is malformed |
| `011-inner-non-first-fragment.bin` | an inner non-first fragment ends the chain walk without an upper layer header |
| `012-inner-nine-extension-headers.bin` | 01 §3.1 header count budget on the inner chain |
| `013-inner-extension-header-byte-budget.bin` | 01 §3.1 byte budget on the inner chain |
| `014-inner-header-split-across-buffers.bin` | a chain that splits the L3 headers is refused rather than walked |
| `015-outer-next-header-neither-route-nor-ipv6.bin` | only Routing and IPv6 may follow the outer header |
| `016-srh-only-pad1-tlv-area.bin` | eight Pad1 octets: the TLV walk must terminate exactly on the SRH end |
