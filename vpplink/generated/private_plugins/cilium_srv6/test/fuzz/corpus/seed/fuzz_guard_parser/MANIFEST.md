# Seed corpus — fuzz_guard_parser

Starting points for the coverage-guided runs. These are small, mostly
well-formed inputs whose only job is to put the fuzzer inside the parser
instead of making it discover the IPv6 version nibble on its own. They are
replayed by the blocking PR gate as well, but nothing here is a regression
test: a seed that stops being interesting can be deleted.

Every file uses the 4 octet framing of `harness/cilium_fuzz.h`
(flags, avail_cut, chain_extra, then the packet).

| file | what it is |
| --- | --- |
| `001-tcp-no-extension-headers.bin` | the minimal PASS |
| `002-ipv6-in-ipv6-outside-block.bin` | one level of encapsulation, PASS |
| `003-ipv6-in-ipv6-inside-block.bin` | DROP_INNER_BLOCK_DA |
| `004-outer-routing-header.bin` | DROP_ROUTING_HDR |
| `005-non-first-fragment.bin` | PASS_NON_FIRST_FRAGMENT |
| `006-first-fragment-complete.bin` | first fragment carrying its whole chain |
| `007-dstopt-then-tcp.bin` | an extension header in front of the upper layer header |
