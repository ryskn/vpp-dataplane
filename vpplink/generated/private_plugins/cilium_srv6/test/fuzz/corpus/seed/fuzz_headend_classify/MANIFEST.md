# Seed corpus — fuzz_headend_classify

Starting points for the coverage-guided runs. These are small, mostly
well-formed inputs whose only job is to put the fuzzer inside the parser
instead of making it discover the IPv6 version nibble on its own. They are
replayed by the blocking PR gate as well, but nothing here is a regression
test: a seed that stops being interesting can be deleted.

Every file uses the 4 octet framing of `harness/cilium_fuzz.h`
(flags, avail_cut, chain_extra, then the packet).

| file | what it is |
| --- | --- |
| `001-tcp.bin` | TCP: discriminator is the destination port |
| `002-udp.bin` | UDP: same key shape, different protocol |
| `003-icmp6.bin` | ICMPv6: discriminator is (type << 8) | code |
| `004-first-fragment.bin` | D-43 FIRST |
| `005-non-first-fragment.bin` | D-43 NON_FIRST |
| `006-atomic-fragment.bin` | D-43 ATOMIC |
