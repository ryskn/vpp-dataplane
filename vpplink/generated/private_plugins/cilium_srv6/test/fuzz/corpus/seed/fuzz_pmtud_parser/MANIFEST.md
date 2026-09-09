# Seed corpus — fuzz_pmtud_parser

Starting points for the coverage-guided runs. These are small, mostly
well-formed inputs whose only job is to put the fuzzer inside the parser
instead of making it discover the IPv6 version nibble on its own. They are
replayed by the blocking PR gate as well, but nothing here is a regression
test: a seed that stops being interesting can be deleted.

Every file uses the 4 octet framing of `harness/cilium_fuzz.h`
(flags, avail_cut, chain_extra, then the packet).

| file | what it is |
| --- | --- |
| `001-ptb-plain-quote.bin` | a PTB quoting an IPv6-in-IPv6 packet |
| `002-ptb-quote-with-srh.bin` | the quote continues into an SRH |
| `003-destination-unreachable.bin` | NOT_PTB: type 1 |
| `004-ptb-quote-outer-only.bin` | a quote that stops after the quoted outer header |
