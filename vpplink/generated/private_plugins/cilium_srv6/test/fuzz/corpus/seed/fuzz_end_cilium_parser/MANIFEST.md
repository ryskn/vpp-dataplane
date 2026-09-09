# Seed corpus — fuzz_end_cilium_parser

Starting points for the coverage-guided runs. These are small, mostly
well-formed inputs whose only job is to put the fuzzer inside the parser
instead of making it discover the IPv6 version nibble on its own. They are
replayed by the blocking PR gate as well, but nothing here is a regression
test: a seed that stops being interesting can be deleted.

Every file uses the 4 octet framing of `harness/cilium_fuzz.h`
(flags, avail_cut, chain_extra, then the packet).

| file | what it is |
| --- | --- |
| `001-no-srh-to-endpoint.bin` | the minimal accepted packet |
| `002-srh-one-segment.bin` | accepted with an SRH to remove |
| `003-srh-with-padn-tlv.bin` | accepted with a TLV area |
| `004-inner-destination-mismatch.bin` | IP_MISMATCH |
| `005-inner-udp.bin` | an inner protocol with a shorter upper layer header |
