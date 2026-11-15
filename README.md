# tundra

A user-space TCP/IP stack in C++23: Ethernet, ARP, IPv4, ICMP, UDP and TCP (RFC 9293, with NewReno loss
recovery), designed to run over a Linux TAP/TUN device. It is single-threaded, injects its clock, and keeps
errors as values. It is tested the way a production stack should be:

- scripted packet exchanges;
- deterministic simulations over hundreds of lossy, reordering networks;
- ASan and UBSan.

It was built with an AI coding agent from a spec written first ([docs/design.md](docs/design.md)). The
agent context is in [AGENTS.md](AGENTS.md), [CLAUDE.md](CLAUDE.md) and [.claude/](.claude).

## Status

| Done | Still to do |
|------|-------------|
| Wire formats with `std::expected` parsers; the internet checksum in four variants (scalar, 64-bit, unrolled, NEON/SSE2) | TAP/TUN device and epoll event loop (`apps/tundra`) |
| ARP, IPv4, ICMP echo and port unreachable, UDP | libFuzzer targets; checksum and throughput benchmarks |
| TCP: all 11 states, MSS, window scaling, RFC 6298 RTO, slow start, NewReno fast recovery, zero-window probing, RFC 5961 challenge ACKs, RFC 6528 ISNs | Interop with Linux over TAP (`ping`, `curl`, `tc netem`, SHA-256-verified transfers) |
| A simulated link on a virtual clock, with delay, jitter, loss, duplication and bandwidth | Results in the README; CI |

## Build and test

Everything runs in a Debian trixie container (GCC 14, Clang 19), so you need only Docker:

```
scripts/dev.sh cmake --preset debug
scripts/dev.sh cmake --build --preset debug
scripts/dev.sh ctest --preset debug          # or --preset asan, --preset clang
```

All 43 tests pass under GCC, Clang, and ASan with UBSan. One of them echoes random data across 200 seeded
random networks and checks every byte. To replay a single network and capture it for tcpdump or
Wireshark:

```
scripts/dev.sh bash -c 'SIM_SEED=2 SIM_PCAP=/src/build/seed2.pcap ./build/debug/tundra_tests --gtest_filter=SimProperty*'
```

## What the tests caught

- **The 200-network test found an ACK war.** After both ends timed out and rewound for go-back-N, their
  pure ACKs carried the rewound sequence number. Each end treated the other's ACKs as old duplicates and
  dropped them unprocessed, so they traded ACKs until one side gave up. Pure ACKs now carry `snd_max`,
  as BSD does.
- **The zero-window test found a stall.** A window update that acknowledged nothing new never resumed
  sending.
- **The checksum property test caught the reference implementation.** Its 32-bit sum overflowed past
  about 128 KiB of input.

MIT licensed.
