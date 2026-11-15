# Agent instructions for tundra

Read this before changing anything. It is the shared context for any coding agent (Claude Code reads it
through `CLAUDE.md`).

## What this is

A user-space TCP/IP stack in C++23 over Linux TAP/TUN: Ethernet, ARP, IPv4, ICMP, UDP and TCP
(RFC 9293 with NewReno). The spec is [`docs/design.md`](docs/design.md). **Change the spec first, then the
code.**

## Map

| Path | What lives there |
|------|------------------|
| `include/tundra/bytes.hpp`, `checksum.hpp` | big-endian loads and stores; the internet checksum (four variants) |
| `include/tundra/wire.hpp` | header structs: parse and serialize, `std::expected` errors |
| `include/tundra/clock.hpp`, `timers.hpp` | injected clock (real or virtual), timer queue |
| `include/tundra/tcp.hpp`, `src/tcp.cpp` | sequence arithmetic, the connection state machine, congestion control |
| `include/tundra/stack.hpp`, `src/stack.cpp` | the stack: ARP, IPv4, ICMP, UDP, TCP demultiplexing |
| `include/tundra/sim.hpp`, `pcap.hpp`, `sha256.hpp` | the simulated link, the pcap writer, SHA-256 |
| `include/tundra/linux.hpp`, `src/dev/linux.cpp` | TAP/TUN device and the epoll + timerfd event loop (Linux only) |
| `apps/tundra.cpp` | the app: echo, discard, UDP echo, HTTP with SHA-256 checks |
| `tests/`, `fuzz/`, `bench/` | GoogleTest, libFuzzer (`fuzz_parsers`, `fuzz_stack`), benchmarks and the NEON study |
| `scripts/` | `dev.sh` (the container), `integration.sh`, `fuzz.sh`, `bench.sh` |

## Commands (all inside the container via `scripts/dev.sh`)

```
scripts/dev.sh cmake --preset debug && scripts/dev.sh cmake --build --preset debug
scripts/dev.sh ctest --preset debug             # unit + scripted TCP + simulation tests
scripts/dev.sh ctest --preset asan              # the same under ASan + UBSan (clang)
scripts/dev.sh scripts/fuzz.sh 60               # both fuzzers for 60 s, in parallel
scripts/dev.sh scripts/bench.sh                 # checksum and stack benchmarks
scripts/integration.sh                          # privileged container: TAP + ping/curl/netem against Linux
```

## Invariants — never break these

1. **Never read outside the input span.** Parsers check lengths and return `std::unexpected(ParseError)`;
   the fuzzers exist to prove it.
2. **No type punning on packet memory.** Read fields with `load_be16/32`, write with `store_be16/32`; no
   `reinterpret_cast` to header structs.
3. **Sequence numbers are compared only with `seq_lt`, `seq_le`, `seq_gt`, `seq_ge`** (modulo 2^32), never
   with `<` on raw values.
4. **No wall-clock reads in the stack.** Time comes from the injected `Clock`; tests use `ManualClock`, so
   they never sleep and never flake.
5. **Every checksum variant equals `scalar16`** for every length and alignment.
6. **A TCP change cites its RFC section** in a comment and comes with a scripted test, and the simulation
   suite (200 seeds) must still pass.

## Conventions

- C++23 (GCC 14, Clang 19). `clang-format` (config in repo), warnings on and clean (`-Wall -Wextra
  -Wpedantic -Wshadow`).
- Types `PascalCase`, functions and variables `snake_case`, constants `kPascalCase`.
- No exceptions on the data path; `std::expected` for fallible parsing. RAII for file descriptors.
- Dependencies only through CMake `FetchContent` at pinned tags (GoogleTest, Google Benchmark).

## Workflow

1. Small steps; each commit builds with both GCC and Clang and passes `ctest`.
2. Benchmark and interop numbers in the README come only from saved script output in `docs/results/`, with
   the machine they ran on. Never edit a number by hand.

## Guardrails

- Never `git push`. Never run anything with `--privileged` or `NET_ADMIN` outside `scripts/integration.sh`.
- Never configure network interfaces on the host; the TAP device lives inside the integration container.
