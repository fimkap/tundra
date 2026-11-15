# tundra

A user-space TCP/IP stack in C++23: Ethernet, ARP, IPv4, ICMP, UDP and TCP (RFC 9293, with NewReno loss
recovery), running on a Linux TAP device against the real Linux stack. It is single-threaded and keeps
errors as values, and its clock is injected, so the same code runs in real time on a device and in
virtual time in a simulator.

| Question | What the tests and measurements show (M1, Docker, Linux 7.0) |
|----------|---------------------------------------------------------------|
| [Does it talk to Linux?](#against-linux-over-tap) | Yes: ping, UDP and TCP echo, HTTP, and 20 parallel downloads. Bulk transfers both ways match SHA-256 byte for byte, clean and under 1–5% loss. |
| [Is it correct when the network isn't?](#how-its-tested) | It survives 200 random networks with loss, reordering and duplication. The fuzzers ran 38.6 million parser inputs and 598 thousand stack programs clean under ASan and UBSan. |
| [How fast is it?](#speed) | Against Linux it sent at 84 MiB/s and received at 38 MiB/s. Processing alone runs at 5.1 Gbit/s on one core, and the NEON checksum at 50–66 GB/s. |
| [What does loss recovery buy?](#loss-recovery) | At 1% loss NewReno kept 4× the goodput of timeout-only recovery: 6.6 vs 1.6 Mbit/s. |

## Quick start

All you need is Docker. `scripts/dev.sh` runs any command in a Debian trixie container with GCC 14, Clang 19
and the network tools.

**1. Build and run the tests** (about a minute the first time, while the container image builds):

```
scripts/dev.sh cmake --preset debug
scripts/dev.sh cmake --build --preset debug
scripts/dev.sh ctest --preset debug
```

There are 45 tests: the unit tests, scripted TCP exchanges, and the 200-network simulation. The `asan`
preset runs them under ASan and UBSan, and the `clang` preset with Clang.

**2. Talk to it from Linux.** This creates a TAP device in a container with `NET_ADMIN`, starts tundra on
it, and runs everything in [Against Linux over TAP](#against-linux-over-tap):

```
scripts/integration.sh
```

**3. Or poke at it by hand** inside `TUNDRA_PRIVILEGED=1 scripts/dev.sh bash`:

```
ip tuntap add dev tap0 mode tap && ip addr add 10.0.0.1/24 dev tap0 && ip link set tap0 up
cmake --preset release && cmake --build --preset release && ./build/release/tundra --dev tap0 --ip 10.0.0.2/24 &
ping 10.0.0.2
curl -sD- -o f http://10.0.0.2/bytes/1000000     # X-SHA256 header vs: sha256sum f
nc 10.0.0.2 7                                    # TCP echo
```

`--pcap file` records the traffic for Wireshark.

**4. Rerun the measurements:** `scripts/dev.sh scripts/bench.sh` and `scripts/dev.sh scripts/fuzz.sh 120`.
The raw reports are in [docs/results/](docs/results).

## How it works

```
 TapDevice (Linux)  |  SimLink (tests)          <- the driver boundary: frames in, frames out
        | receive(frame)        ^ transmit(frame)
 Stack: Ethernet -> ARP cache / IPv4 -> ICMP | UDP | TCP
        TimerQueue, driven by an injected Clock (CLOCK_MONOTONIC, or virtual in simulations)
        | callbacks: on_data, on_writable, on_peer_closed, on_closed
 apps/tundra: TCP echo :7, discard :9, UDP echo :7, HTTP :80
```

- **One thread, run to completion.** The event loop waits in epoll on the device and on a timerfd armed for
  the next deadline, so the stack needs no locks.
- **Wire formats are parsed, never cast.** Parsers check every length and return `std::expected`. Fields go
  through `load_be16/32`, never through a `reinterpret_cast` onto packet memory.
- **TCP follows RFC 9293's segment-arrival steps:**
  - all eleven states, including simultaneous open and close;
  - the four acceptability cases and trimming;
  - RFC 5961 challenge ACKs, and resets for segments that match no connection.
- **TCP sending:**
  - MSS and window scaling (RFC 7323), and an initial window of 10;
  - slow start, congestion avoidance and NewReno (RFC 5681, 6582);
  - RFC 6298 RTO with Karn's rule, zero-window probing, TIME-WAIT, and SipHash ISNs (RFC 6528).
- **Internally, sequence numbers are 64-bit offsets**, and only the wire uses 32 bits, which rules out a
  class of wrap bugs.
- **Not implemented:** SACK, timestamps, delayed ACKs, Nagle, IP fragmentation, IPv6.

The full scope, and the test that pins each rule, are in [docs/design.md](docs/design.md).

## Against Linux over TAP

[`scripts/integration.sh`](scripts/integration.sh) runs Linux's own tools against tundra: `ping`, `nc`,
`curl` and `sha256sum`. Loss is injected by tundra's device in both directions; extra delay comes from
`tc netem`. Each bulk row downloads from tundra (so tundra's TCP sends) and uploads the same bytes back (so
Linux's TCP sends). Both directions are checked with SHA-256
([report](docs/results/interop.md)):

| link | size | download MiB/s | upload MiB/s | download verified | upload verified |
|---|---:|---:|---:|---|---|
| clean | 64 MiB | 83.6 | 37.7 | yes | yes |
| 1% loss each way | 16 MiB | 5.6 | 13.2 | yes | yes |
| 1% loss each way, +5 ms delay | 8 MiB | 1.1 | 1.7 | yes | yes |
| 5% loss each way, +5 ms delay | 4 MiB | 0.2 | 0.4 | yes | yes |

The basics passed too: ping (0.18 ms average), UDP echo, TCP echo, HTTP, and 20 parallel 1 MiB
downloads, all verified.

Two things limit throughput:

- **Receiving is half the speed of sending.** tundra ACKs every segment (no delayed ACKs), so each received
  segment costs a read and a write.
- **Loss hurts because the timer floor is huge here.** Without SACK, NewReno repairs one hole per round
  trip. Anything it can't repair waits for the RTO, whose 200 ms floor is over a thousand round trips on
  this 0.2 ms link. Linux avoids that with SACK, RACK and tail-loss probes.

## Speed

From [docs/results/bench.md](docs/results/bench.md) (GCC 14, -O3):

**Stack processing cost.** A 16 MiB transfer between two stacks over an ideal in-memory link moved
5.14 Gbit/s of payload (444k segments/s). Both stacks and the link shared one core, so this measures segment
handling, checksums, copies and ACKs, without any network.

**The internet checksum, four ways**, on a buffer misaligned by one byte:

| variant | 64 B | 1500 B | 64 KiB |
|---|---:|---:|---:|
| scalar16 | 14.4 GB/s | 21.4 GB/s | 22.6 GB/s |
| wide64 | 14.5 GB/s | 21.1 GB/s | 12.9 GB/s |
| unrolled | 11.5 GB/s | 19.7 GB/s | 19.1 GB/s |
| simd (NEON) | 15.8 GB/s | 65.6 GB/s | 49.9 GB/s |

Getting the NEON row there took three tries, and each one was measured:

- **The textbook loop was already fast.** GCC auto-vectorized `scalar16` to 22 GB/s.
- **One accumulator was latency-bound at 17 GB/s**, since each pairwise add (UADALP) waits for the one
  before it.
- **Four UADALP accumulators split the compilers:** 7 GB/s under GCC, 69 GB/s under Clang.
- **Widening adds (UADDW) still ran at 7 GB/s** inside the library. The disassembly showed the only
  difference from the fast version: GCC had fused the two 16-byte loads into one `LDP`. Indexing from two
  bases makes it emit two `LDR`s, and the loop runs at 50–66 GB/s.

[`bench/neon_study.cpp`](bench/neon_study.cpp) keeps the variants side by side and is built with both
compilers. Measured on an M1 in Docker; why `LDP` is slow there isn't established. The SSE2 path was checked
for correctness under x86-64 emulation, but not for speed.

### Loss recovery

Goodput in virtual time on a simulated 50 Mbit/s link with a 40 ms round trip and 4 MB transfers, with the
same loss rate both ways, averaged over 5 seeds:

| loss each way | NewReno Mbit/s | timeout-only Mbit/s | NewReno fast retransmits | NewReno timeouts | timeout-only timeouts |
|---:|---:|---:|---:|---:|---:|
| 0.0% | 39.8 | 39.8 | 0.0 | 0.0 | 0.0 |
| 0.1% | 22.7 | 15.7 | 4.0 | 0.0 | 3.8 |
| 0.5% | 9.6 | 2.6 | 17.8 | 0.2 | 23.4 |
| 1.0% | 6.6 | 1.6 | 28.2 | 0.8 | 42.4 |
| 2.0% | 3.7 | 0.9 | 48.6 | 2.8 | 79.0 |
| 5.0% | 1.5 | 0.5 | 111.6 | 16.4 | 172.0 |

Three duplicate ACKs repair a loss within a round trip; without them, every loss waits out the timer.

## How it's tested

| Layer | What it shows |
|-------|---------------|
| Unit (GoogleTest) | Parsers round-trip and reject malformed input. The four checksum variants agree for every length and alignment up to 2 MiB. SHA-256 matches the NIST vectors. |
| Scripted TCP | Given these input segments, the stack sends exactly these: SYN-ACK options, duplicate ACKs for gaps, RSTs for closed ports, challenge ACKs, RTO back-off of 1 s, 2 s, 4 s. |
| Simulation | Two stacks over a lossy link on a virtual clock, with fast retransmit vs the timer and zero-window probing. Then 200 seeded random networks: up to 15% loss, 30 ms jitter, duplication, bandwidth caps and windows from 4 KiB. Every echo must come back exact and both ends must close. |
| Fuzzing (libFuzzer) | Arbitrary bytes into every parser, with checksums fixed up so the fuzzer reaches the options. Programs of segments, clock jumps and API calls into a live stack. Any UB aborts. |
| Interop | Linux on the other side of a TAP device, as above. |

Any failing simulation can be replayed alone and captured for tcpdump:
`SIM_SEED=2 SIM_PCAP=/src/build/seed2.pcap ./build/debug/tundra_tests --gtest_filter=SimProperty*`.

What the checks caught:

- **An ACK war** (the 200-network test). After both ends timed out and rewound for go-back-N, their pure ACKs
  carried the rewound sequence number. Each end saw the other's ACKs as old duplicates and dropped them
  unprocessed, so they traded ACKs until one side gave up. A replayed seed's pcap in tcpdump showed it.
  Pure ACKs now carry `snd_max`, as BSD's `tcp_output` does.
- **A stall after a zero window** (the zero-window test). A window update that acknowledged nothing new
  cancelled the probe timer but never resumed sending.
- **Undefined behaviour in the send buffer** (fuzzing under UBSan). `memcpy` from an empty span's null
  pointer.
- **An overflow in the reference checksum itself** (the checksum property test). Its 32-bit sum overflowed
  past 128 KiB.

## How it was built

I chose the problem, a user-space TCP/IP stack for low-level and networking roles, and the constraints:
tested against Linux, measured, and built in Docker. Claude Code drafted the spec and wrote the code in
steps. [docs/ai-workflow.md](docs/ai-workflow.md) shows what kept that work checkable:

- the invariants in [AGENTS.md](AGENTS.md);
- the guardrails in [.claude/](.claude);
- the test layers above.

## Layout

| Path | Contents |
|------|----------|
| `include/tundra/`, `src/` | bytes, checksum, wire, stack, tcp, timers, sim, pcap, sha256 |
| `src/dev/linux.cpp`, `apps/tundra.cpp` | TAP/TUN device and event loop; the demo app |
| `tests/`, `fuzz/`, `bench/` | GoogleTest, libFuzzer, benchmarks and the NEON study |
| `scripts/` | `dev.sh` (the container), `integration.sh`, `fuzz.sh`, `bench.sh` |

MIT licensed.
