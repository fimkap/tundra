# tundra — design spec

A user-space TCP/IP stack in modern C++ (C++23). It runs on a Linux TAP or TUN device: the kernel hands
it raw Ethernet frames or IP packets, and tundra answers ARP, ping, UDP and TCP itself. It is a teaching
stack in size, around 4,000 lines, but it is held to the standards of a production one:

- it interoperates with the Linux TCP stack across real packet loss;
- every change survives a deterministic simulation run over hundreds of lossy, reordering networks;
- it is fuzzed, and it runs clean under ASan and UBSan.

This spec was written before the code. When the two disagree, one of them is a bug.

## Scope

| Layer | In | Out (for now) |
|-------|----|---------------|
| Device | TAP (Ethernet frames), TUN (IP packets), an in-memory simulated link | io_uring, multi-queue, offloads |
| L2 | Ethernet II, ARP (request, reply, cache, queue packets while resolving) | VLANs, IPv6 neighbour discovery |
| L3 | IPv4: validation, checksum, TTL, ICMP echo, ICMP port unreachable | fragmentation (fragments are dropped; DF is set), options (skipped), IPv6, routing beyond one subnet plus a gateway |
| L4 | UDP; TCP per RFC 9293 | SACK, timestamps, ECN, Nagle, delayed ACKs |

## Architecture

```
  NetDevice (TAP | TUN | SimLink)        <- the "driver": frames in, frames out
        |  receive(frame)      ^ transmit(frame)
  +-----v----------------------+-----------------------------+
  | Stack                                                     |
  |   Ethernet -> ARP cache / IPv4 -> ICMP | UDP | TCP demux  |
  |   TimerQueue (driven by a Clock: real, or virtual in sims)|
  +-----------------------------------------------------------+
        |  callbacks
  apps: echo, discard, HTTP/1.0, bulk sender/receiver
```

- **Single-threaded, run to completion.** The event loop (epoll on the device fd, plus a timerfd for the
  next deadline) calls `Stack::receive(frame)` and `Stack::advance(now)`. There are no locks in the stack.
- **The clock is injected.** Tests and simulations drive a virtual clock, so a 30-second RTO back-off takes
  microseconds and every run is reproducible from its seed.
- **Errors are values.** Parsers return `std::expected<Header, ParseError>`, so malformed input never throws
  and never reads past the buffer. A fuzzer tests that claim.

## Wire formats (`include/tundra/wire`)

There is a header struct per protocol, with `parse(std::span<const std::byte>)` and
`serialize(std::span<std::byte>)`. Multi-byte fields are read with explicit big-endian loads (no
`reinterpret_cast` onto packet memory, so no alignment or aliasing UB). Checksums:

- IPv4 header checksum over the header;
- ICMP over the message;
- UDP and TCP over the RFC 768/9293 pseudo-header plus the segment.

### Internet checksum (RFC 1071), four ways

| Variant | Idea |
|---------|------|
| `scalar16` | add 16-bit words into a 32-bit sum, fold at the end: the textbook loop |
| `wide64` | add 32-bit words into a 64-bit accumulator, fold once at the end |
| `unrolled` | `wide64` with four independent accumulators, so the CPU can run the adds in parallel (ILP) |
| `simd` | NEON on arm64 (`vpadalq_u16`), SSE2 on x86-64, scalar elsewhere |

Every variant must give the same result as `scalar16` for every length and alignment. A property test
checks that over random buffers, and the benchmark measures GB/s per variant and size.

## TCP (`include/tundra/tcp`)

- **States:** all eleven of RFC 9293, including simultaneous open and close.
- **Sequence numbers:** modulo 2^32 arithmetic (`seq_lt`, `seq_le`, ...), tested across the wrap.
- **ISN:** RFC 6528, a keyed hash (SipHash-2-4) of the 4-tuple plus a 4 µs clock.
- **Options:** MSS (sent and honoured) and window scale (RFC 7323). SACK-permitted and timestamps are
  parsed and ignored.
- **Sending:**
  - data goes out as soon as `min(cwnd, rwnd)` allows (no Nagle), in MSS-sized segments;
  - the send buffer holds unacknowledged bytes, so a retransmission re-reads them from there.
- **Receiving:**
  - in-order data goes into a bounded receive buffer;
  - out-of-order segments wait in a reassembly map and are merged when the gap fills;
  - the advertised window is the free space;
  - every segment is ACKed at once; out-of-order arrivals produce duplicate ACKs.
- **Retransmission (RFC 6298):**
  - SRTT, RTTVAR and RTO, with a 200 ms floor (Linux's) and a 60 s ceiling;
  - Karn's rule: no RTT samples from retransmitted data;
  - exponential back-off;
  - after 8 consecutive timeouts the connection is reset.
- **Congestion control (RFC 5681 / 6582, NewReno):** slow start, congestion avoidance, fast retransmit on
  three duplicate ACKs, fast recovery with partial-ACK handling.
- **Zero window:** a persist timer probes with one byte at RTO intervals.
- **Closing:** FIN handling in every state, TIME-WAIT for 2×MSL (MSL configurable, 30 s default), and
  RST for segments that match no connection (RFC 9293 §3.10.7.1).
- **API:** callbacks, not blocking calls. `listen(port, on_accept)`, `connect(addr, port, on_connected)`;
  a connection has `send(bytes) -> accepted`, `on_data`, `on_writable`, `close()`, `abort()`, `on_closed`.

## Devices (`src/dev`)

- `TapDevice` / `TunDevice`: open `/dev/net/tun`, `TUNSETIFF` with `IFF_TAP|IFF_NO_PI` or
  `IFF_TUN|IFF_NO_PI`, non-blocking reads and writes. The interface itself is configured outside, with
  `ip link` and `ip addr`.
- `SimLink`: two endpoints joined in memory. Per direction it has a delay, jitter (which reorders), a
  loss probability, a duplicate probability and a bandwidth cap, all from a seeded PRNG on a virtual
  clock. Simulations and most TCP tests run on it.
- A pcap writer can record any device's traffic for Wireshark.

## Testing

| Kind | What it proves |
|------|----------------|
| Unit (GoogleTest) | parsers and serializers round-trip; checksums agree; sequence arithmetic wraps; ARP cache and timers behave |
| Scripted TCP (packetdrill style) | given these input segments, the stack emits exactly these, including SYN-ACK options, RST on a closed port, the FIN states, zero-window probes, RTO back-off |
| Simulation | for 200 seeds with loss up to 20%, duplication and reordering, a client sends random data to an echo server and gets exactly the same bytes back, and both sides close cleanly |
| Fuzzing (libFuzzer) | arbitrary frames into the parsers and into a live stack never crash, under ASan and UBSan |
| Integration (Docker, `NET_ADMIN`) | against the real Linux stack over a TAP device: `ping`, `curl`, UDP echo, and multi-megabyte transfers verified by SHA-256, with and without `tc netem` loss |

## Experiments

1. Checksum variants: GB/s for 64 B, 1500 B and 64 KiB buffers.
2. Stack processing cost: a bulk transfer between two stacks over an ideal in-memory link, in Gbit/s of
   CPU time and ns per segment.
3. Loss: goodput and retransmissions over a simulated 10 ms RTT link at 0-10% loss, in virtual time.
4. Interop: Linux client to tundra over TAP, with `tc netem` loss, SHA-256 verified.

## Build

CMake presets (`debug`, `release`, `asan`, `fuzz`, `bench`) with Ninja. GoogleTest and Google Benchmark
come in through FetchContent at pinned versions. Everything builds and runs in a Debian trixie container
with GCC 14 and Clang 19 (`scripts/dev.sh`). The stack's core has no Linux headers, so it compiles on
macOS too; only the TAP/TUN devices and the event loop are Linux-specific.
