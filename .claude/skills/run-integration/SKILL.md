---
name: run-integration
description: Run tundra's interop test against the Linux TCP/IP stack over a TAP device and interpret failures. Use after changes to the stack, the TAP device, the event loop or the app.
---

# Interop with Linux

1. `scripts/integration.sh` (or `--record` to update `docs/results/interop.md`). It runs inside the dev
   container with `NET_ADMIN` and `/dev/net/tun`. Never configure interfaces on the host.
2. A failing basic check (ping, echo, HTTP) usually means ARP or IPv4: rerun by hand with `--pcap` and read
   the capture with `tcpdump -nn -e -r`.
3. A SHA-256 mismatch is a TCP bug, never "flakiness". Record a pcap of a smaller transfer, find the first
   segment where the two sides disagree on seq/ack, and write a scripted test that reproduces it before
   fixing.
4. Throughput numbers move between runs on a laptop. Compare ratios, record the whole report, and never
   edit a number by hand.
5. If `tc netem` is unavailable, the script says so and the delay rows run without delay; loss still comes
   from tundra's `--loss`.
