# Benchmarks

- Linux 7.0.14-linuxkit aarch64, 4 CPUs, g++-14 (Debian 14.2.0-19) 14.2.0, -O3 Release, inside Docker
- run at 2026-11-15 22:30 UTC

## Internet checksum

Throughput of the one's-complement sum over a buffer misaligned by one byte.

| variant | 64 B | 1500 B | 64 KiB |
|---|---:|---:|---:|
| scalar16 | 14.4 GB/s | 21.4 GB/s | 22.6 GB/s |
| wide64 | 14.5 GB/s | 21.1 GB/s | 12.9 GB/s |
| unrolled | 11.5 GB/s | 19.7 GB/s | 19.1 GB/s |
| simd (NEON) | 15.8 GB/s | 65.6 GB/s | 49.9 GB/s |

## Stack processing cost

A 16 MiB bulk transfer between two stacks in one process over an ideal in-memory link, real CPU time;
both stacks and the simulated link share one core.

| payload throughput | segments/s | time per 16 MiB |
|---:|---:|---:|
| 5.14 Gbit/s | 444k | 26.1 ms |

## Loss recovery

Goodput in virtual time on a simulated 50 Mbit/s link with a 40 ms round trip, 4 MB transfers, the same
loss rate in both directions, averaged over 5 seeds.

| loss each way | NewReno Mbit/s | timeout-only Mbit/s | NewReno fast retransmits | NewReno timeouts | timeout-only timeouts |
|---:|---:|---:|---:|---:|---:|
| 0.0% | 39.8 | 39.8 | 0.0 | 0.0 | 0.0 |
| 0.1% | 22.7 | 15.7 | 4.0 | 0.0 | 3.8 |
| 0.5% | 9.6 | 2.6 | 17.8 | 0.2 | 23.4 |
| 1.0% | 6.6 | 1.6 | 28.2 | 0.8 | 42.4 |
| 2.0% | 3.7 | 0.9 | 48.6 | 2.8 | 79.0 |
| 5.0% | 1.5 | 0.5 | 111.6 | 16.4 | 172.0 |

## NEON accumulation, by compiler

The same intrinsics (bench/neon_study.cpp) over 64 KiB, built with -O3 by each compiler. The last two rows
differ only in how the loop addresses memory; from the bumped pointer, GCC emits one LDP for both loads.

| NEON loop | GCC 14 |
|---|---:|
| UADALP, 1 accumulator | 17.1 GB/s |
| UADALP, 4 accumulators | 7.1 GB/s |
| UADDW, 4 accumulators, indexed loads | 49.3 GB/s |
| UADDW, 4 accumulators, one bumped pointer | 7.1 GB/s |

| NEON loop | Clang 19 |
|---|---:|
| UADALP, 1 accumulator | 17.3 GB/s |
| UADALP, 4 accumulators | 68.8 GB/s |
| UADDW, 4 accumulators, indexed loads | 49.4 GB/s |
| UADDW, 4 accumulators, one bumped pointer | 49.6 GB/s |
