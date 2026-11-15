#!/usr/bin/env bash
# Build the benchmarks (GCC, Release) and print a Markdown report. Run inside the container:
#   scripts/dev.sh scripts/bench.sh
set -euo pipefail
cd "$(dirname "$0")/.."
cmake --preset bench >/dev/null
cmake --build --preset bench --target tundra_bench tundra_loss_sweep >/dev/null
echo "# Benchmarks"
echo
echo "- $(uname -sr) $(uname -m), $(nproc) CPUs, $(g++-14 --version | head -1), -O3 Release, inside Docker"
echo "- run at $(date -u '+%Y-%m-%d %H:%M UTC')"
./build/bench/tundra_bench --benchmark_format=json --benchmark_out=build/bench/bench.json \
  --benchmark_out_format=json >/dev/null 2>&1
python3 - <<'PY'
import json
d = json.load(open("build/bench/bench.json"))
rows = [b for b in d["benchmarks"] if b["run_type"] == "iteration"]
print("\n## Internet checksum\n")
print("Throughput of the one's-complement sum over a buffer misaligned by one byte.\n")
sizes = [64, 1500, 65536]
labels = []
table = {}
for b in rows:
    if not b["name"].startswith("BM_Checksum"):
        continue
    size = int(b["name"].split("/")[2])
    labels.append(b["label"]) if b["label"] not in labels else None
    table[(b["label"], size)] = b["bytes_per_second"] / 1e9
print("| variant | 64 B | 1500 B | 64 KiB |")
print("|---|---:|---:|---:|")
for l in labels:
    print("| " + l + " | " + " | ".join("%.1f GB/s" % table[(l, s)] for s in sizes) + " |")
for b in rows:
    if b["name"].startswith("BM_TcpBulkTransfer"):
        gbps = b["bytes_per_second"] * 8 / 1e9
        print("\n## Stack processing cost\n")
        print("A 16 MiB bulk transfer between two stacks in one process over an ideal in-memory link, real CPU time;")
        print("both stacks and the simulated link share one core.\n")
        print("| payload throughput | segments/s | time per 16 MiB |")
        print("|---:|---:|---:|")
        print("| %.2f Gbit/s | %.0fk | %.1f ms |" % (gbps, b["segments/s"] / 1e3, b["real_time"]))
PY
echo
echo "## Loss recovery"
echo
echo "Goodput in virtual time on a simulated 50 Mbit/s link with a 40 ms round trip, 4 MB transfers, the same"
echo "loss rate in both directions, averaged over 5 seeds."
echo
./build/bench/tundra_loss_sweep

if [ "$(uname -m)" = aarch64 ]; then
  echo
  echo "## NEON accumulation, by compiler"
  echo
  echo "The same intrinsics (bench/neon_study.cpp) over 64 KiB, built with -O3 by each compiler. The last two rows"
  echo "differ only in how the loop addresses memory; from the bumped pointer, GCC emits one LDP for both loads."
  echo
  g++-14 -std=c++23 -O3 bench/neon_study.cpp -o build/bench/neon_study_gcc
  clang++-19 -std=c++23 -O3 bench/neon_study.cpp -o build/bench/neon_study_clang
  ./build/bench/neon_study_gcc
  echo
  ./build/bench/neon_study_clang
fi
