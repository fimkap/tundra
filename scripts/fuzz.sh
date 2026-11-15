#!/usr/bin/env bash
# Build the libFuzzer targets (clang, ASan + UBSan) and run each for N seconds (default 60), in parallel.
# Run inside the container: scripts/dev.sh scripts/fuzz.sh 60
set -euo pipefail
cd "$(dirname "$0")/.."
secs=${1:-60}
cmake --preset fuzz >/dev/null
cmake --build --preset fuzz --target fuzz_parsers fuzz_stack >/dev/null
mkdir -p build/fuzz/corpus-parsers build/fuzz/corpus-stack build/fuzz/artifacts
run() {
  ./build/fuzz/"$1" -max_total_time="$secs" -print_final_stats=1 -artifact_prefix=build/fuzz/artifacts/ \
    build/fuzz/corpus-"$2" > build/fuzz/"$1".log 2>&1
}
run fuzz_parsers parsers & a=$!
run fuzz_stack stack & b=$!
status=0
wait $a || status=1
wait $b || status=1
echo "| target | seconds | executions | coverage (edges) | features | corpus | result |"
echo "|---|---:|---:|---:|---:|---:|---|"
for t in fuzz_parsers fuzz_stack; do
  log=build/fuzz/$t.log
  done_line=$(grep -E '^#[0-9]+.*DONE' "$log" | tail -1 || true)
  execs=$(grep 'stat::number_of_executed_units' "$log" | awk '{print $2}')
  cov=$(echo "$done_line" | sed -n 's/.*cov: \([0-9]*\).*/\1/p')
  ft=$(echo "$done_line" | sed -n 's/.*ft: \([0-9]*\).*/\1/p')
  corp=$(echo "$done_line" | sed -n 's/.*corp: \([0-9]*\).*/\1/p')
  if grep -qE 'ERROR: (AddressSanitizer|libFuzzer)|runtime error|deadly signal' "$log"; then res="FAILED (see $log)"; status=1; else res="clean"; fi
  echo "| $t | $secs | ${execs:-?} | ${cov:-?} | ${ft:-?} | ${corp:-?} | $res |"
done
exit $status
