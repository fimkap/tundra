#!/usr/bin/env bash
# Runs inside the container (see integration.sh): Linux on one side of tap0, tundra on the other.
set -euo pipefail
cd /src
cmake --preset release >/dev/null
cmake --build --preset release --target tundra-app >/dev/null
BIN=build/release/tundra
IP=10.0.0.2
fail=0
row() { printf '| %s | %s | %s | %s |\n' "$@"; }
check() { [ "$1" = "$2" ] && echo yes || { echo "NO (got '$1')"; fail=1; }; }

ip tuntap add dev tap0 mode tap
ip addr add 10.0.0.1/24 dev tap0
ip link set tap0 up
netem=yes
tc qdisc add dev tap0 root netem delay 0ms 2>/dev/null && tc qdisc del dev tap0 root || netem=no

start() { "$BIN" --dev tap0 --ip "$IP/24" "$@" 2>/tmp/tundra.log & TPID=$!; sleep 0.3; }
stop() { kill "$TPID"; wait "$TPID" 2>/dev/null || true; }
trap 'kill $TPID 2>/dev/null || true' EXIT

# transfer N: download N bytes and upload them back, both checked with SHA-256.
transfer() {
  local n=$1 hdr out resp down up want got echoed
  hdr=$(mktemp); out=$(mktemp); resp=$(mktemp)
  down=$(curl -s --max-time 600 -D "$hdr" -o "$out" -w '%{speed_download}' "http://$IP/bytes/$n")
  want=$(grep -i '^x-sha256:' "$hdr" | tr -d '\r' | awk '{print $2}')
  got=$(sha256sum "$out" | awk '{print $1}')
  up=$(curl -s --max-time 600 --data-binary @"$out" -H 'Content-Type: application/octet-stream' \
       -o "$resp" -w '%{speed_upload}' "http://$IP/sha256")
  echoed=$(tr -d '\n' < "$resp")
  printf '%s|%s|%s|%s' "$(awk -v s="$down" 'BEGIN{printf "%.1f", s/1048576}')" \
    "$(awk -v s="$up" 'BEGIN{printf "%.1f", s/1048576}')" "$(check "$got" "$want")" "$(check "$echoed" "$got")"
  rm -f "$hdr" "$out" "$resp"
}

echo "# tundra interop with Linux"
echo
echo "- $(uname -sr), $(nproc) CPUs, inside Docker; tundra on tap0 (10.0.0.2), Linux on the other side (10.0.0.1)"
echo "- loss is injected by tundra's device in both directions (--loss); added delay by tc netem: $netem"
echo "- run at $(date -u '+%Y-%m-%d %H:%M UTC')"
echo
echo "## Basics"
echo
start
echo "| check | result |"
echo "|---|---|"
echo "| ping (3 packets) | $(ping -c 3 -W 1 "$IP" | grep -o '[0-9]* received' ), $(ping -c 3 -W 1 "$IP" | tail -1 | awk -F/ '{print "avg " $5 " ms"}') |"
echo "| UDP echo | $(check "$(echo hello | nc -u -w1 "$IP" 7)" hello) |"
echo "| TCP echo | $(check "$(printf hello | nc -N -w2 "$IP" 7)" hello) |"
echo "| HTTP GET / | $(curl -s --max-time 5 "http://$IP/" | head -1 | grep -q tundra && echo yes || { echo NO; fail=1; }) |"
ok=0
for i in $(seq 1 20); do
  ( h=$(mktemp); o=$(mktemp)
    curl -s --max-time 120 -D "$h" -o "$o" "http://$IP/bytes/$((1048576 + i))"
    [ "$(grep -i '^x-sha256:' "$h" | tr -d '\r' | awk '{print $2}')" = "$(sha256sum "$o" | awk '{print $1}')" ] && echo ok
    rm -f "$h" "$o" ) &
done > /tmp/parallel.txt
wait $(jobs -p | grep -v "^$TPID$") 2>/dev/null || true
echo "| 20 parallel 1 MiB downloads, SHA-256 verified | $(grep -c ok /tmp/parallel.txt) of 20 |"
[ "$(grep -c ok /tmp/parallel.txt)" = 20 ] || fail=1
stop
echo
echo "## Bulk transfers"
echo
echo "Each row downloads N bytes from tundra (tundra's TCP sends) and uploads them back (Linux's TCP sends);"
echo "both directions are verified with SHA-256."
echo
echo "| link | size | download MiB/s | upload MiB/s | download verified | upload verified |"
echo "|---|---:|---:|---:|---|---|"
scenario() {  # label size loss netem-args...
  local label=$1 size=$2 loss=$3; shift 3
  if [ $# -gt 0 ]; then
    if [ "$netem" = yes ]; then tc qdisc add dev tap0 root netem "$@"; else label="$label (no netem: delay not applied)"; fi
  fi
  if [ "$loss" = 0 ]; then start; else start --loss "$loss"; fi
  IFS='|' read -r d u dv uv <<< "$(transfer "$size")"
  stop
  tc qdisc del dev tap0 root 2>/dev/null || true
  echo "| $label | $((size / 1048576)) MiB | $d | $u | $dv | $uv |"
}
scenario "clean" $((64 << 20)) 0
scenario "1% loss each way" $((16 << 20)) 0.01
scenario "1% loss each way, +5 ms delay" $((8 << 20)) 0.01 delay 5ms
scenario "5% loss each way, +5 ms delay" $((4 << 20)) 0.05 delay 5ms
echo
[ "$fail" = 0 ] && echo "All checks passed." || echo "SOME CHECKS FAILED."
exit "$fail"
