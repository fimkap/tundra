#!/usr/bin/env bash
# Interop with the Linux TCP/IP stack over a TAP device, in the dev container with NET_ADMIN and
# /dev/net/tun. With --record, the report is also written to docs/results/interop.md.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
if [ "${1:-}" = "--record" ]; then
  TUNDRA_PRIVILEGED=1 "$root/scripts/dev.sh" bash scripts/integration-inner.sh | tee "$root/docs/results/interop.md"
  exit "${PIPESTATUS[0]}"
fi
exec env TUNDRA_PRIVILEGED=1 "$root/scripts/dev.sh" bash scripts/integration-inner.sh
