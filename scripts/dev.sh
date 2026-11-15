#!/usr/bin/env bash
# Run a command in the toolchain container with the repository mounted at /src.
#   scripts/dev.sh cmake --preset debug
# Set TUNDRA_PRIVILEGED=1 to add NET_ADMIN and /dev/net/tun (scripts/integration.sh does).
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
image=tundra-dev:latest
if ! docker image inspect "$image" >/dev/null 2>&1 || [ "$root/docker/dev.Dockerfile" -nt "$root/.dev-image-stamp" ]; then
  docker build -q -t "$image" -f "$root/docker/dev.Dockerfile" "$root/docker" >/dev/null
  touch "$root/.dev-image-stamp"
fi
extra=()
if [ "${TUNDRA_PRIVILEGED:-0}" = 1 ]; then
  extra+=(--cap-add NET_ADMIN --device /dev/net/tun)
fi
tty=()
[ -t 0 ] && tty=(-it)
# ${a[@]+"${a[@]}"}: empty arrays are "unbound" under set -u in bash 3.2 (macOS).
exec docker run --rm ${tty[@]+"${tty[@]}"} ${extra[@]+"${extra[@]}"} -v "$root:/src" -w /src "$image" "$@"
