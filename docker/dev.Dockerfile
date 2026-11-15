# Toolchain and network tools for building and testing tundra.
FROM debian:trixie
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential g++-14 clang-19 clang-format-19 libclang-rt-19-dev lld-19 \
      cmake ninja-build git ca-certificates \
      iproute2 iputils-ping curl netcat-openbsd python3 tcpdump procps \
 && rm -rf /var/lib/apt/lists/* \
 && ln -s /usr/bin/clang-format-19 /usr/local/bin/clang-format
WORKDIR /src
