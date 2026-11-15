#include <benchmark/benchmark.h>

#include <random>

#include "tundra/checksum.hpp"

using namespace tundra;

static void BM_Checksum(benchmark::State& state) {
    auto variant = static_cast<checksum::Variant>(state.range(0));
    auto size = static_cast<std::size_t>(state.range(1));
    Buffer buf(size + 1);
    std::mt19937 rng(1);
    for (auto& b : buf) b = to_byte(rng());
    Bytes data(buf.data() + 1, size);  // deliberately misaligned by one byte, like a header after Ethernet
    for (auto _ : state) benchmark::DoNotOptimize(checksum::ones_sum(data, variant));
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(size));
    state.SetLabel(std::string(checksum::name(variant)));
}

BENCHMARK(BM_Checksum)->ArgsProduct({{0, 1, 2, 3}, {64, 1500, 65536}});
