// The stack's own processing cost: a bulk TCP transfer between two stacks in one process over an ideal
// in-memory link (no delay, no loss), timed in real CPU time. It measures segment handling, checksums,
// copies and ACKs, not any network.
#include <benchmark/benchmark.h>

#include <random>

#include "tundra/sim.hpp"
#include "tundra/stack.hpp"

using namespace tundra;

static void BM_TcpBulkTransfer(benchmark::State& state) {
    const std::size_t total = 16 << 20;
    Buffer chunk(64 * 1024);
    std::mt19937 rng(1);
    for (auto& b : chunk) b = to_byte(rng());
    std::uint64_t segments = 0;
    for (auto _ : state) {
        ManualClock clock;
        SimNetwork sim(clock, 1);
        auto [a, b] = sim.connect(LinkType::ethernet, {.delay = 0ns}, {.delay = 0ns});
        StackConfig cc, sc;
        cc.ip = *Ipv4Addr::parse("10.0.0.1"), cc.mac = MacAddr{{2, 0, 0, 0, 0, 1}};
        sc.ip = *Ipv4Addr::parse("10.0.0.2"), sc.mac = MacAddr{{2, 0, 0, 0, 0, 2}};
        Stack client(*a, clock, cc), server(*b, clock, sc);
        sim.attach(a, client);
        sim.attach(b, server);
        std::size_t received = 0;
        server.tcp_listen(9, [&](std::shared_ptr<TcpConnection> c) { c->on_data = [&](Bytes d) { received += d.size(); }; });
        auto c = client.tcp_connect(sc.ip, 9);
        std::size_t sent = 0;
        auto pump = [&] {
            while (sent < total) {
                std::size_t n = c->send(Bytes(chunk).first(std::min(chunk.size(), total - sent)));
                if (n == 0) break;
                sent += n;
            }
        };
        c->on_connected = pump;
        c->on_writable = pump;
        sim.run([&] { return received == total; }, 3600s);
        segments += c->stats().segments_out;
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations() * total));
    state.counters["segments/s"] = benchmark::Counter(static_cast<double>(segments), benchmark::Counter::kIsRate);
}

BENCHMARK(BM_TcpBulkTransfer)->Unit(benchmark::kMillisecond)->MinTime(2.0);
