// Goodput under loss, in virtual time: a 50 Mbit/s link with a 40 ms round trip, 4 MB transfers, loss in
// both directions, averaged over seeds. NewReno (fast retransmit and recovery) against timeout-only
// recovery shows what the duplicate-ACK machinery buys.
#include <cstdio>
#include <random>

#include "tundra/sim.hpp"
#include "tundra/stack.hpp"

using namespace tundra;

struct Result {
    double mbps = 0, fast = 0, timeouts = 0;
};

static Result run(double loss, bool newreno, std::uint64_t seed) {
    ManualClock clock;
    SimNetwork sim(clock, seed);
    LinkParams link{.delay = 20ms, .loss = loss, .bits_per_second = 50'000'000};
    auto [a, b] = sim.connect(LinkType::ethernet, link, link);
    StackConfig cc, sc;
    cc.ip = *Ipv4Addr::parse("10.0.0.1"), cc.mac = MacAddr{{2, 0, 0, 0, 0, 1}}, cc.seed = seed;
    sc.ip = *Ipv4Addr::parse("10.0.0.2"), sc.mac = MacAddr{{2, 0, 0, 0, 0, 2}}, sc.seed = seed + 1;
    cc.tcp.fast_retransmit = sc.tcp.fast_retransmit = newreno;
    cc.tcp.max_retransmits = sc.tcp.max_retransmits = 30;
    Stack client(*a, clock, cc), server(*b, clock, sc);
    sim.attach(a, client);
    sim.attach(b, server);
    const std::size_t total = 4 << 20;
    std::size_t received = 0;
    server.tcp_listen(9, [&](std::shared_ptr<TcpConnection> c) { c->on_data = [&](Bytes d) { received += d.size(); }; });
    Buffer chunk(64 * 1024, std::byte{0x5a});
    auto c = client.tcp_connect(sc.ip, 9);
    std::size_t sent = 0;
    TimePoint start{};
    auto pump = [&] {
        while (sent < total) {
            std::size_t n = c->send(Bytes(chunk).first(std::min(chunk.size(), total - sent)));
            if (n == 0) break;
            sent += n;
        }
    };
    c->on_connected = [&] {
        start = clock.now();
        pump();
    };
    c->on_writable = pump;
    if (!sim.run([&] { return received == total; }, 36000s)) return {};
    double secs = std::chrono::duration<double>(clock.now() - start).count();
    return {total * 8 / secs / 1e6, static_cast<double>(c->stats().fast_retransmits), static_cast<double>(c->stats().timeouts)};
}

int main() {
    const int seeds = 5;
    std::printf("| loss each way | NewReno Mbit/s | timeout-only Mbit/s | NewReno fast retransmits | NewReno timeouts | timeout-only timeouts |\n");
    std::printf("|---:|---:|---:|---:|---:|---:|\n");
    for (double loss : {0.0, 0.001, 0.005, 0.01, 0.02, 0.05}) {
        Result nr, rto;
        for (int s = 1; s <= seeds; ++s) {
            Result x = run(loss, true, static_cast<std::uint64_t>(s)), y = run(loss, false, static_cast<std::uint64_t>(s));
            nr.mbps += x.mbps / seeds, nr.fast += x.fast / seeds, nr.timeouts += x.timeouts / seeds;
            rto.mbps += y.mbps / seeds, rto.timeouts += y.timeouts / seeds;
        }
        std::printf("| %.1f%% | %.1f | %.1f | %.1f | %.1f | %.1f |\n", loss * 100, nr.mbps, rto.mbps, nr.fast, nr.timeouts,
                    rto.timeouts);
    }
}
