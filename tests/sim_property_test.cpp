// Property test: over many random networks, a client echoes random data through a server and gets back
// exactly what it sent, and both ends close cleanly. Each case is a pure function of its seed, so a
// failure prints the seed that reproduces it.
#include <gtest/gtest.h>

#include <cstdlib>
#include <random>

#include "test_util.hpp"
#include "tundra/pcap.hpp"
#include "tundra/sim.hpp"

namespace tundra::test {
namespace {

struct Case {
    LinkParams link;
    std::size_t bytes;
    TcpConfig tcp;
};

Case make_case(std::uint64_t seed) {
    std::mt19937_64 r(seed);
    auto pick = [&](double lo, double hi) { return std::uniform_real_distribution<double>(lo, hi)(r); };
    Case c;
    c.link.delay = Duration(static_cast<std::int64_t>(pick(0.1, 50) * 1e6));
    c.link.jitter = Duration(static_cast<std::int64_t>(pick(0, 30) * 1e6));
    c.link.loss = pick(0, 0.15);
    c.link.duplicate = pick(0, 0.05);
    c.link.bits_per_second = r() % 2 ? 0 : static_cast<std::uint64_t>(pick(1e6, 100e6));
    c.bytes = 1 + r() % 200'000;
    c.tcp.msl = 1s;
    c.tcp.max_retransmits = 15;  // heavy loss must not turn into a give-up
    c.tcp.recv_buffer = std::size_t{4096} << (r() % 7);  // 4 KiB .. 256 KiB: small windows too
    c.tcp.send_buffer = std::size_t{4096} << (r() % 7);
    return c;
}

// SIM_SEED=n runs one case; SIM_PCAP=file also records the client's view of it for tcpdump/Wireshark.
TEST(SimProperty, EchoIsExactOverRandomNetworks) {
    std::uint64_t first = 1, last = 200;
    if (const char* s = std::getenv("SIM_SEED")) first = last = std::strtoull(s, nullptr, 10);
    const char* pcap_path = std::getenv("SIM_PCAP");
    int failures = 0;
    for (std::uint64_t seed = first; seed <= last; ++seed) {
        Case k = make_case(seed);
        ManualClock clock;
        SimNetwork sim(clock, seed);
        auto [a, b] = sim.connect(LinkType::ethernet, k.link, k.link);
        StackConfig cc, sc;
        cc.ip = kPeerIp, cc.mac = kPeerMac, cc.tcp = k.tcp, cc.seed = seed;
        sc.ip = kStackIp, sc.mac = kStackMac, sc.tcp = k.tcp, sc.seed = seed + 1000;
        Stack client(*a, clock, cc), server(*b, clock, sc);
        sim.attach(a, client);
        sim.attach(b, server);
        serve_echo(server, 7);
        std::unique_ptr<PcapWriter> pcap;
        if (pcap_path) {
            pcap = std::make_unique<PcapWriter>(pcap_path, LinkType::ethernet);
            client.set_pcap(pcap.get());
        }

        std::mt19937_64 dr(seed);
        Buffer data(k.bytes);
        for (auto& x : data) x = to_byte(static_cast<unsigned>(dr()));
        Buffer got;
        std::size_t off = 0;
        std::string reason;
        auto c = client.tcp_connect(kStackIp, 7);
        auto pump = [&] {
            while (off < data.size()) {
                std::size_t n = c->send(Bytes(data).subspan(off));
                if (n == 0) break;
                off += n;
            }
        };
        c->on_connected = pump;
        c->on_writable = pump;
        c->on_data = [&](Bytes d) {
            got.insert(got.end(), d.begin(), d.end());
            if (got.size() == data.size()) c->close();
        };
        c->on_closed = [&](std::string_view r) { reason = r; };

        bool done = sim.run([&] { return !reason.empty() && server.tcp_connections() == 0; }, 3600s);
        bool ok = done && reason == "closed" && got == data && client.tcp_connections() == 0;
        if (!ok) {
            ++failures;
            ADD_FAILURE() << "seed " << seed << ": done=" << done << " reason=" << reason << " got " << got.size()
                          << "/" << data.size() << " bytes, loss " << k.link.loss << ", delay "
                          << k.link.delay.count() / 1e6 << " ms, rcvbuf " << k.tcp.recv_buffer;
        }
    }
    EXPECT_EQ(failures, 0) << "of " << (last - first + 1) << " seeds";
}

}  // namespace
}  // namespace tundra::test
