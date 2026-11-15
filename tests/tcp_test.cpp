#include "tundra/tcp.hpp"

#include <gtest/gtest.h>

#include <random>

#include "test_util.hpp"
#include "tundra/sim.hpp"

namespace tundra::test {
namespace {

TEST(Seq, ComparisonsWrap) {
    EXPECT_TRUE(seq_lt(0xfffffff0U, 0x10U));  // across the wrap
    EXPECT_TRUE(seq_gt(0x10U, 0xfffffff0U));
    EXPECT_TRUE(seq_le(5, 5));
    EXPECT_FALSE(seq_lt(5, 5));
    EXPECT_TRUE(seq_lt(0, 0x7fffffffU));
}

TEST(ByteRing, WrapsAround) {
    ByteRing r(8);
    EXPECT_EQ(r.push(buf("abcdef")), 6u);
    r.pop(4);
    EXPECT_EQ(r.push(buf("ghijkl")), 6u);  // wraps
    EXPECT_EQ(r.push(buf("z")), 0u);       // full
    Buffer out(8);
    r.copy_out(0, out);
    EXPECT_EQ(str(out), "efghijkl");
}

// ---- scripted exchanges (packetdrill style) on an IP link ------------------------------------------

struct Scripted : ::testing::Test {
    ManualClock clock;
    CaptureDevice dev{LinkType::ip};
    std::unique_ptr<Stack> s;
    std::shared_ptr<TcpConnection> accepted;
    std::string received;

    void SetUp() override {
        StackConfig c;
        c.ip = kStackIp;
        s = std::make_unique<Stack>(dev, clock, c);
        s->tcp_listen(80, [this](std::shared_ptr<TcpConnection> conn) {
            accepted = conn;
            conn->on_data = [this](Bytes d) { received += str(d); };
        });
    }

    wire::Tcp seg(std::uint32_t seq, std::uint32_t ack, std::uint8_t flags, std::uint16_t dst = 80) {
        wire::Tcp h;
        h.src_port = 40000;
        h.dst_port = dst;
        h.seq = seq;
        h.ack = ack;
        h.flags = flags;
        h.window = 65535;
        return h;
    }

    // handshake completes a connection and returns the stack's ISS.
    std::uint32_t handshake() {
        auto syn = seg(1000, 0, wire::kSyn);
        syn.options.mss = 1460;
        syn.options.window_scale = 7;
        s->receive(tcp_packet(syn));
        auto synack = parse_tcp_out(dev.pop());
        s->receive(tcp_packet(seg(1001, synack.h.seq + 1, wire::kAck)));
        return synack.h.seq;
    }
};

TEST_F(Scripted, SynAckCarriesOptionsAndAcksTheSyn) {
    auto syn = seg(1000, 0, wire::kSyn);
    syn.options.mss = 1400;
    syn.options.window_scale = 7;
    s->receive(tcp_packet(syn));
    ASSERT_EQ(dev.frames.size(), 1u);
    auto out = parse_tcp_out(dev.pop());
    EXPECT_EQ(out.h.flags, wire::kSyn | wire::kAck);
    EXPECT_EQ(out.h.ack, 1001u);
    EXPECT_EQ(out.h.options.mss, 1460);         // ours: MTU 1500 - 40
    EXPECT_EQ(out.h.options.window_scale, 3);   // 256 KiB buffer >> 3 fits 16 bits
    EXPECT_EQ(out.h.window, 65535);             // unscaled in a SYN
    EXPECT_FALSE(accepted);                     // not until the handshake completes
    s->receive(tcp_packet(seg(1001, out.h.seq + 1, wire::kAck)));
    ASSERT_TRUE(accepted);
    EXPECT_EQ(accepted->state(), TcpState::established);
    EXPECT_EQ(accepted->mss(), 1400);  // the smaller of the two
}

TEST_F(Scripted, InOrderOutOfOrderAndGapFill) {
    std::uint32_t iss = handshake();
    s->receive(tcp_packet(seg(1001, iss + 1, wire::kAck | wire::kPsh), buf("hello")));
    auto ack = parse_tcp_out(dev.pop());
    EXPECT_EQ(ack.h.ack, 1006u);
    EXPECT_EQ(received, "hello");

    s->receive(tcp_packet(seg(1011, iss + 1, wire::kAck), buf("world")));  // gap at 1006..1010
    auto dup = parse_tcp_out(dev.pop());
    EXPECT_EQ(dup.h.ack, 1006u);  // duplicate ACK: still waiting for 1006
    EXPECT_EQ(received, "hello");

    s->receive(tcp_packet(seg(1006, iss + 1, wire::kAck), buf("12345")));
    auto full = parse_tcp_out(dev.pop());
    EXPECT_EQ(full.h.ack, 1016u);
    EXPECT_EQ(received, "hello12345world");
    // The advertised window is scaled by our shift of 3.
    EXPECT_EQ(full.h.window, (256 * 1024) >> 3);
}

TEST_F(Scripted, RetransmittedOldDataIsAcknowledgedNotRedelivered) {
    std::uint32_t iss = handshake();
    s->receive(tcp_packet(seg(1001, iss + 1, wire::kAck), buf("abc")));
    dev.frames.clear();
    s->receive(tcp_packet(seg(1001, iss + 1, wire::kAck), buf("abcdef")));  // overlaps: only "def" is new
    EXPECT_EQ(received, "abcdef");
    EXPECT_EQ(parse_tcp_out(dev.pop()).h.ack, 1007u);
}

TEST_F(Scripted, ResetsForClosedPorts) {
    // A SYN to a port nobody listens on: RST|ACK acknowledging the SYN, seq 0 (RFC 9293 §3.10.7.1).
    s->receive(tcp_packet(seg(5000, 0, wire::kSyn, 81)));
    auto r1 = parse_tcp_out(dev.pop());
    EXPECT_EQ(r1.h.flags, wire::kRst | wire::kAck);
    EXPECT_EQ(r1.h.ack, 5001u);
    EXPECT_EQ(r1.h.seq, 0u);
    // A stray ACK: RST with the sequence number taken from its ACK field.
    s->receive(tcp_packet(seg(7000, 123456, wire::kAck, 81)));
    auto r2 = parse_tcp_out(dev.pop());
    EXPECT_EQ(r2.h.flags, wire::kRst);
    EXPECT_EQ(r2.h.seq, 123456u);
    // A RST is never answered.
    s->receive(tcp_packet(seg(7000, 0, wire::kRst, 81)));
    EXPECT_TRUE(dev.frames.empty());
}

TEST_F(Scripted, RstOnlyAtRcvNxtElseChallengeAck) {
    std::uint32_t iss = handshake();
    s->receive(tcp_packet(seg(1500, iss + 1, wire::kRst)));  // in the window but not at RCV.NXT
    auto challenge = parse_tcp_out(dev.pop());
    EXPECT_EQ(challenge.h.flags, wire::kAck);
    EXPECT_EQ(accepted->state(), TcpState::established);
    std::string reason;
    accepted->on_closed = [&](std::string_view r) { reason = r; };
    s->receive(tcp_packet(seg(1001, iss + 1, wire::kRst)));
    EXPECT_EQ(reason, "reset");
    EXPECT_EQ(s->tcp_connections(), 0u);
}

TEST_F(Scripted, RetransmitsSynAckWithBackoff) {
    auto syn = seg(1000, 0, wire::kSyn);
    s->receive(tcp_packet(syn));
    dev.frames.clear();
    std::vector<Duration> gaps;
    TimePoint last = clock.now();
    for (int i = 0; i < 3; ++i) {
        clock.set(*s->next_deadline());
        s->run_timers();
        ASSERT_EQ(dev.frames.size(), 1u);
        EXPECT_EQ(parse_tcp_out(dev.pop()).h.flags, wire::kSyn | wire::kAck);
        gaps.push_back(clock.now() - last);
        last = clock.now();
    }
    EXPECT_EQ(gaps[0], 1s);  // RFC 6298: initial RTO of 1 s, then doubled
    EXPECT_EQ(gaps[1], 2s);
    EXPECT_EQ(gaps[2], 4s);
}

// ---- two stacks over a simulated link -------------------------------------------------------------

struct Net {
    ManualClock clock;
    SimNetwork sim;
    std::unique_ptr<Stack> client, server;

    Net(LinkParams params, std::uint64_t seed, TcpConfig tcp = {}) : sim(clock, seed) {
        auto [a, b] = sim.connect(LinkType::ethernet, params, params);
        StackConfig cc, sc;
        cc.ip = kPeerIp, cc.mac = kPeerMac, cc.tcp = tcp, cc.seed = seed;
        sc.ip = kStackIp, sc.mac = kStackMac, sc.tcp = tcp, sc.seed = seed + 1;
        client = std::make_unique<Stack>(*a, clock, cc);
        server = std::make_unique<Stack>(*b, clock, sc);
        sim.attach(a, *client);
        sim.attach(b, *server);
    }
};

// EchoClient sends data, collects the echo, and closes once everything came back.
struct EchoClient {
    Buffer sent, received;
    std::size_t offset = 0;
    bool connected = false, closed = false;
    std::string reason;
    std::shared_ptr<TcpConnection> c;

    void start(Stack& s, Ipv4Addr dst, std::uint16_t port, Buffer data) {
        sent = std::move(data);
        c = s.tcp_connect(dst, port);
        auto pump = [this] {
            while (offset < sent.size()) {
                std::size_t n = c->send(Bytes(sent).subspan(offset));
                if (n == 0) break;
                offset += n;
            }
        };
        c->on_connected = [this, pump] {
            connected = true;
            pump();
        };
        c->on_writable = pump;
        c->on_data = [this](Bytes d) {
            received.insert(received.end(), d.begin(), d.end());
            if (received.size() == sent.size()) c->close();
        };
        c->on_closed = [this](std::string_view r) {
            closed = true;
            reason = r;
        };
    }
};

Buffer random_bytes(std::size_t n, std::uint64_t seed) {
    std::mt19937_64 rng(seed);
    Buffer b(n);
    for (auto& x : b) x = to_byte(static_cast<unsigned>(rng()));
    return b;
}

TcpConfig short_msl() {
    TcpConfig t;
    t.msl = 1s;
    return t;
}

TEST(Sim, EchoAndGracefulClose) {
    Net n({.delay = 2ms}, 1, short_msl());
    serve_echo(*n.server, 7);
    EchoClient e;
    e.start(*n.client, kStackIp, 7, random_bytes(200'000, 1));
    ASSERT_TRUE(n.sim.run([&] { return e.closed; }, 60s));
    EXPECT_EQ(e.reason, "closed");
    EXPECT_EQ(e.received, e.sent);
    // The client went through TIME-WAIT (2 x MSL); the server side is gone too.
    ASSERT_TRUE(n.sim.run([&] { return n.server->tcp_connections() == 0; }, 10s));
    EXPECT_EQ(n.client->tcp_connections(), 0u);
}

TEST(Sim, ConnectToClosedPortIsRefused) {
    Net n({.delay = 1ms}, 2);
    EchoClient e;
    e.start(*n.client, kStackIp, 9, buf("x"));
    ASSERT_TRUE(n.sim.run([&] { return e.closed; }, 10s));
    EXPECT_EQ(e.reason, "refused");
}

TEST(Sim, ConnectTimesOutWhenEverythingIsLost) {
    TcpConfig t;
    t.max_retransmits = 3;
    Net n({.delay = 1ms, .loss = 1.0}, 3, t);
    EchoClient e;
    TimePoint start = n.clock.now();
    e.start(*n.client, kStackIp, 7, buf("x"));
    ASSERT_TRUE(n.sim.run([&] { return e.closed; }, 120s));
    EXPECT_EQ(e.reason, "timeout");
    // 1 + 2 + 4 + 8 seconds of back-off before giving up.
    EXPECT_EQ(n.clock.now() - start, 15s);
}

TEST(Sim, TransferSurvivesLossReorderingAndDuplication) {
    Net n({.delay = 10ms, .jitter = 8ms, .loss = 0.05, .duplicate = 0.02}, 4, short_msl());
    serve_echo(*n.server, 7);
    EchoClient e;
    e.start(*n.client, kStackIp, 7, random_bytes(300'000, 4));
    ASSERT_TRUE(n.sim.run([&] { return e.closed; }, 600s));
    EXPECT_EQ(e.received, e.sent);
    EXPECT_GT(e.c->stats().retransmits, 0u);
    EXPECT_GT(e.c->stats().out_of_order, 0u);
}

TEST(Sim, SimultaneousClose) {
    Net n({.delay = 5ms}, 5, short_msl());
    std::shared_ptr<TcpConnection> srv;
    std::string server_reason;
    n.server->tcp_listen(7, [&](std::shared_ptr<TcpConnection> c) {
        srv = c;
        c->on_closed = [&](std::string_view r) { server_reason = r; };
    });
    EchoClient e;
    e.start(*n.client, kStackIp, 7, {});
    ASSERT_TRUE(n.sim.run([&] { return srv && e.connected; }, 10s));
    srv->close();  // both FINs cross on the wire
    e.c->close();
    ASSERT_TRUE(n.sim.run([&] { return e.closed && !server_reason.empty(); }, 30s));
    EXPECT_EQ(e.reason, "closed");
    EXPECT_EQ(server_reason, "closed");
}

}  // namespace
}  // namespace tundra::test
