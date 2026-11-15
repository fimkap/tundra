#include "tundra/stack.hpp"

#include <gtest/gtest.h>

#include "test_util.hpp"

namespace tundra::test {
namespace {

StackConfig config() {
    StackConfig c;
    c.ip = kStackIp;
    c.mac = kStackMac;
    return c;
}

Buffer ethernet(std::uint16_t type, MacAddr dst, Bytes payload) {
    Buffer f(wire::kEthernetSize + payload.size());
    wire::write_ethernet(f, {dst, kPeerMac, type});
    std::copy(payload.begin(), payload.end(), f.begin() + wire::kEthernetSize);
    return f;
}

Buffer arp_frame(std::uint16_t op, Ipv4Addr target, MacAddr dst = MacAddr::broadcast()) {
    Buffer a(wire::kArpSize);
    wire::write_arp(a, {op, kPeerMac, kPeerIp, op == wire::kArpReply ? kStackMac : MacAddr{}, target});
    return ethernet(wire::kEtherArp, dst, a);
}

TEST(Arp, AnswersRequestsForItsAddressOnly) {
    ManualClock clock;
    CaptureDevice dev(LinkType::ethernet);
    Stack s(dev, clock, config());
    s.receive(arp_frame(wire::kArpRequest, *Ipv4Addr::parse("10.0.0.99")));
    EXPECT_TRUE(dev.frames.empty());
    s.receive(arp_frame(wire::kArpRequest, kStackIp));
    ASSERT_EQ(dev.frames.size(), 1u);
    auto f = dev.pop();
    auto eth = wire::parse_ethernet(f);
    auto arp = wire::parse_arp(Bytes(f).subspan(wire::kEthernetSize));
    ASSERT_TRUE(eth && arp);
    EXPECT_EQ(eth->dst, kPeerMac);
    EXPECT_EQ(arp->op, wire::kArpReply);
    EXPECT_EQ(arp->sender_mac, kStackMac);
    EXPECT_EQ(arp->target_ip, kPeerIp);
}

TEST(Arp, QueuesUntilResolvedThenFlushes) {
    ManualClock clock;
    CaptureDevice dev(LinkType::ethernet);
    Stack s(dev, clock, config());
    s.udp_send(5000, kPeerIp, 7, buf("one"));
    s.udp_send(5000, kPeerIp, 7, buf("two"));
    ASSERT_EQ(dev.frames.size(), 1u);  // one ARP request, the datagrams wait
    EXPECT_EQ(wire::parse_ethernet(dev.pop())->ethertype, wire::kEtherArp);
    s.receive(arp_frame(wire::kArpReply, kStackIp, kStackMac));
    ASSERT_EQ(dev.frames.size(), 2u);
    for (auto& f : dev.frames) {
        auto eth = wire::parse_ethernet(f);
        EXPECT_EQ(eth->ethertype, wire::kEtherIpv4);
        EXPECT_EQ(eth->dst, kPeerMac);
    }
}

TEST(Arp, GivesUpAfterThreeRequests) {
    ManualClock clock;
    CaptureDevice dev(LinkType::ethernet);
    Stack s(dev, clock, config());
    s.udp_send(5000, kPeerIp, 7, buf("lost"));
    for (int i = 0; i < 5; ++i) {
        clock.advance(1100ms);
        s.run_timers();
    }
    EXPECT_EQ(s.stats().arp_requests_out, 3u);
    EXPECT_EQ(s.stats().dropped_no_arp, 1u);
}

TEST(Icmp, EchoReplyOnIpLink) {
    ManualClock clock;
    CaptureDevice dev(LinkType::ip);
    Stack s(dev, clock, config());
    auto req = ip_packet(wire::kProtoIcmp, 8 + 4, [](MutBytes m) {
        m[8] = std::byte{'p'}, m[9] = std::byte{'i'}, m[10] = std::byte{'n'}, m[11] = std::byte{'g'};
        wire::write_icmp(m, {wire::kIcmpEchoRequest, 0, 0x00420001});
    });
    s.receive(req);
    ASSERT_EQ(dev.frames.size(), 1u);
    auto f = dev.pop();
    auto ip = wire::parse_ipv4(f);
    ASSERT_TRUE(ip);
    EXPECT_EQ(ip->dst, kPeerIp);
    Bytes m = Bytes(f).subspan(20);
    auto icmp = wire::parse_icmp(m);
    ASSERT_TRUE(icmp);
    EXPECT_EQ(icmp->type, wire::kIcmpEchoReply);
    EXPECT_EQ(icmp->rest, 0x00420001U);
    EXPECT_EQ(str(m.subspan(8)), "ping");
}

TEST(Udp, DeliversToBoundPortAndRejectsOthers) {
    ManualClock clock;
    CaptureDevice dev(LinkType::ip);
    Stack s(dev, clock, config());
    std::string got;
    s.udp_bind(7, [&](Ipv4Addr src, std::uint16_t port, Bytes p) {
        got = str(p);
        EXPECT_EQ(src, kPeerIp);
        EXPECT_EQ(port, 4000);
    });
    auto dgram = [](std::uint16_t dst_port) {
        auto payload = buf("hello");
        return ip_packet(wire::kProtoUdp, 8 + payload.size(), [&](MutBytes out) {
            std::copy(payload.begin(), payload.end(), out.begin() + 8);
            wire::write_udp(out, {4000, dst_port, static_cast<std::uint16_t>(8 + payload.size())}, kPeerIp, kStackIp);
        });
    };
    s.receive(dgram(7));
    EXPECT_EQ(got, "hello");
    s.receive(dgram(9));
    ASSERT_EQ(dev.frames.size(), 1u);
    auto f = dev.pop();
    auto icmp = wire::parse_icmp(Bytes(f).subspan(20));
    ASSERT_TRUE(icmp);
    EXPECT_EQ(icmp->type, wire::kIcmpDestUnreachable);
    EXPECT_EQ(icmp->code, wire::kIcmpPortUnreachable);
}

TEST(Ipv4, DropsCorruptAndForeignPackets) {
    ManualClock clock;
    CaptureDevice dev(LinkType::ip);
    Stack s(dev, clock, config());
    auto p = ip_packet(wire::kProtoUdp, 8, [](MutBytes out) {
        wire::write_udp(out, {1, 7, 8}, kPeerIp, kStackIp);
    });
    p[8] = std::byte{3};  // TTL changed without fixing the checksum
    s.receive(p);
    EXPECT_EQ(s.stats().dropped_malformed, 1u);
    auto other = ip_packet(wire::kProtoUdp, 8, [](MutBytes out) { wire::write_udp(out, {1, 7, 8}, kPeerIp, kPeerIp); },
                           kPeerIp, *Ipv4Addr::parse("10.0.0.3"));
    s.receive(other);
    EXPECT_EQ(s.stats().dropped_not_for_us, 1u);
    EXPECT_TRUE(dev.frames.empty());
}

}  // namespace
}  // namespace tundra::test
