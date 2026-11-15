#include "tundra/wire.hpp"

#include <gtest/gtest.h>

#include "tundra/checksum.hpp"

namespace tundra::wire {
namespace {

const Ipv4Addr kA = *Ipv4Addr::parse("10.0.0.1");
const Ipv4Addr kB = *Ipv4Addr::parse("10.0.0.2");

TEST(Addr, ParseAndPrint) {
    EXPECT_EQ(kA.v, 0x0a000001U);
    EXPECT_EQ(kB.str(), "10.0.0.2");
    EXPECT_FALSE(Ipv4Addr::parse("10.0.0"));
    EXPECT_FALSE(Ipv4Addr::parse("10.0.0.256"));
    EXPECT_FALSE(Ipv4Addr::parse("10.0.0.1x"));
    EXPECT_EQ(MacAddr::broadcast().str(), "ff:ff:ff:ff:ff:ff");
}

TEST(Ethernet, RoundTrip) {
    Buffer f(kEthernetSize);
    Ethernet h{MacAddr::broadcast(), MacAddr{{2, 0, 0, 0, 0, 1}}, kEtherArp};
    write_ethernet(f, h);
    auto p = parse_ethernet(f);
    ASSERT_TRUE(p);
    EXPECT_EQ(p->dst, h.dst);
    EXPECT_EQ(p->src, h.src);
    EXPECT_EQ(p->ethertype, kEtherArp);
    EXPECT_EQ(parse_ethernet(Bytes(f).first(13)).error(), ParseError::too_short);
}

TEST(Arp, RoundTripAndUnsupported) {
    Buffer b(kArpSize);
    Arp a{kArpRequest, MacAddr{{2, 0, 0, 0, 0, 1}}, kA, MacAddr{}, kB};
    write_arp(b, a);
    auto p = parse_arp(b);
    ASSERT_TRUE(p);
    EXPECT_EQ(p->op, kArpRequest);
    EXPECT_EQ(p->sender_ip, kA);
    EXPECT_EQ(p->target_ip, kB);
    b[1] = std::byte{6};  // hardware type 6 (IEEE 802)
    EXPECT_EQ(parse_arp(b).error(), ParseError::unsupported);
}

Buffer ipv4_packet(std::size_t payload) {
    Buffer b(kIpv4MinSize + payload);
    write_ipv4(b, Ipv4{.total_length = static_cast<std::uint16_t>(b.size()), .id = 7, .ttl = 64,
                       .protocol = kProtoUdp, .src = kA, .dst = kB});
    return b;
}

TEST(Ipv4, RoundTrip) {
    auto b = ipv4_packet(10);
    auto p = parse_ipv4(b);
    ASSERT_TRUE(p) << to_string(p.error());
    EXPECT_EQ(p->protocol, kProtoUdp);
    EXPECT_EQ(p->total_length, 30);
    EXPECT_EQ(p->src, kA);
    EXPECT_TRUE(p->dont_fragment);
}

TEST(Ipv4, Rejects) {
    auto b = ipv4_packet(10);
    auto bad = b;
    bad[8] = std::byte{1};  // TTL changed, checksum not
    EXPECT_EQ(parse_ipv4(bad).error(), ParseError::bad_checksum);
    EXPECT_EQ(parse_ipv4(Bytes(b).first(19)).error(), ParseError::too_short);
    EXPECT_EQ(parse_ipv4(Bytes(b).first(25)).error(), ParseError::bad_length);  // total length 30 > 25

    auto frag = b;
    store_be16(frag.data() + 6, 0x2000);  // more fragments
    store_be16(frag.data() + 10, 0);
    store_be16(frag.data() + 10, checksum::compute(Bytes(frag).first(20)));
    EXPECT_EQ(parse_ipv4(frag).error(), ParseError::fragmented);

    auto v6 = b;
    v6[0] = std::byte{0x65};
    EXPECT_EQ(parse_ipv4(v6).error(), ParseError::bad_version);
}

TEST(Ipv4, SkipsOptions) {
    Buffer b(24 + 4);
    write_ipv4(b, Ipv4{.total_length = 28, .protocol = kProtoUdp, .src = kA, .dst = kB});
    // Rewrite as IHL 6 with a 4-byte NOP option block and fix the checksum.
    Buffer withopt(28);
    std::copy(b.begin(), b.begin() + 20, withopt.begin());
    withopt[0] = std::byte{0x46};
    for (int i = 20; i < 24; ++i) withopt[i] = std::byte{1};
    store_be16(withopt.data() + 10, 0);
    store_be16(withopt.data() + 10, checksum::compute(Bytes(withopt).first(24)));
    auto p = parse_ipv4(withopt);
    ASSERT_TRUE(p) << to_string(p.error());
    EXPECT_EQ(p->header_size, 24);
}

TEST(Icmp, EchoRoundTrip) {
    Buffer m(kIcmpHeaderSize + 5);
    m[8] = std::byte{'p'};
    write_icmp(m, Icmp{kIcmpEchoRequest, 0, 0x12340001});
    auto p = parse_icmp(m);
    ASSERT_TRUE(p);
    EXPECT_EQ(p->type, kIcmpEchoRequest);
    EXPECT_EQ(p->rest, 0x12340001U);
    m[12] = std::byte{9};
    EXPECT_EQ(parse_icmp(m).error(), ParseError::bad_checksum);
}

TEST(Udp, RoundTripAndPseudoHeader) {
    Buffer s(kUdpSize + 3);
    s[8] = std::byte{'h'};
    write_udp(s, Udp{1234, 7, static_cast<std::uint16_t>(s.size())}, kA, kB);
    auto p = parse_udp(s, kA, kB);
    ASSERT_TRUE(p);
    EXPECT_EQ(p->dst_port, 7);
    // The checksum covers the addresses: delivered to the wrong host, it fails.
    EXPECT_EQ(parse_udp(s, kA, *Ipv4Addr::parse("10.0.0.3")).error(), ParseError::bad_checksum);
    store_be16(s.data() + 6, 0);  // zero = not computed: accepted
    EXPECT_TRUE(parse_udp(s, kA, *Ipv4Addr::parse("10.0.0.3")));
}

TEST(Tcp, RoundTripWithOptions) {
    Tcp h{.src_port = 40000, .dst_port = 80, .seq = 0xfffffff0, .ack = 0, .flags = kSyn, .window = 65535, .urgent = 0, .options = {}};
    h.options.mss = 1460;
    h.options.window_scale = 7;
    Buffer s(tcp_header_size(h.options) + 4);
    s[s.size() - 1] = std::byte{'x'};
    write_tcp(s, h, kA, kB);
    auto p = parse_tcp(s, kA, kB);
    ASSERT_TRUE(p) << to_string(p.error());
    EXPECT_EQ(p->seq, 0xfffffff0U);
    EXPECT_EQ(p->flags, kSyn);
    EXPECT_EQ(p->header_size, 28);
    EXPECT_EQ(p->options.mss, 1460);
    EXPECT_EQ(p->options.window_scale, 7);
    s[s.size() - 1] = std::byte{'y'};
    EXPECT_EQ(parse_tcp(s, kA, kB).error(), ParseError::bad_checksum);
}

// The option block Linux puts in a SYN: MSS, SACK-permitted, timestamps, NOP, window scale.
TEST(Tcp, ParsesLinuxSynOptions) {
    Buffer s(40);
    store_be16(s.data(), 51000);
    store_be16(s.data() + 2, 80);
    store_be32(s.data() + 4, 1);
    s[12] = std::byte{10 << 4};
    s[13] = std::byte{kSyn};
    store_be16(s.data() + 14, 64240);
    const unsigned opts[] = {2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7};
    for (std::size_t i = 0; i < 20; ++i) s[20 + i] = to_byte(opts[i]);
    store_be16(s.data() + 16, checksum::compute(s, checksum::pseudo_header_sum(kA.v, kB.v, kProtoTcp, 40)));
    auto p = parse_tcp(s, kA, kB);
    ASSERT_TRUE(p) << to_string(p.error());
    EXPECT_EQ(p->options.mss, 1460);
    EXPECT_EQ(p->options.window_scale, 7);
    EXPECT_TRUE(p->options.sack_permitted);
}

TEST(Tcp, RejectsMalformedOptions) {
    for (unsigned bad_len : {0u, 1u, 9u}) {
        Buffer s(24);
        s[12] = std::byte{6 << 4};
        s[20] = std::byte{2};
        s[21] = to_byte(bad_len);
        store_be16(s.data() + 16, checksum::compute(s, checksum::pseudo_header_sum(kA.v, kB.v, kProtoTcp, 24)));
        EXPECT_EQ(parse_tcp(s, kA, kB).error(), ParseError::bad_options) << "len " << bad_len;
    }
    EXPECT_EQ(flags_str(kSyn | kAck), "S.");
}

}  // namespace
}  // namespace tundra::wire
