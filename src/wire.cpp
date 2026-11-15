#include "tundra/wire.hpp"

#include <charconv>
#include <cstdio>

#include "tundra/checksum.hpp"

namespace tundra {

std::string MacAddr::str() const {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    return buf;
}

std::optional<Ipv4Addr> Ipv4Addr::parse(std::string_view s) {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
        unsigned part = 0;
        auto [p, ec] = std::from_chars(s.data(), s.data() + s.size(), part);
        if (ec != std::errc{} || part > 255 || p == s.data()) return std::nullopt;
        v = (v << 8) | part;
        s.remove_prefix(static_cast<std::size_t>(p - s.data()));
        if (i < 3) {
            if (s.empty() || s.front() != '.') return std::nullopt;
            s.remove_prefix(1);
        }
    }
    if (!s.empty()) return std::nullopt;
    return Ipv4Addr{v};
}

std::string Ipv4Addr::str() const {
    return std::to_string(v >> 24) + "." + std::to_string((v >> 16) & 0xff) + "." + std::to_string((v >> 8) & 0xff) +
           "." + std::to_string(v & 0xff);
}

std::string_view to_string(ParseError e) {
    switch (e) {
        case ParseError::too_short: return "too short";
        case ParseError::bad_version: return "bad version";
        case ParseError::bad_length: return "bad length";
        case ParseError::bad_checksum: return "bad checksum";
        case ParseError::bad_options: return "bad options";
        case ParseError::fragmented: return "fragmented";
        case ParseError::unsupported: return "unsupported";
    }
    return "?";
}

namespace wire {
namespace {

MacAddr load_mac(const std::byte* p) {
    MacAddr m;
    for (std::size_t i = 0; i < 6; ++i) m.b[i] = u8(p[i]);
    return m;
}

void store_mac(std::byte* p, const MacAddr& m) {
    for (std::size_t i = 0; i < 6; ++i) p[i] = std::byte{m.b[i]};
}

std::uint32_t pseudo(Ipv4Addr src, Ipv4Addr dst, std::uint8_t proto, std::size_t len) {
    return checksum::pseudo_header_sum(src.v, dst.v, proto, static_cast<std::uint16_t>(len));
}

}  // namespace

std::expected<Ethernet, ParseError> parse_ethernet(Bytes f) {
    if (f.size() < kEthernetSize) return std::unexpected(ParseError::too_short);
    return Ethernet{load_mac(f.data()), load_mac(f.data() + 6), load_be16(f.data() + 12)};
}

void write_ethernet(MutBytes out, const Ethernet& h) {
    store_mac(out.data(), h.dst);
    store_mac(out.data() + 6, h.src);
    store_be16(out.data() + 12, h.ethertype);
}

std::expected<Arp, ParseError> parse_arp(Bytes p) {
    if (p.size() < kArpSize) return std::unexpected(ParseError::too_short);
    // Only Ethernet hardware (1) and IPv4 protocol (0x0800) with 6- and 4-byte addresses.
    if (load_be16(p.data()) != 1 || load_be16(p.data() + 2) != kEtherIpv4 || u8(p[4]) != 6 || u8(p[5]) != 4) {
        return std::unexpected(ParseError::unsupported);
    }
    return Arp{load_be16(p.data() + 6), load_mac(p.data() + 8), Ipv4Addr{load_be32(p.data() + 14)},
               load_mac(p.data() + 18), Ipv4Addr{load_be32(p.data() + 24)}};
}

void write_arp(MutBytes out, const Arp& a) {
    store_be16(out.data(), 1);
    store_be16(out.data() + 2, kEtherIpv4);
    out[4] = std::byte{6};
    out[5] = std::byte{4};
    store_be16(out.data() + 6, a.op);
    store_mac(out.data() + 8, a.sender_mac);
    store_be32(out.data() + 14, a.sender_ip.v);
    store_mac(out.data() + 18, a.target_mac);
    store_be32(out.data() + 24, a.target_ip.v);
}

std::expected<Ipv4, ParseError> parse_ipv4(Bytes p) {
    if (p.size() < kIpv4MinSize) return std::unexpected(ParseError::too_short);
    std::uint8_t vihl = u8(p[0]);
    if ((vihl >> 4) != 4) return std::unexpected(ParseError::bad_version);
    std::size_t ihl = (vihl & 0x0fU) * 4U;
    if (ihl < kIpv4MinSize || ihl > p.size()) return std::unexpected(ParseError::bad_length);
    std::uint16_t total = load_be16(p.data() + 2);
    if (total < ihl || total > p.size()) return std::unexpected(ParseError::bad_length);
    if (checksum::ones_sum(p.first(ihl)) != 0xffff) return std::unexpected(ParseError::bad_checksum);
    std::uint16_t frag = load_be16(p.data() + 6);
    bool mf = (frag & 0x2000U) != 0;
    if (mf || (frag & 0x1fffU) != 0) return std::unexpected(ParseError::fragmented);
    Ipv4 h;
    h.header_size = static_cast<std::uint8_t>(ihl);
    h.tos = u8(p[1]);
    h.total_length = total;
    h.id = load_be16(p.data() + 4);
    h.dont_fragment = (frag & 0x4000U) != 0;
    h.ttl = u8(p[8]);
    h.protocol = u8(p[9]);
    h.src = Ipv4Addr{load_be32(p.data() + 12)};
    h.dst = Ipv4Addr{load_be32(p.data() + 16)};
    return h;
}

void write_ipv4(MutBytes out, const Ipv4& h) {
    out[0] = std::byte{0x45};
    out[1] = std::byte{h.tos};
    store_be16(out.data() + 2, h.total_length);
    store_be16(out.data() + 4, h.id);
    store_be16(out.data() + 6, h.dont_fragment ? 0x4000 : 0);
    out[8] = std::byte{h.ttl};
    out[9] = std::byte{h.protocol};
    store_be16(out.data() + 10, 0);
    store_be32(out.data() + 12, h.src.v);
    store_be32(out.data() + 16, h.dst.v);
    store_be16(out.data() + 10, checksum::compute(out.first(kIpv4MinSize)));
}

std::expected<Icmp, ParseError> parse_icmp(Bytes m) {
    if (m.size() < kIcmpHeaderSize) return std::unexpected(ParseError::too_short);
    if (checksum::ones_sum(m) != 0xffff) return std::unexpected(ParseError::bad_checksum);
    return Icmp{u8(m[0]), u8(m[1]), load_be32(m.data() + 4)};
}

void write_icmp(MutBytes m, const Icmp& h) {
    m[0] = std::byte{h.type};
    m[1] = std::byte{h.code};
    store_be16(m.data() + 2, 0);
    store_be32(m.data() + 4, h.rest);
    store_be16(m.data() + 2, checksum::compute(m));
}

std::expected<Udp, ParseError> parse_udp(Bytes s, Ipv4Addr src, Ipv4Addr dst) {
    if (s.size() < kUdpSize) return std::unexpected(ParseError::too_short);
    Udp h{load_be16(s.data()), load_be16(s.data() + 2), load_be16(s.data() + 4)};
    if (h.length < kUdpSize || h.length > s.size()) return std::unexpected(ParseError::bad_length);
    std::uint16_t sum = load_be16(s.data() + 6);
    if (sum != 0 && checksum::ones_sum(s.first(h.length), checksum::Variant::simd,
                                       pseudo(src, dst, kProtoUdp, h.length)) != 0xffff) {
        return std::unexpected(ParseError::bad_checksum);  // a zero checksum means "not computed"
    }
    return h;
}

void write_udp(MutBytes s, const Udp& h, Ipv4Addr src, Ipv4Addr dst) {
    store_be16(s.data(), h.src_port);
    store_be16(s.data() + 2, h.dst_port);
    store_be16(s.data() + 4, h.length);
    store_be16(s.data() + 6, 0);
    std::uint16_t sum = checksum::compute(s.first(h.length), pseudo(src, dst, kProtoUdp, h.length));
    store_be16(s.data() + 6, sum == 0 ? 0xffff : sum);  // RFC 768: transmit an all-ones zero
}

std::expected<Tcp, ParseError> parse_tcp(Bytes s, Ipv4Addr src, Ipv4Addr dst) {
    if (s.size() < kTcpMinSize) return std::unexpected(ParseError::too_short);
    std::size_t off = (u8(s[12]) >> 4) * 4U;
    if (off < kTcpMinSize || off > s.size()) return std::unexpected(ParseError::bad_length);
    if (checksum::ones_sum(s, checksum::Variant::simd, pseudo(src, dst, kProtoTcp, s.size())) != 0xffff) {
        return std::unexpected(ParseError::bad_checksum);
    }
    Tcp h;
    h.src_port = load_be16(s.data());
    h.dst_port = load_be16(s.data() + 2);
    h.seq = load_be32(s.data() + 4);
    h.ack = load_be32(s.data() + 8);
    h.header_size = static_cast<std::uint8_t>(off);
    h.flags = u8(s[13]) & 0x3fU;
    h.window = load_be16(s.data() + 14);
    h.urgent = load_be16(s.data() + 18);
    // Options (RFC 9293 §3.2): kind 0 ends the list, 1 is padding, others are kind, length, data.
    for (std::size_t i = kTcpMinSize; i < off;) {
        std::uint8_t kind = u8(s[i]);
        if (kind == 0) break;
        if (kind == 1) {
            ++i;
            continue;
        }
        if (i + 1 >= off) return std::unexpected(ParseError::bad_options);
        std::size_t len = u8(s[i + 1]);
        if (len < 2 || i + len > off) return std::unexpected(ParseError::bad_options);
        if (kind == 2 && len == 4) h.options.mss = load_be16(s.data() + i + 2);
        if (kind == 3 && len == 3) h.options.window_scale = u8(s[i + 2]);
        if (kind == 4 && len == 2) h.options.sack_permitted = true;
        i += len;
    }
    return h;
}

std::size_t tcp_header_size(const TcpOptions& o) {
    std::size_t n = kTcpMinSize;
    if (o.mss) n += 4;
    if (o.window_scale) n += 4;  // NOP + 3-byte option keeps 4-byte alignment
    return n;
}

void write_tcp(MutBytes s, const Tcp& h, Ipv4Addr src, Ipv4Addr dst) {
    std::size_t hs = tcp_header_size(h.options);
    store_be16(s.data(), h.src_port);
    store_be16(s.data() + 2, h.dst_port);
    store_be32(s.data() + 4, h.seq);
    store_be32(s.data() + 8, h.ack);
    s[12] = to_byte(static_cast<unsigned>(hs / 4) << 4);
    s[13] = std::byte{h.flags};
    store_be16(s.data() + 14, h.window);
    store_be16(s.data() + 16, 0);
    store_be16(s.data() + 18, h.urgent);
    std::size_t i = kTcpMinSize;
    if (h.options.mss) {
        s[i] = std::byte{2};
        s[i + 1] = std::byte{4};
        store_be16(s.data() + i + 2, *h.options.mss);
        i += 4;
    }
    if (h.options.window_scale) {
        s[i] = std::byte{1};  // NOP
        s[i + 1] = std::byte{3};
        s[i + 2] = std::byte{3};
        s[i + 3] = std::byte{*h.options.window_scale};
        i += 4;
    }
    store_be16(s.data() + 16, checksum::compute(s, pseudo(src, dst, kProtoTcp, s.size())));
}

std::string flags_str(std::uint8_t f) {
    std::string out;
    if (f & kSyn) out += "S";
    if (f & kFin) out += "F";
    if (f & kRst) out += "R";
    if (f & kPsh) out += "P";
    if (f & kAck) out += ".";
    return out.empty() ? "-" : out;
}

}  // namespace wire
}  // namespace tundra
