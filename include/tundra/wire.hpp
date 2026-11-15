// Wire formats: Ethernet II, ARP, IPv4, ICMP, UDP and TCP. Parsers check every length before reading and
// return errors as values; serializers write into caller-provided spans and fill in checksums.
#pragma once

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>

#include "tundra/bytes.hpp"

namespace tundra {

struct MacAddr {
    std::array<std::uint8_t, 6> b{};
    static constexpr MacAddr broadcast() { return {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}; }
    bool operator==(const MacAddr&) const = default;
    std::string str() const;
};

struct Ipv4Addr {
    std::uint32_t v = 0;  // host byte order
    static std::optional<Ipv4Addr> parse(std::string_view dotted);
    auto operator<=>(const Ipv4Addr&) const = default;
    std::string str() const;
};

enum class ParseError {
    too_short,
    bad_version,
    bad_length,
    bad_checksum,
    bad_options,
    fragmented,  // IPv4 fragments are not reassembled
    unsupported,
};

std::string_view to_string(ParseError e);

namespace wire {

// ---- Ethernet II -----------------------------------------------------------------------------------
inline constexpr std::size_t kEthernetSize = 14;
inline constexpr std::uint16_t kEtherIpv4 = 0x0800;
inline constexpr std::uint16_t kEtherArp = 0x0806;

struct Ethernet {
    MacAddr dst, src;
    std::uint16_t ethertype = 0;
};

std::expected<Ethernet, ParseError> parse_ethernet(Bytes frame);
void write_ethernet(MutBytes out, const Ethernet& h);

// ---- ARP (Ethernet + IPv4 only) --------------------------------------------------------------------
inline constexpr std::size_t kArpSize = 28;
inline constexpr std::uint16_t kArpRequest = 1;
inline constexpr std::uint16_t kArpReply = 2;

struct Arp {
    std::uint16_t op = 0;
    MacAddr sender_mac;
    Ipv4Addr sender_ip;
    MacAddr target_mac;
    Ipv4Addr target_ip;
};

std::expected<Arp, ParseError> parse_arp(Bytes payload);
void write_arp(MutBytes out, const Arp& a);

// ---- IPv4 ------------------------------------------------------------------------------------------
inline constexpr std::size_t kIpv4MinSize = 20;
inline constexpr std::uint8_t kProtoIcmp = 1;
inline constexpr std::uint8_t kProtoTcp = 6;
inline constexpr std::uint8_t kProtoUdp = 17;

struct Ipv4 {
    std::uint8_t header_size = 20;  // IHL in bytes
    std::uint8_t tos = 0;
    std::uint16_t total_length = 0;
    std::uint16_t id = 0;
    bool dont_fragment = true;
    std::uint8_t ttl = 64;
    std::uint8_t protocol = 0;
    Ipv4Addr src, dst;
};

// parse_ipv4 validates version, header length, total length and header checksum, and rejects fragments.
// Options are skipped (header_size tells where the payload starts).
std::expected<Ipv4, ParseError> parse_ipv4(Bytes packet);
// write_ipv4 writes a 20-byte header (no options) including its checksum.
void write_ipv4(MutBytes out, const Ipv4& h);

// ---- ICMP ------------------------------------------------------------------------------------------
inline constexpr std::size_t kIcmpHeaderSize = 8;
inline constexpr std::uint8_t kIcmpEchoReply = 0;
inline constexpr std::uint8_t kIcmpDestUnreachable = 3;
inline constexpr std::uint8_t kIcmpEchoRequest = 8;
inline constexpr std::uint8_t kIcmpPortUnreachable = 3;  // code for kIcmpDestUnreachable

struct Icmp {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
    std::uint32_t rest = 0;  // identifier and sequence for echo
};

std::expected<Icmp, ParseError> parse_icmp(Bytes message);  // verifies the checksum over the message
void write_icmp(MutBytes message, const Icmp& h);           // header at the front; checksum over all

// ---- UDP -------------------------------------------------------------------------------------------
inline constexpr std::size_t kUdpSize = 8;

struct Udp {
    std::uint16_t src_port = 0, dst_port = 0;
    std::uint16_t length = 0;  // header + payload
};

std::expected<Udp, ParseError> parse_udp(Bytes segment, Ipv4Addr src, Ipv4Addr dst);
void write_udp(MutBytes segment, const Udp& h, Ipv4Addr src, Ipv4Addr dst);  // payload already in place

// ---- TCP -------------------------------------------------------------------------------------------
inline constexpr std::size_t kTcpMinSize = 20;
inline constexpr std::uint8_t kFin = 0x01;
inline constexpr std::uint8_t kSyn = 0x02;
inline constexpr std::uint8_t kRst = 0x04;
inline constexpr std::uint8_t kPsh = 0x08;
inline constexpr std::uint8_t kAck = 0x10;
inline constexpr std::uint8_t kUrg = 0x20;

struct TcpOptions {
    std::optional<std::uint16_t> mss;
    std::optional<std::uint8_t> window_scale;
    bool sack_permitted = false;  // parsed, not acted on
};

struct Tcp {
    std::uint16_t src_port = 0, dst_port = 0;
    std::uint32_t seq = 0, ack = 0;
    std::uint8_t header_size = 20;  // data offset in bytes
    std::uint8_t flags = 0;
    std::uint16_t window = 0;
    std::uint16_t urgent = 0;
    TcpOptions options;
};

std::expected<Tcp, ParseError> parse_tcp(Bytes segment, Ipv4Addr src, Ipv4Addr dst);
// tcp_header_size is 20 plus the options this header will carry, padded to 4 bytes.
std::size_t tcp_header_size(const TcpOptions& o);
// write_tcp writes the header and options at the front of segment and the checksum over all of segment
// (the payload must already follow the header).
void write_tcp(MutBytes segment, const Tcp& h, Ipv4Addr src, Ipv4Addr dst);

std::string flags_str(std::uint8_t flags);

}  // namespace wire
}  // namespace tundra
