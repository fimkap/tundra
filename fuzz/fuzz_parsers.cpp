// Arbitrary bytes into every parser. Checksums are fixed up first, so the fuzzer reaches the code behind
// the checksum checks (TCP options, IPv4 header validation) instead of bouncing off them. Every input
// also checks a property: all four checksum variants agree.
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "tundra/checksum.hpp"
#include "tundra/wire.hpp"

using namespace tundra;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    Bytes raw(reinterpret_cast<const std::byte*>(data), size);
    const Ipv4Addr a{0x0a000001}, b{0x0a000002};

    std::uint16_t want = checksum::ones_sum(raw, checksum::Variant::scalar16);
    for (auto v : checksum::kAllVariants) {
        if (checksum::ones_sum(raw, v) != want) __builtin_trap();
    }

    (void)wire::parse_ethernet(raw);
    (void)wire::parse_arp(raw);
    (void)wire::parse_icmp(raw);
    (void)wire::parse_udp(raw, a, b);

    Buffer buf(raw.begin(), raw.end());
    if (buf.size() >= wire::kTcpMinSize) {  // a TCP segment with a valid checksum
        store_be16(buf.data() + 16, 0);
        store_be16(buf.data() + 16, checksum::compute(buf, checksum::pseudo_header_sum(a.v, b.v, wire::kProtoTcp,
                                                                                       static_cast<std::uint16_t>(buf.size()))));
        if (auto h = wire::parse_tcp(buf, a, b); h && h->header_size > buf.size()) __builtin_trap();
    }
    buf.assign(raw.begin(), raw.end());
    if (buf.size() >= wire::kIpv4MinSize) {  // an IPv4 header with a valid checksum
        std::size_t ihl = std::min<std::size_t>((std::to_integer<unsigned>(buf[0]) & 0x0f) * 4u, buf.size());
        if (ihl >= wire::kIpv4MinSize) {
            store_be16(buf.data() + 10, 0);
            store_be16(buf.data() + 10, checksum::compute(Bytes(buf).first(ihl)));
        }
        if (auto ip = wire::parse_ipv4(buf)) {
            if (ip->header_size > ip->total_length || ip->total_length > buf.size()) __builtin_trap();
            Bytes l4 = Bytes(buf).subspan(ip->header_size, ip->total_length - ip->header_size);
            (void)wire::parse_tcp(l4, ip->src, ip->dst);
            (void)wire::parse_udp(l4, ip->src, ip->dst);
            (void)wire::parse_icmp(l4);
        }
    }
    return 0;
}
