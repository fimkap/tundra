// Helpers shared by the tests: a device that records what the stack sends, frame builders for scripted
// exchanges, and an echo service.
#pragma once

#include <cstring>
#include <deque>
#include <memory>
#include <stdexcept>
#include <string>

#include "tundra/checksum.hpp"
#include "tundra/netdev.hpp"
#include "tundra/stack.hpp"
#include "tundra/wire.hpp"

namespace tundra::test {

inline const Ipv4Addr kPeerIp = *Ipv4Addr::parse("10.0.0.1");
inline const Ipv4Addr kStackIp = *Ipv4Addr::parse("10.0.0.2");
inline const MacAddr kPeerMac{{0x02, 0, 0, 0, 0, 0x01}};
inline const MacAddr kStackMac{{0x02, 0, 0, 0, 0, 0x02}};

// CaptureDevice keeps every frame the stack transmits.
class CaptureDevice final : public NetDevice {
public:
    explicit CaptureDevice(LinkType t) : type_(t) {}
    LinkType link_type() const override { return type_; }
    void transmit(Bytes frame) override { frames.emplace_back(frame.begin(), frame.end()); }
    Buffer pop() {
        Buffer f = std::move(frames.front());
        frames.pop_front();
        return f;
    }
    std::deque<Buffer> frames;

private:
    LinkType type_;
};

// ip_packet wraps an L4 payload (written by fill) in an IPv4 header from the peer to the stack.
template <typename Fill>
Buffer ip_packet(std::uint8_t proto, std::size_t l4_len, Fill fill, Ipv4Addr src = kPeerIp, Ipv4Addr dst = kStackIp) {
    Buffer p(wire::kIpv4MinSize + l4_len);
    fill(MutBytes(p).subspan(wire::kIpv4MinSize));
    wire::write_ipv4(p, {.total_length = static_cast<std::uint16_t>(p.size()), .protocol = proto, .src = src, .dst = dst});
    return p;
}

inline Buffer tcp_packet(const wire::Tcp& h, Bytes payload = {}) {
    std::size_t hs = wire::tcp_header_size(h.options);
    return ip_packet(wire::kProtoTcp, hs + payload.size(), [&](MutBytes out) {
        std::copy(payload.begin(), payload.end(), out.begin() + static_cast<std::ptrdiff_t>(hs));
        wire::write_tcp(out, h, kPeerIp, kStackIp);
    });
}

// ParsedTcp is a transmitted segment decoded for assertions (IP links: no Ethernet header).
struct ParsedTcp {
    wire::Tcp h;
    Buffer payload;
};

inline ParsedTcp parse_tcp_out(const Buffer& frame) {
    auto ip = wire::parse_ipv4(frame);
    if (!ip || ip->protocol != wire::kProtoTcp) throw std::runtime_error("not a TCP packet");
    Bytes seg = Bytes(frame).subspan(ip->header_size, ip->total_length - ip->header_size);
    auto h = wire::parse_tcp(seg, ip->src, ip->dst);
    if (!h) throw std::runtime_error("bad TCP segment");
    return {*h, Buffer(seg.begin() + h->header_size, seg.end())};
}

inline std::string str(Bytes b) { return std::string(reinterpret_cast<const char*>(b.data()), b.size()); }
inline Buffer buf(std::string_view s) {
    Buffer b(s.size());
    std::memcpy(b.data(), s.data(), s.size());
    return b;
}

// serve_echo makes a listener that echoes everything back and closes when the peer closes.
inline void serve_echo(Stack& s, std::uint16_t port) {
    s.tcp_listen(port, [](std::shared_ptr<TcpConnection> c) {
        std::weak_ptr<TcpConnection> w = c;
        auto pending = std::make_shared<Buffer>();
        auto flush = [w, pending] {
            auto conn = w.lock();
            if (!conn || pending->empty()) return;
            std::size_t n = conn->send(*pending);
            pending->erase(pending->begin(), pending->begin() + static_cast<std::ptrdiff_t>(n));
        };
        c->on_data = [pending, flush](Bytes d) {
            pending->insert(pending->end(), d.begin(), d.end());
            flush();
        };
        c->on_peer_closed = [w, pending] {
            auto conn = w.lock();
            if (conn && pending->empty()) conn->close();
        };
        c->on_writable = [w, pending, flush] {
            flush();
            auto conn = w.lock();
            if (conn && pending->empty() && conn->state() == TcpState::close_wait) conn->close();
        };
    });
}

}  // namespace tundra::test
