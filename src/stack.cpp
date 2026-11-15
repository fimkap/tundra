#include "tundra/stack.hpp"

#include <algorithm>
#include <random>

#include "tundra/checksum.hpp"
#include "tundra/pcap.hpp"

namespace tundra {
namespace {

// SipHash-2-4 (Aumasson & Bernstein), used as the keyed hash for initial sequence numbers (RFC 6528).
std::uint64_t rotl(std::uint64_t x, int b) { return (x << b) | (x >> (64 - b)); }

std::uint64_t siphash24(const std::uint64_t key[2], const std::uint8_t* in, std::size_t len) {
    std::uint64_t v0 = 0x736f6d6570736575ULL ^ key[0], v1 = 0x646f72616e646f6dULL ^ key[1];
    std::uint64_t v2 = 0x6c7967656e657261ULL ^ key[0], v3 = 0x7465646279746573ULL ^ key[1];
    auto round = [&] {
        v0 += v1, v1 = rotl(v1, 13), v1 ^= v0, v0 = rotl(v0, 32);
        v2 += v3, v3 = rotl(v3, 16), v3 ^= v2;
        v0 += v3, v3 = rotl(v3, 21), v3 ^= v0;
        v2 += v1, v1 = rotl(v1, 17), v1 ^= v2, v2 = rotl(v2, 32);
    };
    std::uint64_t b = static_cast<std::uint64_t>(len) << 56;
    std::size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        std::uint64_t m = 0;
        for (int k = 0; k < 8; ++k) m |= static_cast<std::uint64_t>(in[i + k]) << (8 * k);
        v3 ^= m;
        round(), round();
        v0 ^= m;
    }
    for (int k = 0; i + k < len; ++k) b |= static_cast<std::uint64_t>(in[i + k]) << (8 * k);
    v3 ^= b;
    round(), round();
    v0 ^= b;
    v2 ^= 0xff;
    round(), round(), round(), round();
    return v0 ^ v1 ^ v2 ^ v3;
}

constexpr auto kArpLifetime = std::chrono::seconds(60);
constexpr auto kArpRetry = std::chrono::seconds(1);
constexpr int kArpMaxRequests = 3;
constexpr std::size_t kArpMaxPending = 64;

}  // namespace

Stack::Stack(NetDevice& dev, Clock& clock, StackConfig cfg) : dev_(dev), clock_(clock), cfg_(std::move(cfg)) {
    l2_ = dev_.link_type() == LinkType::ethernet ? wire::kEthernetSize : 0;
    std::mt19937_64 rng(cfg_.seed);
    isn_key_[0] = rng();
    isn_key_[1] = rng();
    next_port_ = static_cast<std::uint16_t>(49152 + rng() % 16384);
}

Stack::~Stack() {
    for (auto& [t, c] : conns_) {
        c->on_closed = nullptr;  // the application may already be gone
    }
}

void Stack::transmit(Bytes frame) {
    ++stats_.frames_out;
    if (pcap_) pcap_->write(clock_.now(), frame);
    dev_.transmit(frame);
}

void Stack::receive(Bytes frame) {
    ++stats_.frames_in;
    if (pcap_) pcap_->write(clock_.now(), frame);
    if (l2_ == 0) {
        on_ipv4(frame);
    } else {
        auto eth = wire::parse_ethernet(frame);
        if (!eth) {
            ++stats_.dropped_malformed;
        } else if (eth->dst != cfg_.mac && eth->dst != MacAddr::broadcast()) {
            ++stats_.dropped_not_for_us;
        } else if (eth->ethertype == wire::kEtherArp) {
            on_arp(frame.subspan(wire::kEthernetSize));
        } else if (eth->ethertype == wire::kEtherIpv4) {
            on_ipv4(frame.subspan(wire::kEthernetSize));
        } else {
            ++stats_.dropped_not_for_us;
        }
    }
    collect_garbage();
}

void Stack::run_timers() {
    timers_.run_due(clock_.now());
    // ARP retries for destinations still unresolved.
    TimePoint now = clock_.now();
    for (auto it = pending_.begin(); it != pending_.end();) {
        auto& p = it->second;
        if (now - p.last_request >= kArpRetry) {
            if (p.requests >= kArpMaxRequests) {
                stats_.dropped_no_arp += p.frames.size();
                it = pending_.erase(it);
                continue;
            }
            send_arp(wire::kArpRequest, MacAddr::broadcast(), Ipv4Addr{it->first}, MacAddr{});
            p.last_request = now;
            ++p.requests;
        }
        ++it;
    }
    collect_garbage();
}

// ---- ARP -------------------------------------------------------------------------------------------

void Stack::send_arp(std::uint16_t op, MacAddr dst_mac, Ipv4Addr target_ip, MacAddr target_mac) {
    Buffer f(wire::kEthernetSize + wire::kArpSize);
    wire::write_ethernet(f, {dst_mac, cfg_.mac, wire::kEtherArp});
    wire::write_arp(MutBytes(f).subspan(wire::kEthernetSize), {op, cfg_.mac, cfg_.ip, target_mac, target_ip});
    (op == wire::kArpRequest ? stats_.arp_requests_out : stats_.arp_replies_out)++;
    transmit(f);
}

void Stack::on_arp(Bytes payload) {
    auto a = wire::parse_arp(payload);
    if (!a) {
        ++stats_.dropped_malformed;
        return;
    }
    if (a->target_ip != cfg_.ip) {
        ++stats_.dropped_not_for_us;
        return;
    }
    // Learn (or refresh) the sender's address, then flush anything waiting for it (RFC 826).
    arp_[a->sender_ip.v] = {a->sender_mac, clock_.now() + kArpLifetime};
    if (auto it = pending_.find(a->sender_ip.v); it != pending_.end()) {
        auto frames = std::move(it->second.frames);
        pending_.erase(it);
        for (auto& f : frames) {
            wire::write_ethernet(f, {a->sender_mac, cfg_.mac, wire::kEtherIpv4});
            transmit(f);
        }
    }
    if (a->op == wire::kArpRequest) send_arp(wire::kArpReply, a->sender_mac, a->sender_ip, a->sender_mac);
}

bool Stack::on_link(Ipv4Addr a) const {
    std::uint32_t mask = cfg_.prefix_len == 0 ? 0 : ~std::uint32_t{0} << (32 - cfg_.prefix_len);
    return (a.v & mask) == (cfg_.ip.v & mask);
}

void Stack::transmit_frame(Ipv4Addr dst, Buffer frame) {
    if (l2_ == 0) {
        transmit(frame);
        return;
    }
    Ipv4Addr next_hop = (on_link(dst) || !cfg_.gateway) ? dst : *cfg_.gateway;
    auto it = arp_.find(next_hop.v);
    if (it != arp_.end() && it->second.expires > clock_.now()) {
        wire::write_ethernet(frame, {it->second.mac, cfg_.mac, wire::kEtherIpv4});
        transmit(frame);
        return;
    }
    auto& p = pending_[next_hop.v];
    if (p.frames.size() >= kArpMaxPending) {
        ++stats_.dropped_no_arp;
        return;
    }
    p.frames.push_back(std::move(frame));
    if (p.requests == 0) {
        send_arp(wire::kArpRequest, MacAddr::broadcast(), next_hop, MacAddr{});
        p.last_request = clock_.now();
        p.requests = 1;
    }
}

// ---- IPv4 ------------------------------------------------------------------------------------------

void Stack::send_ip(std::uint8_t protocol, Ipv4Addr dst, std::size_t l4_len, const std::function<void(MutBytes)>& fill) {
    Buffer f(l2_ + wire::kIpv4MinSize + l4_len);
    fill(MutBytes(f).subspan(l2_ + wire::kIpv4MinSize));
    wire::write_ipv4(MutBytes(f).subspan(l2_),
                     {.total_length = static_cast<std::uint16_t>(wire::kIpv4MinSize + l4_len),
                      .id = ip_id_++,
                      .protocol = protocol,
                      .src = cfg_.ip,
                      .dst = dst});
    transmit_frame(dst, std::move(f));
}

void Stack::on_ipv4(Bytes packet) {
    auto ip = wire::parse_ipv4(packet);
    if (!ip) {
        ++stats_.dropped_malformed;
        return;
    }
    if (ip->dst != cfg_.ip) {
        ++stats_.dropped_not_for_us;
        return;
    }
    Bytes datagram = packet.first(ip->total_length);  // drop Ethernet padding
    Bytes l4 = datagram.subspan(ip->header_size);
    switch (ip->protocol) {
        case wire::kProtoIcmp: on_icmp(*ip, datagram, l4); break;
        case wire::kProtoUdp: on_udp(*ip, datagram, l4); break;
        case wire::kProtoTcp: on_tcp(*ip, l4); break;
        default: ++stats_.dropped_not_for_us; break;
    }
}

void Stack::on_icmp(const wire::Ipv4& ip, Bytes, Bytes message) {
    auto icmp = wire::parse_icmp(message);
    if (!icmp) {
        ++stats_.dropped_malformed;
        return;
    }
    if (icmp->type != wire::kIcmpEchoRequest) return;
    ++stats_.icmp_echo_replies;
    send_ip(wire::kProtoIcmp, ip.src, message.size(), [&](MutBytes out) {
        std::copy(message.begin(), message.end(), out.begin());
        wire::write_icmp(out, {wire::kIcmpEchoReply, 0, icmp->rest});
    });
}

// ---- UDP -------------------------------------------------------------------------------------------

bool Stack::udp_bind(std::uint16_t port, UdpHandler handler) { return udp_.emplace(port, std::move(handler)).second; }

void Stack::udp_send(std::uint16_t src_port, Ipv4Addr dst, std::uint16_t dst_port, Bytes payload) {
    ++stats_.udp_out;
    std::size_t len = wire::kUdpSize + payload.size();
    send_ip(wire::kProtoUdp, dst, len, [&](MutBytes out) {
        std::copy(payload.begin(), payload.end(), out.begin() + wire::kUdpSize);
        wire::write_udp(out, {src_port, dst_port, static_cast<std::uint16_t>(len)}, cfg_.ip, dst);
    });
}

void Stack::on_udp(const wire::Ipv4& ip, Bytes datagram, Bytes segment) {
    auto u = wire::parse_udp(segment, ip.src, ip.dst);
    if (!u) {
        ++stats_.dropped_malformed;
        return;
    }
    ++stats_.udp_in;
    auto it = udp_.find(u->dst_port);
    if (it == udp_.end()) {
        // Port unreachable, quoting the IP header and the first 8 bytes (RFC 792).
        ++stats_.icmp_unreachable_out;
        std::size_t quote = std::min<std::size_t>(datagram.size(), ip.header_size + 8);
        send_ip(wire::kProtoIcmp, ip.src, wire::kIcmpHeaderSize + quote, [&](MutBytes out) {
            std::copy(datagram.begin(), datagram.begin() + static_cast<std::ptrdiff_t>(quote),
                      out.begin() + wire::kIcmpHeaderSize);
            wire::write_icmp(out, {wire::kIcmpDestUnreachable, wire::kIcmpPortUnreachable, 0});
        });
        return;
    }
    it->second(ip.src, u->src_port, segment.subspan(wire::kUdpSize, u->length - wire::kUdpSize));
}

// ---- TCP -------------------------------------------------------------------------------------------

std::uint32_t Stack::make_isn(const FourTuple& t) {
    // RFC 6528: ISN = M + F(4-tuple, secret), M a 4-microsecond clock.
    std::uint8_t in[12];
    for (int i = 0; i < 4; ++i) {
        in[i] = static_cast<std::uint8_t>(t.local_ip.v >> (8 * i));
        in[4 + i] = static_cast<std::uint8_t>(t.remote_ip.v >> (8 * i));
    }
    in[8] = static_cast<std::uint8_t>(t.local_port);
    in[9] = static_cast<std::uint8_t>(t.local_port >> 8);
    in[10] = static_cast<std::uint8_t>(t.remote_port);
    in[11] = static_cast<std::uint8_t>(t.remote_port >> 8);
    auto m = static_cast<std::uint32_t>(clock_.now().time_since_epoch().count() / 4000);
    return m + static_cast<std::uint32_t>(siphash24(isn_key_, in, sizeof in));
}

bool Stack::tcp_listen(std::uint16_t port, AcceptHandler handler) {
    return listeners_.emplace(port, std::move(handler)).second;
}

std::shared_ptr<TcpConnection> Stack::tcp_connect(Ipv4Addr dst, std::uint16_t port) {
    FourTuple t{cfg_.ip, 0, dst, port};
    for (int tries = 0; tries < 16384; ++tries) {
        t.local_port = next_port_;
        next_port_ = next_port_ == 65535 ? 49152 : static_cast<std::uint16_t>(next_port_ + 1);
        if (!conns_.contains(t) && !listeners_.contains(t.local_port)) break;
    }
    auto c = std::make_shared<TcpConnection>(*this, t, cfg_.tcp);
    conns_.emplace(t, c);
    ++stats_.tcp_connections_opened;
    c->open_active(make_isn(t));
    collect_garbage();
    return c;
}

void Stack::send_tcp(const FourTuple& t, const wire::Tcp& h, Bytes payload) {
    std::size_t hs = wire::tcp_header_size(h.options);
    send_ip(wire::kProtoTcp, t.remote_ip, hs + payload.size(), [&](MutBytes out) {
        std::copy(payload.begin(), payload.end(), out.begin() + static_cast<std::ptrdiff_t>(hs));
        wire::write_tcp(out, h, cfg_.ip, t.remote_ip);
    });
}

void Stack::send_rst_for(const wire::Tcp& h, Ipv4Addr from, std::size_t payload_len) {
    // RFC 9293 §3.10.7.1: never answer a RST; take the sequence from the ACK if there is one, otherwise
    // acknowledge everything the segment occupied.
    if (h.flags & wire::kRst) return;
    wire::Tcp r;
    r.src_port = h.dst_port;
    r.dst_port = h.src_port;
    if (h.flags & wire::kAck) {
        r.seq = h.ack;
        r.flags = wire::kRst;
    } else {
        r.ack = h.seq + static_cast<std::uint32_t>(payload_len) + ((h.flags & wire::kSyn) ? 1 : 0) +
                ((h.flags & wire::kFin) ? 1 : 0);
        r.flags = wire::kRst | wire::kAck;
    }
    ++stats_.tcp_resets_out;
    send_tcp(FourTuple{cfg_.ip, h.dst_port, from, h.src_port}, r, {});
}

void Stack::on_tcp(const wire::Ipv4& ip, Bytes segment) {
    auto h = wire::parse_tcp(segment, ip.src, ip.dst);
    if (!h) {
        ++stats_.dropped_malformed;
        return;
    }
    Bytes payload = segment.subspan(h->header_size);
    FourTuple t{cfg_.ip, h->dst_port, ip.src, h->src_port};
    if (auto it = conns_.find(t); it != conns_.end()) {
        auto c = it->second;  // may be released while it handles the segment
        c->on_segment(*h, payload);
        return;
    }
    // No connection: a SYN to a listening port opens one (§3.10.7.2); anything else gets a RST.
    auto l = listeners_.find(h->dst_port);
    if (l != listeners_.end() && (h->flags & (wire::kSyn | wire::kAck | wire::kRst)) == wire::kSyn) {
        auto c = std::make_shared<TcpConnection>(*this, t, cfg_.tcp);
        conns_.emplace(t, c);
        ++stats_.tcp_connections_opened;
        c->open_passive(*h, make_isn(t));
        return;
    }
    if (l != listeners_.end() && (h->flags & wire::kRst)) return;  // a RST to a listener is ignored
    send_rst_for(*h, ip.src, payload.size());
}

void Stack::tcp_established(TcpConnection& c) {
    auto l = listeners_.find(c.tuple().local_port);
    if (l != listeners_.end() && l->second) l->second(c.shared_from_this());
}

void Stack::tcp_release(TcpConnection& c) {
    auto it = conns_.find(c.tuple());
    if (it != conns_.end() && it->second.get() == &c) {
        graveyard_.push_back(std::move(it->second));
        conns_.erase(it);
    }
}

}  // namespace tundra
