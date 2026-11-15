// Structure-aware fuzzing of a live stack. The input is read as a program: well-formed TCP segments
// (valid checksums, sequence numbers near the connection's window so they get past the acceptability
// test), raw frames, UDP and ICMP, clock jumps that fire timers, and application calls (send, close,
// abort, pause, resume, connect). ASan and UBSan watch everything.
#include <fuzzer/FuzzedDataProvider.h>

#include <memory>
#include <vector>

#include "tundra/checksum.hpp"
#include "tundra/stack.hpp"

using namespace tundra;

namespace {

const Ipv4Addr kPeer{0x0a000001}, kUs{0x0a000002};
const MacAddr kPeerMac{{2, 0, 0, 0, 0, 1}}, kUsMac{{2, 0, 0, 0, 0, 2}};

struct Dev final : NetDevice {
    LinkType link_type() const override { return LinkType::ethernet; }
    void transmit(Bytes f) override { last.assign(f.begin(), f.end()); }
    Buffer last;
};

Buffer ip_frame(std::uint8_t proto, std::size_t l4_len, auto fill) {
    Buffer f(wire::kEthernetSize + wire::kIpv4MinSize + l4_len);
    wire::write_ethernet(f, {kUsMac, kPeerMac, wire::kEtherIpv4});
    fill(MutBytes(f).subspan(wire::kEthernetSize + wire::kIpv4MinSize));
    wire::write_ipv4(MutBytes(f).subspan(wire::kEthernetSize),
                     {.total_length = static_cast<std::uint16_t>(wire::kIpv4MinSize + l4_len), .protocol = proto,
                      .src = kPeer, .dst = kUs});
    return f;
}

Bytes bytes_of(const std::vector<std::uint8_t>& v) { return std::as_bytes(std::span(v.data(), v.size())); }

void put(MutBytes out, std::size_t at, const std::vector<std::uint8_t>& v) {
    std::copy(v.begin(), v.end(), reinterpret_cast<std::uint8_t*>(out.data()) + at);  // no memcpy(nullptr, 0)
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    FuzzedDataProvider in(data, size);
    ManualClock clock;
    Dev dev;
    StackConfig cfg;
    cfg.ip = kUs;
    cfg.mac = kUsMac;
    cfg.tcp.recv_buffer = std::size_t{1024} << in.ConsumeIntegralInRange(0, 8);
    cfg.tcp.send_buffer = std::size_t{1024} << in.ConsumeIntegralInRange(0, 8);
    cfg.tcp.msl = 1s;
    Stack s(dev, clock, cfg);
    std::vector<std::shared_ptr<TcpConnection>> conns;
    s.tcp_listen(80, [&](std::shared_ptr<TcpConnection> c) {
        c->on_data = [](Bytes) {};
        conns.push_back(std::move(c));
    });
    s.udp_bind(7, [&](Ipv4Addr src, std::uint16_t port, Bytes p) { s.udp_send(7, src, port, p); });

    // Introduce the peer, so the stack can answer without waiting on ARP.
    {
        Buffer f(wire::kEthernetSize + wire::kArpSize);
        wire::write_ethernet(f, {MacAddr::broadcast(), kPeerMac, wire::kEtherArp});
        wire::write_arp(MutBytes(f).subspan(wire::kEthernetSize), {wire::kArpRequest, kPeerMac, kPeer, MacAddr{}, kUs});
        s.receive(f);
    }

    std::uint32_t peer_seq = 1000, our_seq = 0;
    while (in.remaining_bytes() > 0) {
        switch (in.ConsumeIntegralInRange(0, 6)) {
            case 0: {  // a raw frame
                auto f = in.ConsumeBytes<std::uint8_t>(in.ConsumeIntegralInRange<std::size_t>(0, 1600));
                s.receive(bytes_of(f));
                break;
            }
            case 1: {  // a well-formed TCP segment
                wire::Tcp h;
                h.src_port = static_cast<std::uint16_t>(40000 + in.ConsumeIntegralInRange(0, 2));
                h.dst_port = in.ConsumeBool() ? 80 : in.ConsumeIntegral<std::uint16_t>();
                h.flags = in.ConsumeIntegral<std::uint8_t>() & 0x3f;
                h.seq = peer_seq + static_cast<std::uint32_t>(in.ConsumeIntegralInRange(-3000, 70000));
                h.ack = our_seq + static_cast<std::uint32_t>(in.ConsumeIntegralInRange(-3000, 300000));
                h.window = in.ConsumeIntegral<std::uint16_t>();
                if (in.ConsumeBool()) h.options.mss = in.ConsumeIntegral<std::uint16_t>();
                if (in.ConsumeBool()) h.options.window_scale = in.ConsumeIntegralInRange<std::uint8_t>(0, 20);
                auto payload = in.ConsumeBytes<std::uint8_t>(in.ConsumeIntegralInRange<std::size_t>(0, 3000));
                if (in.ConsumeBool()) {
                    peer_seq = h.seq + static_cast<std::uint32_t>(payload.size()) + ((h.flags & wire::kSyn) ? 1 : 0) +
                               ((h.flags & wire::kFin) ? 1 : 0);
                }
                std::size_t hs = wire::tcp_header_size(h.options);
                s.receive(ip_frame(wire::kProtoTcp, hs + payload.size(), [&](MutBytes out) {
                    put(out, hs, payload);
                    wire::write_tcp(out, h, kPeer, kUs);
                }));
                break;
            }
            case 2: {  // UDP to the echo port or elsewhere
                auto payload = in.ConsumeBytes<std::uint8_t>(in.ConsumeIntegralInRange<std::size_t>(0, 1400));
                std::uint16_t port = in.ConsumeBool() ? 7 : in.ConsumeIntegral<std::uint16_t>();
                std::size_t len = wire::kUdpSize + payload.size();
                s.receive(ip_frame(wire::kProtoUdp, len, [&](MutBytes out) {
                    put(out, wire::kUdpSize, payload);
                    wire::write_udp(out, {5000, port, static_cast<std::uint16_t>(len)}, kPeer, kUs);
                }));
                break;
            }
            case 3: {  // ICMP echo
                auto payload = in.ConsumeBytes<std::uint8_t>(in.ConsumeIntegralInRange<std::size_t>(0, 1400));
                s.receive(ip_frame(wire::kProtoIcmp, wire::kIcmpHeaderSize + payload.size(), [&](MutBytes out) {
                    put(out, wire::kIcmpHeaderSize, payload);
                    wire::write_icmp(out, {wire::kIcmpEchoRequest, 0, in.ConsumeIntegral<std::uint32_t>()});
                }));
                break;
            }
            case 4:  // time passes: retransmissions, probes, TIME-WAIT
                clock.advance(std::chrono::milliseconds(in.ConsumeIntegralInRange(0, 70000)));
                s.run_timers();
                break;
            case 5: {  // the application does something
                if (conns.empty()) break;
                auto& c = conns[in.ConsumeIntegralInRange<std::size_t>(0, conns.size() - 1)];
                switch (in.ConsumeIntegralInRange(0, 4)) {
                    case 0: {
                        auto d = in.ConsumeBytes<std::uint8_t>(in.ConsumeIntegralInRange<std::size_t>(0, 20000));
                        c->send(bytes_of(d));
                        break;
                    }
                    case 1: c->close(); break;
                    case 2: c->abort(); break;
                    case 3: c->pause_reading(); break;
                    case 4: c->resume_reading(); break;
                }
                break;
            }
            case 6:  // an active open
                if (conns.size() < 8) conns.push_back(s.tcp_connect(kPeer, in.ConsumeIntegral<std::uint16_t>()));
                break;
        }
        // Learn the stack's sequence numbers from what it sent, so later segments can acknowledge them.
        if (auto eth = wire::parse_ethernet(dev.last); eth && eth->ethertype == wire::kEtherIpv4) {
            Bytes p = Bytes(dev.last).subspan(wire::kEthernetSize);
            if (auto ip = wire::parse_ipv4(p); ip && ip->protocol == wire::kProtoTcp) {
                if (auto t = wire::parse_tcp(p.subspan(ip->header_size, ip->total_length - ip->header_size), ip->src, ip->dst)) {
                    our_seq = t->seq;
                }
            }
        }
    }
    return 0;
}
