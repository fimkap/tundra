// The stack: Ethernet and ARP (on TAP devices), IPv4, ICMP echo, UDP sockets and TCP connections, run to
// completion on one thread. Feed it frames with receive() and let it fire timers with run_timers().
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <vector>

#include "tundra/clock.hpp"
#include "tundra/netdev.hpp"
#include "tundra/tcp.hpp"
#include "tundra/timers.hpp"
#include "tundra/wire.hpp"

namespace tundra {

class PcapWriter;

struct StackConfig {
    Ipv4Addr ip;
    std::uint8_t prefix_len = 24;
    std::optional<Ipv4Addr> gateway;
    MacAddr mac;  // used on Ethernet (TAP) links
    std::uint16_t mtu = 1500;
    TcpConfig tcp;
    std::uint64_t seed = 1;  // ISN secret and ephemeral ports: a fixed seed makes simulations reproducible
};

struct StackStats {
    std::uint64_t frames_in = 0, frames_out = 0;
    std::uint64_t dropped_malformed = 0, dropped_not_for_us = 0, dropped_no_arp = 0;
    std::uint64_t arp_requests_out = 0, arp_replies_out = 0;
    std::uint64_t icmp_echo_replies = 0, icmp_unreachable_out = 0;
    std::uint64_t udp_in = 0, udp_out = 0;
    std::uint64_t tcp_resets_out = 0, tcp_connections_opened = 0;
};

class Stack {
public:
    Stack(NetDevice& dev, Clock& clock, StackConfig cfg);
    ~Stack();
    Stack(const Stack&) = delete;
    Stack& operator=(const Stack&) = delete;

    void receive(Bytes frame);
    void run_timers();
    std::optional<TimePoint> next_deadline() { return timers_.next_deadline(); }

    using UdpHandler = std::function<void(Ipv4Addr src, std::uint16_t src_port, Bytes payload)>;
    bool udp_bind(std::uint16_t port, UdpHandler handler);
    void udp_send(std::uint16_t src_port, Ipv4Addr dst, std::uint16_t dst_port, Bytes payload);

    using AcceptHandler = std::function<void(std::shared_ptr<TcpConnection>)>;
    bool tcp_listen(std::uint16_t port, AcceptHandler handler);
    std::shared_ptr<TcpConnection> tcp_connect(Ipv4Addr dst, std::uint16_t port);

    const StackStats& stats() const { return stats_; }
    const StackConfig& config() const { return cfg_; }
    Clock& clock() { return clock_; }
    TimerQueue& timers() { return timers_; }
    std::size_t tcp_connections() const { return conns_.size(); }
    void set_pcap(PcapWriter* pcap) { pcap_ = pcap; }

private:
    friend class TcpConnection;

    void send_tcp(const FourTuple& t, const wire::Tcp& h, Bytes payload);
    void tcp_established(TcpConnection& c);
    void tcp_release(TcpConnection& c);
    std::uint16_t tcp_mss() const { return static_cast<std::uint16_t>(cfg_.mtu - 40); }

    void on_arp(Bytes payload);
    void on_ipv4(Bytes packet);
    void on_icmp(const wire::Ipv4& ip, Bytes packet, Bytes message);
    void on_udp(const wire::Ipv4& ip, Bytes packet, Bytes segment);
    void on_tcp(const wire::Ipv4& ip, Bytes segment);
    void send_rst_for(const wire::Tcp& h, Ipv4Addr from, std::size_t payload_len);

    // send_ip builds an IPv4 packet around an L4 payload written by fill, then sends it (resolving the
    // next hop with ARP on Ethernet links).
    void send_ip(std::uint8_t protocol, Ipv4Addr dst, std::size_t l4_len, const std::function<void(MutBytes)>& fill);
    void transmit_frame(Ipv4Addr next_hop, Buffer frame);
    void transmit(Bytes frame);
    void send_arp(std::uint16_t op, MacAddr dst_mac, Ipv4Addr target_ip, MacAddr target_mac);
    bool on_link(Ipv4Addr a) const;
    std::uint32_t make_isn(const FourTuple& t);
    void collect_garbage() { graveyard_.clear(); }

    NetDevice& dev_;
    Clock& clock_;
    StackConfig cfg_;
    StackStats stats_;
    TimerQueue timers_;
    PcapWriter* pcap_ = nullptr;
    std::size_t l2_ = 0;  // link header size: 14 on Ethernet, 0 on IP links
    std::uint16_t ip_id_ = 1;

    struct ArpEntry {
        MacAddr mac;
        TimePoint expires;
    };
    struct Pending {
        std::vector<Buffer> frames;
        TimePoint last_request{};
        int requests = 0;
    };
    std::unordered_map<std::uint32_t, ArpEntry> arp_;
    std::unordered_map<std::uint32_t, Pending> pending_;

    std::unordered_map<std::uint16_t, UdpHandler> udp_;
    std::unordered_map<std::uint16_t, AcceptHandler> listeners_;
    std::unordered_map<FourTuple, std::shared_ptr<TcpConnection>, FourTupleHash> conns_;
    std::vector<std::shared_ptr<TcpConnection>> graveyard_;  // closed this turn; freed after it
    std::uint64_t isn_key_[2]{};
    std::uint16_t next_port_ = 49152;
};

}  // namespace tundra
