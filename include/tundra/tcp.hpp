// TCP per RFC 9293, with RFC 6298 retransmission timing and RFC 5681 congestion control.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string_view>

#include "tundra/clock.hpp"
#include "tundra/timers.hpp"
#include "tundra/wire.hpp"

namespace tundra {

class Stack;

// Sequence numbers live in a 32-bit circle; compare them only with these (RFC 9293 §3.4).
inline bool seq_lt(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b) < 0; }
inline bool seq_le(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b) <= 0; }
inline bool seq_gt(std::uint32_t a, std::uint32_t b) { return seq_lt(b, a); }
inline bool seq_ge(std::uint32_t a, std::uint32_t b) { return seq_le(b, a); }

enum class TcpState : std::uint8_t {
    closed,
    listen,
    syn_sent,
    syn_received,
    established,
    fin_wait_1,
    fin_wait_2,
    close_wait,
    closing,
    last_ack,
    time_wait,
};

std::string_view to_string(TcpState s);

struct TcpConfig {
    std::size_t send_buffer = 256 * 1024;
    std::size_t recv_buffer = 256 * 1024;
    Duration rto_initial = 1s;    // RFC 6298 §2.1
    Duration rto_min = 200ms;     // Linux's floor; RFC 6298 suggests 1 s
    Duration rto_max = 60s;
    Duration msl = 30s;           // TIME-WAIT lasts 2 * msl
    int max_retransmits = 8;      // consecutive timeouts before giving up
    bool window_scaling = true;   // RFC 7323
};

struct TcpStats {
    std::uint64_t segments_in = 0, segments_out = 0;
    std::uint64_t bytes_in = 0, bytes_out = 0;  // payload, first transmissions only for bytes_out
    std::uint64_t retransmits = 0;              // segments sent again
    std::uint64_t timeouts = 0, fast_retransmits = 0, dup_acks = 0, out_of_order = 0;
};

struct FourTuple {
    Ipv4Addr local_ip;
    std::uint16_t local_port = 0;
    Ipv4Addr remote_ip;
    std::uint16_t remote_port = 0;
    bool operator==(const FourTuple&) const = default;
};

struct FourTupleHash {
    std::size_t operator()(const FourTuple& t) const noexcept {
        std::uint64_t a = (std::uint64_t{t.local_ip.v} << 32) | t.remote_ip.v;
        std::uint64_t b = (std::uint64_t{t.local_port} << 16) | t.remote_port;
        return std::hash<std::uint64_t>{}(a * 0x9e3779b97f4a7c15ULL ^ b);
    }
};

// ByteRing is a fixed-capacity byte FIFO: the send buffer (unacknowledged and unsent bytes) and the
// receive buffer (bytes the application hasn't taken while reading is paused).
class ByteRing {
public:
    explicit ByteRing(std::size_t capacity) : buf_(capacity) {}
    std::size_t size() const { return size_; }
    std::size_t capacity() const { return buf_.size(); }
    std::size_t space() const { return buf_.size() - size_; }
    std::size_t push(Bytes data);
    void copy_out(std::size_t offset, MutBytes dst) const;
    void pop(std::size_t n);

private:
    std::vector<std::byte> buf_;
    std::size_t head_ = 0, size_ = 0;
};

class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
public:
    // Application callbacks; all optional.
    std::function<void()> on_connected;               // an active open completed
    std::function<void(Bytes)> on_data;               // in-order bytes from the peer
    std::function<void()> on_writable;                // the send buffer has room again
    std::function<void()> on_peer_closed;             // FIN: the peer will send nothing more
    std::function<void(std::string_view)> on_closed;  // gone: "closed", "reset", "refused", "timeout", "aborted"

    // send queues bytes and returns how many fit in the send buffer.
    std::size_t send(Bytes data);
    // close sends FIN after everything queued (a half close: data keeps arriving until the peer's FIN).
    void close();
    // abort sends RST and forgets the connection.
    void abort();
    // pause_reading stops on_data; arriving bytes wait in the receive buffer and the advertised window
    // shrinks until resume_reading delivers them (flow control).
    void pause_reading() { paused_ = true; }
    void resume_reading();

    TcpState state() const { return state_; }
    const FourTuple& tuple() const { return tuple_; }
    const TcpStats& stats() const { return stats_; }
    std::size_t send_space() const { return sndbuf_.space(); }
    std::size_t unacknowledged() const;
    std::uint64_t cwnd() const { return cwnd_; }
    std::uint16_t mss() const { return mss_; }
    Duration rto() const { return rto_; }
    Duration srtt() const { return srtt_; }

    TcpConnection(Stack& stack, const FourTuple& t, const TcpConfig& cfg);
    ~TcpConnection();

private:
    friend class Stack;

    void open_active(std::uint32_t iss);
    void open_passive(const wire::Tcp& syn, std::uint32_t iss);
    void on_segment(const wire::Tcp& h, Bytes payload);

    void on_syn_sent(const wire::Tcp& h);
    bool on_ack(const wire::Tcp& h, std::int64_t seq, bool has_payload);
    void on_data_in(std::int64_t seq, Bytes payload);
    void on_fin_in();
    void apply_syn_options(const wire::Tcp& syn, bool we_offered_ws);
    void deliver(Bytes data);

    void try_send();
    void emit(std::uint64_t seq, std::uint8_t flags, Bytes payload = {});
    void send_ack() { emit(snd_nxt_, wire::kAck); }
    std::uint32_t advertised_window() const;
    std::uint64_t data_end() const { return data_base_ + sndbuf_.size(); }

    void arm_rto();
    void restart_rto();
    void on_rto();
    void update_rto(Duration sample);
    void enter_time_wait();
    void finish(std::string_view reason);

    std::int64_t rel_seq(std::uint32_t wire_seq) const;
    std::uint64_t rel_ack(std::uint32_t wire_ack) const;

    Stack& stack_;
    FourTuple tuple_;
    TcpConfig cfg_;
    TcpState state_ = TcpState::closed;
    TcpStats stats_;

    // Sequence numbers are kept as 64-bit offsets from the initial ones (0 is the SYN, data starts at 1),
    // so nothing wraps internally; only the wire uses 32 bits.
    std::uint32_t iss_ = 0, irs_ = 0;
    std::uint64_t snd_una_ = 0, snd_nxt_ = 0, snd_max_ = 0;
    std::uint64_t data_base_ = 1;  // offset of sndbuf_[0]
    bool fin_queued_ = false;
    std::optional<std::uint64_t> fin_seq_;
    std::uint64_t snd_wnd_ = 0;
    std::uint64_t wl1_ = 0, wl2_ = 0;  // segment seq and ack of the last window update
    std::uint8_t snd_wscale_ = 0, rcv_wscale_ = 0;
    std::uint16_t mss_ = 536;

    std::uint64_t rcv_nxt_ = 0;
    std::map<std::uint64_t, Buffer> ooo_;  // out-of-order segments by offset
    std::optional<std::uint64_t> ooo_fin_;
    bool paused_ = false;
    bool peer_closed_ = false;

    ByteRing sndbuf_, rcvbuf_;

    std::uint64_t cwnd_ = 0, ssthresh_ = UINT64_MAX;
    int dupacks_ = 0;
    bool in_recovery_ = false;
    std::uint64_t recover_ = 0;

    bool rtt_timing_ = false;
    std::uint64_t rtt_seq_ = 0;
    TimePoint rtt_start_{};
    bool have_srtt_ = false;
    Duration srtt_{}, rttvar_{}, rto_;
    int backoff_ = 0;

    TimerQueue::Id rto_timer_ = 0, persist_timer_ = 0, time_wait_timer_ = 0;
};

}  // namespace tundra
