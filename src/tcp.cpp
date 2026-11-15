#include "tundra/tcp.hpp"

#include <algorithm>
#include <cstring>

#include "tundra/stack.hpp"

namespace tundra {

std::string_view to_string(TcpState s) {
    switch (s) {
        case TcpState::closed: return "CLOSED";
        case TcpState::listen: return "LISTEN";
        case TcpState::syn_sent: return "SYN-SENT";
        case TcpState::syn_received: return "SYN-RECEIVED";
        case TcpState::established: return "ESTABLISHED";
        case TcpState::fin_wait_1: return "FIN-WAIT-1";
        case TcpState::fin_wait_2: return "FIN-WAIT-2";
        case TcpState::close_wait: return "CLOSE-WAIT";
        case TcpState::closing: return "CLOSING";
        case TcpState::last_ack: return "LAST-ACK";
        case TcpState::time_wait: return "TIME-WAIT";
    }
    return "?";
}

// ---- ByteRing --------------------------------------------------------------------------------------

std::size_t ByteRing::push(Bytes data) {
    std::size_t n = std::min(data.size(), space());
    if (n == 0) return 0;  // an empty span may have a null data(): memcpy from null is UB even for 0 bytes
    std::size_t tail = (head_ + size_) % buf_.size();
    std::size_t first = std::min(n, buf_.size() - tail);
    std::memcpy(buf_.data() + tail, data.data(), first);
    std::memcpy(buf_.data(), data.data() + first, n - first);
    size_ += n;
    return n;
}

void ByteRing::copy_out(std::size_t offset, MutBytes dst) const {
    if (dst.empty()) return;
    std::size_t start = (head_ + offset) % buf_.size();
    std::size_t first = std::min(dst.size(), buf_.size() - start);
    std::memcpy(dst.data(), buf_.data() + start, first);
    std::memcpy(dst.data() + first, buf_.data(), dst.size() - first);
}

void ByteRing::pop(std::size_t n) {
    n = std::min(n, size_);
    head_ = (head_ + n) % buf_.size();
    size_ -= n;
    if (size_ == 0) head_ = 0;
}

// ---- TcpConnection ---------------------------------------------------------------------------------

TcpConnection::TcpConnection(Stack& stack, const FourTuple& t, const TcpConfig& cfg)
    : stack_(stack), tuple_(t), cfg_(cfg), sndbuf_(cfg.send_buffer), rcvbuf_(cfg.recv_buffer), rto_(cfg.rto_initial) {}

TcpConnection::~TcpConnection() {
    stack_.timers().cancel(rto_timer_);
    stack_.timers().cancel(persist_timer_);
    stack_.timers().cancel(time_wait_timer_);
}

std::size_t TcpConnection::unacknowledged() const { return static_cast<std::size_t>(snd_max_ - snd_una_); }

std::int64_t TcpConnection::rel_seq(std::uint32_t wire_seq) const {
    std::uint32_t expected = irs_ + static_cast<std::uint32_t>(rcv_nxt_);
    return static_cast<std::int64_t>(rcv_nxt_) + static_cast<std::int32_t>(wire_seq - expected);
}

std::uint64_t TcpConnection::rel_ack(std::uint32_t wire_ack) const {
    std::uint32_t una = iss_ + static_cast<std::uint32_t>(snd_una_);
    std::int64_t r = static_cast<std::int64_t>(snd_una_) + static_cast<std::int32_t>(wire_ack - una);
    return r < 0 ? 0 : static_cast<std::uint64_t>(r);
}

std::uint32_t TcpConnection::advertised_window() const {
    std::uint64_t free = rcvbuf_.capacity() - rcvbuf_.size();
    return static_cast<std::uint32_t>(free);
}

void TcpConnection::emit(std::uint64_t seq, std::uint8_t flags, Bytes payload) {
    wire::Tcp h;
    h.src_port = tuple_.local_port;
    h.dst_port = tuple_.remote_port;
    h.seq = iss_ + static_cast<std::uint32_t>(seq);
    h.flags = flags;
    if (flags & wire::kAck) h.ack = irs_ + static_cast<std::uint32_t>(rcv_nxt_);
    std::uint64_t wnd = advertised_window();
    if (flags & wire::kSyn) {
        // The window in a SYN is never scaled (RFC 7323 §2.2); the options announce MSS and our shift.
        h.window = static_cast<std::uint16_t>(std::min<std::uint64_t>(wnd, 65535));
        h.options.mss = stack_.tcp_mss();
        if (cfg_.window_scaling && (state_ == TcpState::syn_sent || rcv_wscale_ > 0 || snd_wscale_ > 0)) {
            h.options.window_scale = rcv_wscale_;
        }
    } else {
        h.window = static_cast<std::uint16_t>(std::min<std::uint64_t>(wnd >> rcv_wscale_, 65535));
    }
    ++stats_.segments_out;
    stack_.send_tcp(tuple_, h, payload);
}

void TcpConnection::apply_syn_options(const wire::Tcp& syn, bool we_offered_ws) {
    mss_ = std::min<std::uint16_t>(syn.options.mss.value_or(536), stack_.tcp_mss());
    if (we_offered_ws && syn.options.window_scale) {
        snd_wscale_ = std::min<std::uint8_t>(*syn.options.window_scale, 14);  // RFC 7323 §2.3
    } else {
        snd_wscale_ = 0;
        rcv_wscale_ = 0;  // scaling only applies if both sides offered it
    }
    // Initial window of 10 segments (RFC 6928).
    cwnd_ = std::uint64_t{10} * mss_;
}

static std::uint8_t wscale_for(std::size_t buffer) {
    std::uint8_t s = 0;
    while ((buffer >> s) > 65535 && s < 14) ++s;
    return s;
}

void TcpConnection::open_active(std::uint32_t iss) {
    iss_ = iss;
    rcv_wscale_ = cfg_.window_scaling ? wscale_for(cfg_.recv_buffer) : 0;
    state_ = TcpState::syn_sent;
    emit(0, wire::kSyn);
    snd_nxt_ = snd_max_ = 1;
    rtt_timing_ = true;
    rtt_seq_ = 1;
    rtt_start_ = stack_.clock().now();
    arm_rto();
}

void TcpConnection::open_passive(const wire::Tcp& syn, std::uint32_t iss) {
    iss_ = iss;
    irs_ = syn.seq;
    rcv_nxt_ = 1;
    bool ws = cfg_.window_scaling && syn.options.window_scale.has_value();
    rcv_wscale_ = ws ? wscale_for(cfg_.recv_buffer) : 0;
    apply_syn_options(syn, cfg_.window_scaling);
    snd_wnd_ = syn.window;  // unscaled in a SYN
    state_ = TcpState::syn_received;
    emit(0, wire::kSyn | wire::kAck);
    snd_nxt_ = snd_max_ = 1;
    rtt_timing_ = true;
    rtt_seq_ = 1;
    rtt_start_ = stack_.clock().now();
    arm_rto();
}

std::size_t TcpConnection::send(Bytes data) {
    switch (state_) {
        case TcpState::syn_sent:
        case TcpState::syn_received:
        case TcpState::established:
        case TcpState::close_wait: break;
        default: return 0;
    }
    if (fin_queued_) return 0;
    std::size_t n = sndbuf_.push(data);
    try_send();
    return n;
}

void TcpConnection::close() {
    switch (state_) {
        case TcpState::syn_sent: finish("closed"); return;
        case TcpState::syn_received:
        case TcpState::established:
            fin_queued_ = true;
            state_ = TcpState::fin_wait_1;
            break;
        case TcpState::close_wait:
            fin_queued_ = true;
            state_ = TcpState::last_ack;
            break;
        default: return;
    }
    try_send();
}

void TcpConnection::abort() {
    if (state_ == TcpState::closed) return;
    if (state_ != TcpState::syn_sent && state_ != TcpState::time_wait) emit(snd_max_, wire::kRst | wire::kAck);
    finish("aborted");
}

void TcpConnection::resume_reading() {
    paused_ = false;
    bool was_closed = rcvbuf_.size() == rcvbuf_.capacity();
    while (rcvbuf_.size() > 0 && !paused_) {
        Buffer chunk(std::min<std::size_t>(rcvbuf_.size(), 64 * 1024));
        rcvbuf_.copy_out(0, chunk);
        rcvbuf_.pop(chunk.size());
        if (on_data) on_data(chunk);
    }
    // Tell the peer the window opened (RFC 9293 §3.8.6.2.2), or it stays stuck in zero-window probing.
    if (was_closed || rcvbuf_.size() == 0) send_ack();
}

void TcpConnection::deliver(Bytes data) {
    stats_.bytes_in += data.size();
    if (paused_ || rcvbuf_.size() > 0) {
        rcvbuf_.push(data);  // the window guaranteed room
        return;
    }
    if (on_data) on_data(data);
}

// ---- segment arrival, RFC 9293 §3.10.7 --------------------------------------------------------------

void TcpConnection::on_segment(const wire::Tcp& h, Bytes payload) {
    ++stats_.segments_in;
    if (state_ == TcpState::closed || state_ == TcpState::listen) return;
    if (state_ == TcpState::syn_sent) {
        on_syn_sent(h);
        return;
    }

    // First: is the segment acceptable? (§3.10.7.4, the four cases)
    std::int64_t seq = rel_seq(h.seq);
    std::uint64_t seg_len = payload.size() + ((h.flags & wire::kSyn) ? 1 : 0) + ((h.flags & wire::kFin) ? 1 : 0);
    std::int64_t nxt = static_cast<std::int64_t>(rcv_nxt_);
    std::int64_t wnd = advertised_window();
    bool acceptable;
    if (seg_len == 0) {
        acceptable = wnd == 0 ? seq == nxt : (seq >= nxt && seq < nxt + wnd);
    } else {
        std::int64_t last = seq + static_cast<std::int64_t>(seg_len) - 1;
        acceptable = wnd > 0 && ((seq >= nxt && seq < nxt + wnd) || (last >= nxt && last < nxt + wnd));
    }
    // With a zero window no data is acceptable, but ACKs and RSTs at RCV.NXT still are.
    bool window_closed_but_valid = !acceptable && wnd == 0 && seq == nxt;
    if (!acceptable && !window_closed_but_valid) {
        if (!(h.flags & wire::kRst)) send_ack();
        return;
    }
    bool probe = window_closed_but_valid && !payload.empty();  // a zero-window probe: answer with our window
    if (window_closed_but_valid) payload = {};

    // Trim what we already have from the front and what doesn't fit the window from the back.
    std::uint8_t flags = h.flags;
    if (seq < nxt) {
        if (flags & wire::kSyn) {
            flags &= static_cast<std::uint8_t>(~wire::kSyn);
            ++seq;
        }
        std::size_t dup = static_cast<std::size_t>(std::min<std::int64_t>(nxt - seq, static_cast<std::int64_t>(payload.size())));
        payload = payload.subspan(dup);
        seq += static_cast<std::int64_t>(dup);
    }
    if (seq + static_cast<std::int64_t>(payload.size()) > nxt + wnd) {
        payload = payload.first(static_cast<std::size_t>(std::max<std::int64_t>(0, nxt + wnd - seq)));
        flags &= static_cast<std::uint8_t>(~wire::kFin);
    }

    // Second: RST. Accept it only at exactly RCV.NXT; elsewhere in the window, send a challenge ACK
    // (RFC 5961 §3.2) so a blind attacker can't reset us.
    if (flags & wire::kRst) {
        if (seq == nxt) {
            finish(state_ == TcpState::syn_received ? "refused" : "reset");
        } else {
            send_ack();
        }
        return;
    }

    // Fourth: a SYN in the window is an error in a synchronized state: challenge ACK (RFC 5961 §4.2).
    if (flags & wire::kSyn) {
        send_ack();
        return;
    }

    // Fifth: the ACK field.
    if (!(flags & wire::kAck)) return;
    if (state_ == TcpState::syn_received) {
        std::uint64_t ack = rel_ack(h.ack);
        if (ack > snd_una_ && ack <= snd_max_) {
            state_ = TcpState::established;
            snd_wnd_ = std::uint64_t{h.window} << snd_wscale_;
            wl1_ = static_cast<std::uint64_t>(seq);
            wl2_ = ack;
            stack_.tcp_established(*this);
            if (state_ == TcpState::closed) return;
        } else {
            wire::Tcp rst;
            rst.src_port = tuple_.local_port;
            rst.dst_port = tuple_.remote_port;
            rst.seq = h.ack;
            rst.flags = wire::kRst;
            stack_.send_tcp(tuple_, rst, {});
            return;
        }
    }
    if (!on_ack(h, seq, !payload.empty())) return;

    // Our FIN acknowledged moves the closing states on.
    bool fin_acked = fin_seq_ && snd_una_ > *fin_seq_;
    switch (state_) {
        case TcpState::fin_wait_1:
            if (fin_acked) state_ = TcpState::fin_wait_2;
            break;
        case TcpState::closing:
            if (fin_acked) {
                enter_time_wait();
                return;
            }
            break;
        case TcpState::last_ack:
            if (fin_acked) {
                finish("closed");
                return;
            }
            break;
        case TcpState::time_wait:
            // A retransmitted FIN: acknowledge it and restart the 2*MSL timer.
            if (flags & wire::kFin) {
                send_ack();
                enter_time_wait();
            }
            return;
        default: break;
    }

    // Sixth/seventh: data, then FIN.
    bool acked_something = false;
    if (!payload.empty() &&
        (state_ == TcpState::established || state_ == TcpState::fin_wait_1 || state_ == TcpState::fin_wait_2)) {
        on_data_in(seq, payload);
        acked_something = true;
    }
    if (flags & wire::kFin) {
        std::uint64_t fin_at = static_cast<std::uint64_t>(seq) + payload.size();
        if (fin_at == rcv_nxt_) {
            on_fin_in();
            return;  // on_fin_in acknowledges
        }
        if (fin_at > rcv_nxt_) ooo_fin_ = fin_at;  // arrives before the data it follows
        acked_something = true;
    }
    if (acked_something || probe) send_ack();  // every data segment is acknowledged at once (no delayed ACKs)
}

void TcpConnection::on_syn_sent(const wire::Tcp& h) {
    bool ack_ok = false;
    if (h.flags & wire::kAck) {
        // Only our SYN is outstanding: the ACK must be ISS+1.
        if (h.ack != iss_ + 1) {
            if (!(h.flags & wire::kRst)) {
                wire::Tcp rst;
                rst.src_port = tuple_.local_port;
                rst.dst_port = tuple_.remote_port;
                rst.seq = h.ack;
                rst.flags = wire::kRst;
                stack_.send_tcp(tuple_, rst, {});
            }
            return;
        }
        ack_ok = true;
    }
    if (h.flags & wire::kRst) {
        if (ack_ok) finish("refused");
        return;
    }
    if (!(h.flags & wire::kSyn)) return;

    irs_ = h.seq;
    rcv_nxt_ = 1;
    apply_syn_options(h, cfg_.window_scaling);
    if (ack_ok) {
        snd_una_ = 1;
        snd_wnd_ = h.window;  // unscaled in a SYN-ACK
        wl1_ = 0;
        wl2_ = 1;
        state_ = TcpState::established;
        if (rtt_timing_ && backoff_ == 0) update_rto(stack_.clock().now() - rtt_start_);
        rtt_timing_ = false;
        backoff_ = 0;
        stack_.timers().cancel(rto_timer_);
        send_ack();
        if (on_connected) on_connected();
        try_send();
    } else {
        // Simultaneous open (RFC 9293 §3.5): both sides sent SYN.
        state_ = TcpState::syn_received;
        emit(0, wire::kSyn | wire::kAck);
    }
}

// on_ack processes the acknowledgment and window fields; false means drop the rest of the segment.
bool TcpConnection::on_ack(const wire::Tcp& h, std::int64_t seq, bool has_payload) {
    std::uint64_t ack = rel_ack(h.ack);
    if (ack > snd_max_) {  // acknowledges something never sent
        send_ack();
        return false;
    }
    std::uint64_t new_wnd = std::uint64_t{h.window} << snd_wscale_;
    std::uint64_t old_wnd = snd_wnd_;
    if (ack >= snd_una_) {
        // Window update rule (§3.10.7.4): only from a newer segment, so reordered old ones can't shrink it.
        auto useq = static_cast<std::uint64_t>(seq);
        if (wl1_ < useq || (wl1_ == useq && wl2_ <= ack)) {
            snd_wnd_ = new_wnd;
            wl1_ = useq;
            wl2_ = ack;
        }
    }
    bool window_opened = old_wnd == 0 && snd_wnd_ > 0;
    if (window_opened) {  // stop probing; sending resumes below even if this ACK acknowledges nothing new
        stack_.timers().cancel(persist_timer_);
        persist_backoff_ = 0;
    }
    if (ack > snd_una_) {
        std::uint64_t acked = ack - snd_una_;
        if (rtt_timing_ && ack >= rtt_seq_) {  // Karn: on_rto stops timing after a retransmission
            update_rto(stack_.clock().now() - rtt_start_);
            rtt_timing_ = false;
        }
        std::uint64_t data_acked_to = std::min(ack, data_end());
        if (data_acked_to > data_base_) {
            sndbuf_.pop(static_cast<std::size_t>(data_acked_to - data_base_));
            data_base_ = data_acked_to;
        }
        snd_una_ = ack;
        if (snd_nxt_ < snd_una_) snd_nxt_ = snd_una_;
        if (in_recovery_) {
            if (ack >= recover_) {
                // Full ACK (RFC 6582 §3.2 step 3): everything outstanding at the loss is acknowledged.
                cwnd_ = std::min(ssthresh_, snd_max_ - snd_una_ + mss_);
                in_recovery_ = false;
            } else {
                // Partial ACK: the next hole is lost too. Retransmit it now instead of waiting for the
                // RTO, and deflate the window by what was acknowledged (RFC 6582 §3.2 step 4).
                retransmit_head();
                cwnd_ = cwnd_ > acked ? cwnd_ - acked : 0;
                if (acked >= mss_) cwnd_ += mss_;
                cwnd_ = std::max<std::uint64_t>(cwnd_, mss_);
            }
        } else if (cwnd_ < ssthresh_) {
            // Congestion control (RFC 5681 §3.1): slow start, then congestion avoidance.
            cwnd_ += std::min<std::uint64_t>(acked, mss_);
        } else {
            cwnd_ += std::max<std::uint64_t>(1, std::uint64_t{mss_} * mss_ / cwnd_);
        }
        dupacks_ = 0;
        backoff_ = 0;
        if (snd_una_ < snd_max_) {
            restart_rto();
        } else {
            stack_.timers().cancel(rto_timer_);
        }
        try_send();
        if (on_writable && sndbuf_.space() > 0 && state_ != TcpState::closed) on_writable();
    } else if (window_opened) {
        try_send();  // a pure window update: nothing was acknowledged, but now there is room
    } else if (ack == snd_una_ && !has_payload && new_wnd == old_wnd && snd_max_ > snd_una_) {
        ++dupacks_;  // RFC 5681 §2: same ACK, no data, same window, data outstanding
        ++stats_.dup_acks;
        if (cfg_.fast_retransmit) {
            if (dupacks_ == 3 && !in_recovery_ && snd_una_ >= recover_) {
                // Fast retransmit (RFC 5681 §3.2): three duplicates mean a lost segment, not reordering.
                // The snd_una_ >= recover_ check keeps one loss episode from triggering it twice (RFC 6582).
                ssthresh_ = std::max<std::uint64_t>((snd_max_ - snd_una_) / 2, 2 * std::uint64_t{mss_});
                recover_ = snd_max_;
                in_recovery_ = true;
                ++stats_.fast_retransmits;
                rtt_timing_ = false;  // Karn
                retransmit_head();
                cwnd_ = ssthresh_ + 3 * std::uint64_t{mss_};  // the three segments that left the network
            } else if (in_recovery_) {
                cwnd_ += mss_;  // each further duplicate means another segment left: send a new one
                try_send();
            }
        }
    }
    return state_ != TcpState::closed;
}

// retransmit_head resends the first unacknowledged segment (or the FIN) without moving snd_nxt_.
void TcpConnection::retransmit_head() {
    std::uint64_t end = data_end();
    if (snd_una_ < end) {
        auto len = static_cast<std::size_t>(std::min<std::uint64_t>(mss_, end - snd_una_));
        Buffer seg(len);
        sndbuf_.copy_out(static_cast<std::size_t>(snd_una_ - data_base_), seg);
        emit(snd_una_, wire::kAck, seg);
        ++stats_.retransmits;
    } else if (fin_seq_ && snd_una_ == *fin_seq_) {
        emit(*fin_seq_, wire::kFin | wire::kAck);
        ++stats_.retransmits;
    }
}

void TcpConnection::on_data_in(std::int64_t seq, Bytes payload) {
    auto useq = static_cast<std::uint64_t>(seq);
    if (useq == rcv_nxt_) {
        deliver(payload);
        rcv_nxt_ += payload.size();
        // Pull in out-of-order segments the new data made contiguous.
        while (!ooo_.empty() && ooo_.begin()->first <= rcv_nxt_) {
            auto it = ooo_.begin();
            std::uint64_t end = it->first + it->second.size();
            if (end > rcv_nxt_) {
                deliver(Bytes(it->second).subspan(static_cast<std::size_t>(rcv_nxt_ - it->first)));
                rcv_nxt_ = end;
            }
            ooo_.erase(it);
        }
        if (ooo_fin_ && *ooo_fin_ == rcv_nxt_) {
            ooo_fin_.reset();
            on_fin_in();
        }
    } else {
        ++stats_.out_of_order;
        auto& slot = ooo_[useq];
        if (slot.size() < payload.size()) slot.assign(payload.begin(), payload.end());
    }
}

void TcpConnection::on_fin_in() {
    rcv_nxt_ += 1;  // the FIN takes one sequence number
    send_ack();
    if (!peer_closed_) {
        peer_closed_ = true;
        if (on_peer_closed) on_peer_closed();
    }
    switch (state_) {
        case TcpState::syn_received:
        case TcpState::established: state_ = TcpState::close_wait; break;
        case TcpState::fin_wait_1:
            if (fin_seq_ && snd_una_ > *fin_seq_) {
                enter_time_wait();
            } else {
                state_ = TcpState::closing;  // simultaneous close
            }
            break;
        case TcpState::fin_wait_2: enter_time_wait(); break;
        default: break;
    }
}

// ---- sending ---------------------------------------------------------------------------------------

void TcpConnection::try_send() {
    switch (state_) {
        case TcpState::established:
        case TcpState::close_wait:
        case TcpState::fin_wait_1:
        case TcpState::closing:
        case TcpState::last_ack: break;
        default: return;
    }
    for (;;) {
        std::uint64_t end = data_end();
        if (snd_nxt_ < end) {
            std::uint64_t limit = snd_una_ + std::min(cwnd_, snd_wnd_);
            if (snd_nxt_ >= limit) {
                // Zero window with nothing in flight: no ACK will come to reopen it, so probe (§3.8.6.1).
                if (snd_wnd_ == 0 && snd_una_ == snd_max_) arm_persist();
                break;
            }
            auto len = static_cast<std::size_t>(std::min({std::uint64_t{mss_}, end - snd_nxt_, limit - snd_nxt_}));
            Buffer seg(len);
            sndbuf_.copy_out(static_cast<std::size_t>(snd_nxt_ - data_base_), seg);
            std::uint8_t flags = wire::kAck | (snd_nxt_ + len == end ? wire::kPsh : 0);
            emit(snd_nxt_, flags, seg);
            if (snd_nxt_ < snd_max_) {
                ++stats_.retransmits;
            } else {
                stats_.bytes_out += len;
                if (!rtt_timing_) {
                    rtt_timing_ = true;
                    rtt_seq_ = snd_nxt_ + len;
                    rtt_start_ = stack_.clock().now();
                }
            }
            snd_nxt_ += len;
            snd_max_ = std::max(snd_max_, snd_nxt_);
            arm_rto();
        } else if (fin_queued_ && snd_nxt_ == end) {
            if (snd_max_ > end) ++stats_.retransmits;
            emit(end, wire::kFin | wire::kAck);
            fin_seq_ = end;
            snd_nxt_ = end + 1;
            snd_max_ = std::max(snd_max_, snd_nxt_);
            arm_rto();
            break;
        } else {
            break;
        }
    }
}

// ---- timers ----------------------------------------------------------------------------------------

void TcpConnection::arm_rto() {
    if (rto_timer_ != 0) return;
    rto_timer_ = stack_.timers().schedule(stack_.clock().now() + rto_, [w = weak_from_this()] {
        if (auto c = w.lock()) {
            c->rto_timer_ = 0;
            c->on_rto();
        }
    });
}

void TcpConnection::restart_rto() {
    stack_.timers().cancel(rto_timer_);
    arm_rto();
}

void TcpConnection::on_rto() {
    bool handshake = state_ == TcpState::syn_sent || state_ == TcpState::syn_received;
    if (!handshake && snd_una_ >= snd_max_) return;  // nothing outstanding
    if (++backoff_ > cfg_.max_retransmits) {
        if (!handshake) emit(snd_max_, wire::kRst | wire::kAck);
        finish("timeout");
        return;
    }
    ++stats_.timeouts;
    rto_ = std::min(rto_ * 2, cfg_.rto_max);  // exponential back-off (RFC 6298 §5.5)
    rtt_timing_ = false;                      // Karn's rule
    // RFC 5681 §3.1 (4): halve the flight into ssthresh and restart from one segment.
    std::uint64_t flight = snd_max_ - snd_una_;
    ssthresh_ = std::max<std::uint64_t>(flight / 2, 2 * std::uint64_t{mss_});
    cwnd_ = mss_;
    dupacks_ = 0;
    in_recovery_ = false;
    recover_ = snd_max_;
    if (state_ == TcpState::syn_sent) {
        ++stats_.retransmits;
        emit(0, wire::kSyn);
        arm_rto();
        return;
    }
    if (state_ == TcpState::syn_received) {
        ++stats_.retransmits;
        emit(0, wire::kSyn | wire::kAck);
        arm_rto();
        return;
    }
    snd_nxt_ = snd_una_;  // go back and resend from the first unacknowledged byte
    try_send();
}

void TcpConnection::arm_persist() {
    if (persist_timer_ != 0) return;
    Duration wait = std::min(rto_ * (1 << std::min(persist_backoff_, 10)), cfg_.rto_max);
    persist_timer_ = stack_.timers().schedule(stack_.clock().now() + wait, [w = weak_from_this()] {
        if (auto c = w.lock()) {
            c->persist_timer_ = 0;
            c->on_persist();
        }
    });
}

void TcpConnection::on_persist() {
    if (snd_wnd_ > 0) {
        persist_backoff_ = 0;
        try_send();
        return;
    }
    if (snd_nxt_ < data_end()) {
        // One byte past the closed window; the receiver drops it but must answer with its window.
        Buffer one(1);
        sndbuf_.copy_out(static_cast<std::size_t>(snd_nxt_ - data_base_), one);
        emit(snd_nxt_, wire::kAck, one);
        ++stats_.window_probes;
    }
    ++persist_backoff_;
    arm_persist();
}

void TcpConnection::update_rto(Duration r) {
    // RFC 6298 §2: SRTT and RTTVAR with alpha = 1/8, beta = 1/4.
    if (!have_srtt_) {
        srtt_ = r;
        rttvar_ = r / 2;
        have_srtt_ = true;
    } else {
        Duration diff = srtt_ > r ? srtt_ - r : r - srtt_;
        rttvar_ = (3 * rttvar_ + diff) / 4;
        srtt_ = (7 * srtt_ + r) / 8;
    }
    rto_ = std::clamp<Duration>(srtt_ + std::max<Duration>(1ms, 4 * rttvar_), cfg_.rto_min, cfg_.rto_max);
}

void TcpConnection::enter_time_wait() {
    state_ = TcpState::time_wait;
    stack_.timers().cancel(rto_timer_);
    stack_.timers().cancel(time_wait_timer_);
    time_wait_timer_ = stack_.timers().schedule(stack_.clock().now() + 2 * cfg_.msl, [w = weak_from_this()] {
        if (auto c = w.lock()) {
            c->time_wait_timer_ = 0;
            c->finish("closed");
        }
    });
}

void TcpConnection::finish(std::string_view reason) {
    if (state_ == TcpState::closed) return;
    state_ = TcpState::closed;
    stack_.timers().cancel(rto_timer_);
    stack_.timers().cancel(persist_timer_);
    stack_.timers().cancel(time_wait_timer_);
    auto self = shared_from_this();  // keep alive through the callback
    stack_.tcp_release(*this);
    if (on_closed) on_closed(reason);
}

}  // namespace tundra
