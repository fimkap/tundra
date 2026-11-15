// The Linux side: a TAP/TUN device and an event loop that drives a Stack from it. Everything else in
// tundra is portable; only this needs Linux headers.
#pragma once

#include <atomic>
#include <expected>
#include <memory>
#include <random>
#include <string>

#include "tundra/netdev.hpp"

namespace tundra {

class Stack;

class TapDevice final : public NetDevice {
public:
    // open attaches to an existing interface (ip tuntap add dev NAME mode tap|tun), non-blocking.
    static std::expected<std::unique_ptr<TapDevice>, std::string> open(const std::string& name, LinkType type);
    ~TapDevice() override;
    TapDevice(const TapDevice&) = delete;
    TapDevice& operator=(const TapDevice&) = delete;

    LinkType link_type() const override { return type_; }
    void transmit(Bytes frame) override;
    // read_frame reads one frame into buf and returns its size, or 0 when nothing is waiting.
    std::size_t read_frame(MutBytes buf);
    int fd() const { return fd_; }

    // set_loss drops this fraction of frames in both directions, to test loss recovery against the real
    // Linux stack when tc netem isn't available.
    void set_loss(double p, std::uint64_t seed) {
        loss_ = p;
        rng_.seed(seed);
    }

    std::uint64_t frames_in = 0, frames_out = 0, dropped_full = 0, dropped_loss = 0;

private:
    TapDevice(int fd, LinkType t) : fd_(fd), type_(t) {}
    bool lose();
    int fd_;
    LinkType type_;
    double loss_ = 0;
    std::mt19937_64 rng_;
};

// run_event_loop drives the stack until stop is set: epoll waits on the device and on a timerfd armed
// for the stack's next deadline; each wake-up drains the device and runs due timers.
std::expected<void, std::string> run_event_loop(Stack& stack, TapDevice& dev, const std::atomic<bool>& stop);

}  // namespace tundra
