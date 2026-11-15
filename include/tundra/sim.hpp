// A simulated network on a virtual clock: frames travel between ports with delay, jitter (which
// reorders), loss, duplication and a bandwidth cap, all drawn from a seeded PRNG. A simulation run is a
// pure function of its seed.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <queue>
#include <random>
#include <vector>

#include "tundra/clock.hpp"
#include "tundra/netdev.hpp"

namespace tundra {

class Stack;

struct LinkParams {
    Duration delay = 1ms;
    Duration jitter = 0ns;           // uniform extra delay in [0, jitter): reorders frames
    double loss = 0;                 // probability a frame is dropped
    double duplicate = 0;            // probability a frame is delivered twice
    std::uint64_t bits_per_second = 0;  // 0: unlimited
};

class SimNetwork {
public:
    class Port final : public NetDevice {
    public:
        LinkType link_type() const override { return type_; }
        void transmit(Bytes frame) override;
        std::uint64_t sent = 0, dropped = 0, duplicated = 0;

    private:
        friend class SimNetwork;
        Port(SimNetwork& net, LinkType t) : net_(net), type_(t) {}
        SimNetwork& net_;
        LinkType type_;
        Port* peer_ = nullptr;
        LinkParams params_;
        TimePoint wire_free_{};  // when the outgoing "wire" finishes the previous frame
        std::function<void(Bytes)> deliver_;
    };

    SimNetwork(ManualClock& clock, std::uint64_t seed) : clock_(clock), rng_(seed) {}

    // connect creates two ports joined by a link; each direction uses its own parameters.
    std::pair<Port*, Port*> connect(LinkType type, LinkParams a_to_b, LinkParams b_to_a);
    // attach makes frames arriving at port go to stack (Stack::receive).
    void attach(Port* port, Stack& stack);
    void on_deliver(Port* port, std::function<void(Bytes)> fn) { port->deliver_ = std::move(fn); }

    // run advances virtual time event by event (frame arrivals and stack timers) until done() is true,
    // nothing is left to happen, or the deadline passes. It returns done().
    bool run(const std::function<bool()>& done, Duration limit);
    std::size_t in_flight() const { return events_.size(); }

private:
    struct Event {
        TimePoint at;
        std::uint64_t order;
        Port* to;
        Buffer frame;
        bool operator>(const Event& o) const { return at != o.at ? at > o.at : order > o.order; }
    };
    void send(Port* from, Bytes frame);

    ManualClock& clock_;
    std::mt19937_64 rng_;
    std::vector<std::unique_ptr<Port>> ports_;
    std::vector<Stack*> stacks_;
    std::priority_queue<Event, std::vector<Event>, std::greater<>> events_;
    std::uint64_t order_ = 0;
};

}  // namespace tundra
