#include "tundra/sim.hpp"

#include <algorithm>

#include "tundra/stack.hpp"

namespace tundra {

std::pair<SimNetwork::Port*, SimNetwork::Port*> SimNetwork::connect(LinkType type, LinkParams a_to_b,
                                                                    LinkParams b_to_a) {
    ports_.emplace_back(new Port(*this, type));
    Port* a = ports_.back().get();
    ports_.emplace_back(new Port(*this, type));
    Port* b = ports_.back().get();
    a->peer_ = b;
    b->peer_ = a;
    a->params_ = a_to_b;
    b->params_ = b_to_a;
    return {a, b};
}

void SimNetwork::attach(Port* port, Stack& stack) {
    port->deliver_ = [&stack](Bytes f) { stack.receive(f); };
    stacks_.push_back(&stack);
}

void SimNetwork::Port::transmit(Bytes frame) { net_.send(this, frame); }

void SimNetwork::send(Port* from, Bytes frame) {
    ++from->sent;
    const LinkParams& p = from->params_;
    std::uniform_real_distribution<double> u(0, 1);
    if (p.loss > 0 && u(rng_) < p.loss) {
        ++from->dropped;
        return;
    }
    int copies = 1;
    if (p.duplicate > 0 && u(rng_) < p.duplicate) {
        copies = 2;
        ++from->duplicated;
    }
    TimePoint depart = clock_.now();
    if (p.bits_per_second > 0) {
        // Frames queue behind each other on the wire: serialization delay at the link rate.
        depart = std::max(depart, from->wire_free_) +
                 Duration(static_cast<std::int64_t>(frame.size() * 8 * 1'000'000'000ULL / p.bits_per_second));
        from->wire_free_ = depart;
    }
    for (int i = 0; i < copies; ++i) {
        Duration jitter{0};
        if (p.jitter.count() > 0) jitter = Duration(std::uniform_int_distribution<std::int64_t>(0, p.jitter.count() - 1)(rng_));
        events_.push({depart + p.delay + jitter, order_++, from->peer_, Buffer(frame.begin(), frame.end())});
    }
}

bool SimNetwork::run(const std::function<bool()>& done, Duration limit) {
    TimePoint deadline = clock_.now() + limit;
    while (!done()) {
        TimePoint next = TimePoint::max();
        if (!events_.empty()) next = events_.top().at;
        for (Stack* s : stacks_) {
            if (auto d = s->next_deadline()) next = std::min(next, *d);
        }
        if (next == TimePoint::max() || next > deadline) break;
        if (next > clock_.now()) clock_.set(next);
        while (!events_.empty() && events_.top().at <= clock_.now()) {
            Event e = events_.top();
            events_.pop();
            if (e.to->deliver_) e.to->deliver_(e.frame);
        }
        for (Stack* s : stacks_) s->run_timers();
    }
    return done();
}

}  // namespace tundra
