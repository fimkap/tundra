#include "tundra/timers.hpp"

namespace tundra {

TimerQueue::Id TimerQueue::schedule(TimePoint when, std::function<void()> fn) {
    Id id = next_++;
    heap_.push({when, id});
    fns_.emplace(id, std::move(fn));
    return id;
}

void TimerQueue::cancel(Id& id) {
    if (id != 0) fns_.erase(id);
    id = 0;
}

std::optional<TimePoint> TimerQueue::next_deadline() {
    while (!heap_.empty() && !fns_.contains(heap_.top().id)) heap_.pop();
    if (heap_.empty()) return std::nullopt;
    return heap_.top().when;
}

std::size_t TimerQueue::run_due(TimePoint now) {
    std::size_t ran = 0;
    while (!heap_.empty() && heap_.top().when <= now) {
        Entry e = heap_.top();
        heap_.pop();
        auto it = fns_.find(e.id);
        if (it == fns_.end()) continue;  // cancelled
        auto fn = std::move(it->second);
        fns_.erase(it);
        fn();
        ++ran;
    }
    return ran;
}

}  // namespace tundra
