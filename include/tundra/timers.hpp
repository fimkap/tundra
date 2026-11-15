#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <queue>
#include <unordered_map>
#include <vector>

#include "tundra/clock.hpp"

namespace tundra {

// TimerQueue is a min-heap of deadlines. Cancelling is O(1): the callback is dropped and its heap entry
// skipped when it surfaces.
class TimerQueue {
public:
    using Id = std::uint64_t;  // 0 means "no timer"

    Id schedule(TimePoint when, std::function<void()> fn);
    void cancel(Id& id);  // also resets id to 0
    std::optional<TimePoint> next_deadline();
    // run_due runs every timer due at or before now, earliest first, including ones scheduled by the
    // callbacks themselves. It returns how many ran.
    std::size_t run_due(TimePoint now);
    std::size_t size() const { return fns_.size(); }

private:
    struct Entry {
        TimePoint when;
        Id id;
        bool operator>(const Entry& o) const { return when != o.when ? when > o.when : id > o.id; }
    };
    std::priority_queue<Entry, std::vector<Entry>, std::greater<>> heap_;
    std::unordered_map<Id, std::function<void()>> fns_;
    Id next_ = 1;
};

}  // namespace tundra
