// Time is injected. The stack never reads a wall clock: the event loop gives it a steady clock, tests and
// simulations a manual one, so a 60-second back-off takes no real time and every run is reproducible.
#pragma once

#include <chrono>

namespace tundra {

using Duration = std::chrono::nanoseconds;
using TimePoint = std::chrono::time_point<std::chrono::steady_clock, Duration>;
using namespace std::chrono_literals;

class Clock {
public:
    virtual ~Clock() = default;
    virtual TimePoint now() const = 0;
};

class SteadyClock final : public Clock {
public:
    TimePoint now() const override { return std::chrono::steady_clock::now(); }
};

class ManualClock final : public Clock {
public:
    TimePoint now() const override { return t_; }
    void set(TimePoint t) { t_ = t; }
    void advance(Duration d) { t_ += d; }

private:
    TimePoint t_{std::chrono::seconds(1)};
};

}  // namespace tundra
