#include "tundra/timers.hpp"

#include <gtest/gtest.h>

namespace tundra {
namespace {

TEST(Timers, RunInDeadlineOrderAndCancel) {
    TimerQueue q;
    TimePoint t0{std::chrono::seconds(10)};
    std::vector<int> order;
    q.schedule(t0 + 3ms, [&] { order.push_back(3); });
    auto id = q.schedule(t0 + 2ms, [&] { order.push_back(2); });
    q.schedule(t0 + 1ms, [&] { order.push_back(1); });
    q.cancel(id);
    EXPECT_EQ(id, 0u);
    EXPECT_EQ(q.next_deadline(), t0 + 1ms);
    EXPECT_EQ(q.run_due(t0 + 5ms), 2u);
    EXPECT_EQ(order, (std::vector<int>{1, 3}));
    EXPECT_FALSE(q.next_deadline());
}

TEST(Timers, CallbacksCanScheduleDueTimers) {
    TimerQueue q;
    TimePoint t0{std::chrono::seconds(1)};
    int n = 0;
    q.schedule(t0, [&] {
        ++n;
        q.schedule(t0, [&] { ++n; });  // due now: runs in the same pass
    });
    EXPECT_EQ(q.run_due(t0), 2u);
    EXPECT_EQ(n, 2);
}

}  // namespace
}  // namespace tundra
