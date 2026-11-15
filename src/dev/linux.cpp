#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "tundra/linux.hpp"
#include "tundra/stack.hpp"

namespace tundra {

std::expected<std::unique_ptr<TapDevice>, std::string> TapDevice::open(const std::string& name, LinkType type) {
    int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return std::unexpected(std::string("open /dev/net/tun: ") + std::strerror(errno));
    ifreq ifr{};
    // IFF_NO_PI: no 4-byte packet-info header; frames are exactly what's on the wire.
    ifr.ifr_flags = static_cast<short>((type == LinkType::ethernet ? IFF_TAP : IFF_TUN) | IFF_NO_PI);
    std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    if (::ioctl(fd, TUNSETIFF, &ifr) < 0) {
        std::string err = std::string("TUNSETIFF ") + name + ": " + std::strerror(errno);
        ::close(fd);
        return std::unexpected(err);
    }
    return std::unique_ptr<TapDevice>(new TapDevice(fd, type));
}

TapDevice::~TapDevice() { ::close(fd_); }

bool TapDevice::lose() {
    if (loss_ <= 0) return false;
    return std::uniform_real_distribution<double>(0, 1)(rng_) < loss_;
}

void TapDevice::transmit(Bytes frame) {
    if (lose()) {
        ++dropped_loss;
        return;
    }
    ssize_t n = ::write(fd_, frame.data(), frame.size());
    if (n < 0) {
        ++dropped_full;  // EAGAIN: the queue toward the kernel is full; TCP will retransmit
        return;
    }
    ++frames_out;
}

std::size_t TapDevice::read_frame(MutBytes buf) {
    for (;;) {
        ssize_t n = ::read(fd_, buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            return 0;  // EAGAIN: drained
        }
        if (lose()) {
            ++dropped_loss;
            continue;
        }
        ++frames_in;
        return static_cast<std::size_t>(n);
    }
}

std::expected<void, std::string> run_event_loop(Stack& stack, TapDevice& dev, const std::atomic<bool>& stop) {
    int ep = ::epoll_create1(EPOLL_CLOEXEC);
    int tfd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (ep < 0 || tfd < 0) return std::unexpected(std::string("epoll/timerfd: ") + std::strerror(errno));
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = dev.fd();
    ::epoll_ctl(ep, EPOLL_CTL_ADD, dev.fd(), &ev);
    ev.data.fd = tfd;
    ::epoll_ctl(ep, EPOLL_CTL_ADD, tfd, &ev);

    Buffer frame(65536);
    std::optional<TimePoint> armed;
    while (!stop.load(std::memory_order_relaxed)) {
        // steady_clock is CLOCK_MONOTONIC on Linux, so a deadline converts directly to an absolute timer.
        auto next = stack.next_deadline();
        if (next != armed) {
            itimerspec its{};
            if (next) {
                auto ns = std::max<std::int64_t>(next->time_since_epoch().count(), 1);
                its.it_value.tv_sec = ns / 1'000'000'000;
                its.it_value.tv_nsec = ns % 1'000'000'000;
            }
            ::timerfd_settime(tfd, TFD_TIMER_ABSTIME, &its, nullptr);
            armed = next;
        }
        epoll_event events[4];
        int n = ::epoll_wait(ep, events, 4, 200);  // wake at least every 200 ms to notice stop
        if (n < 0 && errno != EINTR) {
            ::close(ep), ::close(tfd);
            return std::unexpected(std::string("epoll_wait: ") + std::strerror(errno));
        }
        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == tfd) {
                std::uint64_t expirations;
                [[maybe_unused]] auto r = ::read(tfd, &expirations, sizeof expirations);
                armed.reset();
            } else {
                // Drain what's queued, but yield to timers after a burst so they can't starve.
                for (int burst = 0; burst < 256; ++burst) {
                    std::size_t len = dev.read_frame(frame);
                    if (len == 0) break;
                    stack.receive(Bytes(frame).first(len));
                }
            }
        }
        stack.run_timers();
    }
    ::close(ep);
    ::close(tfd);
    return {};
}

}  // namespace tundra
