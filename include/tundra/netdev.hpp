// The device boundary, the stack's "driver" interface: frames in through Stack::receive, frames out
// through transmit. A TAP device carries Ethernet frames, a TUN device bare IPv4 packets.
#pragma once

#include "tundra/bytes.hpp"
#include "tundra/wire.hpp"

namespace tundra {

enum class LinkType { ethernet, ip };

class NetDevice {
public:
    virtual ~NetDevice() = default;
    virtual LinkType link_type() const = 0;
    // transmit sends one frame. It never blocks; a device that can't take the frame drops it, as a NIC
    // with a full ring would, and TCP recovers.
    virtual void transmit(Bytes frame) = 0;
};

}  // namespace tundra
