// A pcap writer, so any run (a test, a simulation, the TAP app) can be opened in Wireshark.
#pragma once

#include <cstdio>
#include <string>

#include "tundra/clock.hpp"
#include "tundra/netdev.hpp"

namespace tundra {

class PcapWriter {
public:
    PcapWriter(const std::string& path, LinkType type);
    ~PcapWriter();
    PcapWriter(const PcapWriter&) = delete;
    PcapWriter& operator=(const PcapWriter&) = delete;
    bool ok() const { return f_ != nullptr; }
    void write(TimePoint t, Bytes frame);

private:
    std::FILE* f_ = nullptr;
};

}  // namespace tundra
