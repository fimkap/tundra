#include "tundra/pcap.hpp"

#include <cstdint>

namespace tundra {

PcapWriter::PcapWriter(const std::string& path, LinkType type) : f_(std::fopen(path.c_str(), "wb")) {
    if (!f_) return;
    // Global header: magic, version 2.4, UTC, accuracy, snaplen, link type (1 Ethernet, 101 raw IP).
    const std::uint32_t hdr[6] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, type == LinkType::ethernet ? 1u : 101u};
    std::fwrite(hdr, sizeof hdr, 1, f_);
}

PcapWriter::~PcapWriter() {
    if (f_) std::fclose(f_);
}

void PcapWriter::write(TimePoint t, Bytes frame) {
    if (!f_) return;
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(t.time_since_epoch()).count();
    const std::uint32_t rec[4] = {static_cast<std::uint32_t>(us / 1000000), static_cast<std::uint32_t>(us % 1000000),
                                  static_cast<std::uint32_t>(frame.size()), static_cast<std::uint32_t>(frame.size())};
    std::fwrite(rec, sizeof rec, 1, f_);
    std::fwrite(frame.data(), 1, frame.size(), f_);
}

}  // namespace tundra
