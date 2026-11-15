// SHA-256 (FIPS 180-4), so the demo app and the interop test can prove transfers byte-exact without
// pulling in a crypto library.
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "tundra/bytes.hpp"

namespace tundra {

class Sha256 {
public:
    Sha256();
    void update(Bytes data);
    std::array<std::uint8_t, 32> finish();
    static std::string hex(const std::array<std::uint8_t, 32>& digest);

private:
    void compress(const std::uint8_t* block);
    std::uint32_t h_[8];
    std::uint8_t block_[64];
    std::size_t used_ = 0;
    std::uint64_t total_ = 0;
};

}  // namespace tundra
