// The internet checksum (RFC 1071): the one's-complement of the one's-complement sum of 16-bit words.
// Four implementations of the sum, so they can be compared; all must agree bit for bit.
#pragma once

#include <array>
#include <cstdint>
#include <string_view>

#include "tundra/bytes.hpp"

namespace tundra::checksum {

enum class Variant {
    scalar16,  // 16-bit big-endian words into a 32-bit sum: the textbook loop
    wide64,    // 32-bit native words into a 64-bit sum, byte-swapped once at the end (RFC 1071 §2.B)
    unrolled,  // wide64 with four independent accumulators, so adds run in parallel
    simd,      // NEON (arm64) or SSE2 (x86-64); falls back to unrolled elsewhere
};

inline constexpr std::array kAllVariants{Variant::scalar16, Variant::wide64, Variant::unrolled, Variant::simd};

std::string_view name(Variant v);

// ones_sum returns the folded 16-bit one's-complement sum of data (not inverted), in host value space for
// big-endian words. initial is a partial sum to fold in (e.g. a pseudo-header).
std::uint16_t ones_sum(Bytes data, Variant v = Variant::simd, std::uint32_t initial = 0);

// The checksum to store in a header: the complement of the sum. Verifying a received header over its
// own checksum field gives 0.
inline std::uint16_t compute(Bytes data, std::uint32_t initial = 0) {
    return static_cast<std::uint16_t>(~ones_sum(data, Variant::simd, initial));
}

// pseudo_header_sum is the partial sum of the TCP/UDP pseudo-header (RFC 9293 §3.1, RFC 768).
inline std::uint32_t pseudo_header_sum(std::uint32_t src, std::uint32_t dst, std::uint8_t protocol,
                                       std::uint16_t length) {
    return (src >> 16) + (src & 0xffff) + (dst >> 16) + (dst & 0xffff) + protocol + length;
}

}  // namespace tundra::checksum
