// Byte-order helpers. Packet fields are always read and written through these, never by casting packet
// memory to a struct: memcpy into a local is well-defined for any alignment, and compilers turn it into
// a single load plus a byte swap.
#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <vector>

namespace tundra {

using Bytes = std::span<const std::byte>;
using MutBytes = std::span<std::byte>;
using Buffer = std::vector<std::byte>;

inline std::uint16_t load_be16(const std::byte* p) {
    std::uint16_t v;
    std::memcpy(&v, p, sizeof v);
    if constexpr (std::endian::native == std::endian::little) v = std::byteswap(v);
    return v;
}

inline std::uint32_t load_be32(const std::byte* p) {
    std::uint32_t v;
    std::memcpy(&v, p, sizeof v);
    if constexpr (std::endian::native == std::endian::little) v = std::byteswap(v);
    return v;
}

inline void store_be16(std::byte* p, std::uint16_t v) {
    if constexpr (std::endian::native == std::endian::little) v = std::byteswap(v);
    std::memcpy(p, &v, sizeof v);
}

inline void store_be32(std::byte* p, std::uint32_t v) {
    if constexpr (std::endian::native == std::endian::little) v = std::byteswap(v);
    std::memcpy(p, &v, sizeof v);
}

inline std::byte to_byte(unsigned v) { return static_cast<std::byte>(v & 0xffU); }
inline std::uint8_t u8(std::byte b) { return std::to_integer<std::uint8_t>(b); }

// as_bytes views a string or vector of chars as bytes (tests and apps).
template <typename T>
Bytes as_bytes_of(const T& c) {
    return std::as_bytes(std::span(c.data(), c.size()));
}

}  // namespace tundra
