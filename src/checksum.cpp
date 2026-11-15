#include "tundra/checksum.hpp"

#include <bit>
#include <cstring>

#if defined(__aarch64__)
#include <arm_neon.h>
#elif defined(__SSE2__)
#include <emmintrin.h>
#endif

namespace tundra::checksum {
namespace {

std::uint16_t fold64(std::uint64_t s) {
    s = (s & 0xffffffffU) + (s >> 32);
    s = (s & 0xffffffffU) + (s >> 32);
    s = (s & 0xffffU) + (s >> 16);
    s = (s & 0xffffU) + (s >> 16);
    s = (s & 0xffffU) + (s >> 16);
    return static_cast<std::uint16_t>(s);
}

// A sum taken over native (little-endian) words is the byte-swapped sum of big-endian words.
std::uint16_t from_native(std::uint16_t folded) {
    if constexpr (std::endian::native == std::endian::little) return std::byteswap(folded);
    return folded;
}

std::uint16_t sum_scalar16(Bytes d) {
    // 64 bits: a 32-bit sum of 16-bit words overflows past ~128 KiB (2^16 words of 0xffff). Packets never
    // get there, but the function takes any span; the property test over 1 MiB caught it.
    std::uint64_t s = 0;
    std::size_t i = 0;
    for (; i + 1 < d.size(); i += 2) s += load_be16(d.data() + i);
    if (i < d.size()) s += static_cast<std::uint32_t>(u8(d[i])) << 8;  // odd byte: pad with zero
    return fold64(s);
}

// Native-order tail: the remaining (< 4) bytes, the last odd byte as the low byte of a native word.
std::uint64_t native_tail(const std::byte* p, std::size_t n) {
    std::uint64_t s = 0;
    for (; n >= 2; n -= 2, p += 2) {
        std::uint16_t w;
        std::memcpy(&w, p, 2);
        s += w;
    }
    if (n == 1) {
        std::uint16_t w = 0;
        std::memcpy(&w, p, 1);
        s += w;
    }
    return s;
}

std::uint16_t sum_wide64(Bytes d) {
    const std::byte* p = d.data();
    std::size_t n = d.size();
    std::uint64_t s = 0;
    for (; n >= 4; n -= 4, p += 4) {
        std::uint32_t w;
        std::memcpy(&w, p, 4);
        s += w;
    }
    return from_native(fold64(s + native_tail(p, n)));
}

std::uint16_t sum_unrolled(Bytes d) {
    const std::byte* p = d.data();
    std::size_t n = d.size();
    std::uint64_t a = 0, b = 0, c = 0, e = 0;
    for (; n >= 16; n -= 16, p += 16) {
        std::uint32_t w[4];
        std::memcpy(w, p, 16);
        a += w[0];
        b += w[1];
        c += w[2];
        e += w[3];
    }
    std::uint64_t s = a + b + c + e;
    for (; n >= 4; n -= 4, p += 4) {
        std::uint32_t w;
        std::memcpy(&w, p, 4);
        s += w;
    }
    return from_native(fold64(s + native_tail(p, n)));
}

std::uint16_t sum_simd(Bytes d) {
#if defined(__aarch64__)
    const std::byte* p = d.data();
    std::size_t n = d.size();
    std::uint64_t total = 0;
    while (n >= 16) {
        // vpadalq_u16 adds pairs of 16-bit lanes into 32-bit lanes; flush to 64 bits before they can overflow.
        uint32x4_t acc = vdupq_n_u32(0);
        std::size_t blocks = std::min<std::size_t>(n / 16, 16384);
        for (std::size_t i = 0; i < blocks; ++i, p += 16) {
            acc = vpadalq_u16(acc, vreinterpretq_u16_u8(vld1q_u8(reinterpret_cast<const std::uint8_t*>(p))));
        }
        n -= blocks * 16;
        total += vaddlvq_u32(acc);
    }
    for (; n >= 4; n -= 4, p += 4) {
        std::uint32_t w;
        std::memcpy(&w, p, 4);
        total += w;
    }
    return from_native(fold64(total + native_tail(p, n)));
#elif defined(__SSE2__)
    const std::byte* p = d.data();
    std::size_t n = d.size();
    std::uint64_t total = 0;
    const __m128i zero = _mm_setzero_si128();
    while (n >= 16) {
        // Widen 16-bit lanes to 32 bits and add; flush before the 32-bit lanes can overflow.
        __m128i lo = zero, hi = zero;
        std::size_t blocks = std::min<std::size_t>(n / 16, 32768);
        for (std::size_t i = 0; i < blocks; ++i, p += 16) {
            __m128i v = _mm_loadu_si128(reinterpret_cast<const __m128i*>(p));
            lo = _mm_add_epi32(lo, _mm_unpacklo_epi16(v, zero));
            hi = _mm_add_epi32(hi, _mm_unpackhi_epi16(v, zero));
        }
        n -= blocks * 16;
        alignas(16) std::uint32_t l[4], h[4];
        _mm_store_si128(reinterpret_cast<__m128i*>(l), lo);
        _mm_store_si128(reinterpret_cast<__m128i*>(h), hi);
        for (int i = 0; i < 4; ++i) total += static_cast<std::uint64_t>(l[i]) + h[i];
    }
    for (; n >= 4; n -= 4, p += 4) {
        std::uint32_t w;
        std::memcpy(&w, p, 4);
        total += w;
    }
    return from_native(fold64(total + native_tail(p, n)));
#else
    return sum_unrolled(d);
#endif
}

}  // namespace

std::string_view name(Variant v) {
    switch (v) {
        case Variant::scalar16: return "scalar16";
        case Variant::wide64: return "wide64";
        case Variant::unrolled: return "unrolled";
        case Variant::simd:
#if defined(__aarch64__)
            return "simd (NEON)";
#elif defined(__SSE2__)
            return "simd (SSE2)";
#else
            return "simd (none: unrolled)";
#endif
    }
    return "?";
}

std::uint16_t ones_sum(Bytes data, Variant v, std::uint32_t initial) {
    std::uint16_t s = 0;
    switch (v) {
        case Variant::scalar16: s = sum_scalar16(data); break;
        case Variant::wide64: s = sum_wide64(data); break;
        case Variant::unrolled: s = sum_unrolled(data); break;
        case Variant::simd: s = sum_simd(data); break;
    }
    return fold64(static_cast<std::uint64_t>(s) + initial);
}

}  // namespace tundra::checksum
