// How the accumulation strategy of a NEON checksum loop performs, built with whichever compiler builds
// this file. scripts/bench.sh builds it with both GCC and Clang: the same intrinsics perform very
// differently between them.
#include <arm_neon.h>

#include <bit>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <vector>

using u8 = std::uint8_t;

namespace {

std::uint16_t fold(std::uint64_t s) {
    for (int i = 0; i < 4; ++i) s = (s & 0xffff) + (s >> 16);
    return std::byteswap(static_cast<std::uint16_t>(s));
}

// Each variant assumes n is a multiple of 128 (the measurement uses 64 KiB).
std::uint16_t uadalp1(const u8* p, std::size_t n) {
    uint32x4_t a = vdupq_n_u32(0);
    for (std::size_t i = 0; i < n; i += 16) a = vpadalq_u16(a, vreinterpretq_u16_u8(vld1q_u8(p + i)));
    return fold(vaddlvq_u32(a));
}

std::uint16_t uadalp4(const u8* p, std::size_t n) {
    uint32x4_t a0 = vdupq_n_u32(0), a1 = a0, a2 = a0, a3 = a0;
    for (std::size_t i = 0; i < n; i += 64) {
        a0 = vpadalq_u16(a0, vreinterpretq_u16_u8(vld1q_u8(p + i)));
        a1 = vpadalq_u16(a1, vreinterpretq_u16_u8(vld1q_u8(p + i + 16)));
        a2 = vpadalq_u16(a2, vreinterpretq_u16_u8(vld1q_u8(p + i + 32)));
        a3 = vpadalq_u16(a3, vreinterpretq_u16_u8(vld1q_u8(p + i + 48)));
    }
    return fold(vaddlvq_u32(a0) + vaddlvq_u32(a1) + vaddlvq_u32(a2) + vaddlvq_u32(a3));
}

// The same as uaddw4, but with one pointer bumped by 32: GCC fuses the two loads into one LDP.
std::uint16_t uaddw4_ldp(const u8* p, std::size_t n) {
    uint32x4_t a0 = vdupq_n_u32(0), a1 = a0, a2 = a0, a3 = a0;
    for (const u8* end = p + n; p < end; p += 32) {
        uint16x8_t x = vreinterpretq_u16_u8(vld1q_u8(p)), y = vreinterpretq_u16_u8(vld1q_u8(p + 16));
        a0 = vaddw_u16(a0, vget_low_u16(x));
        a1 = vaddw_high_u16(a1, x);
        a2 = vaddw_u16(a2, vget_low_u16(y));
        a3 = vaddw_high_u16(a3, y);
    }
    return fold(vaddlvq_u32(a0) + vaddlvq_u32(a1) + vaddlvq_u32(a2) + vaddlvq_u32(a3));
}

std::uint16_t uaddw4(const u8* p, std::size_t n) {
    uint32x4_t a0 = vdupq_n_u32(0), a1 = a0, a2 = a0, a3 = a0;
    for (std::size_t i = 0; i < n; i += 32) {
        uint16x8_t x = vreinterpretq_u16_u8(vld1q_u8(p + i)), y = vreinterpretq_u16_u8(vld1q_u8(p + i + 16));
        a0 = vaddw_u16(a0, vget_low_u16(x));
        a1 = vaddw_high_u16(a1, x);
        a2 = vaddw_u16(a2, vget_low_u16(y));
        a3 = vaddw_high_u16(a3, y);
    }
    return fold(vaddlvq_u32(a0) + vaddlvq_u32(a1) + vaddlvq_u32(a2) + vaddlvq_u32(a3));
}

}  // namespace

int main() {
    std::vector<u8> buf(65536 + 64);
    for (std::size_t i = 0; i < buf.size(); ++i) buf[i] = static_cast<u8>(i * 7 + i / 3);
    const u8* data = buf.data() + 1;  // misaligned, as in the main benchmark
    struct Variant {
        const char* name;
        std::uint16_t (*fn)(const u8*, std::size_t);
    } variants[] = {{"UADALP, 1 accumulator", uadalp1}, {"UADALP, 4 accumulators", uadalp4}, {"UADDW, 4 accumulators, indexed loads", uaddw4},
                    {"UADDW, 4 accumulators, one bumped pointer", uaddw4_ldp}};
#if defined(__clang__)
    std::printf("| %s | Clang %d |\n|---|---:|\n", "NEON loop", __clang_major__);
#else
    std::printf("| %s | GCC %d |\n|---|---:|\n", "NEON loop", __GNUC__);
#endif
    const std::uint16_t want = uadalp1(data, 65536);
    for (auto& v : variants) {
        volatile std::uint16_t sink = 0;
        auto t0 = std::chrono::steady_clock::now();
        const int iters = 20000;
        for (int i = 0; i < iters; ++i) sink = v.fn(data, 65536);
        double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        std::printf("| %s | %.1f GB/s%s |\n", v.name, 65536.0 * iters / s / 1e9, v.fn(data, 65536) == want ? "" : " (WRONG RESULT)");
    }
}
