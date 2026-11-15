#include "tundra/checksum.hpp"

#include <gtest/gtest.h>

#include <random>

namespace tundra {
namespace {

Buffer bytes_of(std::initializer_list<unsigned> v) {
    Buffer b;
    for (unsigned x : v) b.push_back(to_byte(x));
    return b;
}

// RFC 1071 §3: the sum of 00 01 f2 03 f4 f5 f6 f7 is ddf2.
TEST(Checksum, Rfc1071Example) {
    auto b = bytes_of({0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7});
    for (auto v : checksum::kAllVariants) EXPECT_EQ(checksum::ones_sum(b, v), 0xddf2) << checksum::name(v);
}

// A real IPv4 header including its checksum field verifies to zero.
TEST(Checksum, Ipv4HeaderVerifies) {
    auto h = bytes_of({0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8, 0x00,
                       0x01, 0xc0, 0xa8, 0x00, 0xc7});
    EXPECT_EQ(checksum::compute(h), 0);
    h[10] = h[11] = std::byte{0};
    EXPECT_EQ(checksum::compute(h), 0xb861);
}

TEST(Checksum, OddLengthPadsWithZero) {
    auto b = bytes_of({0x12, 0x34, 0x56});
    for (auto v : checksum::kAllVariants) EXPECT_EQ(checksum::ones_sum(b, v), 0x1234 + 0x5600) << checksum::name(v);
}

TEST(Checksum, InitialSumFolds) {
    auto b = bytes_of({0xff, 0xff});
    EXPECT_EQ(checksum::ones_sum(b, checksum::Variant::scalar16, 0x0001), 0x0001);  // ffff + 1 folds to 1
}

// Every variant must equal scalar16 for every length and starting alignment, including sizes large enough
// to exercise the SIMD loops' overflow flushes.
TEST(Checksum, AllVariantsAgreeOnRandomData) {
    std::mt19937 rng(42);
    Buffer buf(3 << 20);
    for (auto& b : buf) b = to_byte(rng());
    std::vector<std::size_t> lengths;
    for (std::size_t n = 0; n <= 300; ++n) lengths.push_back(n);
    for (std::size_t n : {1499u, 1500u, 4096u, 65535u, 65536u, 1u << 20, (2u << 20) + 7}) lengths.push_back(n);
    for (std::size_t offset = 0; offset < 8; ++offset) {
        for (std::size_t n : lengths) {
            Bytes d(buf.data() + offset, n);
            auto want = checksum::ones_sum(d, checksum::Variant::scalar16);
            for (auto v : checksum::kAllVariants) {
                ASSERT_EQ(checksum::ones_sum(d, v), want) << checksum::name(v) << " len " << n << " offset " << offset;
            }
        }
    }
}

TEST(Checksum, AllOnesDoesNotOverflow) {
    Buffer buf(1 << 21, std::byte{0xff});
    auto want = checksum::ones_sum(buf, checksum::Variant::scalar16);
    EXPECT_EQ(want, 0xffff);
    for (auto v : checksum::kAllVariants) EXPECT_EQ(checksum::ones_sum(buf, v), want) << checksum::name(v);
}

TEST(Bytes, BigEndianRoundTrip) {
    Buffer b(6);
    store_be16(b.data(), 0x1234);
    store_be32(b.data() + 2, 0xdeadbeef);
    EXPECT_EQ(u8(b[0]), 0x12);
    EXPECT_EQ(u8(b[2]), 0xde);
    EXPECT_EQ(load_be16(b.data()), 0x1234);
    EXPECT_EQ(load_be32(b.data() + 2), 0xdeadbeefU);
}

}  // namespace
}  // namespace tundra
