#include "tundra/sha256.hpp"

#include <gtest/gtest.h>

#include <string>

namespace tundra {
namespace {

std::string digest(std::string_view s, std::size_t chunk = 1 << 20) {
    Sha256 h;
    for (std::size_t i = 0; i < s.size(); i += chunk) {
        auto part = s.substr(i, chunk);
        h.update(std::as_bytes(std::span(part.data(), part.size())));
    }
    return Sha256::hex(h.finish());
}

// FIPS 180-4 / NIST test vectors.
TEST(Sha256, NistVectors) {
    EXPECT_EQ(digest(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    EXPECT_EQ(digest("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(digest("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    std::string million(1'000'000, 'a');
    EXPECT_EQ(digest(million), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    EXPECT_EQ(digest(million, 7), digest(million));  // chunking must not matter
}

}  // namespace
}  // namespace tundra
