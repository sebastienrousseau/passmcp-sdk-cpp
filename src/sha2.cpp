// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/sha2.hpp>

#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace passmcp {
namespace {

constexpr std::array<std::uint32_t, 64> K256 = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

constexpr std::array<std::uint64_t, 80> K512 = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

std::uint32_t load_be32(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 24U) |
           (static_cast<std::uint32_t>(p[1]) << 16U) |
           (static_cast<std::uint32_t>(p[2]) << 8U) |
           static_cast<std::uint32_t>(p[3]);
}

std::uint64_t load_be64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8U) | static_cast<std::uint64_t>(p[i]);
    return v;
}

void store_be64(std::uint8_t* dst, std::uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        dst[i] = static_cast<std::uint8_t>(val & 0xffU);
        val >>= 8U;
    }
}

std::string hex_from_bytes(const std::uint8_t* data, std::size_t len) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(digits[(data[i] >> 4U) & 0x0fU]);
        out.push_back(digits[data[i] & 0x0fU]);
    }
    return out;
}

std::string hex_from_u64(const std::array<std::uint64_t, 8>& state) {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(128);
    for (std::uint64_t word : state) {
        for (int shift = 60; shift >= 0; shift -= 4) {
            out.push_back(digits[(word >> static_cast<unsigned>(shift)) & 0x0fULL]);
        }
    }
    return out;
}

void sha256_compress(std::array<std::uint32_t, 8>& h, const std::uint8_t* block) {
    std::array<std::uint32_t, 64> w{};
    for (std::size_t i = 0; i < 16; ++i) w[i] = load_be32(block + (i * 4));
    for (std::size_t i = 16; i < 64; ++i) {
        std::uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3U);
        std::uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10U);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto v = h;
    for (std::size_t i = 0; i < 64; ++i) {
        std::uint32_t sig1 = std::rotr(v[4], 6) ^ std::rotr(v[4], 11) ^ std::rotr(v[4], 25);
        std::uint32_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        std::uint32_t temp1 = v[7] + sig1 + ch + K256[i] + w[i];
        std::uint32_t sig0 = std::rotr(v[0], 2) ^ std::rotr(v[0], 13) ^ std::rotr(v[0], 22);
        std::uint32_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        std::uint32_t temp2 = sig0 + maj;
        v = {temp1 + temp2, v[0], v[1], v[2], v[3] + temp1, v[4], v[5], v[6]};
    }
    for (std::size_t i = 0; i < 8; ++i) h[i] += v[i];
}

void sha512_compress(std::array<std::uint64_t, 8>& h, const std::uint8_t* block) {
    std::array<std::uint64_t, 80> w{};
    for (std::size_t i = 0; i < 16; ++i) w[i] = load_be64(block + (i * 8));
    for (std::size_t i = 16; i < 80; ++i) {
        std::uint64_t s0 = std::rotr(w[i - 15], 1) ^ std::rotr(w[i - 15], 8) ^ (w[i - 15] >> 7U);
        std::uint64_t s1 = std::rotr(w[i - 2], 19) ^ std::rotr(w[i - 2], 61) ^ (w[i - 2] >> 6U);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto v = h;
    for (std::size_t i = 0; i < 80; ++i) {
        std::uint64_t sig1 = std::rotr(v[4], 14) ^ std::rotr(v[4], 18) ^ std::rotr(v[4], 41);
        std::uint64_t ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        std::uint64_t temp1 = v[7] + sig1 + ch + K512[i] + w[i];
        std::uint64_t sig0 = std::rotr(v[0], 28) ^ std::rotr(v[0], 34) ^ std::rotr(v[0], 39);
        std::uint64_t maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        std::uint64_t temp2 = sig0 + maj;
        v = {temp1 + temp2, v[0], v[1], v[2], v[3] + temp1, v[4], v[5], v[6]};
    }
    for (std::size_t i = 0; i < 8; ++i) h[i] += v[i];
}

std::vector<std::uint8_t> pad_message(std::string_view input, std::size_t block_size, std::size_t len_bytes) {
    const std::size_t rem = (input.size() + 1 + len_bytes) % block_size;
    const std::size_t zero_pad = rem == 0 ? 0 : (block_size - rem);
    std::vector<std::uint8_t> buf(input.size() + 1 + zero_pad + len_bytes, 0U);
    if (!input.empty()) std::memcpy(buf.data(), input.data(), input.size());
    buf[input.size()] = 0x80U;
    const std::uint64_t bit_len_lo = static_cast<std::uint64_t>(input.size()) * 8ULL;
    if (len_bytes == 16) {
        const std::uint64_t bit_len_hi = static_cast<std::uint64_t>(input.size()) >> 61U;
        store_be64(buf.data() + buf.size() - 16, bit_len_hi);
    }
    store_be64(buf.data() + buf.size() - 8, bit_len_lo);
    return buf;
}

} // namespace

std::array<std::uint8_t, 32> sha256_bytes(std::string_view input) {
    std::array<std::uint32_t, 8> h = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U};
    std::vector<std::uint8_t> padded = pad_message(input, 64, 8);
    for (std::size_t off = 0; off < padded.size(); off += 64) {
        sha256_compress(h, padded.data() + off);
    }
    std::array<std::uint8_t, 32> out{};
    for (std::size_t i = 0; i < 8; ++i) {
        out[i * 4 + 0] = static_cast<std::uint8_t>((h[i] >> 24U) & 0xffU);
        out[i * 4 + 1] = static_cast<std::uint8_t>((h[i] >> 16U) & 0xffU);
        out[i * 4 + 2] = static_cast<std::uint8_t>((h[i] >> 8U) & 0xffU);
        out[i * 4 + 3] = static_cast<std::uint8_t>(h[i] & 0xffU);
    }
    return out;
}

std::string sha256_hex(std::string_view input) {
    auto bytes = sha256_bytes(input);
    return hex_from_bytes(bytes.data(), bytes.size());
}

std::string sha512_hex(std::string_view input) {
    std::array<std::uint64_t, 8> h = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    std::vector<std::uint8_t> padded = pad_message(input, 128, 16);
    for (std::size_t off = 0; off < padded.size(); off += 128) {
        sha512_compress(h, padded.data() + off);
    }
    return hex_from_u64(h);
}

} // namespace passmcp
