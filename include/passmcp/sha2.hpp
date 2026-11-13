// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_SHA2_HPP
#define PASSMCP_SHA2_HPP

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace passmcp {

/** Computes the raw 32-byte SHA-256 digest of UTF-8 bytes in `input`. */
[[nodiscard]] std::array<std::uint8_t, 32> sha256_bytes(std::string_view input);

/** Computes the lowercase 64-character SHA-256 hex digest of UTF-8 bytes in `input`. */
[[nodiscard]] std::string sha256_hex(std::string_view input);

/** Computes the lowercase 128-character SHA-512 hex digest of UTF-8 bytes in `input`. */
[[nodiscard]] std::string sha512_hex(std::string_view input);

} // namespace passmcp

#endif // PASSMCP_SHA2_HPP
