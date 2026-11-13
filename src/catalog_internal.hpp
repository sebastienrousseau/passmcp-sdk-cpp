// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_CATALOG_INTERNAL_HPP
#define PASSMCP_CATALOG_INTERNAL_HPP

#include <passmcp/server.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace passmcp::detail {

[[nodiscard]] std::string trim_ascii(std::string_view sv);
[[nodiscard]] std::optional<std::string> validate_tool_args(const JsonValue& schema, const JsonValue& args);
[[nodiscard]] std::optional<std::string> validate_prompt_args(
    const std::vector<PromptArgument>& declared, const JsonValue& args);

} // namespace passmcp::detail

#endif // PASSMCP_CATALOG_INTERNAL_HPP
