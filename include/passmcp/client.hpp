// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_CLIENT_HPP
#define PASSMCP_CLIENT_HPP

#include <passmcp/attestation.hpp>
#include <passmcp/json.hpp>
#include <passmcp/server.hpp>

#include <cstdint>
#include <functional>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace passmcp {

/**
 * Client-side tool execution safety policy. Defaults to read-only (`allow_mutations == false`),
 * refusing mutating and unannotated tools unless mutations are explicitly enabled.
 */
class Policy {
public:
    explicit constexpr Policy(bool allow_mutations = false) noexcept : allow_mutations_(allow_mutations) {}

    [[nodiscard]] static constexpr Policy read_only() noexcept { return Policy(false); }
    [[nodiscard]] static constexpr Policy allowing_mutations() noexcept { return Policy(true); }

    [[nodiscard]] constexpr bool allow_mutations() const noexcept { return allow_mutations_; }
    [[nodiscard]] bool allows(const ToolDescriptor& tool) const noexcept;
    void enforce(const ToolDescriptor& tool) const;

private:
    bool allow_mutations_;
};

/** Exception raised when an MCP server returns a JSON-RPC 2.0 error object. */
class RpcError : public std::runtime_error {
public:
    RpcError(int code, const std::string& message, JsonValue data);

    [[nodiscard]] int code() const noexcept { return code_; }
    [[nodiscard]] const JsonValue& data() const noexcept { return data_; }

private:
    int code_;
    JsonValue data_;
};

/**
 * Policy-enforcing MCP JSON-RPC 2.0 client with read-only-by-default tool
 * execution, SEP-2549 cache metadata validation, and offline attestation gating.
 */
class McpClient {
public:
    using Transport = std::function<std::string(const std::string&)>;

    explicit McpClient(Transport transport, Policy policy = Policy::read_only());

    [[nodiscard]] static McpClient for_server(const McpServer& server, Policy policy = Policy::read_only());

    McpClient& require_attestation(
        const Attestation& attestation, std::string_view transport_kind, std::string_view endpoint);

    [[nodiscard]] const Policy& policy() const noexcept { return policy_; }

    [[nodiscard]] JsonValue discover();
    [[nodiscard]] JsonValue initialize();
    void ping();
    [[nodiscard]] std::vector<ToolDescriptor> list_tools();
    [[nodiscard]] std::string call_tool(std::string_view name, const JsonValue& arguments = JsonValue::object());
    [[nodiscard]] std::string read_resource(std::string_view uri);
    [[nodiscard]] JsonValue rpc(std::string_view method, const JsonValue& params = JsonValue::object());

private:
    void notify(std::string_view method);
    void validate_stateless_meta_if_required(const JsonValue& result) const;
    std::vector<ToolDescriptor> cache_tool_list(const JsonValue& raw_tools);

    Transport transport_;
    Policy policy_;
    std::int64_t next_id_ = 1;
    std::string negotiated_revision_ = std::string(McpServer::kRev20260728);
    bool tools_cached_ = false;
    std::map<std::string, ToolDescriptor> cached_tools_;
};

} // namespace passmcp

#endif // PASSMCP_CLIENT_HPP
