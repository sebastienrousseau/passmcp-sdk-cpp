// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_SERVER_HPP
#define PASSMCP_SERVER_HPP

#include <passmcp/json.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace passmcp {

/**
 * SEP-2549 list response cache metadata (`ttlMs >= 0` and
 * `cacheScope` in `{"public", "private"}`).
 */
class CacheHints {
public:
    CacheHints(std::int64_t ttl_ms, std::string cache_scope);

    [[nodiscard]] static CacheHints public_scope(std::int64_t ttl_ms);
    [[nodiscard]] static CacheHints private_scope(std::int64_t ttl_ms);
    [[nodiscard]] static CacheHints of_seconds(bool cacheable, std::int64_t ttl_seconds, std::string cache_scope);
    [[nodiscard]] static CacheHints from_meta(const JsonValue& meta);
    [[nodiscard]] static CacheHints from_result(const JsonValue& result);

    [[nodiscard]] std::int64_t ttl_ms() const noexcept { return ttl_ms_; }
    [[nodiscard]] const std::string& cache_scope() const noexcept { return cache_scope_; }
    [[nodiscard]] JsonValue to_meta() const;
    void apply_to_list_result(JsonValue& out) const;

private:
    std::int64_t ttl_ms_;
    std::string cache_scope_;
};

/**
 * Strict HTTP `Origin` allowlist validator for Streamable HTTP servers.
 */
class OriginGuard {
public:
    OriginGuard() = default;
    explicit OriginGuard(const std::vector<std::string>& allowed_origins);

    [[nodiscard]] bool is_allowed(std::string_view origin_header) const;
    [[nodiscard]] int status_for(std::string_view origin_header) const;

private:
    std::set<std::string> allowed_;
};

/**
 * MCP tool descriptor carrying schemas, titles, and safety annotations used by client `Policy`.
 */
struct ToolDescriptor {
    std::string name;
    std::string description;
    bool annotated = true;
    bool read_only_hint = true;
    bool destructive_hint = false;
    bool idempotent_hint = true;
    bool open_world_hint = false;
    std::string title{};
    std::optional<JsonValue> input_schema{};
    std::optional<JsonValue> output_schema{};

    [[nodiscard]] static ToolDescriptor read_only(std::string name, std::string description);
    [[nodiscard]] static ToolDescriptor mutating(std::string name, std::string description, bool destructive);
    [[nodiscard]] static ToolDescriptor unannotated(std::string name, std::string description);
    [[nodiscard]] static ToolDescriptor from_wire(const JsonValue& obj);
    [[nodiscard]] JsonValue effective_input_schema() const;
    [[nodiscard]] JsonValue to_wire() const;
};

/** Structured tool output pairing textual content with optional `structuredContent`. */
struct ToolResult {
    std::string text;
    std::optional<JsonValue> structured_content{};
};

/** Metadata for a single prompt argument. */
struct PromptArgument {
    std::string name;
    std::string description;
    bool required = false;
};

/** HTTP status + body envelope produced by `McpServer::handle_http`. */
struct HttpReply {
    int status = 200;
    std::string body;
};

/**
 * Capability-gated MCP JSON-RPC 2.0 server supporting revisions
 * `2026-07-28` (default), `2025-11-25`, and `2025-06-18`.
 */
class McpServer {
public:
    static constexpr std::string_view kRev20260728 = "2026-07-28";
    static constexpr std::string_view kRev20251125 = "2025-11-25";
    static constexpr std::string_view kRev20250618 = "2025-06-18";

    using ToolHandler = std::function<std::string(const std::string&)>;
    using StructuredToolHandler = std::function<ToolResult(const JsonValue&)>;
    using ResourceReader = std::function<std::string(const std::string&)>;
    using PromptRenderer = std::function<std::string(const JsonValue&)>;

    McpServer(std::string name, std::string version, std::string revision = std::string(kRev20260728));

    [[nodiscard]] const std::string& name() const noexcept { return name_; }
    [[nodiscard]] const std::string& version() const noexcept { return version_; }
    [[nodiscard]] const std::string& revision() const noexcept { return revision_; }
    [[nodiscard]] const OriginGuard& origin_guard() const noexcept { return origin_guard_; }

    McpServer& set_instructions(std::string instructions);
    McpServer& set_cache_hints(CacheHints hints);
    McpServer& set_origin_guard(OriginGuard guard);

    McpServer& register_read_only_tool(std::string name, std::string description, ToolHandler handler);
    McpServer& register_tool(ToolDescriptor tool, ToolHandler handler);
    McpServer& register_structured_tool(ToolDescriptor tool, StructuredToolHandler handler);
    McpServer& register_resource(std::string uri, std::string name, std::string mime_type, ResourceReader reader);
    McpServer& register_resource(
        std::string uri,
        std::string name,
        std::string title,
        std::string description,
        std::string mime_type,
        ResourceReader reader);
    McpServer& register_resource_template(std::string uri_template, std::string name, std::string mime_type);
    McpServer& register_prompt(std::string name, std::string description, PromptRenderer renderer);
    McpServer& register_prompt(
        std::string name,
        std::string title,
        std::string description,
        std::vector<PromptArgument> arguments,
        PromptRenderer renderer);

    [[nodiscard]] std::string handle_json(std::string_view raw) const;
    [[nodiscard]] HttpReply handle_http(std::string_view origin_header, std::string_view raw) const;

private:
    struct ToolEntry {
        ToolDescriptor descriptor;
        StructuredToolHandler handler;
    };
    struct ResourceEntry {
        std::string uri;
        std::string name;
        std::string title;
        std::string description;
        std::string mime_type;
        ResourceReader reader;
    };
    struct TemplateEntry {
        std::string uri_template;
        std::string name;
        std::string mime_type;
    };
    struct PromptEntry {
        std::string name;
        std::string title;
        std::string description;
        std::vector<PromptArgument> arguments;
        PromptRenderer renderer;
    };

    [[nodiscard]] bool has_tools() const noexcept { return !tools_.empty(); }
    [[nodiscard]] bool has_resources() const noexcept { return !resources_.empty() || !templates_.empty(); }
    [[nodiscard]] bool has_prompts() const noexcept { return !prompts_.empty(); }

    [[nodiscard]] JsonValue derived_capabilities() const;
    [[nodiscard]] JsonValue server_info() const;
    [[nodiscard]] JsonValue wire_tools() const;
    [[nodiscard]] JsonValue wire_resources() const;
    [[nodiscard]] JsonValue wire_templates() const;
    [[nodiscard]] JsonValue wire_prompts() const;

    [[nodiscard]] JsonValue dispatch_method(std::string_view method, const JsonValue& params) const;
    [[nodiscard]] JsonValue dispatch_list_method(std::string_view method) const;
    [[nodiscard]] JsonValue handle_initialize() const;
    [[nodiscard]] JsonValue handle_discover() const;
    [[nodiscard]] JsonValue handle_tools_call(const JsonValue& params) const;
    [[nodiscard]] JsonValue handle_resources_read(const JsonValue& params) const;
    [[nodiscard]] JsonValue handle_prompts_get(const JsonValue& params) const;

    std::string name_;
    std::string version_;
    std::string revision_;
    std::string instructions_;
    CacheHints cache_hints_;
    OriginGuard origin_guard_;
    std::vector<ToolEntry> tools_;
    std::vector<ResourceEntry> resources_;
    std::vector<TemplateEntry> templates_;
    std::vector<PromptEntry> prompts_;
};

using Server = McpServer;

} // namespace passmcp

#endif // PASSMCP_SERVER_HPP
