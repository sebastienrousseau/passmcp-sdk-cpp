// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/server.hpp>

#include "catalog_internal.hpp"

#include <stdexcept>
#include <utility>

namespace passmcp {
namespace {

struct RpcFault {
    int code;
    std::string message;
    std::optional<JsonValue> data;
};

JsonValue sanitize_id(const JsonValue* id_ptr) {
    if (id_ptr != nullptr && (id_ptr->is_string() || id_ptr->is_number() || id_ptr->is_null())) {
        return *id_ptr;
    }
    return JsonValue(nullptr);
}

std::string make_result_response(const JsonValue& id, JsonValue result) {
    JsonValue env = JsonValue::object();
    env.set("jsonrpc", "2.0");
    env.set("id", id);
    env.set("result", std::move(result));
    return env.dump();
}

std::string make_error_response(const JsonValue& id, int code, std::string_view msg, std::optional<JsonValue> data) {
    JsonValue err = JsonValue::object();
    err.set("code", code);
    err.set("message", std::string(msg));
    if (data.has_value()) err.set("data", std::move(*data));
    JsonValue env = JsonValue::object();
    env.set("jsonrpc", "2.0");
    env.set("id", id);
    env.set("error", std::move(err));
    return env.dump();
}

void require_capability(bool enabled, std::string_view cap) {
    if (!enabled) throw RpcFault{-32601, "Capability not declared: " + std::string(cap), std::nullopt};
}

std::string require_param_str(const JsonValue& params, std::string_view key) {
    const JsonValue* p = params.find(key);
    if (p == nullptr || !p->is_string() || detail::trim_ascii(p->as_string()).empty()) {
        throw RpcFault{-32602, "Invalid params: missing required string '" + std::string(key) + "'", std::nullopt};
    }
    return p->as_string();
}

JsonValue extract_args_object(const JsonValue& params) {
    const JsonValue* a = params.find("arguments");
    if (a == nullptr || a->is_null()) return JsonValue::object();
    if (!a->is_object()) throw RpcFault{-32602, "Invalid params: arguments must be a JSON object", std::nullopt};
    return *a;
}

JsonValue make_tool_result(std::string_view text, const std::optional<JsonValue>& structured, bool is_error) {
    JsonValue item = JsonValue::object();
    item.set("type", "text");
    item.set("text", std::string(text));
    JsonValue arr = JsonValue::array();
    arr.push_back(std::move(item));
    JsonValue res = JsonValue::object();
    res.set("content", std::move(arr));
    if (structured.has_value()) res.set("structuredContent", *structured);
    res.set("isError", is_error);
    return res;
}

JsonValue make_list_result(bool enabled, std::string_view cap, std::string key, JsonValue items,
                           std::string_view revision, const CacheHints& hints) {
    require_capability(enabled, cap);
    JsonValue out = JsonValue::object();
    if (revision == McpServer::kRev20260728) out.set("resultType", "complete");
    out.set(std::move(key), std::move(items));
    if (revision == McpServer::kRev20260728) hints.apply_to_list_result(out);
    return out;
}

std::optional<std::string> valid_jsonrpc_method(const JsonValue& req) {
    const JsonValue* ver = req.find("jsonrpc");
    if (ver == nullptr || !ver->is_string() || ver->as_string() != "2.0") return std::nullopt;
    const JsonValue* m = req.find("method");
    return (m != nullptr && m->is_string() && !m->as_string().empty())
               ? std::optional<std::string>(m->as_string())
               : std::nullopt;
}

JsonValue extract_rpc_params(const JsonValue& req) {
    const JsonValue* raw_params = req.find("params");
    if (raw_params == nullptr || raw_params->is_null()) return JsonValue::object();
    if (!raw_params->is_object()) {
        throw RpcFault{-32602, "Invalid params: expected JSON object", std::nullopt};
    }
    return *raw_params;
}

} // namespace

McpServer::McpServer(std::string name, std::string version, std::string revision)
    : name_(std::move(name)),
      version_(std::move(version)),
      revision_(std::move(revision)),
      cache_hints_(CacheHints::private_scope(60000)) {
    if (detail::trim_ascii(name_).empty() || detail::trim_ascii(version_).empty()) {
        throw std::invalid_argument("Server name and version must not be empty");
    }
    if (revision_ != kRev20260728 && revision_ != kRev20251125 && revision_ != kRev20250618) {
        throw std::invalid_argument("Unsupported MCP revision: " + revision_);
    }
}

McpServer& McpServer::set_instructions(std::string instructions) {
    instructions_ = std::move(instructions);
    return *this;
}

McpServer& McpServer::set_cache_hints(CacheHints hints) {
    cache_hints_ = std::move(hints);
    return *this;
}

McpServer& McpServer::set_origin_guard(OriginGuard guard) {
    origin_guard_ = std::move(guard);
    return *this;
}

McpServer& McpServer::register_read_only_tool(std::string name, std::string description, ToolHandler handler) {
    return register_tool(ToolDescriptor::read_only(std::move(name), std::move(description)), std::move(handler));
}

McpServer& McpServer::register_tool(ToolDescriptor tool, ToolHandler handler) {
    return register_structured_tool(std::move(tool), [h = std::move(handler)](const JsonValue& args) {
        return ToolResult{h(args.dump()), std::nullopt};
    });
}

McpServer& McpServer::register_structured_tool(ToolDescriptor tool, StructuredToolHandler handler) {
    if (detail::trim_ascii(tool.name).empty()) throw std::invalid_argument("Tool name must not be empty");
    for (auto& existing : tools_) {
        if (existing.descriptor.name == tool.name) {
            existing.descriptor = std::move(tool);
            existing.handler = std::move(handler);
            return *this;
        }
    }
    tools_.push_back(ToolEntry{std::move(tool), std::move(handler)});
    return *this;
}

McpServer& McpServer::register_resource(
    std::string uri, std::string name, std::string mime_type, ResourceReader reader) {
    return register_resource(std::move(uri), std::move(name), "", "", std::move(mime_type), std::move(reader));
}

McpServer& McpServer::register_resource(
    std::string uri,
    std::string name,
    std::string title,
    std::string description,
    std::string mime_type,
    ResourceReader reader) {
    if (detail::trim_ascii(uri).empty()) throw std::invalid_argument("Resource URI must not be empty");
    resources_.push_back(ResourceEntry{
        std::move(uri), std::move(name), std::move(title),
        std::move(description), std::move(mime_type), std::move(reader)});
    return *this;
}

McpServer& McpServer::register_resource_template(std::string uri_template, std::string name, std::string mime_type) {
    if (detail::trim_ascii(uri_template).empty()) throw std::invalid_argument("URI template must not be empty");
    templates_.push_back(TemplateEntry{std::move(uri_template), std::move(name), std::move(mime_type)});
    return *this;
}

McpServer& McpServer::register_prompt(std::string name, std::string description, PromptRenderer renderer) {
    return register_prompt(std::move(name), "", std::move(description), {}, std::move(renderer));
}

McpServer& McpServer::register_prompt(
    std::string name,
    std::string title,
    std::string description,
    std::vector<PromptArgument> arguments,
    PromptRenderer renderer) {
    if (detail::trim_ascii(name).empty()) throw std::invalid_argument("Prompt name must not be empty");
    prompts_.push_back(PromptEntry{
        std::move(name), std::move(title), std::move(description),
        std::move(arguments), std::move(renderer)});
    return *this;
}

HttpReply McpServer::handle_http(std::string_view origin_header, std::string_view raw) const {
    if (!origin_guard_.is_allowed(origin_header)) return HttpReply{403, ""};
    std::string body = handle_json(raw);
    return body.empty() ? HttpReply{202, ""} : HttpReply{200, std::move(body)};
}

std::string McpServer::handle_json(std::string_view raw) const {
    JsonValue req;
    try {
        req = JsonValue::parse(raw);
    } catch (const std::exception&) {
        return make_error_response(JsonValue(nullptr), -32700, "Parse error: invalid JSON payload", std::nullopt);
    }
    if (!req.is_object()) return make_error_response(JsonValue(nullptr), -32600, "Invalid Request", std::nullopt);
    const JsonValue* id_ptr = req.find("id");
    JsonValue id = sanitize_id(id_ptr);
    auto method = valid_jsonrpc_method(req);
    if (!method.has_value()) {
        return make_error_response(id, -32600, "Invalid Request", std::nullopt);
    }
    if (id_ptr == nullptr) return "";
    try {
        return make_result_response(id, dispatch_method(*method, extract_rpc_params(req)));
    } catch (const RpcFault& fault) {
        return make_error_response(id, fault.code, fault.message, fault.data);
    }
}

JsonValue McpServer::dispatch_method(std::string_view method, const JsonValue& params) const {
    if (method == "initialize") return handle_initialize();
    if (method == "ping") return JsonValue::object();
    if (method == "server/discover") return handle_discover();
    if (method == "tools/call") return handle_tools_call(params);
    if (method == "resources/read") return handle_resources_read(params);
    if (method == "prompts/get") return handle_prompts_get(params);
    return dispatch_list_method(method);
}

JsonValue McpServer::dispatch_list_method(std::string_view method) const {
    if (method == "tools/list") {
        return make_list_result(has_tools(), "tools", "tools", wire_tools(), revision_, cache_hints_);
    }
    if (method == "resources/list") {
        return make_list_result(has_resources(), "resources", "resources", wire_resources(), revision_, cache_hints_);
    }
    if (method == "resources/templates/list") {
        return make_list_result(
            has_resources(), "resources", "resourceTemplates", wire_templates(), revision_, cache_hints_);
    }
    if (method == "prompts/list") {
        return make_list_result(has_prompts(), "prompts", "prompts", wire_prompts(), revision_, cache_hints_);
    }
    throw RpcFault{-32601, "Method not found: unknown method '" + std::string(method) + "'", std::nullopt};
}

JsonValue McpServer::handle_initialize() const {
    JsonValue out = JsonValue::object();
    out.set("protocolVersion", revision_);
    out.set("capabilities", derived_capabilities());
    out.set("serverInfo", server_info());
    if (!instructions_.empty()) out.set("instructions", instructions_);
    return out;
}

JsonValue McpServer::handle_discover() const {
    JsonValue versions = JsonValue::array();
    versions.push_back(std::string(kRev20260728));
    versions.push_back(std::string(kRev20251125));
    versions.push_back(std::string(kRev20250618));

    JsonValue out = JsonValue::object();
    out.set("resultType", "discover");
    out.set("protocolVersion", revision_);
    out.set("supportedVersions", std::move(versions));
    out.set("serverInfo", server_info());
    out.set("capabilities", derived_capabilities());
    if (!instructions_.empty()) out.set("instructions", instructions_);
    if (has_tools()) out.set("tools", wire_tools());
    if (has_resources()) {
        out.set("resources", wire_resources());
        out.set("resourceTemplates", wire_templates());
    }
    if (has_prompts()) out.set("prompts", wire_prompts());
    JsonValue meta = JsonValue::object();
    meta.set("io.modelcontextprotocol/serverInfo", server_info());
    if (revision_ == kRev20260728) {
        meta.set("ttlMs", cache_hints_.ttl_ms());
        meta.set("cacheScope", cache_hints_.cache_scope());
        out.set("ttlMs", cache_hints_.ttl_ms());
        out.set("cacheScope", cache_hints_.cache_scope());
    }
    out.set("_meta", std::move(meta));
    return out;
}

JsonValue McpServer::handle_tools_call(const JsonValue& params) const {
    require_capability(has_tools(), "tools");
    std::string tool_name = require_param_str(params, "name");
    for (const auto& entry : tools_) {
        if (entry.descriptor.name == tool_name) {
            JsonValue args = extract_args_object(params);
            auto schema_err = detail::validate_tool_args(entry.descriptor.effective_input_schema(), args);
            if (schema_err.has_value()) throw RpcFault{-32602, *schema_err, std::nullopt};
            try {
                ToolResult res = entry.handler(args);
                return make_tool_result(res.text, res.structured_content, false);
            } catch (const std::exception& ex) {
                return make_tool_result(ex.what(), std::nullopt, true);
            }
        }
    }
    throw RpcFault{-32602, "Unknown tool '" + tool_name + "'; call tools/list for available tools", std::nullopt};
}

JsonValue McpServer::handle_resources_read(const JsonValue& params) const {
    require_capability(has_resources(), "resources");
    std::string uri = require_param_str(params, "uri");
    for (const auto& entry : resources_) {
        if (entry.uri == uri) {
            JsonValue item = JsonValue::object();
            item.set("uri", entry.uri);
            item.set("mimeType", entry.mime_type);
            item.set("text", entry.reader(uri));
            JsonValue contents = JsonValue::array();
            contents.push_back(std::move(item));
            JsonValue out = JsonValue::object();
            out.set("contents", std::move(contents));
            return out;
        }
    }
    const int code = (revision_ == kRev20260728) ? -32602 : -32002;
    JsonValue err_data = JsonValue::object();
    err_data.set("uri", uri);
    throw RpcFault{code, "Resource not found; call resources/list for available URIs", std::move(err_data)};
}

JsonValue McpServer::handle_prompts_get(const JsonValue& params) const {
    require_capability(has_prompts(), "prompts");
    std::string name = require_param_str(params, "name");
    for (const auto& entry : prompts_) {
        if (entry.name == name) {
            JsonValue args = extract_args_object(params);
            auto arg_err = detail::validate_prompt_args(entry.arguments, args);
            if (arg_err.has_value()) throw RpcFault{-32602, *arg_err, std::nullopt};
            JsonValue content = JsonValue::object();
            content.set("type", "text");
            content.set("text", entry.renderer(args));
            JsonValue msg = JsonValue::object();
            msg.set("role", "user");
            msg.set("content", std::move(content));
            JsonValue msgs = JsonValue::array();
            msgs.push_back(std::move(msg));
            JsonValue out = JsonValue::object();
            out.set("description", entry.description);
            out.set("messages", std::move(msgs));
            return out;
        }
    }
    throw RpcFault{-32602, "Unknown prompt '" + name + "'; call prompts/list first", std::nullopt};
}

JsonValue McpServer::derived_capabilities() const {
    JsonValue caps = JsonValue::object();
    if (has_tools()) caps.set("tools", JsonValue::object());
    if (has_resources()) caps.set("resources", JsonValue::object());
    if (has_prompts()) caps.set("prompts", JsonValue::object());
    return caps;
}

JsonValue McpServer::server_info() const {
    JsonValue info = JsonValue::object();
    info.set("name", name_);
    info.set("version", version_);
    return info;
}

JsonValue McpServer::wire_tools() const {
    JsonValue arr = JsonValue::array();
    for (const auto& entry : tools_) arr.push_back(entry.descriptor.to_wire());
    return arr;
}

JsonValue McpServer::wire_resources() const {
    JsonValue arr = JsonValue::array();
    for (const auto& entry : resources_) {
        JsonValue item = JsonValue::object();
        item.set("uri", entry.uri);
        item.set("name", entry.name);
        if (!entry.title.empty()) item.set("title", entry.title);
        if (!entry.description.empty()) item.set("description", entry.description);
        item.set("mimeType", entry.mime_type);
        arr.push_back(std::move(item));
    }
    return arr;
}

JsonValue McpServer::wire_templates() const {
    JsonValue arr = JsonValue::array();
    for (const auto& entry : templates_) {
        JsonValue item = JsonValue::object();
        item.set("uriTemplate", entry.uri_template);
        item.set("name", entry.name);
        item.set("mimeType", entry.mime_type);
        arr.push_back(std::move(item));
    }
    return arr;
}

JsonValue McpServer::wire_prompts() const {
    JsonValue arr = JsonValue::array();
    for (const auto& entry : prompts_) {
        JsonValue item = JsonValue::object();
        item.set("name", entry.name);
        if (!entry.title.empty()) item.set("title", entry.title);
        item.set("description", entry.description);
        if (!entry.arguments.empty()) {
            JsonValue args = JsonValue::array();
            for (const auto& arg : entry.arguments) {
                JsonValue a = JsonValue::object();
                a.set("name", arg.name);
                if (!arg.description.empty()) a.set("description", arg.description);
                a.set("required", arg.required);
                args.push_back(std::move(a));
            }
            item.set("arguments", std::move(args));
        }
        arr.push_back(std::move(item));
    }
    return arr;
}

} // namespace passmcp
