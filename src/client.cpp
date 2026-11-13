// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/client.hpp>

#include <utility>

namespace passmcp {

bool Policy::allows(const ToolDescriptor& tool) const noexcept {
    return tool.read_only_hint || allow_mutations_;
}

void Policy::enforce(const ToolDescriptor& tool) const {
    if (!allows(tool)) {
        throw std::runtime_error("Policy refused execution of non-read-only tool: " + tool.name);
    }
}

RpcError::RpcError(int code, const std::string& message, JsonValue data)
    : std::runtime_error(message), code_(code), data_(std::move(data)) {}

McpClient::McpClient(Transport transport, Policy policy)
    : transport_(std::move(transport)), policy_(policy) {
    if (!transport_) {
        throw std::invalid_argument("Client transport must not be empty");
    }
}

McpClient McpClient::for_server(const McpServer& server, Policy policy) {
    return McpClient([&server](const std::string& req) { return server.handle_json(req); }, policy);
}

McpClient& McpClient::require_attestation(
    const Attestation& attestation, std::string_view transport_kind, std::string_view endpoint) {
    attestation.validate();
    if (!attestation.covers(transport_kind, endpoint)) {
        throw std::runtime_error("Attestation does not cover target endpoint");
    }
    return *this;
}

JsonValue McpClient::discover() {
    JsonValue res = rpc("server/discover");
    if (auto rev = res.opt_string("protocolVersion"); rev.has_value() && !rev->empty()) {
        negotiated_revision_ = *rev;
    }
    validate_stateless_meta_if_required(res);
    if (const JsonValue* tools = res.find("tools"); tools != nullptr && tools->is_array()) {
        cache_tool_list(*tools);
    }
    return res;
}

JsonValue McpClient::initialize() {
    JsonValue client_info = JsonValue::object();
    client_info.set("name", "passmcp-sdk-cpp");
    client_info.set("version", "0.0.10");

    JsonValue params = JsonValue::object();
    params.set("protocolVersion", std::string(McpServer::kRev20260728));
    params.set("capabilities", JsonValue::object());
    params.set("clientInfo", std::move(client_info));

    JsonValue res = rpc("initialize", params);
    if (auto rev = res.opt_string("protocolVersion"); rev.has_value() && !rev->empty()) {
        negotiated_revision_ = *rev;
    }
    notify("notifications/initialized");
    return res;
}

void McpClient::ping() {
    (void)rpc("ping");
}

std::vector<ToolDescriptor> McpClient::list_tools() {
    JsonValue res = rpc("tools/list");
    validate_stateless_meta_if_required(res);
    return cache_tool_list(res.at("tools"));
}

std::string McpClient::call_tool(std::string_view name, const JsonValue& arguments) {
    if (!tools_cached_) {
        (void)list_tools();
    }
    auto it = cached_tools_.find(std::string(name));
    if (it == cached_tools_.end()) {
        throw std::runtime_error("Policy refused execution of unknown tool: " + std::string(name));
    }
    policy_.enforce(it->second);

    JsonValue params = JsonValue::object();
    params.set("name", std::string(name));
    params.set("arguments", arguments);
    JsonValue res = rpc("tools/call", params);
    const auto& content = res.at("content").as_array();
    if (content.empty()) {
        return "";
    }
    return content.front().opt_string("text").value_or("");
}

std::string McpClient::read_resource(std::string_view uri) {
    JsonValue params = JsonValue::object();
    params.set("uri", std::string(uri));
    JsonValue res = rpc("resources/read", params);
    const auto& contents = res.at("contents").as_array();
    if (contents.empty()) {
        return "";
    }
    return contents.front().opt_string("text").value_or("");
}

JsonValue McpClient::rpc(std::string_view method, const JsonValue& params) {
    JsonValue req = JsonValue::object();
    req.set("jsonrpc", "2.0");
    req.set("id", next_id_++);
    req.set("method", std::string(method));
    req.set("params", params);

    JsonValue resp = JsonValue::parse(transport_(req.dump()));
    if (const JsonValue* err = resp.find("error"); err != nullptr && !err->is_null()) {
        int code = static_cast<int>(err->req_int("code"));
        std::string msg = err->opt_string("message").value_or("RPC error");
        const JsonValue* data_ptr = err->find("data");
        JsonValue data = (data_ptr != nullptr && data_ptr->is_object()) ? *data_ptr : JsonValue::object();
        throw RpcError(code, msg, std::move(data));
    }
    return resp.at("result");
}

void McpClient::notify(std::string_view method) {
    JsonValue note = JsonValue::object();
    note.set("jsonrpc", "2.0");
    note.set("method", std::string(method));
    (void)transport_(note.dump());
}

void McpClient::validate_stateless_meta_if_required(const JsonValue& result) const {
    if (negotiated_revision_ == McpServer::kRev20260728) {
        (void)CacheHints::from_result(result);
    }
}

std::vector<ToolDescriptor> McpClient::cache_tool_list(const JsonValue& raw_tools) {
    cached_tools_.clear();
    std::vector<ToolDescriptor> out;
    for (const auto& item : raw_tools.as_array()) {
        ToolDescriptor td = ToolDescriptor::from_wire(item);
        cached_tools_.emplace(td.name, td);
        out.push_back(std::move(td));
    }
    tools_cached_ = true;
    return out;
}

} // namespace passmcp
