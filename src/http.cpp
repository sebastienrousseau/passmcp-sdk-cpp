// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/http.hpp>

#include "catalog_internal.hpp"
#include <passmcp/oauth.hpp>
#include <passmcp/sha2.hpp>

#include <cctype>
#include <stdexcept>
#include <utility>

namespace passmcp {
namespace {

bool iequals_ascii(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string_view reason_phrase(int status) {
    switch (status) {
        case 200: return "OK";
        case 202: return "Accepted";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        default: return "Error";
    }
}

std::optional<std::string> lookup_header(
    const std::vector<std::pair<std::string, std::string>>& headers, std::string_view name) {
    for (const auto& [k, v] : headers) {
        if (iequals_ascii(k, name)) return v;
    }
    return std::nullopt;
}

void upsert_header(
    std::vector<std::pair<std::string, std::string>>& headers, std::string name, std::string value) {
    for (auto& [k, v] : headers) {
        if (iequals_ascii(k, name)) {
            v = std::move(value);
            return;
        }
    }
    headers.emplace_back(std::move(name), std::move(value));
}

void parse_header_lines(
    std::string_view block, std::vector<std::pair<std::string, std::string>>& out) {
    std::size_t pos = 0;
    while (pos < block.size()) {
        auto eol = block.find("\r\n", pos);
        std::string_view line = eol == std::string::npos ? block.substr(pos) : block.substr(pos, eol - pos);
        pos = eol == std::string::npos ? block.size() : eol + 2;
        if (line.empty()) continue;
        auto colon = line.find(':');
        if (colon == std::string::npos) throw std::invalid_argument("Malformed HTTP header line");
        std::string key = detail::trim_ascii(line.substr(0, colon));
        std::string val = detail::trim_ascii(line.substr(colon + 1));
        upsert_header(out, std::move(key), std::move(val));
    }
}

std::optional<std::string> extract_bearer_token(const std::optional<std::string>& hdr) {
    if (!hdr.has_value()) return std::nullopt;
    std::string s = detail::trim_ascii(*hdr);
    if (s.size() <= 7 || !iequals_ascii(std::string_view(s).substr(0, 7), "Bearer ")) return std::nullopt;
    std::string tok = detail::trim_ascii(std::string_view(s).substr(7));
    return tok.empty() ? std::nullopt : std::optional<std::string>(std::move(tok));
}

HttpResponse json_http_reply(int status, std::string body) {
    HttpResponse resp;
    resp.status = status;
    resp.set_header("Content-Type", "application/json");
    resp.body = std::move(body);
    return resp;
}

std::string rpc_err_json(const JsonValue& id, int code, std::string_view message) {
    JsonValue err = JsonValue::object();
    err.set("code", code);
    err.set("message", std::string(message));
    JsonValue env = JsonValue::object();
    env.set("jsonrpc", "2.0");
    env.set("id", id);
    env.set("error", std::move(err));
    return env.dump();
}

bool reply_has_error_code(std::string_view raw_reply, int expected_code) {
    JsonValue doc = JsonValue::parse(raw_reply);
    const JsonValue* err = doc.find("error");
    return err != nullptr && err->is_object() && err->opt_int("code", 0) == expected_code;
}

bool reply_has_any_error(std::string_view raw_reply) {
    JsonValue doc = JsonValue::parse(raw_reply);
    const JsonValue* err = doc.find("error");
    return err != nullptr && !err->is_null();
}

std::optional<std::string> extract_body_target(const JsonValue* params) {
    if (params == nullptr || !params->is_object()) return std::nullopt;
    if (auto n = params->opt_string("name"); n.has_value()) return n;
    if (auto u = params->opt_string("uri"); u.has_value()) return u;
    return std::nullopt;
}

void attach_stateless_headers(HttpRequest& req, std::string_view raw_json) {
    req.set_header("MCP-Protocol-Version", std::string(McpServer::kRev20260728));
    try {
        JsonValue env = JsonValue::parse(raw_json);
        if (!env.is_object()) return;
        if (auto m = env.opt_string("method"); m.has_value() && !m->empty()) {
            req.set_header("MCP-Method", *m);
        }
        if (auto target = extract_body_target(env.find("params")); target.has_value() && !target->empty()) {
            req.set_header("MCP-Name", *target);
        }
    } catch (const std::exception&) {
        // Leave mirrored method unset when testing malformed payload handling.
    }
}

JsonValue extract_rpc_id(const JsonValue* raw_id) {
    if (raw_id != nullptr && (raw_id->is_string() || raw_id->is_number())) return *raw_id;
    return JsonValue(nullptr);
}

std::string decode_client_http_response(const HttpResponse& resp) {
    if (resp.status == 202) return "";
    if (resp.status == 401) {
        throw std::runtime_error("HTTP 401 Unauthorized: " + resp.header("WWW-Authenticate").value_or(""));
    }
    if (resp.status == 403) throw std::runtime_error("HTTP 403 Forbidden");
    bool rpc_status = resp.status == 200 || resp.status == 400 || resp.status == 404;
    if (!resp.body.empty() && rpc_status) return resp.body;
    throw std::runtime_error("Unexpected HTTP status " + std::to_string(resp.status));
}

} // namespace

std::optional<std::string> HttpRequest::header(std::string_view name) const {
    return lookup_header(headers, name);
}

void HttpRequest::set_header(std::string name, std::string value) {
    upsert_header(headers, std::move(name), std::move(value));
}

std::optional<std::string> HttpResponse::header(std::string_view name) const {
    return lookup_header(headers, name);
}

void HttpResponse::set_header(std::string name, std::string value) {
    upsert_header(headers, std::move(name), std::move(value));
}

HttpRequest parse_http_request(std::string_view raw_wire) {
    auto sep = raw_wire.find("\r\n\r\n");
    if (sep == std::string_view::npos) throw std::invalid_argument("Malformed HTTP/1.1 request");
    auto eol = raw_wire.find("\r\n");
    std::string_view start = raw_wire.substr(0, eol);
    auto sp1 = start.find(' ');
    auto sp2 = sp1 == std::string_view::npos ? std::string_view::npos : start.find(' ', sp1 + 1);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
        throw std::invalid_argument("Invalid HTTP request start line");
    }
    HttpRequest req;
    req.method = std::string(start.substr(0, sp1));
    req.path = std::string(start.substr(sp1 + 1, sp2 - sp1 - 1));
    if (sep > eol + 2) parse_header_lines(raw_wire.substr(eol + 2, sep - (eol + 2)), req.headers);
    req.body = std::string(raw_wire.substr(sep + 4));
    return req;
}

std::string serialize_http_request(const HttpRequest& req, std::string_view host) {
    std::string out = req.method + " " + (req.path.empty() ? "/" : req.path) + " HTTP/1.1\r\n";
    out += "Host: " + std::string(host) + "\r\n";
    for (const auto& [k, v] : req.headers) out += k + ": " + v + "\r\n";
    out += "Content-Length: " + std::to_string(req.body.size()) + "\r\n\r\n";
    out += req.body;
    return out;
}

HttpResponse parse_http_response(std::string_view raw_wire) {
    auto sep = raw_wire.find("\r\n\r\n");
    if (sep == std::string_view::npos) throw std::invalid_argument("Malformed HTTP/1.1 response");
    auto eol = raw_wire.find("\r\n");
    std::string_view start = raw_wire.substr(0, eol);
    auto sp1 = start.find(' ');
    if (sp1 == std::string_view::npos || sp1 + 4 > start.size()) {
        throw std::invalid_argument("Invalid HTTP response status line");
    }
    HttpResponse resp;
    resp.status = std::stoi(std::string(start.substr(sp1 + 1, 3)));
    if (sep > eol + 2) parse_header_lines(raw_wire.substr(eol + 2, sep - (eol + 2)), resp.headers);
    resp.body = std::string(raw_wire.substr(sep + 4));
    return resp;
}

std::string serialize_http_response(const HttpResponse& resp) {
    std::string out = "HTTP/1.1 " + std::to_string(resp.status) + " " + std::string(reason_phrase(resp.status)) + "\r\n";
    for (const auto& [k, v] : resp.headers) out += k + ": " + v + "\r\n";
    out += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n\r\n";
    out += resp.body;
    return out;
}

HttpServerProcessor::HttpServerProcessor(const McpServer& server) : server_(&server) {}

HttpServerProcessor& HttpServerProcessor::require_bearer_auth(
    BearerValidator validator, std::string resource_metadata_url) {
    bearer_validator_ = std::move(validator);
    resource_metadata_url_ = std::move(resource_metadata_url);
    return *this;
}

HttpServerProcessor& HttpServerProcessor::enable_sessions(bool enabled) {
    sessions_enabled_ = enabled;
    return *this;
}

HttpResponse HttpServerProcessor::handle(const HttpRequest& request) {
    if (!server_->origin_guard().is_allowed(request.header("Origin").value_or(""))) {
        return HttpResponse{403, {}, ""};
    }
    if (auto auth_err = check_bearer(request); auth_err.has_value()) return *auth_err;
    if (!iequals_ascii(request.method, "POST")) {
        HttpResponse r{405, {}, ""};
        r.set_header("Allow", "POST");
        return r;
    }
    return handle_post(request);
}

std::string HttpServerProcessor::handle_wire(std::string_view raw_http) {
    return serialize_http_response(handle(parse_http_request(raw_http)));
}

std::optional<HttpResponse> HttpServerProcessor::check_bearer(const HttpRequest& request) const {
    if (!bearer_validator_) return std::nullopt;
    auto tok = extract_bearer_token(request.header("Authorization"));
    if (tok.has_value() && bearer_validator_(*tok)) return std::nullopt;
    HttpResponse unauth{401, {}, ""};
    unauth.set_header("WWW-Authenticate", build_bearer_challenge(resource_metadata_url_));
    return unauth;
}

HttpResponse HttpServerProcessor::handle_post(const HttpRequest& request) {
    JsonValue env;
    try {
        env = JsonValue::parse(request.body);
    } catch (const std::exception&) {
        return json_http_reply(400, rpc_err_json(JsonValue(nullptr), -32700, "Parse error: invalid JSON payload"));
    }
    if (!env.is_object()) {
        return json_http_reply(400, rpc_err_json(JsonValue(nullptr), -32600, "Invalid Request"));
    }
    JsonValue id = extract_rpc_id(env.find("id"));
    std::string method = env.opt_string("method").value_or("");
    if (auto mismatch = check_mirrored_headers(request, env, id, method); mismatch.has_value()) {
        return *mismatch;
    }
    if (requires_existing_session(method)) {
        auto sid = request.header("Mcp-Session-Id");
        if (!sid.has_value() || active_sessions_.find(*sid) == active_sessions_.end()) {
            return HttpResponse{404, {}, ""};
        }
    }
    return dispatch_post_body(request, method);
}

HttpResponse HttpServerProcessor::dispatch_post_body(const HttpRequest& request, std::string_view method) {
    std::string reply = server_->handle_json(request.body);
    if (reply.empty()) return HttpResponse{202, {}, ""};
    if (is_stateless_request(request) && reply_has_error_code(reply, -32601)) {
        return json_http_reply(404, std::move(reply));
    }
    HttpResponse ok = json_http_reply(200, std::move(reply));
    bool issue_session = sessions_enabled_ && server_->revision() != McpServer::kRev20260728 && method == "initialize";
    if (issue_session && !reply_has_any_error(ok.body)) {
        ok.set_header("Mcp-Session-Id", mint_session_id());
    }
    return ok;
}

std::optional<HttpResponse> HttpServerProcessor::check_mirrored_headers(
    const HttpRequest& request, const JsonValue& env, const JsonValue& id, std::string_view body_method) const {
    auto hdr_method = request.header("MCP-Method");
    if (!is_stateless_request(request) && !hdr_method.has_value()) return std::nullopt;
    if (hdr_method.has_value() && !hdr_method->empty() && *hdr_method != body_method) {
        return json_http_reply(400, rpc_err_json(id, -32020, "HeaderMismatch: MCP-Method disagrees with body"));
    }
    if (auto hdr_name = request.header("MCP-Name"); hdr_name.has_value() && !hdr_name->empty()) {
        auto target = extract_body_target(env.find("params"));
        if (target.has_value() && *hdr_name != *target) {
            return json_http_reply(400, rpc_err_json(id, -32020, "HeaderMismatch: MCP-Name disagrees with body"));
        }
    }
    return std::nullopt;
}

bool HttpServerProcessor::is_stateless_request(const HttpRequest& request) const {
    auto ver = request.header("MCP-Protocol-Version");
    return ver == McpServer::kRev20260728 || (!ver.has_value() && server_->revision() == McpServer::kRev20260728);
}

bool HttpServerProcessor::requires_existing_session(std::string_view method) const {
    return sessions_enabled_ && server_->revision() != McpServer::kRev20260728 &&
           method != "initialize" && method != "server/discover";
}

std::string HttpServerProcessor::mint_session_id() {
    std::string seed = server_->name() + ":" + std::to_string(next_session_seq_++);
    std::string sid = "mcp-sess-" + sha256_hex(seed).substr(0, 32);
    active_sessions_.insert(sid);
    return sid;
}

HttpTransport::HttpTransport(std::string path, Exchange exchange)
    : state_(std::make_shared<State>(State{
          path.empty() ? "/mcp" : std::move(path), std::move(exchange), "", "", "", true})) {
    if (!state_->exchange) throw std::invalid_argument("HttpTransport exchange must not be empty");
}

HttpTransport HttpTransport::in_memory(HttpServerProcessor& processor) {
    return HttpTransport("/mcp", [&processor](const HttpRequest& req) { return processor.handle(req); });
}

HttpTransport HttpTransport::over_wire(WireExchange wire_exchange, std::string host, std::string path) {
    return HttpTransport(std::move(path), [wx = std::move(wire_exchange), h = std::move(host)](const HttpRequest& req) {
        return parse_http_response(wx(serialize_http_request(req, h)));
    });
}

HttpTransport& HttpTransport::set_bearer_token(std::string token) {
    state_->bearer_token = std::move(token);
    return *this;
}

HttpTransport& HttpTransport::set_origin(std::string origin) {
    state_->origin = std::move(origin);
    return *this;
}

HttpTransport& HttpTransport::set_stateless_headers(bool enabled) {
    state_->stateless_headers = enabled;
    return *this;
}

HttpTransport& HttpTransport::set_session_id(std::string session_id) {
    state_->session_id = std::move(session_id);
    return *this;
}

std::string HttpTransport::session_id() const { return state_->session_id; }

std::string HttpTransport::operator()(const std::string& raw_json) const {
    HttpRequest req{"POST", state_->path, {}, raw_json};
    req.set_header("Content-Type", "application/json");
    req.set_header("Accept", "application/json, text/event-stream");
    if (!state_->bearer_token.empty()) req.set_header("Authorization", "Bearer " + state_->bearer_token);
    if (!state_->origin.empty()) req.set_header("Origin", state_->origin);
    if (!state_->session_id.empty()) req.set_header("Mcp-Session-Id", state_->session_id);
    if (state_->stateless_headers) attach_stateless_headers(req, raw_json);

    HttpResponse resp = state_->exchange(req);
    if (auto sid = resp.header("Mcp-Session-Id"); sid.has_value() && !sid->empty()) {
        state_->session_id = *sid;
    }
    return decode_client_http_response(resp);
}

} // namespace passmcp
