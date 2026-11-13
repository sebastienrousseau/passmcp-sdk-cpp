// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_HTTP_HPP
#define PASSMCP_HTTP_HPP

#include <passmcp/server.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace passmcp {

/** Transport-agnostic HTTP request envelope with HTTP/1.1 wire serialization helpers. */
struct HttpRequest {
    std::string method = "POST";
    std::string path = "/mcp";
    std::vector<std::pair<std::string, std::string>> headers{};
    std::string body{};

    [[nodiscard]] std::optional<std::string> header(std::string_view name) const;
    void set_header(std::string name, std::string value);
};

/** Transport-agnostic HTTP response envelope with HTTP/1.1 wire serialization helpers. */
struct HttpResponse {
    int status = 200;
    std::vector<std::pair<std::string, std::string>> headers{};
    std::string body{};

    [[nodiscard]] std::optional<std::string> header(std::string_view name) const;
    void set_header(std::string name, std::string value);
};

/** Parses a raw HTTP/1.1 request message into an `HttpRequest`. */
[[nodiscard]] HttpRequest parse_http_request(std::string_view raw_wire);

/** Serializes an `HttpRequest` into an HTTP/1.1 wire payload. */
[[nodiscard]] std::string serialize_http_request(const HttpRequest& req, std::string_view host = "localhost");

/** Parses a raw HTTP/1.1 response message into an `HttpResponse`. */
[[nodiscard]] HttpResponse parse_http_response(std::string_view raw_wire);

/** Serializes an `HttpResponse` into an HTTP/1.1 wire payload. */
[[nodiscard]] std::string serialize_http_response(const HttpResponse& resp);

/**
 * Pure Streamable HTTP server processor (`HttpRequest -> HttpResponse`) and HTTP/1.1 wire handler.
 */
class HttpServerProcessor {
public:
    using BearerValidator = std::function<bool(std::string_view)>;

    explicit HttpServerProcessor(const McpServer& server);

    HttpServerProcessor& require_bearer_auth(BearerValidator validator, std::string resource_metadata_url);
    HttpServerProcessor& enable_sessions(bool enabled);

    [[nodiscard]] HttpResponse handle(const HttpRequest& request);
    [[nodiscard]] std::string handle_wire(std::string_view raw_http);

private:
    [[nodiscard]] std::optional<HttpResponse> check_bearer(const HttpRequest& request) const;
    [[nodiscard]] HttpResponse handle_post(const HttpRequest& request);
    [[nodiscard]] HttpResponse dispatch_post_body(const HttpRequest& request, std::string_view method);
    [[nodiscard]] std::optional<HttpResponse> check_mirrored_headers(
        const HttpRequest& request, const JsonValue& env, const JsonValue& id, std::string_view body_method) const;
    [[nodiscard]] bool is_stateless_request(const HttpRequest& request) const;
    [[nodiscard]] bool requires_existing_session(std::string_view method) const;
    [[nodiscard]] std::string mint_session_id();

    const McpServer* server_;
    BearerValidator bearer_validator_;
    std::string resource_metadata_url_;
    bool sessions_enabled_ = false;
    std::uint64_t next_session_seq_ = 1;
    std::set<std::string> active_sessions_;
};

/**
 * Client-side Streamable HTTP transport usable directly as `McpClient::Transport`.
 */
class HttpTransport {
public:
    using Exchange = std::function<HttpResponse(const HttpRequest&)>;
    using WireExchange = std::function<std::string(std::string_view)>;

    HttpTransport(std::string path, Exchange exchange);

    [[nodiscard]] static HttpTransport in_memory(HttpServerProcessor& processor);
    [[nodiscard]] static HttpTransport over_wire(
        WireExchange wire_exchange, std::string host = "localhost", std::string path = "/mcp");

    HttpTransport& set_bearer_token(std::string token);
    HttpTransport& set_origin(std::string origin);
    HttpTransport& set_stateless_headers(bool enabled);
    HttpTransport& set_session_id(std::string session_id);

    [[nodiscard]] std::string session_id() const;
    [[nodiscard]] std::string operator()(const std::string& raw_json) const;

private:
    struct State {
        std::string path;
        Exchange exchange;
        std::string bearer_token;
        std::string origin;
        std::string session_id;
        bool stateless_headers = true;
    };

    std::shared_ptr<State> state_;
};

} // namespace passmcp

#endif // PASSMCP_HTTP_HPP
