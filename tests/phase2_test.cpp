// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/client.hpp>
#include <passmcp/http.hpp>
#include <passmcp/json.hpp>
#include <passmcp/oauth.hpp>
#include <passmcp/server.hpp>
#include <passmcp/stdio.hpp>

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void check(bool cond, const char* msg) {
    if (!cond) {
        std::cerr << "FAIL: " << msg << "\n";
        std::exit(1);
    }
}

template <typename Ex, typename Fn>
void expect_throws(Fn&& fn, const char* msg) {
    try {
        fn();
    } catch (const Ex&) {
        return;
    }
    std::cerr << "FAIL (expected exception): " << msg << "\n";
    std::exit(1);
}

template <typename Fn>
passmcp::RpcError expect_rpc_code(Fn&& fn, int code, const char* msg) {
    try {
        fn();
    } catch (const passmcp::RpcError& err) {
        check(err.code() == code, msg);
        return err;
    }
    std::cerr << "FAIL (expected RpcError): " << msg << "\n";
    std::exit(1);
}

passmcp::McpServer make_demo_server() {
    passmcp::McpServer srv{"demo", "0.0.10"};
    srv.set_instructions("Demo server instructions")
       .set_cache_hints(passmcp::CacheHints::of_seconds(true, 300, "public"));

    passmcp::JsonValue ep_prop = passmcp::JsonValue::object();
    ep_prop.set("type", "string");
    passmcp::JsonValue props = passmcp::JsonValue::object();
    props.set("endpoint", std::move(ep_prop));
    passmcp::JsonValue req = passmcp::JsonValue::array();
    req.push_back("endpoint");
    passmcp::JsonValue in_schema = passmcp::JsonValue::object();
    in_schema.set("type", "object");
    in_schema.set("additionalProperties", false);
    in_schema.set("required", std::move(req));
    in_schema.set("properties", std::move(props));

    passmcp::JsonValue str_t = passmcp::JsonValue::object();
    str_t.set("type", "string");
    passmcp::JsonValue out_props = passmcp::JsonValue::object();
    out_props.set("endpoint", str_t);
    out_props.set("transport", str_t);
    passmcp::JsonValue out_req = passmcp::JsonValue::array();
    out_req.push_back("endpoint");
    out_req.push_back("transport");
    passmcp::JsonValue out_schema = passmcp::JsonValue::object();
    out_schema.set("type", "object");
    out_schema.set("required", std::move(out_req));
    out_schema.set("properties", std::move(out_props));

    auto tool = passmcp::ToolDescriptor::read_only(
        "inspect_target", "Inspect an MCP target endpoint without side effects.");
    tool.title = "Inspect MCP Target";
    tool.input_schema = std::move(in_schema);
    tool.output_schema = std::move(out_schema);

    srv.register_structured_tool(tool, [](const passmcp::JsonValue& args) {
        std::string ep = args.req_string("endpoint");
        std::string tr = ep.rfind("https://", 0) == 0 ? "http" : "stdio";
        passmcp::JsonValue sc = passmcp::JsonValue::object();
        sc.set("endpoint", ep);
        sc.set("transport", tr);
        return passmcp::ToolResult{sc.dump(), sc};
    });

    srv.register_resource(
        "passmcp://sdk/overview", "sdk-overview", "SDK Overview",
        "SDK overview resource.", "text/plain",
        [](const std::string&) { return std::string{"overview-body"}; });

    srv.register_prompt(
        "audit_summary", "Audit Summary", "Summarize audit.",
        {passmcp::PromptArgument{"server_name", "Server name", true}},
        [](const passmcp::JsonValue& args) { return "Audit " + args.req_string("server_name"); });

    return srv;
}

void test_stdio_framing_and_child_process() {
    auto srv = make_demo_server();
    std::istringstream in(
        "{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n"
        "{malformed-json\n"
        "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}\n");
    std::ostringstream out;
    passmcp::serve_stdio(srv, in, out);

    std::istringstream lines(out.str());
    std::string line1;
    std::string line2;
    std::string extra;
    check(static_cast<bool>(std::getline(lines, line1)), "stdio parse error line emitted");
    check(static_cast<bool>(std::getline(lines, line2)), "stdio ping reply line emitted");
    check(!static_cast<bool>(std::getline(lines, extra)), "notification omitted on stdio");
    check(passmcp::JsonValue::parse(line1).at("error").req_int("code") == -32700, "stdio -32700 recovery");
    check(passmcp::JsonValue::parse(line2).req_int("id") == 7, "stdio continued after malformed line");

    passmcp::McpClient mem_client(passmcp::StdioTransport::in_memory(srv));
    (void)mem_client.initialize();
    auto disc = mem_client.discover();
    check(disc.req_string("resultType") == "discover", "discover resultType");
    check(disc.at("_meta").at("io.modelcontextprotocol/serverInfo").req_string("name") == "demo",
          "discover _meta serverInfo");

    auto child = passmcp::StdioTransport::spawn({PASSMCP_STDIO_SERVER_BIN});
    passmcp::McpClient proc_client(child);
    (void)proc_client.initialize();
    proc_client.ping();
    check(proc_client.list_tools().size() == 1, "spawned stdio_server listed 1 tool");
    passmcp::JsonValue call_args = passmcp::JsonValue::object();
    call_args.set("endpoint", "https://mcp.example.com/mcp");
    check(proc_client.call_tool("inspect_target", call_args).find("\"http\"") != std::string::npos,
          "spawned stdio_server inspect_target");
    check(proc_client.read_resource("passmcp://sdk/overview").find("2026-07-28") != std::string::npos,
          "spawned stdio_server resource read");
    child.close();
}

void test_http_processor_wire_and_sessions() {
    auto srv = make_demo_server();
    srv.set_origin_guard(passmcp::OriginGuard({"https://app.example.com"}));
    passmcp::HttpServerProcessor proc(srv);
    proc.require_bearer_auth(
        [](std::string_view tok) { return tok == "secret-tok"; },
        "https://mcp.example.com/.well-known/oauth-protected-resource");

    passmcp::HttpRequest bad_origin;
    bad_origin.set_header("Origin", "https://evil.example");
    check(proc.handle(bad_origin).status == 403, "HTTP disallowed Origin -> 403");

    auto unauth = proc.handle(passmcp::HttpRequest{});
    check(unauth.status == 401, "HTTP missing Bearer -> 401");
    auto chal = passmcp::parse_bearer_challenge(unauth.header("WWW-Authenticate").value_or(""));
    check(chal.resource_metadata == "https://mcp.example.com/.well-known/oauth-protected-resource",
          "HTTP 401 WWW-Authenticate resource_metadata");

    passmcp::HttpRequest get_req{"GET", "/mcp", {}, ""};
    get_req.set_header("Authorization", "Bearer secret-tok");
    auto get_resp = proc.handle(get_req);
    check(get_resp.status == 405 && get_resp.header("Allow") == "POST", "HTTP GET -> 405 Allow: POST");

    passmcp::HttpRequest bad_json{"POST", "/mcp", {}, "{bad"};
    bad_json.set_header("Authorization", "Bearer secret-tok");
    auto bad_resp = proc.handle(bad_json);
    check(bad_resp.status == 400 && bad_resp.body.find("-32700") != std::string::npos, "HTTP malformed -> 400 -32700");

    passmcp::HttpRequest note{"POST", "/mcp", {}, R"({"jsonrpc":"2.0","method":"notifications/initialized"})"};
    note.set_header("Authorization", "Bearer secret-tok");
    auto note_resp = proc.handle(note);
    check(note_resp.status == 202 && note_resp.body.empty(), "HTTP notification -> 202 empty");

    passmcp::HttpRequest mismatch{"POST", "/mcp", {}, R"({"jsonrpc":"2.0","id":1,"method":"ping"})"};
    mismatch.set_header("Authorization", "Bearer secret-tok");
    mismatch.set_header("MCP-Protocol-Version", "2026-07-28");
    mismatch.set_header("MCP-Method", "tools/list");
    auto mm_resp = proc.handle(mismatch);
    check(mm_resp.status == 400 && mm_resp.body.find("-32020") != std::string::npos, "HTTP -32020 header mismatch");

    passmcp::HttpRequest unk{"POST", "/mcp", {}, R"({"jsonrpc":"2.0","id":2,"method":"sampling/createMessage"})"};
    unk.set_header("Authorization", "Bearer secret-tok");
    auto unk_resp = proc.handle(unk);
    check(unk_resp.status == 404 && unk_resp.body.find("-32601") != std::string::npos, "HTTP stateless -32601 -> 404");

    auto wire_tx = passmcp::HttpTransport::over_wire(
        [&proc](std::string_view wire) { return proc.handle_wire(wire); });
    wire_tx.set_bearer_token("secret-tok").set_origin("https://app.example.com");
    passmcp::McpClient wire_client(wire_tx);
    (void)wire_client.discover();
    passmcp::JsonValue args = passmcp::JsonValue::object();
    args.set("endpoint", "stdio://local");
    check(wire_client.call_tool("inspect_target", args).find("\"stdio\"") != std::string::npos,
          "HTTP/1.1 wire client <-> server round-trip");
}

void test_http_sessions() {
    passmcp::McpServer sess_srv{"sess", "0.0.10", std::string(passmcp::McpServer::kRev20251125)};
    sess_srv.register_read_only_tool("ping_tool", "Read-only session tool", [](const std::string&) {
        return std::string{"pong"};
    });
    passmcp::HttpServerProcessor sess_proc(sess_srv);
    sess_proc.enable_sessions(true);
    check(sess_proc.handle(passmcp::HttpRequest{"POST", "/mcp", {}, R"({"jsonrpc":"2.0","id":1,"method":"ping"})"}).status == 404,
          "missing Mcp-Session-Id -> 404");

    auto sess_tx = passmcp::HttpTransport::in_memory(sess_proc).set_stateless_headers(false);
    passmcp::McpClient sess_client(sess_tx);
    (void)sess_client.initialize();
    check(!sess_tx.session_id().empty(), "Mcp-Session-Id issued on initialize");
    check(sess_client.call_tool("ping_tool") == "pong", "Mcp-Session-Id reused on tool call");
    sess_tx.set_session_id("unknown-session");
    expect_throws<std::runtime_error>([&] { sess_client.ping(); }, "unknown Mcp-Session-Id -> 404");
}

void test_oauth_and_schema_validation() {
    constexpr std::string_view kVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    constexpr std::string_view kChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    check(passmcp::compute_s256_challenge(kVerifier) == kChallenge, "RFC 7636 Appendix B S256 vector");
    check(passmcp::verify_s256(kVerifier, kChallenge), "verify_s256 accepts RFC vector");
    check(!passmcp::verify_s256(kVerifier, "wrong"), "verify_s256 rejects wrong challenge");

    std::string gen = passmcp::generate_pkce_verifier();
    check(gen.size() == 64 && passmcp::verify_s256(gen, passmcp::compute_s256_challenge(gen)), "generated PKCE");
    expect_throws<std::invalid_argument>([] { (void)passmcp::generate_pkce_verifier(42); }, "PKCE < 43");
    expect_throws<std::invalid_argument>([] { (void)passmcp::generate_pkce_verifier(129); }, "PKCE > 128");

    auto prm_urls = passmcp::protected_resource_well_known_urls("https://mcp.example.com/mcp");
    check(prm_urls.size() == 2 &&
              prm_urls[0] == "https://mcp.example.com/.well-known/oauth-protected-resource/mcp" &&
              prm_urls[1] == "https://mcp.example.com/.well-known/oauth-protected-resource",
          "RFC 9728 well-known URLs");

    const std::string prm_json =
        R"({"resource":"https://mcp.example.com/mcp","authorization_servers":["https://auth.example.com"]})";
    auto prm = passmcp::validate_protected_resource_metadata(prm_json, "https://mcp.example.com/mcp");
    check(prm.authorization_servers.front() == "https://auth.example.com", "RFC 9728 metadata valid");
    expect_throws<std::invalid_argument>([&] {
        (void)passmcp::validate_protected_resource_metadata(prm_json, "https://other.example.com/mcp");
    }, "RFC 9728 resource mismatch");

    check(passmcp::authorization_server_well_known_url("https://auth.example.com/tenant") ==
              "https://auth.example.com/.well-known/oauth-authorization-server/tenant",
          "RFC 8414 well-known URL");
    const std::string as_json =
        R"({"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/authorize",)"
        R"("token_endpoint":"https://auth.example.com/token","code_challenge_methods_supported":["S256"]})";
    auto as_meta = passmcp::validate_authorization_server_metadata(as_json, "https://auth.example.com");
    check(as_meta.issuer == "https://auth.example.com", "RFC 8414 metadata valid");
    const std::string plain_as =
        R"({"issuer":"https://auth.example.com","authorization_endpoint":"https://auth.example.com/authorize",)"
        R"("token_endpoint":"https://auth.example.com/token","code_challenge_methods_supported":["plain"]})";
    expect_throws<std::invalid_argument>([&] {
        (void)passmcp::validate_authorization_server_metadata(plain_as);
    }, "RFC 8414 without S256 rejected");

    auto srv = make_demo_server();
    auto client = passmcp::McpClient::for_server(srv);
    passmcp::JsonValue bad_call = passmcp::JsonValue::object();
    bad_call.set("name", "inspect_target");
    bad_call.set("arguments", passmcp::JsonValue::object());
    (void)expect_rpc_code([&] { (void)client.rpc("tools/call", bad_call); }, -32602, "missing required arg");

    passmcp::JsonValue wrong_type_args = passmcp::JsonValue::object();
    wrong_type_args.set("endpoint", 99);
    bad_call.set("arguments", std::move(wrong_type_args));
    (void)expect_rpc_code([&] { (void)client.rpc("tools/call", bad_call); }, -32602, "wrong arg type");

    passmcp::JsonValue bad_prompt = passmcp::JsonValue::object();
    bad_prompt.set("name", "audit_summary");
    bad_prompt.set("arguments", passmcp::JsonValue::object());
    (void)expect_rpc_code([&] { (void)client.rpc("prompts/get", bad_prompt); }, -32602, "missing prompt arg");
}

} // namespace

int main() {
    test_stdio_framing_and_child_process();
    test_http_processor_wire_and_sessions();
    test_http_sessions();
    test_oauth_and_schema_validation();
    std::cout << "passmcp-sdk-cpp: all 4 Phase 2 suites passed\n";
    return 0;
}
