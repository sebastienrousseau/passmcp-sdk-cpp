// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/attestation.hpp>
#include <passmcp/client.hpp>
#include <passmcp/json.hpp>
#include <passmcp/server.hpp>
#include <passmcp/sha2.hpp>

#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

namespace {

void check(bool cond, const std::string& msg) {
    if (!cond) {
        throw std::runtime_error("Test assertion failed: " + msg);
    }
}

template <typename Exc, typename Fn>
void expect_throws(Fn&& fn, const std::string& label) {
    try {
        fn();
    } catch (const Exc&) {
        return;
    }
    throw std::runtime_error("Expected exception for: " + label);
}

passmcp::RpcError expect_rpc_code(const std::function<void()>& fn, int want_code, const std::string& label) {
    try {
        fn();
    } catch (const passmcp::RpcError& err) {
        check(err.code() == want_code, label + " (got " + std::to_string(err.code()) + ")");
        return err;
    }
    throw std::runtime_error("Expected RpcError for: " + label);
}

std::string read_fixture() {
    const std::string path = std::string(PASSMCP_TESTDATA_DIR) + "/statement.json";
    std::ifstream ifs(path, std::ios::binary);
    check(ifs.is_open(), "open fixture " + path);
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}

void test_sha2_vectors() {
    check(passmcp::sha256_hex("") ==
              "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          "SHA-256 empty");
    check(passmcp::sha256_hex("abc") ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "SHA-256 abc");
    check(passmcp::sha256_hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
              "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
          "SHA-256 multi-block");
    check(passmcp::sha256_hex("http\nhttps://mcp.example.com/mcp") ==
              "a386a033799c95c21f3d01b2f0efcf71b95b1ef2a420908ce34e3c1eb41a2325",
          "SHA-256 passmcp target descriptor");

    check(passmcp::sha512_hex("") ==
              "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
              "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
          "SHA-512 empty");
    check(passmcp::sha512_hex("abc") ==
              "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
              "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
          "SHA-512 abc");
    check(passmcp::sha512_hex(
              "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
              "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu") ==
              "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
              "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
          "SHA-512 multi-block");
}

void test_json_parser() {
    auto obj = passmcp::JsonValue::parse(R"({"msg":"hi\n\uD83D\uDE80","n":42,"f":-2.5e1,"b":true})");
    check(obj.req_string("msg") == "hi\n\xF0\x9F\x9A\x80", "UTF-16 surrogate pair decode");
    check(obj.req_int("n") == 42, "int parse");
    check(obj.at("f").as_number() == -25.0, "float parse");
    auto round = passmcp::JsonValue::parse(obj.dump());
    check(round.req_string("msg") == obj.req_string("msg"), "JSON dump/parse round-trip");

    expect_throws<std::invalid_argument>([] { (void)passmcp::JsonValue::parse("{bad}"); }, "unquoted key");
    expect_throws<std::invalid_argument>([] { (void)passmcp::JsonValue::parse("{} extra"); }, "trailing token");
    expect_throws<std::invalid_argument>([] { (void)passmcp::JsonValue::parse("01"); }, "leading zero");
    expect_throws<std::invalid_argument>([] { (void)passmcp::JsonValue::parse("{\"a\":1,}"); }, "trailing comma");
}

void test_attestation_fixture_and_sha512(const std::string& fixture) {
    auto st = passmcp::Attestation::parse(fixture);
    check(st.covers("http", "https://mcp.example.com/mcp"), "covers exact target");
    check(st.covers("http", "  https://mcp.example.com/mcp\n"), "covers trimmed endpoint");
    check(!st.covers("stdio", "https://mcp.example.com/mcp"), "wrong transport rejected");
    check(!st.covers("http", "https://other.example.com/mcp"), "wrong endpoint rejected");
    check(st.score_total() == 88.0, "score_total == 88");
    check(st.score_grade() == "B", "score_grade == B");
    auto origin = st.verdict_for("protocol.origin");
    check(origin.has_value() && origin->status == "fail" && origin->severity == "major", "verdict_for hit");
    check(!st.verdict_for("missing.check").has_value(), "verdict_for miss");

    const std::string desc = "http\nhttps://mcp.example.com/mcp";
    const std::string h512 = passmcp::sha512_hex(desc);
    auto root = passmcp::JsonValue::parse(fixture);
    auto& sub0 = root.find_mut("subject")->as_array_mut()[0];
    passmcp::JsonValue d512 = passmcp::JsonValue::object();
    d512.set("sha512", h512);
    sub0.set("digest", d512);
    auto st512 = passmcp::Attestation::parse(root.dump());
    check(st512.covers("http", "https://mcp.example.com/mcp"), "sha512-only covers target");

    passmcp::JsonValue bad_both = passmcp::JsonValue::object();
    bad_both.set("sha256", passmcp::sha256_hex(desc));
    bad_both.set("sha512", "00" + h512.substr(2));
    sub0.set("digest", bad_both);
    expect_throws<std::invalid_argument>(
        [&] { (void)passmcp::Attestation::parse(root.dump()); }, "mismatched sha512 alongside valid sha256");
}

void expect_tamper(const std::string& fixture, const std::function<void(passmcp::JsonValue&)>& fn, const std::string& label) {
    auto root = passmcp::JsonValue::parse(fixture);
    fn(root);
    expect_throws<std::invalid_argument>([&] { (void)passmcp::Attestation::parse(root.dump()); }, label);
}

void test_attestation_tampering(const std::string& fixture) {
    expect_tamper(fixture, [](auto& r) { r.set("_type", "bad"); }, "wrong _type");
    expect_tamper(fixture, [](auto& r) { r.set("predicateType", "bad"); }, "wrong predicateType");
    expect_tamper(fixture, [](auto& r) { r.set("subject", passmcp::JsonValue::array()); }, "empty subject");
    expect_tamper(fixture, [](auto& r) {
        auto s = r.at("subject").as_array()[0];
        r.find_mut("subject")->push_back(s);
    }, "two subjects");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("subject")->as_array_mut()[0].set("name", "https://wrong.example.com/mcp");
    }, "subject name mismatch");
    expect_tamper(fixture, [](auto& r) {
        auto d = passmcp::JsonValue::object();
        d.set("md5", "1234");
        r.find_mut("subject")->as_array_mut()[0].set("digest", d);
    }, "unknown digest only");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("predicate")->set("subjectKind", "file");
    }, "wrong subjectKind");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("predicate")->find_mut("target")->set("transport", "ws");
    }, "invalid transport");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("predicate")->find_mut("instrument")->set("name", "");
    }, "empty instrument");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("predicate")->set("ranAt", "0001-01-01T00:00:00Z");
    }, "zero ranAt");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("predicate")->set("verdicts", passmcp::JsonValue::array());
    }, "empty verdicts");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("predicate")->find_mut("judgedAgainst")->set("checkInventory", "");
    }, "empty checkInventory");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("predicate")->find_mut("judgedAgainst")->set("rubric", "");
    }, "score without rubric");
    expect_tamper(fixture, [](auto& r) {
        r.find_mut("predicate")->find_mut("counts")->set("fail", 9);
    }, "mismatched counts");
}

void test_capabilities_and_sep2164() {
    passmcp::McpServer bare{"bare", "0.0.10"};
    auto client = passmcp::McpClient::for_server(bare);
    auto init = client.initialize();
    check(init.at("capabilities").as_object().empty(), "bare capabilities empty");
    client.ping();

    (void)expect_rpc_code([&] { (void)client.rpc("tools/list"); }, -32601, "undeclared tools/list");
    (void)expect_rpc_code([&] { (void)client.rpc("resources/list"); }, -32601, "undeclared resources/list");
    (void)expect_rpc_code([&] { (void)client.rpc("prompts/list"); }, -32601, "undeclared prompts/list");

    bare.register_resource("mcp://cfg/a", "a", "text/plain", [](const std::string&) { return std::string{"val"}; });
    check(client.read_resource("mcp://cfg/a") == "val", "read registered resource");
    auto err2026 = expect_rpc_code(
        [&] { (void)client.read_resource("mcp://cfg/missing"); }, -32602, "SEP-2164 -32602 on 2026-07-28");
    check(err2026.data().req_string("uri") == "mcp://cfg/missing", "SEP-2164 data.uri");

    passmcp::McpServer legacy{"leg", "0.0.10", std::string(passmcp::McpServer::kRev20251125)};
    legacy.register_resource_template("mcp://cfg/{id}", "tpl", "text/plain");
    auto leg_client = passmcp::McpClient::for_server(legacy);
    (void)leg_client.initialize();
    auto err_leg = expect_rpc_code(
        [&] { (void)leg_client.read_resource("mcp://cfg/missing"); }, -32002, "-32002 on 2025-11-25");
    check(err_leg.data().req_string("uri") == "mcp://cfg/missing", "legacy data.uri");
}

void test_sep2549_origin_and_policy() {
    expect_throws<std::invalid_argument>([] { (void)passmcp::CacheHints(-1, "public"); }, "negative ttlMs");
    expect_throws<std::invalid_argument>([] { (void)passmcp::CacheHints(0, "global"); }, "invalid cacheScope");
    expect_throws<std::invalid_argument>([] { (void)passmcp::OriginGuard({"*"}); }, "wildcard origin");

    int mutations = 0;
    passmcp::McpServer srv{"ops", "0.0.10"};
    srv.set_cache_hints(passmcp::CacheHints::public_scope(12000))
       .set_origin_guard(passmcp::OriginGuard({"https://ui.example.com/"}));
    srv.register_read_only_tool("health", "probe", [](const std::string&) { return std::string{"ok"}; });
    srv.register_tool(passmcp::ToolDescriptor::mutating("wipe", "wipe", true), [&](const std::string&) {
        ++mutations;
        return std::string{"wiped"};
    });
    srv.register_tool(passmcp::ToolDescriptor::unannotated("raw", "unannotated"), [&](const std::string&) {
        ++mutations;
        return std::string{"ran"};
    });
    srv.register_prompt("hello", "greet", [](const passmcp::JsonValue& args) {
        return "hi " + args.opt_string("who").value_or("world");
    });

    const std::string ping_req = R"({"jsonrpc":"2.0","id":1,"method":"ping"})";
    const std::string note_req = R"({"jsonrpc":"2.0","method":"notifications/initialized"})";
    check(srv.handle_http("", ping_req).status == 200, "empty Origin allowed");
    check(srv.handle_http("https://ui.example.com", ping_req).status == 200, "allowlisted Origin allowed");
    check(srv.handle_http("https://evil.invalid", ping_req).status == 403, "foreign Origin 403");
    check(srv.handle_http("null", ping_req).status == 403, "Origin: null 403");
    auto ack = srv.handle_http("", note_req);
    check(ack.status == 202 && ack.body.empty(), "notification returns 202 empty");

    auto safe = passmcp::McpClient::for_server(srv);
    auto disc = safe.discover();
    auto hints = passmcp::CacheHints::from_meta(disc.at("_meta"));
    check(hints.ttl_ms() == 12000 && hints.cache_scope() == "public", "SEP-2549 _meta validated");

    check(safe.call_tool("health") == "ok", "readOnly tool runs");
    expect_throws<std::runtime_error>([&] { (void)safe.call_tool("wipe"); }, "mutating refused by default");
    expect_throws<std::runtime_error>([&] { (void)safe.call_tool("raw"); }, "unannotated refused by default");
    check(mutations == 0, "refused tools never invoked");

    auto permissive = passmcp::McpClient::for_server(srv, passmcp::Policy::allowing_mutations());
    check(permissive.call_tool("wipe") == "wiped" && mutations == 1, "allowing_mutations permits wipe");
}

} // namespace

int main() {
    const std::string fixture = read_fixture();
    test_sha2_vectors();
    test_json_parser();
    test_attestation_fixture_and_sha512(fixture);
    test_attestation_tampering(fixture);
    test_capabilities_and_sep2164();
    test_sep2549_origin_and_policy();
    std::cout << "passmcp-sdk-cpp: all 6 test suites passed\n";
    return 0;
}
