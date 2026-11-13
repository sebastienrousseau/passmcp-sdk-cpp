// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/oauth.hpp>

#include "catalog_internal.hpp"
#include <passmcp/json.hpp>
#include <passmcp/sha2.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <map>
#include <random>
#include <stdexcept>

namespace passmcp {
namespace {

constexpr std::string_view kB64Url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string base64url_nopad(const std::uint8_t* data, std::size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    std::size_t i = 0;
    while (i + 3 <= len) {
        std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16U) |
                          (static_cast<std::uint32_t>(data[i + 1]) << 8U) |
                          static_cast<std::uint32_t>(data[i + 2]);
        out.push_back(kB64Url[(v >> 18U) & 0x3fU]);
        out.push_back(kB64Url[(v >> 12U) & 0x3fU]);
        out.push_back(kB64Url[(v >> 6U) & 0x3fU]);
        out.push_back(kB64Url[v & 0x3fU]);
        i += 3;
    }
    if (len - i == 1) {
        std::uint32_t v = static_cast<std::uint32_t>(data[i]) << 16U;
        out.push_back(kB64Url[(v >> 18U) & 0x3fU]);
        out.push_back(kB64Url[(v >> 12U) & 0x3fU]);
    } else if (len - i == 2) {
        std::uint32_t v = (static_cast<std::uint32_t>(data[i]) << 16U) |
                          (static_cast<std::uint32_t>(data[i + 1]) << 8U);
        out.push_back(kB64Url[(v >> 18U) & 0x3fU]);
        out.push_back(kB64Url[(v >> 12U) & 0x3fU]);
        out.push_back(kB64Url[(v >> 6U) & 0x3fU]);
    }
    return out;
}

void fill_random_bytes(std::vector<std::uint8_t>& buf) {
    std::ifstream urandom("/dev/urandom", std::ios::in | std::ios::binary);
    if (urandom.good()) {
        urandom.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        if (static_cast<std::size_t>(urandom.gcount()) == buf.size()) return;
    }
    std::random_device rd;
    for (auto& b : buf) b = static_cast<std::uint8_t>(rd() & 0xffU);
}

constexpr std::string_view kPkceUnreserved =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";

void validate_verifier_syntax(std::string_view v) {
    if (v.size() < 43 || v.size() > 128) {
        throw std::invalid_argument("PKCE verifier must be 43..128 characters");
    }
    for (char c : v) {
        if (kPkceUnreserved.find(c) == std::string_view::npos) {
            throw std::invalid_argument("Invalid character in PKCE verifier");
        }
    }
}

std::string to_lower_ascii(std::string_view sv) {
    std::string out(sv);
    for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

struct ParsedHttpsUrl {
    std::string origin;
    std::string path;
    bool has_query_or_frag = false;
};

ParsedHttpsUrl parse_https_url(std::string_view raw, std::string_view label) {
    std::string s = detail::trim_ascii(raw);
    if (s.size() < 9 || to_lower_ascii(s.substr(0, 8)) != "https://") {
        throw std::invalid_argument(std::string(label) + " must use https://");
    }
    std::string rest = s.substr(8);
    bool has_qf = rest.find('?') != std::string::npos || rest.find('#') != std::string::npos;
    auto qpos = rest.find_first_of("?#");
    if (qpos != std::string::npos) rest.erase(qpos);
    auto slash = rest.find('/');
    std::string authority = slash == std::string::npos ? rest : rest.substr(0, slash);
    std::string path = slash == std::string::npos ? "" : rest.substr(slash);
    if (authority.empty()) throw std::invalid_argument(std::string(label) + " missing host");
    std::string lower_auth = to_lower_ascii(authority);
    if (lower_auth.size() > 4 && lower_auth.substr(lower_auth.size() - 4) == ":443") {
        lower_auth.erase(lower_auth.size() - 4);
    }
    return ParsedHttpsUrl{"https://" + lower_auth, path, has_qf};
}

std::string normalize_https_resource(std::string_view raw, std::string_view label) {
    auto u = parse_https_url(raw, label);
    while (u.path.size() > 1 && u.path.back() == '/') u.path.pop_back();
    if (u.path == "/") u.path.clear();
    return u.origin + u.path;
}

std::vector<std::string> read_str_array(const JsonValue& doc, std::string_view field, bool non_empty) {
    const JsonValue* node = doc.find(field);
    if (node == nullptr || !node->is_array()) {
        throw std::invalid_argument("Expected JSON array for " + std::string(field));
    }
    const auto& arr = node->as_array();
    if (non_empty && arr.empty()) throw std::invalid_argument(std::string(field) + " must not be empty");
    std::vector<std::string> out;
    out.reserve(arr.size());
    for (const auto& item : arr) {
        if (!item.is_string() || detail::trim_ascii(item.as_string()).empty()) {
            throw std::invalid_argument(std::string(field) + " must contain non-empty strings");
        }
        out.push_back(item.as_string());
    }
    return out;
}

void append_auth_param(std::vector<std::string>& parts, std::string_view key, std::string_view val) {
    if (val.empty()) return;
    std::string escaped;
    for (char c : val) {
        if (c == '\\' || c == '"') escaped.push_back('\\');
        escaped.push_back(c);
    }
    parts.push_back(std::string(key) + "=\"" + escaped + "\"");
}

std::size_t read_quoted_attr(std::string_view src, std::size_t pos, std::string& val_out) {
    std::size_t i = pos;
    while (i < src.size()) {
        char c = src[i++];
        if (c == '\\' && i < src.size()) {
            val_out.push_back(src[i++]);
        } else if (c == '"') {
            return i;
        } else {
            val_out.push_back(c);
        }
    }
    throw std::invalid_argument("Unterminated quoted string in WWW-Authenticate");
}

std::size_t skip_auth_delims(std::string_view src, std::size_t pos) {
    while (pos < src.size() && (std::isspace(static_cast<unsigned char>(src[pos])) != 0 || src[pos] == ',')) {
        ++pos;
    }
    return pos;
}

std::size_t read_auth_value(std::string_view rest, std::size_t pos, std::string& val) {
    while (pos < rest.size() && std::isspace(static_cast<unsigned char>(rest[pos])) != 0) ++pos;
    if (pos < rest.size() && rest[pos] == '"') return read_quoted_attr(rest, pos + 1, val);
    std::size_t end = pos;
    while (end < rest.size() && rest[end] != ',' && std::isspace(static_cast<unsigned char>(rest[end])) == 0) ++end;
    val = std::string(rest.substr(pos, end - pos));
    return end;
}

} // namespace

std::string generate_pkce_verifier(std::size_t length) {
    if (length < 43 || length > 128) {
        throw std::invalid_argument("PKCE verifier length must be in [43, 128]");
    }
    std::vector<std::uint8_t> rnd(length);
    fill_random_bytes(rnd);
    std::string out;
    out.reserve(length);
    for (std::uint8_t b : rnd) out.push_back(kB64Url[b & 0x3fU]);
    return out;
}

std::string compute_s256_challenge(std::string_view verifier) {
    validate_verifier_syntax(verifier);
    auto digest = sha256_bytes(verifier);
    return base64url_nopad(digest.data(), digest.size());
}

bool verify_s256(std::string_view verifier, std::string_view challenge) {
    if (challenge.empty()) return false;
    std::string expected = compute_s256_challenge(verifier);
    if (expected.size() != challenge.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < expected.size(); ++i) {
        diff |= static_cast<unsigned char>(expected[i] ^ challenge[i]);
    }
    return diff == 0;
}

std::string build_bearer_challenge(
    std::string_view resource_metadata,
    std::string_view scope,
    std::string_view error,
    std::string_view error_description) {
    std::vector<std::string> parts;
    append_auth_param(parts, "resource_metadata", resource_metadata);
    append_auth_param(parts, "scope", scope);
    append_auth_param(parts, "error", error);
    append_auth_param(parts, "error_description", error_description);
    if (parts.empty()) return "Bearer";
    std::string out = "Bearer ";
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) out += ", ";
        out += parts[i];
    }
    return out;
}

BearerChallenge parse_bearer_challenge(std::string_view header_value) {
    std::string s = detail::trim_ascii(header_value);
    if (s.size() < 6 || to_lower_ascii(s.substr(0, 6)) != "bearer") {
        throw std::invalid_argument("Expected Bearer scheme in WWW-Authenticate");
    }
    std::string rest = detail::trim_ascii(s.substr(6));
    std::map<std::string, std::string> attrs;
    std::size_t i = skip_auth_delims(rest, 0);
    while (i < rest.size()) {
        auto eq = rest.find('=', i);
        if (eq == std::string::npos || eq == i) throw std::invalid_argument("Malformed WWW-Authenticate parameter");
        std::string key = to_lower_ascii(detail::trim_ascii(rest.substr(i, eq - i)));
        std::string val;
        i = read_auth_value(rest, eq + 1, val);
        attrs[std::move(key)] = std::move(val);
        i = skip_auth_delims(rest, i);
    }
    return BearerChallenge{
        attrs["resource_metadata"], attrs["scope"], attrs["error"], attrs["error_description"]};
}

std::vector<std::string> protected_resource_well_known_urls(std::string_view resource_url) {
    auto u = parse_https_url(resource_url, "resource_url");
    std::string root = u.origin + "/.well-known/oauth-protected-resource";
    while (u.path.size() > 1 && u.path.back() == '/') u.path.pop_back();
    if (u.path.empty() || u.path == "/") return {root};
    return {root + u.path, root};
}

ProtectedResourceMetadata validate_protected_resource_metadata(
    std::string_view raw_json, std::string_view expected_resource) {
    std::string norm_expected = normalize_https_resource(expected_resource, "expected_resource");
    JsonValue doc = JsonValue::parse(raw_json);
    std::string resource = doc.req_string("resource");
    if (normalize_https_resource(resource, "metadata.resource") != norm_expected) {
        throw std::invalid_argument("RFC 9728 resource mismatch against expected endpoint");
    }
    auto servers = read_str_array(doc, "authorization_servers", true);
    for (const auto& srv : servers) (void)parse_https_url(srv, "authorization_servers");
    std::vector<std::string> scopes;
    if (doc.contains("scopes_supported")) scopes = read_str_array(doc, "scopes_supported", false);
    return ProtectedResourceMetadata{std::move(resource), std::move(servers), std::move(scopes)};
}

std::string authorization_server_well_known_url(std::string_view issuer_url) {
    auto u = parse_https_url(issuer_url, "issuer_url");
    if (u.has_query_or_frag) throw std::invalid_argument("OAuth issuer must not carry query or fragment");
    while (u.path.size() > 1 && u.path.back() == '/') u.path.pop_back();
    std::string base = u.origin + "/.well-known/oauth-authorization-server";
    return (u.path.empty() || u.path == "/") ? base : (base + u.path);
}

AuthorizationServerMetadata validate_authorization_server_metadata(
    std::string_view raw_json, std::string_view expected_issuer) {
    JsonValue doc = JsonValue::parse(raw_json);
    std::string issuer = doc.req_string("issuer");
    (void)parse_https_url(issuer, "issuer");
    if (!expected_issuer.empty() && issuer != expected_issuer) {
        throw std::invalid_argument("RFC 8414 issuer mismatch");
    }
    std::string auth_ep = doc.req_string("authorization_endpoint");
    (void)parse_https_url(auth_ep, "authorization_endpoint");
    std::string token_ep = doc.req_string("token_endpoint");
    (void)parse_https_url(token_ep, "token_endpoint");
    std::string reg_ep = doc.opt_string("registration_endpoint").value_or("");
    if (!reg_ep.empty()) (void)parse_https_url(reg_ep, "registration_endpoint");
    auto methods = read_str_array(doc, "code_challenge_methods_supported", true);
    if (std::find(methods.begin(), methods.end(), "S256") == methods.end()) {
        throw std::invalid_argument("OAuth 2.1 requires S256 in code_challenge_methods_supported");
    }
    return AuthorizationServerMetadata{
        std::move(issuer), std::move(auth_ep), std::move(token_ep), std::move(reg_ep), std::move(methods)};
}

} // namespace passmcp
