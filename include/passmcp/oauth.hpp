// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_OAUTH_HPP
#define PASSMCP_OAUTH_HPP

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace passmcp {

/** Parsed `WWW-Authenticate: Bearer ...` challenge parameters. */
struct BearerChallenge {
    std::string resource_metadata;
    std::string scope;
    std::string error;
    std::string error_description;
};

/** Validated RFC 9728 OAuth Protected Resource Metadata document. */
struct ProtectedResourceMetadata {
    std::string resource;
    std::vector<std::string> authorization_servers;
    std::vector<std::string> scopes_supported;
};

/** Validated RFC 8414 OAuth 2.1 Authorization Server Metadata document. */
struct AuthorizationServerMetadata {
    std::string issuer;
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string registration_endpoint;
    std::vector<std::string> code_challenge_methods_supported;
};

/** Generates a URL-safe RFC 7636 PKCE verifier of `length` characters (`43..128`). */
[[nodiscard]] std::string generate_pkce_verifier(std::size_t length = 64);

/** Computes `BASE64URL-NOPAD(SHA256(verifier))` per RFC 7636 section 4.2. */
[[nodiscard]] std::string compute_s256_challenge(std::string_view verifier);

/** Constant-time verification of `verifier` against an `S256` `challenge`. */
[[nodiscard]] bool verify_s256(std::string_view verifier, std::string_view challenge);

/** Builds an RFC 9728 / RFC 6750 `WWW-Authenticate: Bearer ...` header value. */
[[nodiscard]] std::string build_bearer_challenge(
    std::string_view resource_metadata,
    std::string_view scope = "",
    std::string_view error = "",
    std::string_view error_description = "");

/** Parses a `WWW-Authenticate: Bearer ...` header into structured attributes. */
[[nodiscard]] BearerChallenge parse_bearer_challenge(std::string_view header_value);

/** Derives RFC 9728 section 3.1 Protected Resource Metadata well-known candidate URLs. */
[[nodiscard]] std::vector<std::string> protected_resource_well_known_urls(std::string_view resource_url);

/** Validates an RFC 9728 Protected Resource Metadata document with strict `resource` binding. */
[[nodiscard]] ProtectedResourceMetadata validate_protected_resource_metadata(
    std::string_view raw_json, std::string_view expected_resource);

/** Derives the RFC 8414 section 3 Authorization Server Metadata well-known URL for an HTTPS issuer. */
[[nodiscard]] std::string authorization_server_well_known_url(std::string_view issuer_url);

/** Validates an RFC 8414 Authorization Server Metadata document for OAuth 2.1 + PKCE `S256`. */
[[nodiscard]] AuthorizationServerMetadata validate_authorization_server_metadata(
    std::string_view raw_json, std::string_view expected_issuer = "");

} // namespace passmcp

#endif // PASSMCP_OAUTH_HPP
