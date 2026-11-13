<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

All notable changes to passmcp-sdk-cpp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions are
[Semantic Versioning](https://semver.org/) shaped.

**This repository carries passmcp's version.** It is in lockstep with
[passmcp](https://github.com/sebastienrousseau/passmcp) ([ADR 0013](https://github.com/sebastienrousseau/passmcp/blob/main/docs/adr/0013-language-sdks-are-apache-satellites.md)):
it starts at `Status: Unreleased` on `feat/v0.0.10` and joins the family
release stream with its first signed tag.

## [Unreleased]

## [0.0.10] - 2026-11-13

### Added

- **Initial C++20 MCP client and server core (`passmcp::sdk`)** covering MCP
  revisions `2025-06-18`, `2025-11-25`, and `2026-07-28`: capability-gated
  JSON-RPC 2.0 dispatch (`initialize`, `ping`, stateless `server/discover` with
  `_meta["io.modelcontextprotocol/serverInfo"]`, `tools/list`, `tools/call`,
  `resources/list`, `resources/templates/list`, `resources/read`, `prompts/list`,
  `prompts/get`), JSON Schema argument validation (`-32602`), `structuredContent`
  tool output, SEP-2164 unknown-resource errors (`-32602` with `error.data.uri` on
  `2026-07-28`), SEP-2549 list cache hints (`ttlMs` and `cacheScope`), strict HTTP
  `Origin` validation, and read-only-by-default client tool execution policy
  (`readOnlyHint: true`).
- **Stdio and Streamable HTTP transports** (`serve_stdio`, `StdioTransport` over
  in-memory streams and POSIX child processes, `HttpServerProcessor` with HTTP/1.1
  wire parser/serializer, `2026-07-28` mirrored header `-32020` checks, `404`
  stateless unknown-method status, `Mcp-Session-Id` management, and `HttpTransport`)
  plus the runnable `stdio_server` reference server target.
- **OAuth 2.1 + PKCE + metadata discovery (`oauth.hpp`)** covering RFC 7636 `S256`
  PKCE verifier generation and verification, `WWW-Authenticate` Bearer challenge
  building/parsing, RFC 9728 Protected Resource Metadata URL derivation and strict
  `resource` binding validation, and RFC 8414 Authorization Server Metadata HTTPS
  + `S256` validation.
- **Offline `passmcp` attestation verifier** for `https://in-toto.io/Statement/v1`
  statements carrying `https://satellion.com/attestation/mcp-evaluation/v1`,
  recomputing SHA-256 and SHA-512 over the canonical target descriptor
  (`transport + "\n" + trim(endpoint)`) and verifying verdict counts, rubric
  presence, `covers(transport, endpoint)`, and `verdict_for(check_id)` against
  `passmcp-reporting`'s fixture.
