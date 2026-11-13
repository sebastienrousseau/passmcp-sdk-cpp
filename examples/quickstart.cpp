// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/attestation.hpp>
#include <passmcp/client.hpp>
#include <passmcp/server.hpp>

#include <filesystem>
#include <iostream>
#include <string>

int main() {
    passmcp::McpServer srv{"billing", "0.0.10"};
    srv.set_cache_hints(passmcp::CacheHints::public_scope(30000));
    srv.register_read_only_tool("health", "Read-only health probe",
        [](const std::string&) { return std::string{"ok"}; });

    std::string fixture_path = "testdata/statement.json";
#ifdef PASSMCP_DEFAULT_STATEMENT_PATH
    if (!std::filesystem::exists(fixture_path)) {
        fixture_path = PASSMCP_DEFAULT_STATEMENT_PATH;
    }
#endif

    auto st = passmcp::Attestation::parse_file(fixture_path);
    if (!st.covers("http", "https://mcp.example.com/mcp")) {
        return 1;
    }

    auto client = passmcp::McpClient::for_server(srv);
    client.require_attestation(st, "http", "https://mcp.example.com/mcp");
    auto discovered = client.discover();
    auto health = client.call_tool("health");

    std::cout << "quickstart ok: protocol=" << discovered.req_string("protocolVersion")
              << " health=" << health
              << " grade=" << st.score_grade().value_or("none") << "\n";
    return health == "ok" ? 0 : 1;
}
