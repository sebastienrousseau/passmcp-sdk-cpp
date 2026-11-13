// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_STDIO_HPP
#define PASSMCP_STDIO_HPP

#include <passmcp/server.hpp>

#include <iosfwd>
#include <memory>
#include <string>
#include <vector>

namespace passmcp {

/**
 * Serves `server` over newline-delimited UTF-8 JSON-RPC 2.0 streams until `in` reaches EOF.
 *
 * Notifications (frames without `id`) emit no output line; malformed frames return a single-line
 * `-32700` JSON-RPC error response without terminating the loop; flushes `out` after every frame.
 */
void serve_stdio(const McpServer& server, std::istream& in, std::ostream& out);

/** Serves `server` over `std::cin` and `std::cout` until EOF without writing banners to stdout. */
void serve_stdio(const McpServer& server);

/**
 * Client-side MCP `stdio` transport supporting in-memory server framing, stream pairs,
 * and spawned POSIX child processes (`pipe` + `fork` + `execvp`).
 */
class StdioTransport {
public:
    struct Impl;

    /** Creates an in-memory stdio transport framing every call through `serve_stdio`. */
    [[nodiscard]] static StdioTransport in_memory(const McpServer& server);

    /** Wraps an existing stream pair (`server_stdout` to read replies, `server_stdin` to write requests). */
    [[nodiscard]] static StdioTransport from_streams(std::istream& server_stdout, std::ostream& server_stdin);

    /** Spawns a child MCP server process and connects to its `stdin`/`stdout` pipes. */
    [[nodiscard]] static StdioTransport spawn(const std::vector<std::string>& command);

    /** Sends a single-line JSON-RPC request or notification and returns the response frame (or `""`). */
    [[nodiscard]] std::string operator()(const std::string& raw_json) const;

    /** Closes underlying pipes and reaps any spawned child process. */
    void close() const;

private:
    explicit StdioTransport(std::shared_ptr<Impl> impl) noexcept;

    std::shared_ptr<Impl> impl_;
};

} // namespace passmcp

#endif // PASSMCP_STDIO_HPP
