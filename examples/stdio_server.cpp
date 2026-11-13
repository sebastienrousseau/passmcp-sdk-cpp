// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/json.hpp>
#include <passmcp/server.hpp>
#include <passmcp/stdio.hpp>

#include <string>

namespace {

passmcp::ToolDescriptor make_inspect_tool() {
    passmcp::JsonValue endpoint_prop = passmcp::JsonValue::object();
    endpoint_prop.set("type", "string");
    endpoint_prop.set("description", "HTTPS or stdio target endpoint identifier to inspect");
    passmcp::JsonValue in_props = passmcp::JsonValue::object();
    in_props.set("endpoint", std::move(endpoint_prop));
    passmcp::JsonValue in_req = passmcp::JsonValue::array();
    in_req.push_back("endpoint");
    passmcp::JsonValue in_schema = passmcp::JsonValue::object();
    in_schema.set("type", "object");
    in_schema.set("additionalProperties", false);
    in_schema.set("required", std::move(in_req));
    in_schema.set("properties", std::move(in_props));

    passmcp::JsonValue str_type = passmcp::JsonValue::object();
    str_type.set("type", "string");
    passmcp::JsonValue out_props = passmcp::JsonValue::object();
    out_props.set("endpoint", str_type);
    out_props.set("transport", str_type);
    passmcp::JsonValue out_req = passmcp::JsonValue::array();
    out_req.push_back("endpoint");
    out_req.push_back("transport");
    passmcp::JsonValue out_schema = passmcp::JsonValue::object();
    out_schema.set("type", "object");
    out_schema.set("required", std::move(out_req));
    out_schema.set("properties", std::move(out_props));

    auto tool = passmcp::ToolDescriptor::read_only(
        "inspect_target",
        "Inspect an MCP server endpoint and classify its transport binding without mutating state.");
    tool.title = "Inspect MCP Target";
    tool.input_schema = std::move(in_schema);
    tool.output_schema = std::move(out_schema);
    return tool;
}

passmcp::McpServer build_reference_server() {
    passmcp::McpServer srv{"passmcp-sdk-cpp-demo", "0.0.9"};
    srv.set_instructions(
           "Reference MCP server built with passmcp-sdk demonstrating read-only tools, "
           "SEP-2164 resources, prompts, and SEP-2549 cache hints.")
       .set_cache_hints(passmcp::CacheHints::of_seconds(true, 300, "public"));

    srv.register_structured_tool(make_inspect_tool(), [](const passmcp::JsonValue& args) {
        std::string ep = args.req_string("endpoint");
        bool is_http = ep.rfind("http://", 0) == 0 || ep.rfind("https://", 0) == 0;
        std::string transport = is_http ? "http" : "stdio";
        passmcp::JsonValue structured = passmcp::JsonValue::object();
        structured.set("endpoint", ep);
        structured.set("transport", transport);
        std::string text = structured.dump();
        return passmcp::ToolResult{std::move(text), std::move(structured)};
    });

    srv.register_resource(
        "passmcp://sdk/overview",
        "sdk-overview",
        "SDK Overview",
        "Overview of the passmcp SDK capabilities and supported MCP revisions.",
        "text/plain",
        [](const std::string&) {
            return std::string{"passmcp-sdk-cpp supports MCP 2026-07-28, 2025-11-25, and 2025-06-18."};
        });

    srv.register_prompt(
        "audit_summary",
        "Audit Summary Prompt",
        "Generate a concise audit summary prompt for a named MCP server.",
        {passmcp::PromptArgument{"server_name", "Name of the MCP server being audited", true}},
        [](const passmcp::JsonValue& args) {
            return "Summarize passmcp evaluation findings and remediation steps for " +
                   args.req_string("server_name") + ".";
        });

    return srv;
}

} // namespace

int main() {
    const auto srv = build_reference_server();
    passmcp::serve_stdio(srv);
    return 0;
}
