// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include "catalog_internal.hpp"

#include <cctype>
#include <stdexcept>
#include <utility>

namespace passmcp {
namespace {

std::string normalize_origin(std::string_view raw) {
    std::string s = detail::trim_ascii(raw);
    if (!s.empty() && s.back() == '/') s.pop_back();
    return s;
}

bool iequals_null(std::string_view s) {
    return s.size() == 4 && (s[0] == 'n' || s[0] == 'N') && (s[1] == 'u' || s[1] == 'U') &&
           (s[2] == 'l' || s[2] == 'L') && (s[3] == 'l' || s[3] == 'L');
}

JsonValue default_input_schema() {
    JsonValue s = JsonValue::object();
    s.set("type", "object");
    s.set("properties", JsonValue::object());
    s.set("additionalProperties", false);
    return s;
}

bool matches_json_type(std::string_view type_name, const JsonValue& val) {
    if (type_name == "string") return val.is_string();
    if (type_name == "boolean") return val.is_bool();
    if (type_name == "integer") return val.is_int();
    if (type_name == "number") return val.is_number();
    if (type_name == "object") return val.is_object();
    if (type_name == "array") return val.is_array();
    return true;
}

std::optional<std::string> check_required_fields(const JsonValue* req_node, const JsonValue& args) {
    if (req_node == nullptr || !req_node->is_array()) return std::nullopt;
    for (const auto& item : req_node->as_array()) {
        if (!item.is_string()) continue;
        const std::string& key = item.as_string();
        const JsonValue* found = args.find(key);
        if (found == nullptr || found->is_null()) {
            return "Missing required argument '" + key + "'; provide a valid value";
        }
    }
    return std::nullopt;
}

std::optional<std::string> check_property_types(const JsonValue& props, const JsonValue& args) {
    for (const auto& [key, val] : args.as_object()) {
        if (val.is_null()) continue;
        const JsonValue* spec = props.find(key);
        if (spec == nullptr || !spec->is_object()) continue;
        if (auto expected = spec->opt_string("type"); expected.has_value()) {
            if (!matches_json_type(*expected, val)) {
                return "Argument '" + key + "' must be of type " + *expected;
            }
        }
    }
    return std::nullopt;
}

} // namespace

namespace detail {

std::string trim_ascii(std::string_view sv) {
    std::size_t a = 0;
    while (a < sv.size() && std::isspace(static_cast<unsigned char>(sv[a])) != 0) ++a;
    std::size_t b = sv.size();
    while (b > a && std::isspace(static_cast<unsigned char>(sv[b - 1])) != 0) --b;
    return std::string(sv.substr(a, b - a));
}

std::optional<std::string> validate_tool_args(const JsonValue& schema, const JsonValue& args) {
    if (!schema.is_object()) return std::nullopt;
    if (auto req_err = check_required_fields(schema.find("required"), args); req_err.has_value()) {
        return req_err;
    }
    const JsonValue* raw_props = schema.find("properties");
    const JsonValue empty_props = JsonValue::object();
    const JsonValue& props = (raw_props != nullptr && raw_props->is_object()) ? *raw_props : empty_props;
    const JsonValue* addl = schema.find("additionalProperties");
    if (addl != nullptr && addl->is_bool() && !addl->as_bool()) {
        for (const auto& [key, _] : args.as_object()) {
            if (!props.contains(key)) {
                return "Unknown argument '" + key + "'; call tools/list to inspect allowed properties";
            }
        }
    }
    return check_property_types(props, args);
}

std::optional<std::string> validate_prompt_args(
    const std::vector<PromptArgument>& declared, const JsonValue& args) {
    for (const auto& decl : declared) {
        const JsonValue* val = args.find(decl.name);
        if (decl.required && (val == nullptr || !val->is_string() || trim_ascii(val->as_string()).empty())) {
            return "Missing required prompt argument '" + decl.name + "'; provide a non-empty string";
        }
        if (val != nullptr && !val->is_null() && !val->is_string()) {
            return "Prompt argument '" + decl.name + "' must be of type string";
        }
    }
    return std::nullopt;
}

} // namespace detail

CacheHints::CacheHints(std::int64_t ttl_ms, std::string cache_scope)
    : ttl_ms_(ttl_ms), cache_scope_(std::move(cache_scope)) {
    if (ttl_ms_ < 0) throw std::invalid_argument("SEP-2549 ttlMs must be >= 0");
    if (cache_scope_ != "public" && cache_scope_ != "private") {
        throw std::invalid_argument("SEP-2549 cacheScope must be public or private");
    }
}

CacheHints CacheHints::public_scope(std::int64_t ttl_ms) { return CacheHints(ttl_ms, "public"); }
CacheHints CacheHints::private_scope(std::int64_t ttl_ms) { return CacheHints(ttl_ms, "private"); }

CacheHints CacheHints::of_seconds(bool cacheable, std::int64_t ttl_seconds, std::string cache_scope) {
    if (ttl_seconds < 0) throw std::invalid_argument("SEP-2549 ttl_seconds must be >= 0");
    return CacheHints(cacheable ? ttl_seconds * 1000 : 0, std::move(cache_scope));
}

CacheHints CacheHints::from_meta(const JsonValue& meta) {
    if (!meta.is_object()) throw std::invalid_argument("SEP-2549 metadata must be an object");
    return CacheHints(meta.req_int("ttlMs"), meta.req_string("cacheScope"));
}

CacheHints CacheHints::from_result(const JsonValue& result) {
    if (result.is_object() && result.contains("ttlMs")) return from_meta(result);
    if (const JsonValue* meta = result.find("_meta"); meta != nullptr && meta->is_object()) {
        return from_meta(*meta);
    }
    throw std::invalid_argument("Missing SEP-2549 ttlMs/cacheScope on list result");
}

JsonValue CacheHints::to_meta() const {
    JsonValue m = JsonValue::object();
    m.set("ttlMs", ttl_ms_);
    m.set("cacheScope", cache_scope_);
    return m;
}

void CacheHints::apply_to_list_result(JsonValue& out) const {
    out.set("ttlMs", ttl_ms_);
    out.set("cacheScope", cache_scope_);
    out.set("_meta", to_meta());
}

OriginGuard::OriginGuard(const std::vector<std::string>& allowed_origins) {
    for (const auto& raw : allowed_origins) {
        std::string clean = normalize_origin(raw);
        if (clean.empty() || clean == "*" || iequals_null(clean)) {
            throw std::invalid_argument("Invalid Origin allowlist entry");
        }
        allowed_.insert(std::move(clean));
    }
}

bool OriginGuard::is_allowed(std::string_view origin_header) const {
    if (origin_header.empty()) return true;
    std::string clean = normalize_origin(origin_header);
    if (clean.empty() || iequals_null(clean)) return false;
    return allowed_.find(clean) != allowed_.end();
}

int OriginGuard::status_for(std::string_view origin_header) const {
    return is_allowed(origin_header) ? 200 : 403;
}

ToolDescriptor ToolDescriptor::read_only(std::string name, std::string description) {
    if (detail::trim_ascii(name).empty()) throw std::invalid_argument("Tool name must not be empty");
    return ToolDescriptor{std::move(name), std::move(description), true, true, false, true, false};
}

ToolDescriptor ToolDescriptor::mutating(std::string name, std::string description, bool destructive) {
    if (detail::trim_ascii(name).empty()) throw std::invalid_argument("Tool name must not be empty");
    return ToolDescriptor{std::move(name), std::move(description), true, false, destructive, false, false};
}

ToolDescriptor ToolDescriptor::unannotated(std::string name, std::string description) {
    if (detail::trim_ascii(name).empty()) throw std::invalid_argument("Tool name must not be empty");
    return ToolDescriptor{std::move(name), std::move(description), false, false, true, false, false};
}

ToolDescriptor ToolDescriptor::from_wire(const JsonValue& obj) {
    auto opt_obj = [&obj](std::string_view key) -> std::optional<JsonValue> {
        const JsonValue* s = obj.find(key);
        return (s != nullptr && s->is_object()) ? std::optional<JsonValue>(*s) : std::nullopt;
    };
    auto hint = [](const JsonValue& ann, std::string_view key, bool fallback) -> bool {
        const JsonValue* v = ann.find(key);
        return (v != nullptr && v->is_bool()) ? v->as_bool() : fallback;
    };
    std::string name = obj.req_string("name");
    std::string desc = obj.opt_string("description").value_or("");
    std::string title = obj.opt_string("title").value_or("");
    auto in_s = opt_obj("inputSchema");
    auto out_s = opt_obj("outputSchema");
    const JsonValue* ann = obj.find("annotations");
    if (ann == nullptr || !ann->is_object()) {
        auto td = ToolDescriptor::unannotated(std::move(name), std::move(desc));
        td.title = std::move(title);
        td.input_schema = std::move(in_s);
        td.output_schema = std::move(out_s);
        return td;
    }
    return ToolDescriptor{
        std::move(name), std::move(desc), true,
        hint(*ann, "readOnlyHint", false),
        hint(*ann, "destructiveHint", true),
        hint(*ann, "idempotentHint", false),
        hint(*ann, "openWorldHint", false),
        std::move(title), std::move(in_s), std::move(out_s)};
}

JsonValue ToolDescriptor::effective_input_schema() const {
    return input_schema.has_value() ? *input_schema : default_input_schema();
}

JsonValue ToolDescriptor::to_wire() const {
    JsonValue out = JsonValue::object();
    out.set("name", name);
    if (!title.empty()) out.set("title", title);
    out.set("description", description);
    out.set("inputSchema", effective_input_schema());
    if (output_schema.has_value()) out.set("outputSchema", *output_schema);
    if (annotated) {
        JsonValue ann = JsonValue::object();
        if (!title.empty()) ann.set("title", title);
        ann.set("readOnlyHint", read_only_hint);
        ann.set("destructiveHint", destructive_hint);
        ann.set("idempotentHint", idempotent_hint);
        ann.set("openWorldHint", open_world_hint);
        out.set("annotations", std::move(ann));
    }
    return out;
}

} // namespace passmcp
