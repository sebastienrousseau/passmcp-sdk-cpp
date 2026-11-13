// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_JSON_HPP
#define PASSMCP_JSON_HPP

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace passmcp {

/**
 * Compact RFC 8259 JSON value, parser, and serializer with insertion-ordered objects.
 */
class JsonValue {
public:
    using Array = std::vector<JsonValue>;
    using Object = std::vector<std::pair<std::string, JsonValue>>;

    JsonValue() noexcept;
    JsonValue(std::nullptr_t) noexcept;
    JsonValue(bool v) noexcept;
    JsonValue(int v) noexcept;
    JsonValue(std::int64_t v) noexcept;
    JsonValue(double v) noexcept;
    JsonValue(const char* v);
    JsonValue(std::string v) noexcept;
    JsonValue(std::string_view v);
    JsonValue(Array v) noexcept;
    JsonValue(Object v) noexcept;

    [[nodiscard]] static JsonValue object();
    [[nodiscard]] static JsonValue array();
    [[nodiscard]] static JsonValue parse(std::string_view input);

    [[nodiscard]] std::string dump() const;

    [[nodiscard]] bool is_null() const noexcept;
    [[nodiscard]] bool is_bool() const noexcept;
    [[nodiscard]] bool is_int() const noexcept;
    [[nodiscard]] bool is_number() const noexcept;
    [[nodiscard]] bool is_string() const noexcept;
    [[nodiscard]] bool is_array() const noexcept;
    [[nodiscard]] bool is_object() const noexcept;

    [[nodiscard]] bool as_bool() const;
    [[nodiscard]] std::int64_t as_int() const;
    [[nodiscard]] double as_number() const;
    [[nodiscard]] const std::string& as_string() const;
    [[nodiscard]] const Array& as_array() const;
    [[nodiscard]] Array& as_array_mut();
    [[nodiscard]] const Object& as_object() const;
    [[nodiscard]] Object& as_object_mut();

    void set(std::string key, JsonValue val);
    void erase(std::string_view key);
    void push_back(JsonValue val);

    [[nodiscard]] bool contains(std::string_view key) const;
    [[nodiscard]] const JsonValue* find(std::string_view key) const;
    [[nodiscard]] JsonValue* find_mut(std::string_view key);
    [[nodiscard]] const JsonValue& at(std::string_view key) const;

    [[nodiscard]] std::optional<std::string> opt_string(std::string_view key) const;
    [[nodiscard]] std::string req_string(std::string_view key) const;
    [[nodiscard]] std::int64_t opt_int(std::string_view key, std::int64_t fallback) const;
    [[nodiscard]] std::int64_t req_int(std::string_view key) const;

private:
    using Storage = std::variant<std::nullptr_t, bool, std::int64_t, double, std::string, Array, Object>;
    Storage data_;
};

} // namespace passmcp

#endif // PASSMCP_JSON_HPP
