// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/json.hpp>

#include <charconv>
#include <cmath>
#include <cstdio>
#include <sstream>
#include <stdexcept>

namespace passmcp {

JsonValue::JsonValue() noexcept : data_(nullptr) {}
JsonValue::JsonValue(std::nullptr_t) noexcept : data_(nullptr) {}
JsonValue::JsonValue(bool v) noexcept : data_(v) {}
JsonValue::JsonValue(int v) noexcept : data_(static_cast<std::int64_t>(v)) {}
JsonValue::JsonValue(std::int64_t v) noexcept : data_(v) {}
JsonValue::JsonValue(double v) noexcept : data_(v) {}
JsonValue::JsonValue(const char* v) : data_(std::string(v == nullptr ? "" : v)) {}
JsonValue::JsonValue(std::string v) noexcept : data_(std::move(v)) {}
JsonValue::JsonValue(std::string_view v) : data_(std::string(v)) {}
JsonValue::JsonValue(Array v) noexcept : data_(std::move(v)) {}
JsonValue::JsonValue(Object v) noexcept : data_(std::move(v)) {}

JsonValue JsonValue::object() { return JsonValue(Object{}); }
JsonValue JsonValue::array() { return JsonValue(Array{}); }

bool JsonValue::is_null() const noexcept { return std::holds_alternative<std::nullptr_t>(data_); }
bool JsonValue::is_bool() const noexcept { return std::holds_alternative<bool>(data_); }
bool JsonValue::is_int() const noexcept { return std::holds_alternative<std::int64_t>(data_); }
bool JsonValue::is_number() const noexcept { return is_int() || std::holds_alternative<double>(data_); }
bool JsonValue::is_string() const noexcept { return std::holds_alternative<std::string>(data_); }
bool JsonValue::is_array() const noexcept { return std::holds_alternative<Array>(data_); }
bool JsonValue::is_object() const noexcept { return std::holds_alternative<Object>(data_); }

bool JsonValue::as_bool() const {
    if (!is_bool()) throw std::invalid_argument("Expected JSON boolean");
    return std::get<bool>(data_);
}

std::int64_t JsonValue::as_int() const {
    if (!is_int()) throw std::invalid_argument("Expected JSON integer");
    return std::get<std::int64_t>(data_);
}

double JsonValue::as_number() const {
    if (is_int()) return static_cast<double>(std::get<std::int64_t>(data_));
    if (std::holds_alternative<double>(data_)) return std::get<double>(data_);
    throw std::invalid_argument("Expected JSON number");
}

const std::string& JsonValue::as_string() const {
    if (!is_string()) throw std::invalid_argument("Expected JSON string");
    return std::get<std::string>(data_);
}

const JsonValue::Array& JsonValue::as_array() const {
    if (!is_array()) throw std::invalid_argument("Expected JSON array");
    return std::get<Array>(data_);
}

JsonValue::Array& JsonValue::as_array_mut() {
    if (!is_array()) throw std::invalid_argument("Expected JSON array");
    return std::get<Array>(data_);
}

const JsonValue::Object& JsonValue::as_object() const {
    if (!is_object()) throw std::invalid_argument("Expected JSON object");
    return std::get<Object>(data_);
}

JsonValue::Object& JsonValue::as_object_mut() {
    if (!is_object()) throw std::invalid_argument("Expected JSON object");
    return std::get<Object>(data_);
}

void JsonValue::set(std::string key, JsonValue val) {
    auto& obj = as_object_mut();
    for (auto& kv : obj) {
        if (kv.first == key) {
            kv.second = std::move(val);
            return;
        }
    }
    obj.emplace_back(std::move(key), std::move(val));
}

void JsonValue::erase(std::string_view key) {
    auto& obj = as_object_mut();
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if (it->first == key) {
            obj.erase(it);
            return;
        }
    }
}

void JsonValue::push_back(JsonValue val) { as_array_mut().push_back(std::move(val)); }

const JsonValue* JsonValue::find(std::string_view key) const {
    if (!is_object()) return nullptr;
    for (const auto& kv : std::get<Object>(data_)) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

JsonValue* JsonValue::find_mut(std::string_view key) {
    if (!is_object()) return nullptr;
    for (auto& kv : std::get<Object>(data_)) {
        if (kv.first == key) return &kv.second;
    }
    return nullptr;
}

bool JsonValue::contains(std::string_view key) const { return find(key) != nullptr; }

const JsonValue& JsonValue::at(std::string_view key) const {
    const JsonValue* ptr = find(key);
    if (ptr == nullptr) throw std::invalid_argument("Missing JSON key: " + std::string(key));
    return *ptr;
}

std::optional<std::string> JsonValue::opt_string(std::string_view key) const {
    const JsonValue* ptr = find(key);
    return (ptr == nullptr || ptr->is_null()) ? std::nullopt : std::optional<std::string>(ptr->as_string());
}

std::string JsonValue::req_string(std::string_view key) const {
    auto val = opt_string(key);
    if (!val.has_value()) throw std::invalid_argument("Missing string key: " + std::string(key));
    return *val;
}

std::int64_t JsonValue::opt_int(std::string_view key, std::int64_t fallback) const {
    const JsonValue* ptr = find(key);
    return (ptr == nullptr || ptr->is_null()) ? fallback : ptr->as_int();
}

std::int64_t JsonValue::req_int(std::string_view key) const {
    const JsonValue* ptr = find(key);
    if (ptr == nullptr || ptr->is_null()) throw std::invalid_argument("Missing integer key: " + std::string(key));
    return ptr->as_int();
}

namespace {

constexpr int kMaxDepth = 64;

void append_escaped_char(std::string& out, unsigned char c) {
    switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20U) {
                char buf[8];
                std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                out += buf;
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
    }
}

void write_string(std::string& out, std::string_view s) {
    out.push_back('"');
    for (char ch : s) append_escaped_char(out, static_cast<unsigned char>(ch));
    out.push_back('"');
}

void write_value(std::string& out, const JsonValue& v, int depth);

void write_array(std::string& out, const JsonValue::Array& arr, int depth) {
    out.push_back('[');
    for (std::size_t i = 0; i < arr.size(); ++i) {
        if (i > 0) out.push_back(',');
        write_value(out, arr[i], depth);
    }
    out.push_back(']');
}

void write_object(std::string& out, const JsonValue::Object& obj, int depth) {
    out.push_back('{');
    for (std::size_t i = 0; i < obj.size(); ++i) {
        if (i > 0) out.push_back(',');
        write_string(out, obj[i].first);
        out.push_back(':');
        write_value(out, obj[i].second, depth);
    }
    out.push_back('}');
}

void write_value(std::string& out, const JsonValue& v, int depth) {
    if (depth > kMaxDepth) throw std::invalid_argument("JSON serialization depth exceeded");
    if (v.is_null()) out += "null";
    else if (v.is_bool()) out += v.as_bool() ? "true" : "false";
    else if (v.is_int()) out += std::to_string(v.as_int());
    else if (v.is_number()) {
        double d = v.as_number();
        if (!std::isfinite(d)) throw std::invalid_argument("Non-finite float is invalid JSON");
        std::ostringstream oss;
        oss << d;
        out += oss.str();
    } else if (v.is_string()) write_string(out, v.as_string());
    else if (v.is_array()) write_array(out, v.as_array(), depth + 1);
    else write_object(out, v.as_object(), depth + 1);
}

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp <= 0x7fU) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7ffU) {
        out.push_back(static_cast<char>(0xc0U | (cp >> 6U)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else if (cp <= 0xffffU) {
        out.push_back(static_cast<char>(0xe0U | (cp >> 12U)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    } else {
        out.push_back(static_cast<char>(0xf0U | (cp >> 18U)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 12U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | ((cp >> 6U) & 0x3fU)));
        out.push_back(static_cast<char>(0x80U | (cp & 0x3fU)));
    }
}

class Parser {
public:
    explicit Parser(std::string_view src) : src_(src) {}

    JsonValue parse_root() {
        skip_ws();
        JsonValue v = read_value(0);
        skip_ws();
        if (!eof()) {
            throw fail("Unexpected trailing tokens");
        }
        return v;
    }

private:
    std::string_view src_;
    std::size_t pos_ = 0;

    bool eof() const noexcept { return pos_ >= src_.size(); }

    char peek() const {
        if (eof()) {
            throw fail("Unexpected end of JSON input");
        }
        return src_[pos_];
    }

    std::invalid_argument fail(const char* msg) const {
        return std::invalid_argument(std::string(msg) + " at offset " + std::to_string(pos_));
    }

    void skip_ws() noexcept {
        while (!eof()) {
            char c = src_[pos_];
            if (c != ' ' && c != '\t' && c != '\n' && c != '\r') {
                break;
            }
            ++pos_;
        }
    }

    void expect(char expected) {
        if (peek() != expected) {
            throw fail("Unexpected token");
        }
        ++pos_;
    }

    static bool is_digit(char c) noexcept { return c >= '0' && c <= '9'; }

    JsonValue read_value(int depth) {
        if (depth > kMaxDepth) {
            throw fail("Maximum JSON nesting depth exceeded");
        }
        skip_ws();
        switch (peek()) {
            case '{': return read_object(depth + 1);
            case '[': return read_array(depth + 1);
            case '"': return JsonValue(read_string());
            case 't': return read_literal("true", JsonValue(true));
            case 'f': return read_literal("false", JsonValue(false));
            case 'n': return read_literal("null", JsonValue(nullptr));
            default: return read_number();
        }
    }

    JsonValue read_object(int depth) {
        ++pos_;
        skip_ws();
        JsonValue obj = JsonValue::object();
        if (peek() == '}') {
            ++pos_;
            return obj;
        }
        while (true) {
            skip_ws();
            if (peek() != '"') {
                throw fail("Expected object key string");
            }
            std::string key = read_string();
            skip_ws();
            expect(':');
            obj.set(std::move(key), read_value(depth));
            skip_ws();
            char sep = peek();
            ++pos_;
            if (sep == '}') {
                return obj;
            }
            if (sep != ',') {
                throw fail("Expected ',' or '}' in object");
            }
        }
    }

    JsonValue read_array(int depth) {
        ++pos_;
        skip_ws();
        JsonValue arr = JsonValue::array();
        if (peek() == ']') {
            ++pos_;
            return arr;
        }
        while (true) {
            arr.push_back(read_value(depth));
            skip_ws();
            char sep = peek();
            ++pos_;
            if (sep == ']') {
                return arr;
            }
            if (sep != ',') {
                throw fail("Expected ',' or ']' in array");
            }
        }
    }

    std::string read_string() {
        expect('"');
        std::string out;
        while (true) {
            char c = peek();
            ++pos_;
            if (c == '"') {
                return out;
            }
            if (static_cast<unsigned char>(c) < 0x20U) {
                throw fail("Unescaped control character in string");
            }
            if (c == '\\') {
                read_escape(out);
            } else {
                out.push_back(c);
            }
        }
    }

    void read_escape(std::string& out) {
        char esc = peek();
        ++pos_;
        switch (esc) {
            case '"': case '\\': case '/': out.push_back(esc); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            case 'u': read_unicode_escape(out); break;
            default: throw fail("Invalid string escape");
        }
    }

    std::uint32_t read_hex4() {
        if (pos_ + 4 > src_.size()) {
            throw fail("Truncated \\u escape");
        }
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) {
            char c = src_[pos_++];
            std::uint32_t d = 0;
            if (c >= '0' && c <= '9') d = static_cast<std::uint32_t>(c - '0');
            else if (c >= 'a' && c <= 'f') d = static_cast<std::uint32_t>(c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') d = static_cast<std::uint32_t>(c - 'A' + 10);
            else throw fail("Invalid hex digit in \\u escape");
            v = (v << 4U) | d;
        }
        return v;
    }

    void read_unicode_escape(std::string& out) {
        std::uint32_t cp = read_hex4();
        if (cp >= 0xd800U && cp <= 0xdbffU) {
            if (pos_ + 2 > src_.size() || src_[pos_] != '\\' || src_[pos_ + 1] != 'u') {
                throw fail("Unpaired high surrogate");
            }
            pos_ += 2;
            std::uint32_t low = read_hex4();
            if (low < 0xdc00U || low > 0xdfffU) {
                throw fail("Invalid low surrogate");
            }
            cp = 0x10000U + (((cp - 0xd800U) << 10U) | (low - 0xdc00U));
        } else if (cp >= 0xdc00U && cp <= 0xdfffU) {
            throw fail("Unpaired low surrogate");
        }
        append_utf8(out, cp);
    }

    JsonValue read_literal(std::string_view lit, JsonValue val) {
        if (src_.substr(pos_, lit.size()) != lit) throw fail("Invalid literal");
        pos_ += lit.size();
        return val;
    }

    JsonValue read_number() {
        const std::size_t start = pos_;
        if (peek() == '-') ++pos_;
        scan_int_digits();
        const bool floating = scan_frac_and_exp();
        std::string_view tok = src_.substr(start, pos_ - start);
        if (!floating) {
            std::int64_t iv = 0;
            auto [ptr, ec] = std::from_chars(tok.data(), tok.data() + tok.size(), iv);
            if (ec == std::errc{} && ptr == tok.data() + tok.size()) return JsonValue(iv);
        }
        double dv = std::stod(std::string(tok));
        if (!std::isfinite(dv)) throw fail("Numeric overflow");
        return JsonValue(dv);
    }

    void scan_int_digits() {
        char first = peek();
        if (first == '0') {
            ++pos_;
            if (!eof() && is_digit(src_[pos_])) throw fail("Leading zero is invalid");
            return;
        }
        if (!is_digit(first)) throw fail("Expected digit");
        while (!eof() && is_digit(src_[pos_])) ++pos_;
    }

    bool scan_frac_and_exp() {
        bool floating = false;
        if (!eof() && src_[pos_] == '.') {
            floating = true;
            ++pos_;
            require_digits();
        }
        if (!eof() && (src_[pos_] == 'e' || src_[pos_] == 'E')) {
            floating = true;
            ++pos_;
            if (!eof() && (src_[pos_] == '+' || src_[pos_] == '-')) ++pos_;
            require_digits();
        }
        return floating;
    }

    void require_digits() {
        if (eof() || !is_digit(src_[pos_])) throw fail("Expected fractional or exponent digit");
        while (!eof() && is_digit(src_[pos_])) ++pos_;
    }
};

} // namespace

JsonValue JsonValue::parse(std::string_view input) {
    return Parser(input).parse_root();
}

std::string JsonValue::dump() const {
    std::string out;
    write_value(out, *this, 0);
    return out;
}

} // namespace passmcp
