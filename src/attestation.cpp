// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#include <passmcp/attestation.hpp>
#include <passmcp/json.hpp>
#include <passmcp/sha2.hpp>

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace passmcp {
namespace {

std::string trim_ascii(std::string_view sv) {
    const auto is_ws = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
    };
    std::size_t first = 0;
    while (first < sv.size() && is_ws(static_cast<unsigned char>(sv[first]))) {
        ++first;
    }
    std::size_t last = sv.size();
    while (last > first && is_ws(static_cast<unsigned char>(sv[last - 1]))) {
        --last;
    }
    return std::string(sv.substr(first, last - first));
}

std::string str_or_empty(const JsonValue& obj, std::string_view key) {
    auto v = obj.opt_string(key);
    return v.has_value() ? *v : std::string{};
}

bool parse_fixed_digits(std::string_view s, std::size_t off, std::size_t len, int& out) {
    if (off + len > s.size()) {
        return false;
    }
    int acc = 0;
    for (std::size_t i = 0; i < len; ++i) {
        char c = s[off + i];
        if (c < '0' || c > '9') {
            return false;
        }
        acc = (acc * 10) + (c - '0');
    }
    out = acc;
    return true;
}

bool is_valid_tz_suffix(std::string_view tail) {
    if (tail == "Z" || tail == "z") {
        return true;
    }
    if (tail.size() != 6 || (tail[0] != '+' && tail[0] != '-') || tail[3] != ':') {
        return false;
    }
    int hh = 0;
    int mm = 0;
    return parse_fixed_digits(tail, 1, 2, hh) && parse_fixed_digits(tail, 4, 2, mm) && hh <= 23 && mm <= 59;
}

bool has_rfc3339_delims(std::string_view ts) {
    if (ts[4] != '-' || ts[7] != '-' || ts[13] != ':' || ts[16] != ':') return false;
    return ts[10] == 'T' || ts[10] == 't';
}

bool parse_rfc3339_date(std::string_view ts) {
    int year = 0, mon = 0, day = 0;
    if (!parse_fixed_digits(ts, 0, 4, year)) return false;
    if (!parse_fixed_digits(ts, 5, 2, mon) || !parse_fixed_digits(ts, 8, 2, day)) return false;
    return mon >= 1 && mon <= 12 && day >= 1 && day <= 31;
}

bool parse_rfc3339_time(std::string_view ts) {
    int hr = 0, min = 0, sec = 0;
    if (!parse_fixed_digits(ts, 11, 2, hr)) return false;
    if (!parse_fixed_digits(ts, 14, 2, min) || !parse_fixed_digits(ts, 17, 2, sec)) return false;
    return hr <= 23 && min <= 59 && sec <= 60;
}

bool skip_rfc3339_fraction(std::string_view ts, std::size_t& pos) {
    if (pos >= ts.size() || ts[pos] != '.') return true;
    ++pos;
    std::size_t digits = 0;
    while (pos < ts.size() && std::isdigit(static_cast<unsigned char>(ts[pos])) != 0) {
        ++pos;
        ++digits;
    }
    return digits > 0;
}

bool is_valid_rfc3339(std::string_view ts) {
    if (ts.size() < 20 || ts == "0001-01-01T00:00:00Z") return false;
    if (!has_rfc3339_delims(ts) || !parse_rfc3339_date(ts) || !parse_rfc3339_time(ts)) return false;
    std::size_t pos = 19;
    return skip_rfc3339_fraction(ts, pos) && is_valid_tz_suffix(ts.substr(pos));
}

enum class DigestStatus { kOk, kNone, kMismatchSha256, kMismatchSha512 };

DigestStatus check_digests(const std::map<std::string, std::string>& digests, std::string_view descriptor) {
    bool found = false;
    auto it256 = digests.find("sha256");
    if (it256 != digests.end()) {
        found = true;
        if (it256->second != sha256_hex(descriptor)) {
            return DigestStatus::kMismatchSha256;
        }
    }
    auto it512 = digests.find("sha512");
    if (it512 != digests.end()) {
        found = true;
        if (it512->second != sha512_hex(descriptor)) {
            return DigestStatus::kMismatchSha512;
        }
    }
    return found ? DigestStatus::kOk : DigestStatus::kNone;
}

std::vector<Subject> parse_subjects(const JsonValue* raw) {
    if (raw == nullptr || raw->is_null()) {
        return {};
    }
    std::vector<Subject> out;
    for (const auto& item : raw->as_array()) {
        Subject sub;
        sub.name = str_or_empty(item, "name");
        if (const JsonValue* dg = item.find("digest"); dg != nullptr && !dg->is_null()) {
            for (const auto& kv : dg->as_object()) {
                sub.digest[kv.first] = kv.second.as_string();
            }
        }
        out.push_back(std::move(sub));
    }
    return out;
}

std::vector<Verdict> parse_verdicts(const JsonValue* raw) {
    if (raw == nullptr || raw->is_null()) {
        return {};
    }
    std::vector<Verdict> out;
    for (const auto& item : raw->as_array()) {
        Verdict v;
        v.id = str_or_empty(item, "id");
        v.phase = str_or_empty(item, "phase");
        v.status = str_or_empty(item, "status");
        v.severity = str_or_empty(item, "severity");
        v.doc = str_or_empty(item, "doc");
        if (const JsonValue* ev = item.find("evidence"); ev != nullptr && !ev->is_null()) {
            for (const auto& e : ev->as_array()) {
                v.evidence.push_back(e.as_string());
            }
        }
        out.push_back(std::move(v));
    }
    return out;
}

Counts parse_counts(const JsonValue* raw) {
    Counts c;
    if (raw == nullptr || raw->is_null()) {
        return c;
    }
    c.pass = static_cast<int>(raw->opt_int("pass", 0));
    c.warn = static_cast<int>(raw->opt_int("warn", 0));
    c.fail = static_cast<int>(raw->opt_int("fail", 0));
    c.skip = static_cast<int>(raw->opt_int("skip", 0));
    c.info = static_cast<int>(raw->opt_int("info", 0));
    return c;
}

std::optional<Score> parse_score(const JsonValue* raw) {
    if (raw == nullptr || raw->is_null()) {
        return std::nullopt;
    }
    Score s;
    s.total = raw->at("total").as_number();
    s.grade = str_or_empty(*raw, "grade");
    s.categories_assessed = static_cast<int>(raw->opt_int("categoriesAssessed", 0));
    s.categories_total = static_cast<int>(raw->opt_int("categoriesTotal", 0));
    return s;
}

void check_subject_rules(const Attestation& st, std::vector<std::string>& problems) {
    if (st.subjects().empty()) {
        problems.emplace_back("no subject: the statement is about nothing");
        return;
    }
    if (st.subjects().size() != 1) {
        problems.emplace_back("multiple subjects: evaluation covers exactly one server");
        return;
    }
    const Subject& sub = st.subjects().front();
    const std::string want = trim_ascii(st.endpoint());
    const std::string name = trim_ascii(sub.name);
    if (name.empty()) {
        problems.emplace_back("the subject has no name");
    } else if (name != want) {
        problems.emplace_back("subject name does not match predicate.target.endpoint");
    }
    const std::string desc = Attestation::target_descriptor(st.transport(), st.endpoint());
    switch (check_digests(sub.digest, desc)) {
        case DigestStatus::kOk: break;
        case DigestStatus::kNone: problems.emplace_back("subject has no sha256 or sha512 digest"); break;
        case DigestStatus::kMismatchSha256: problems.emplace_back("subject sha256 digest mismatch"); break;
        case DigestStatus::kMismatchSha512: problems.emplace_back("subject sha512 digest mismatch"); break;
    }
}

void check_verdicts_and_counts(const Attestation& st, std::vector<std::string>& problems) {
    Counts tallied;
    for (std::size_t i = 0; i < st.verdicts().size(); ++i) {
        const Verdict& v = st.verdicts()[i];
        if (v.id.empty()) {
            problems.push_back("verdict " + std::to_string(i) + " has empty id");
            continue;
        }
        if (v.status == "pass") ++tallied.pass;
        else if (v.status == "warn") ++tallied.warn;
        else if (v.status == "fail") ++tallied.fail;
        else if (v.status == "skip") ++tallied.skip;
        else if (v.status == "info") ++tallied.info;
        else problems.push_back("verdict " + v.id + " has invalid status: " + v.status);
    }
    if (!st.verdicts().empty() && !(tallied == st.counts())) {
        problems.emplace_back("counts disagree with tallied verdicts");
    }
}

} // namespace

std::string Attestation::target_descriptor(std::string_view transport, std::string_view endpoint) {
    return std::string(transport) + "\n" + trim_ascii(endpoint);
}

Attestation Attestation::parse(std::string_view json_text) {
    JsonValue root = JsonValue::parse(json_text);
    if (!root.is_object()) {
        throw std::invalid_argument("attestation: root must be a JSON object");
    }
    Attestation st;
    st.type_ = str_or_empty(root, "_type");
    st.predicate_type_ = str_or_empty(root, "predicateType");
    st.subjects_ = parse_subjects(root.find("subject"));

    const JsonValue& pred = root.at("predicate");
    st.subject_kind_ = str_or_empty(pred, "subjectKind");
    if (const JsonValue* tgt = pred.find("target"); tgt != nullptr && tgt->is_object()) {
        st.transport_ = str_or_empty(*tgt, "transport");
        st.endpoint_ = str_or_empty(*tgt, "endpoint");
    }
    if (const JsonValue* ja = pred.find("judgedAgainst"); ja != nullptr && ja->is_object()) {
        st.spec_revision_ = str_or_empty(*ja, "specRevision");
        st.rubric_ = str_or_empty(*ja, "rubric");
        st.check_inventory_ = str_or_empty(*ja, "checkInventory");
    }
    if (const JsonValue* inst = pred.find("instrument"); inst != nullptr && inst->is_object()) {
        st.instrument_name_ = str_or_empty(*inst, "name");
        st.instrument_version_ = str_or_empty(*inst, "version");
        st.report_schema_version_ = static_cast<int>(inst->opt_int("reportSchemaVersion", 0));
    }
    st.ran_at_ = str_or_empty(pred, "ranAt");
    st.took_ = str_or_empty(pred, "took");
    st.verdicts_ = parse_verdicts(pred.find("verdicts"));
    st.counts_ = parse_counts(pred.find("counts"));
    st.score_ = parse_score(pred.find("score"));

    st.validate();
    return st;
}

Attestation Attestation::parse_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs.is_open()) {
        throw std::runtime_error("attestation: unable to open file: " + path);
    }
    std::ostringstream buffer;
    buffer << ifs.rdbuf();
    return parse(buffer.str());
}

void Attestation::validate() const {
    auto add_if = [](std::vector<std::string>& out, bool bad, const char* msg) {
        if (bad) out.emplace_back(msg);
    };
    std::vector<std::string> problems;
    add_if(problems, type_ != kStatementType, "invalid _type");
    add_if(problems, predicate_type_ != kPredicateType, "invalid predicateType");
    check_subject_rules(*this, problems);
    add_if(problems, subject_kind_ != kSubjectKind, "invalid subjectKind");
    add_if(problems, trim_ascii(endpoint_).empty(), "empty target endpoint");
    add_if(problems, transport_ != "http" && transport_ != "stdio", "invalid target transport");
    add_if(problems, instrument_name_.empty() || instrument_version_.empty(), "unidentified instrument");
    add_if(problems, !is_valid_rfc3339(ran_at_), "invalid or missing ranAt timestamp");
    add_if(problems, verdicts_.empty(), "empty verdicts");
    add_if(problems, check_inventory_.empty(), "empty judgedAgainst.checkInventory");
    add_if(problems, score_.has_value() && rubric_.empty(), "score present without judgedAgainst.rubric");
    check_verdicts_and_counts(*this, problems);
    if (!problems.empty()) {
        std::string msg = "attestation: ";
        for (std::size_t i = 0; i < problems.size(); ++i) {
            if (i > 0) msg += "; ";
            msg += problems[i];
        }
        throw std::invalid_argument(msg);
    }
}

bool Attestation::covers(std::string_view transport, std::string_view endpoint) const {
    if (subjects_.size() != 1) {
        return false;
    }
    const std::string desc = target_descriptor(transport, endpoint);
    return check_digests(subjects_.front().digest, desc) == DigestStatus::kOk;
}

std::optional<Verdict> Attestation::verdict_for(std::string_view check_id) const {
    for (const auto& v : verdicts_) {
        if (v.id == check_id) {
            return v;
        }
    }
    return std::nullopt;
}

std::optional<double> Attestation::score_total() const noexcept {
    if (!score_.has_value()) {
        return std::nullopt;
    }
    return score_->total;
}

std::optional<std::string> Attestation::score_grade() const {
    if (!score_.has_value()) {
        return std::nullopt;
    }
    return score_->grade;
}

} // namespace passmcp
