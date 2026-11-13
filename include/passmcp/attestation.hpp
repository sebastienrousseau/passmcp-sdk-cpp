// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

#ifndef PASSMCP_ATTESTATION_HPP
#define PASSMCP_ATTESTATION_HPP

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace passmcp {

/** Outcome recorded for a single check inside an evaluation predicate. */
struct Verdict {
    std::string id;
    std::string phase;
    std::string status;
    std::string severity;
    std::vector<std::string> evidence;
    std::string doc;
};

/** Tallied verdict counts across pass, warn, fail, skip, and info statuses. */
struct Counts {
    int pass = 0;
    int warn = 0;
    int fail = 0;
    int skip = 0;
    int info = 0;

    [[nodiscard]] bool operator==(const Counts& other) const noexcept = default;
};

/** Evaluation score summary carried when a rubric is specified. */
struct Score {
    double total = 0.0;
    std::string grade;
    int categories_assessed = 0;
    int categories_total = 0;
};

/** Subject descriptor from the in-toto statement envelope. */
struct Subject {
    std::string name;
    std::map<std::string, std::string> digest;
};

/**
 * Verified offline `in-toto` `Statement/v1` carrying
 * `https://satellion.com/attestation/mcp-evaluation/v1`.
 */
class Attestation {
public:
    static constexpr std::string_view kStatementType = "https://in-toto.io/Statement/v1";
    static constexpr std::string_view kPredicateType = "https://satellion.com/attestation/mcp-evaluation/v1";
    static constexpr std::string_view kSubjectKind = "mcp-target-descriptor";

    [[nodiscard]] static Attestation parse(std::string_view json_text);
    [[nodiscard]] static Attestation parse_file(const std::string& path);
    [[nodiscard]] static std::string target_descriptor(std::string_view transport, std::string_view endpoint);

    void validate() const;

    [[nodiscard]] bool covers(std::string_view transport, std::string_view endpoint) const;
    [[nodiscard]] std::optional<Verdict> verdict_for(std::string_view check_id) const;
    [[nodiscard]] std::optional<double> score_total() const noexcept;
    [[nodiscard]] std::optional<std::string> score_grade() const;

    [[nodiscard]] const std::string& type() const noexcept { return type_; }
    [[nodiscard]] const std::string& predicate_type() const noexcept { return predicate_type_; }
    [[nodiscard]] const std::vector<Subject>& subjects() const noexcept { return subjects_; }
    [[nodiscard]] const std::string& subject_kind() const noexcept { return subject_kind_; }
    [[nodiscard]] const std::string& transport() const noexcept { return transport_; }
    [[nodiscard]] const std::string& endpoint() const noexcept { return endpoint_; }
    [[nodiscard]] const std::string& spec_revision() const noexcept { return spec_revision_; }
    [[nodiscard]] const std::string& rubric() const noexcept { return rubric_; }
    [[nodiscard]] const std::string& check_inventory() const noexcept { return check_inventory_; }
    [[nodiscard]] const std::string& instrument_name() const noexcept { return instrument_name_; }
    [[nodiscard]] const std::string& instrument_version() const noexcept { return instrument_version_; }
    [[nodiscard]] int report_schema_version() const noexcept { return report_schema_version_; }
    [[nodiscard]] const std::string& ran_at() const noexcept { return ran_at_; }
    [[nodiscard]] const std::string& took() const noexcept { return took_; }
    [[nodiscard]] const std::vector<Verdict>& verdicts() const noexcept { return verdicts_; }
    [[nodiscard]] const Counts& counts() const noexcept { return counts_; }
    [[nodiscard]] const std::optional<Score>& score() const noexcept { return score_; }

private:
    std::string type_;
    std::vector<Subject> subjects_;
    std::string predicate_type_;
    std::string subject_kind_;
    std::string transport_;
    std::string endpoint_;
    std::string spec_revision_;
    std::string rubric_;
    std::string check_inventory_;
    std::string instrument_name_;
    std::string instrument_version_;
    int report_schema_version_ = 0;
    std::string ran_at_;
    std::string took_;
    std::vector<Verdict> verdicts_;
    Counts counts_;
    std::optional<Score> score_;
};

} // namespace passmcp

#endif // PASSMCP_ATTESTATION_HPP
