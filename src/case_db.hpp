/**
 * X-Core Case Database v0.1 (判例库)
 * SQLite-backed knowledge base for scan results + LLM classifications.
 * Enables similarity lookup: "have I seen this crypto pattern before?"
 */
#pragma once
#include <string>
#include <vector>
#include "nlohmann.json.hpp"

namespace xcore {

struct CaseInfo {
    int64_t id = 0;
    std::string file_hash;           // SHA-256
    std::string file_path;
    int64_t file_size = 0;
    std::string scan_date;
    nlohmann::json rules_hits;       // compact scan result
    nlohmann::json llm_algorithms;   // parsed ["rsa-2048","aes-128-cbc",...]
    // Evidence confidence — ENGINE-COMPUTED, never model-reported.
    // The model is forbidden from emitting "confidence" (see prompts::classifier).
    // See CaseDB::compute_confidence() for the derivation rules.
    std::string evidence_confidence; // "0.00" ~ "1.00"
    std::string confidence_source;   // manual | rules | llm-only | none
    std::string llm_raw_response;    // original LLM JSON
    std::string notes;
    std::string created_at;
};

struct SimilarCase {
    CaseInfo info;
    int shared_rules = 0;            // how many rule_ids matched
    double similarity = 0.0;         // weighted Jaccard 0.0~1.0
    bool skip_llm = false;           // dual-gate: reuse without LLM
};

class CaseDB {
public:
    explicit CaseDB(const std::string& db_path);
    ~CaseDB();

    bool open();
    void close();
    bool is_open() const;

    // ── CRUD ──────────────────────────────────────────
    bool insert_case(const CaseInfo& ci);
    bool upsert_case(const CaseInfo& ci);

    // ── Query ─────────────────────────────────────────
    CaseInfo find_by_hash(const std::string& sha256);
    std::vector<CaseInfo> find_by_algorithm(const std::string& algo);
    std::vector<CaseInfo> list_all(int limit = 100, int offset = 0);
    bool has_hash(const std::string& sha256);

    // ── Similarity ────────────────────────────────────
    // Given a scan result (from scan()), find most similar historical cases.
    // Similarity = shared rule types × entropy range overlap.
    std::vector<SimilarCase> find_similar(const nlohmann::json& scan_result, int limit = 5);

    // ── Stats ─────────────────────────────────────────
    int case_count();
    nlohmann::json stats();

    // ── Pipeline integration ──────────────────────────
    // Store result from classify/LLM pipeline. Returns true if new case stored.
    bool store_classify_result(const std::string& file_path,
                               const nlohmann::json& scan_result,
                               const std::string& llm_response_json);

    // ── Utility ───────────────────────────────────────
    static std::string sha256_file(const std::string& file_path);
    static std::string sha256_data(const void* data, size_t len);

    // ── Evidence confidence (engine-side, model has no say) ───
    // Rules:
    //   manual  -> 1.00   (a human confirmed it; see notes/_history)
    //   rules   -> 0.40 + 0.15 * (distinct rule categories), capped at 0.95
    //   llm-only (LLM named an algorithm but NO rule evidence) -> 0.00, untrusted
    //   none    -> 0.00
    // Rationale: an LLM naming an algorithm without rule evidence is exactly the
    // failure mode that produced 94 hallucinated knowledge entries (2026-09).
    static void compute_confidence(CaseInfo& ci);

private:
    void* db_ = nullptr;            // sqlite3*
    std::string db_path_;
    void init_schema();
    CaseInfo row_to_case(void* stmt);
};

} // namespace xcore
