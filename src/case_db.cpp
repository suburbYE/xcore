/**
 * X-Core Case Database v0.1 — implementation
 * SQLite3 amalgamation + Windows CryptoAPI SHA-256
 */
#include "case_db.hpp"
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <set>
#include <map>

#define NOMINMAX
#include "sqlite3.h"

#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

namespace xcore {

// ─── SHA-256 via Windows CNG ────────────────────────────

std::string CaseDB::sha256_data(const void* data, size_t len) {
#ifdef _WIN32
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    std::string result(64, '0');

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        return {};
    if (BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0) != 0) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);

    BYTE hash[32];
    BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        result[i * 2]     = hex[hash[i] >> 4];
        result[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    return result;
#else
    return {};
#endif
}

std::string CaseDB::sha256_file(const std::string& file_path) {
#ifdef _WIN32
    std::wstring wpath;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, file_path.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return {};
    wpath.resize(wlen);
    MultiByteToWideChar(CP_UTF8, 0, file_path.c_str(), -1, &wpath[0], wlen);

    HANDLE hFile = CreateFileW(wpath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return {};

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        CloseHandle(hFile);
        return {};
    }

    BCryptCreateHash(hAlg, &hHash, nullptr, 0, nullptr, 0, 0);

    BYTE buf[65536];
    DWORD read = 0;
    while (ReadFile(hFile, buf, sizeof(buf), &read, nullptr) && read > 0) {
        BCryptHashData(hHash, buf, read, 0);
    }

    BYTE hash[32];
    BCryptFinishHash(hHash, hash, sizeof(hash), 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(hFile);

    std::string result(64, '0');
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i) {
        result[i * 2]     = hex[hash[i] >> 4];
        result[i * 2 + 1] = hex[hash[i] & 0xF];
    }
    return result;
#else
    return {};
#endif
}

// ─── SQLite helper ───────────────────────────────────────

static sqlite3* db_ptr(void* db) { return static_cast<sqlite3*>(db); }

// ─── Constructor / Destructor ────────────────────────────

CaseDB::CaseDB(const std::string& db_path) : db_path_(db_path) {}

CaseDB::~CaseDB() { close(); }

bool CaseDB::open() {
    int rc = sqlite3_open(db_path_.c_str(), (sqlite3**)&db_);
    if (rc != SQLITE_OK) return false;
    sqlite3_busy_timeout(db_ptr(db_), 5000);  // 5s lock retry, prevents SQLITE_BUSY under concurrent pipe writes
    init_schema();
    return true;
}

void CaseDB::close() {
    if (db_) {
        sqlite3_close(db_ptr(db_));
        db_ = nullptr;
    }
}

bool CaseDB::is_open() const { return db_ != nullptr; }

void CaseDB::init_schema() {
    auto* db = db_ptr(db_);
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS cases (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash     TEXT NOT NULL UNIQUE,
            file_path     TEXT NOT NULL,
            file_size     INTEGER DEFAULT 0,
            scan_date     TEXT NOT NULL,
            rules_hits    TEXT NOT NULL,
            llm_algorithms TEXT,
            llm_confidence TEXT,
            llm_raw_response TEXT,
            notes         TEXT DEFAULT '',
            created_at    TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE INDEX IF NOT EXISTS idx_cases_hash ON cases(file_hash);
        CREATE INDEX IF NOT EXISTS idx_cases_confidence ON cases(llm_confidence);
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=NORMAL;
    )";
    sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
}

// ─── Row parser ──────────────────────────────────────────

CaseInfo CaseDB::row_to_case(void* stmt_ptr) {
    auto* stmt = static_cast<sqlite3_stmt*>(stmt_ptr);
    CaseInfo c;
    c.id              = sqlite3_column_int64(stmt, 0);
    c.file_hash       = (const char*)sqlite3_column_text(stmt, 1);
    c.file_path       = (const char*)sqlite3_column_text(stmt, 2);
    c.file_size       = sqlite3_column_int64(stmt, 3);
    c.scan_date       = (const char*)sqlite3_column_text(stmt, 4);

    const char* hits  = (const char*)sqlite3_column_text(stmt, 5);
    if (hits) c.rules_hits = nlohmann::json::parse(hits);

    const char* algos = (const char*)sqlite3_column_text(stmt, 6);
    if (algos) c.llm_algorithms = nlohmann::json::parse(algos);

    const char* conf  = (const char*)sqlite3_column_text(stmt, 7);
    if (conf) c.llm_confidence = conf;

    const char* raw   = (const char*)sqlite3_column_text(stmt, 8);
    if (raw) c.llm_raw_response = raw;

    const char* notes = (const char*)sqlite3_column_text(stmt, 9);
    if (notes) c.notes = notes;

    const char* cat   = (const char*)sqlite3_column_text(stmt, 10);
    if (cat) c.created_at = cat;

    return c;
}

// ─── CRUD ────────────────────────────────────────────────

bool CaseDB::insert_case(const CaseInfo& ci) {
    auto* db = db_ptr(db_);
    const char* sql = R"(
        INSERT INTO cases (file_hash, file_path, file_size, scan_date,
                          rules_hits, llm_algorithms, llm_confidence,
                          llm_raw_response, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    )";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    std::string rules_json = ci.rules_hits.dump();
    std::string algos_json = ci.llm_algorithms.dump();
    std::string date = ci.scan_date;
    if (date.empty()) {
        // use SQLite default
    }

    sqlite3_bind_text(stmt, 1, ci.file_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ci.file_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, ci.file_size);
    if (!date.empty())
        sqlite3_bind_text(stmt, 4, date.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, rules_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, algos_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, ci.llm_confidence.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, ci.llm_raw_response.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, ci.notes.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool CaseDB::upsert_case(const CaseInfo& ci) {
    auto* db = db_ptr(db_);
    const char* sql = R"(
        INSERT INTO cases (file_hash, file_path, file_size, scan_date,
                          rules_hits, llm_algorithms, llm_confidence,
                          llm_raw_response, notes)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(file_hash) DO UPDATE SET
            file_path=excluded.file_path, file_size=excluded.file_size,
            scan_date=excluded.scan_date, rules_hits=excluded.rules_hits,
            llm_algorithms=excluded.llm_algorithms,
            llm_confidence=excluded.llm_confidence,
            llm_raw_response=excluded.llm_raw_response,
            notes=excluded.notes
    )";
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);

    std::string rules_json = ci.rules_hits.dump();
    std::string algos_json = ci.llm_algorithms.dump();

    sqlite3_bind_text(stmt, 1, ci.file_hash.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, ci.file_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 3, ci.file_size);
    sqlite3_bind_text(stmt, 4, ci.scan_date.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, rules_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, algos_json.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, ci.llm_confidence.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 8, ci.llm_raw_response.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 9, ci.notes.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

// ─── Query ───────────────────────────────────────────────

CaseInfo CaseDB::find_by_hash(const std::string& sha256) {
    auto* db = db_ptr(db_);
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT * FROM cases WHERE file_hash=? LIMIT 1", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, sha256.c_str(), -1, SQLITE_TRANSIENT);

    CaseInfo c;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        c = row_to_case(stmt);
    }
    sqlite3_finalize(stmt);
    return c;
}

std::vector<CaseInfo> CaseDB::find_by_algorithm(const std::string& algo) {
    auto* db = db_ptr(db_);
    std::vector<CaseInfo> results;
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT * FROM cases WHERE llm_algorithms LIKE ? ORDER BY created_at DESC LIMIT 100",
        -1, &stmt, nullptr);

    std::string pattern = "%" + algo + "%";
    sqlite3_bind_text(stmt, 1, pattern.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(row_to_case(stmt));
    }
    sqlite3_finalize(stmt);
    return results;
}

std::vector<CaseInfo> CaseDB::list_all(int limit, int offset) {
    auto* db = db_ptr(db_);
    std::vector<CaseInfo> results;
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT * FROM cases ORDER BY created_at DESC LIMIT ? OFFSET ?",
        -1, &stmt, nullptr);
    sqlite3_bind_int(stmt, 1, limit);
    sqlite3_bind_int(stmt, 2, offset);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        results.push_back(row_to_case(stmt));
    }
    sqlite3_finalize(stmt);
    return results;
}

bool CaseDB::has_hash(const std::string& sha256) {
    auto* db = db_ptr(db_);
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT 1 FROM cases WHERE file_hash=? LIMIT 1", -1, &stmt, nullptr);
    sqlite3_bind_text(stmt, 1, sha256.c_str(), -1, SQLITE_TRANSIENT);
    bool found = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return found;
}

// ─── Similarity (Weighted Jaccard + Dual-Gate) ──────────

struct RuleHit {
    std::string rule_id;
    int weight;
};

// Extract rule hits from scan result JSON. Only counts rules that actually fired.
static std::vector<RuleHit> extract_rule_hits(const nlohmann::json& scan) {
    std::vector<RuleHit> hits;
    if (!scan.contains("matches") || !scan["matches"].is_array()) return hits;
    for (auto& m : scan["matches"]) {
        bool fired = false;
        std::string t = m.value("type", "");
        if (t == "entropy")
            fired = m.value("region_count", 0) > 0;
        else if (t == "string_match")
            fired = m.value("count", 0) > 0;
        else if (t == "hex_match")
            fired = m.value("count", 0) > 0;
        else if (t == "global_entropy")
            fired = m.value("triggered", false);
        if (fired) {
            hits.push_back({m.value("rule_id", ""), m.value("weight", 1)});
        }
    }
    return hits;
}

// Weighted Jaccard: J_w = Σ(w_i for i∈A∩B) / Σ(w_i for i∈A∪B)
// Also reports whether both samples share any weight=5 rules (hard-feature lock).
static double weighted_jaccard(const std::vector<RuleHit>& a,
                                const std::vector<RuleHit>& b,
                                bool& hard_lock) {
    hard_lock = false;
    if (a.empty() || b.empty()) return 0.0;  // no signatures on either side → not similar

    // collect unique rule_ids from both sides
    std::set<std::string> a_set, b_set;
    std::map<std::string, int> wa, wb;

    for (auto& h : a) { a_set.insert(h.rule_id); wa[h.rule_id] = h.weight; }
    for (auto& h : b) { b_set.insert(h.rule_id); wb[h.rule_id] = h.weight; }

    std::set<std::string> all_ids;
    for (auto& id : a_set) all_ids.insert(id);
    for (auto& id : b_set) all_ids.insert(id);

    double isum = 0.0, usum = 0.0;
    for (auto& rid : all_ids) {
        bool in_a = a_set.count(rid) > 0;
        bool in_b = b_set.count(rid) > 0;
        int w = std::max(in_a ? wa[rid] : 0, in_b ? wb[rid] : 0);
        usum += w;
        if (in_a && in_b) {
            isum += w;
            if (w == 5) hard_lock = true;
        }
    }
    return usum > 0.0 ? isum / usum : 0.0;
}

std::vector<SimilarCase> CaseDB::find_similar(const nlohmann::json& scan_result, int limit) {
    std::vector<SimilarCase> results;
    auto query_hits = extract_rule_hits(scan_result);
    if (query_hits.empty()) return results;  // no crypto signatures → nothing to match

    auto* db = db_ptr(db_);

    // Fetch all cases and compute similarity in-memory
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT * FROM cases ORDER BY created_at DESC", -1, &stmt, nullptr);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        CaseInfo c = row_to_case(stmt);
        auto hist_hits = extract_rule_hits(c.rules_hits);

        bool hard_lock = false;
        double sim = weighted_jaccard(query_hits, hist_hits, hard_lock);

        // Dual-gate calibration
        bool skip = (sim >= 0.75) || (sim >= 0.40 && hard_lock);

        // Count shared rule_ids for display
        std::set<std::string> qset;
        for (auto& h : query_hits) qset.insert(h.rule_id);
        int shared = 0;
        for (auto& h : hist_hits)
            if (qset.count(h.rule_id)) ++shared;

        if (sim > 0.0) {
            SimilarCase sc;
            sc.info        = c;
            sc.shared_rules = shared;
            sc.similarity   = sim;
            sc.skip_llm     = skip;
            results.push_back(sc);
        }
    }
    sqlite3_finalize(stmt);

    std::sort(results.begin(), results.end(),
              [](const SimilarCase& a, const SimilarCase& b) { return a.similarity > b.similarity; });

    if ((int)results.size() > limit)
        results.resize(limit);
    return results;
}

// ─── Stats ───────────────────────────────────────────────

int CaseDB::case_count() {
    auto* db = db_ptr(db_);
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM cases", -1, &stmt, nullptr);
    int count = 0;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

nlohmann::json CaseDB::stats() {
    auto* db = db_ptr(db_);
    nlohmann::json s;
    s["total_cases"] = case_count();

    // Algorithm distribution
    s["algorithms"] = nlohmann::json::object();
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db,
        "SELECT llm_algorithms FROM cases WHERE llm_algorithms IS NOT NULL AND llm_algorithms != ''",
        -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* txt = (const char*)sqlite3_column_text(stmt, 0);
        if (!txt) continue;
        try {
            auto arr = nlohmann::json::parse(txt);
            if (arr.is_array()) {
                for (auto& a : arr) {
                    std::string algo = a.get<std::string>();
                    int cur = s["algorithms"].value(algo, 0);
                    s["algorithms"][algo] = cur + 1;
                }
            }
        } catch (...) {}
    }
    sqlite3_finalize(stmt);

    // Confidence distribution
    s["confidence_dist"] = nlohmann::json::object();
    sqlite3_prepare_v2(db,
        "SELECT llm_confidence, COUNT(*) FROM cases WHERE llm_confidence IS NOT NULL AND llm_confidence != '' GROUP BY llm_confidence",
        -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        s["confidence_dist"][(const char*)sqlite3_column_text(stmt, 0)] = sqlite3_column_int(stmt, 1);
    }
    sqlite3_finalize(stmt);

    return s;
}

// ─── Pipeline integration ────────────────────────────────

static std::string format_date() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    return buf;
}

bool CaseDB::store_classify_result(const std::string& file_path,
                                   const nlohmann::json& scan_result,
                                   const std::string& llm_response_json) {
    // Compute file hash
    std::string hash = sha256_file(file_path);
    if (hash.empty()) return false;

    // Parse LLM response
    nlohmann::json llm_algs = nlohmann::json::array();
    std::string confidence;
    try {
        auto j = nlohmann::json::parse(llm_response_json);
        if (j.contains("algorithms")) llm_algs = j["algorithms"];
        if (j.contains("confidence")) confidence = j["confidence"];
    } catch (...) {}

    // Get file size
    int64_t fsize = 0;
    try {
        std::wstring wpath;
        int wlen = MultiByteToWideChar(CP_UTF8, 0, file_path.c_str(), -1, nullptr, 0);
        wpath.resize(wlen);
        MultiByteToWideChar(CP_UTF8, 0, file_path.c_str(), -1, &wpath[0], wlen);
        WIN32_FILE_ATTRIBUTE_DATA attr;
        if (GetFileAttributesExW(wpath.c_str(), GetFileExInfoStandard, &attr)) {
            fsize = ((int64_t)attr.nFileSizeHigh << 32) | attr.nFileSizeLow;
        }
    } catch (...) {}

    CaseInfo ci;
    ci.file_hash        = hash;
    ci.file_path        = file_path;
    ci.file_size        = fsize;
    ci.scan_date        = format_date();
    ci.rules_hits       = scan_result;
    ci.llm_algorithms   = llm_algs;
    ci.llm_confidence   = confidence;
    ci.llm_raw_response = llm_response_json;

    return upsert_case(ci);
}

} // namespace xcore
