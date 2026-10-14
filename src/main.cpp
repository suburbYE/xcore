/**
 * X-Core unified CLI v0.31.0
 *
 * Subcommands:
 *   xcore scan        <file> <rules.json> [flags]
 *   xcore pipe        <rules.json> [flags]
 *   xcore db          stats [--db <path>]
 *   xcore classify    <file> <rules.json> [flags]
 *   xcore deobfuscate <target.js> [--output <dir>] [--entry <fn>] [--verify]
 *   xcore verify      <original.js> <flattened.js>
 *   xcore pipeline    --url <url> --entry <fn> --target-python <path>
 *   xcore native      --apk <path> [--mode passive] [--json] [--output <dir>] [--full]
 *   xcore native      --so <path> [--fingerprints-dir <dir>] [--json]
 *   xcore native      --generate-probe <scan.json> [--out <script.js>] [--spawn]
 *   xcore native      --pipeline <apk> [--output <dir>] [--spawn]
 */
#include <iostream>
#include <string>
#include <fstream>
#include <cstdlib>
#include <filesystem>
#include "xcore_api.hpp"
#include "llm_client.hpp"
#include "case_db.hpp"
#include "flatten/flatten.hpp"
#include "verify/verifier.hpp"

using json = nlohmann::json;
namespace fs = std::filesystem;

#ifdef _WIN32
#include <windows.h>
#endif

// ─── Platform helpers ─────────────────────────────────────

static std::string get_exe_dir() {
#ifdef _WIN32
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        std::string path(buf, len);
        auto pos = path.rfind('\\');
        if (pos != std::string::npos)
            return path.substr(0, pos);
    }
#endif
    return ".";
}

static std::string exec_cmd(const std::string& cmd) {
    std::string result;
    char buf[256];
    // _popen → cmd /c <cmd>; cmd /c strips outer quotes when cmd starts with "
    // prepend "call " to prevent cmd from breaking quoted paths (e.g. "C:\Program Files\...")
    std::string safe_cmd = cmd;
    if (!cmd.empty() && cmd[0] == '"') {
        safe_cmd = "call " + cmd;
    }
    FILE* pipe = _popen(safe_cmd.c_str(), "r");
    if (!pipe) return "";
    while (fgets(buf, sizeof(buf), pipe) != nullptr)
        result += buf;
    _pclose(pipe);
    return result;
}

// nlohmann::json::value() only falls back when the key is MISSING. If the key
// exists but holds null it throws type_error.302. runner.js emits "h5st":null
// whenever no signature was produced, which silently aborted the whole parse.
static std::string json_str(const json& j, const char* key, const std::string& def = "") {
    auto it = j.find(key);
    return (it != j.end() && it->is_string()) ? it->get<std::string>() : def;
}

static bool json_bool(const json& j, const char* key, bool def = false) {
    auto it = j.find(key);
    return (it != j.end() && it->is_boolean()) ? it->get<bool>() : def;
}

static long long json_int(const json& j, const char* key, long long def = 0) {
    auto it = j.find(key);
    return (it != j.end() && it->is_number()) ? it->get<long long>() : def;
}

// Layer hits are not uniformly typed: L5_cfp emits bare names ("ror_chain_x3")
// while L2_constants emits objects ({"constant":"crc32_poly","section":".rdata",
// "count":1,"locations":[...]}). The summary used to print only is_string()
// hits, so every object layer rendered as "[" then "]" with nothing between —
// i.e. "[, ]", which reads as a match when it is really a rendering gap.
static std::string render_hit(const json& h) {
    if (h.is_string()) return h.get<std::string>();
    if (h.is_number()) return h.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
    if (!h.is_object()) return h.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);

    // Name the hit by whichever identifying field it carries.
    std::string label;
    for (const char* k : {"constant", "name", "id", "algorithm", "fingerprint"}) {
        label = json_str(h, k);
        if (!label.empty()) break;
    }
    if (label.empty()) {
        // Unknown shape: show the first scalar field rather than nothing at all.
        for (auto& [k, v] : h.items()) {
            if (v.is_string() || v.is_number()) { label = k + "=" + v.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace); break; }
        }
    }
    if (label.empty()) return "?";

    std::string extra;
    std::string section = json_str(h, "section");
    if (!section.empty()) extra += " " + section;
    long long count = json_int(h, "count", 0);
    if (count > 0) extra += " x" + std::to_string(count);
    if (h.contains("locations") && h["locations"].is_array() && !h["locations"].empty()) {
        const json& loc = h["locations"][0];
        extra += " @" + (loc.is_string() ? loc.get<std::string>() : loc.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
    }
    return label + (extra.empty() ? "" : "(" + extra.substr(1) + ")");
}

static std::string find_node() {
    // Try to find node.exe
    std::string out = exec_cmd("where node 2>nul");
    if (!out.empty()) {
        auto pos = out.find("\r");
        if (pos != std::string::npos) out = out.substr(0, pos);
        pos = out.find("\n");
        if (pos != std::string::npos) out = out.substr(0, pos);
        if (!out.empty()) return out;
    }
    return "node"; // fallback
}

// ─── Constants ────────────────────────────────────────────
static constexpr size_t MIN_SCAN_SIZE = 1024;  // noise gate: skip files < 1KB

struct RunConfig {
    std::string file;
    std::string rules_path;
    std::string fingerprints_dir;
    std::string model      = "qwen2.5:7b";
    std::string endpoint   = "http://localhost:11434/v1";
    std::string db_path    = "tools/cases.db";
    std::string output_dir;
    std::string entry_fn   = "window.ParamsSign.sign";
    bool brief             = false;
    bool json_output       = false;
    bool force_llm         = false;
    bool verify_output     = false;
    // Scan/classify without recording the result. Previously every successful
    // classification was written to the case DB with no way to opt out, so
    // trying the tool on a new sample silently changed the corpus that later
    // similarity lookups are made against.
    bool no_store          = false;
};

// The version comes from src/version.h, generated by scripts/sync_version.py
// from the VERSION file at the repository root.
//
// It used to be a literal here, described as the single source of truth while
// three other literals lived elsewhere in this file and in xcore.cpp -- two of
// them inside `--json` output. A script reading the binary was told 0.18.0 or
// 0.5 depending on which subcommand it called, while this constant said 0.31.0
// and the documents said something else again. Keep ASCII: MSVC reads this
// file as CP936 and non-ASCII here corrupts the parse.
#include "version.h"

// ── machine-readable output ─────────────────────────────────────────────────
//
// `--json` must mean "stdout is the document". It used to mean "a JSON document
// appears somewhere among the human output": a summary line came first, then
// the document, then case matching and LLM progress, so a caller needed to know
// line numbers to parse it -- which is the same as not being machine-readable.
//
// Redirecting the stream rather than editing each call site is deliberate. The
// pipeline writes to std::cout in about thirty places; converting them one by
// one leaves the next one added to silently corrupt the output again, and the
// failure is invisible in a terminal because everything still looks right.
class JsonModeRedirect {
public:
    explicit JsonModeRedirect(bool on) {
        if (on) saved_ = std::cout.rdbuf(std::cerr.rdbuf());
    }
    ~JsonModeRedirect() {
        if (saved_) std::cout.rdbuf(saved_);
    }
    JsonModeRedirect(const JsonModeRedirect&) = delete;
    JsonModeRedirect& operator=(const JsonModeRedirect&) = delete;

    // The real stdout, for the document itself.
    std::streambuf* real() const {
        return saved_ ? saved_ : std::cout.rdbuf();
    }

private:
    std::streambuf* saved_ = nullptr;
};

static void print_usage() {
    std::cout
        << "X-Core v" << XCORE_VERSION << "   Rule engine + Deobfuscator + Native Targeting\n"
        << "─────────────────────────────────────────────────────────────\n"
        << "  xcore scan        <file> <rules.json> [--fingerprints-dir <dir>] [--model <m>] [--db <path>] [--brief] [--json]\n"
        << "  xcore classify    <file> <rules.json> [--fingerprints-dir <dir>] [--model <m>] [--db <path>] [--json]\n"
        << "  xcore pipe        <rules.json> [--fingerprints-dir <dir>] [--model <m>] [--db <path>] [--json]\n"
        << "  xcore db          stats [--db <path>]      (always JSON)\n"
        << "  xcore deobfuscate <target.js> [--output <dir>] [--entry <fn>] [--verify]\n"
        << "  xcore verify      <original.js> <flattened.js> [--json]\n"
        << "  xcore pipeline    --url <url> --entry <fn> --target-python <path>\n"
        << "  xcore native      --apk <path> [--mode passive] [--json] [--output <dir>] [--full]\n"
        << "  xcore native      --so <path> [--fingerprints-dir <dir>] [--json]\n"
        << "  xcore native      --generate-probe <scan.json> [--out <script.js>] [--spawn]\n"
        << "  xcore native      --pipeline <apk> [--output <dir>] [--spawn]\n"
        << "\n"
        << "  --json: stdout is ONE JSON document and nothing else; progress goes to\n"
        << "          stderr. Exit codes are not 0/1: 0=annotate 1=clean 2=unknown\n"
        << "          3=error (scan incomplete -- do NOT read as 'nothing found').\n"
        << "  --no-store (alias --dry-run): classify but do not write to the case DB.\n"
        << "                                Applies to scan / pipe / classify.\n"
        << "  xcore help\n";
}

static RunConfig parse_args(int argc, char* argv[]) {
    RunConfig cfg;
    int i = 1;

    std::string cmd = argc > 1 ? argv[1] : "";
    if (cmd == "scan" || cmd == "classify") {
        if (argc < 4) { print_usage(); exit(1); }
        cfg.file       = argv[2];
        cfg.rules_path = argv[3];
        cfg.force_llm  = (cmd == "classify");
        i = 4;
    } else if (cmd == "pipe") {
        if (argc < 3) { print_usage(); exit(1); }
        cfg.rules_path = argv[2];
        i = 3;
    } else if (cmd == "deobfuscate") {
        if (argc < 3) { print_usage(); exit(1); }
        cfg.file = argv[2];
        i = 3;
    } else if (cmd == "verify") {
        if (argc < 4) { print_usage(); exit(1); }
        cfg.file       = argv[2]; // original
        cfg.rules_path = argv[3]; // flattened (abuse field)
        // This branch returns early, so the shared flag loop below never runs
        // for `verify` -- meaning --json was silently ignored here and the
        // command could not be used from a script at all.
        for (int k = 4; k < argc; ++k) {
            if (std::string(argv[k]) == "--json") cfg.json_output = true;
        }
        return cfg; // early return, no further flag parsing
    } else if (cmd == "db") {
        i = 2;
    } else if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage(); exit(0);
    } else {
        print_usage(); exit(1);
    }

    for (; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--model" && i + 1 < argc)          cfg.model      = argv[++i];
        else if (a == "--endpoint" && i + 1 < argc)  cfg.endpoint   = argv[++i];
        else if (a == "--db" && i + 1 < argc)        cfg.db_path    = argv[++i];
        else if (a == "--fingerprints-dir" && i + 1 < argc) cfg.fingerprints_dir = argv[++i];
        else if (a == "--output" && i + 1 < argc)    cfg.output_dir = argv[++i];
        else if (a == "--entry" && i + 1 < argc)     cfg.entry_fn   = argv[++i];
        else if (a == "--brief")                     cfg.brief      = true;
        else if (a == "--json")                     cfg.json_output = true;
        else if (a == "--verify")                    cfg.verify_output = true;
        else if (a == "--no-store" || a == "--dry-run") cfg.no_store = true;
    }
    return cfg;
}

// ─── Dual-gate pipeline (existing) ────────────────────────

static int run_pipeline(const json& scan_result,
                        const std::string& file_path,
                        const RunConfig& cfg) {
    xcore::CaseDB casedb(cfg.db_path);
    if (!casedb.open()) {
        std::cerr << "Error: cannot open case DB at " << cfg.db_path << "\n";
        return 1;
    }

    std::string hash = xcore::CaseDB::sha256_file(file_path);
    if (!hash.empty() && casedb.has_hash(hash)) {
        auto existing = casedb.find_by_hash(hash);
        std::cout << "Case #" << existing.id
                  << " (already known)  conf=" << existing.evidence_confidence
                  << " [" << existing.confidence_source << "]"
                  << "  " << existing.llm_algorithms.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
    }

    auto similar = casedb.find_similar(scan_result, 3);
    bool llm_needed = true;

    if (!similar.empty() && !cfg.force_llm) {
        if (!cfg.brief) {
            for (auto& s : similar) {
                std::cout << "  #" << s.info.id
                          << "  sim=" << s.similarity
                          << "  w5=" << (s.skip_llm ? "LOCK" : "-")
                          << "  " << s.info.llm_algorithms.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
            }
        }
        if (similar[0].skip_llm) {
            llm_needed = false;
            if (similar[0].similarity >= 0.40 && similar[0].similarity <= 0.55) {
                std::cout << "[!] BORDERLINE LOCK  sim=" << similar[0].similarity
                          << " -> Case #" << similar[0].info.id << "  "
                          << similar[0].info.llm_algorithms.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
            } else {
                std::cout << "Hard-lock  sim=" << similar[0].similarity
                          << " -> Case #" << similar[0].info.id << "  "
                          << similar[0].info.llm_algorithms.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace)
                          << "  [LLM SKIPPED]\n";
            }
        }
    }

    if (!llm_needed) return 0;

    std::cout << "LLM: " << cfg.model << " @ " << cfg.endpoint << "...\n";

    xcore::LLMConfig llm_cfg;
    llm_cfg.model    = cfg.model;
    llm_cfg.endpoint = cfg.endpoint;

    xcore::LLMClient client(llm_cfg);
    std::string accumulated;
    auto resp = client.chat_stream(
        xcore::prompts::classifier,
        scan_result.dump(2, ' ', false, nlohmann::json::error_handler_t::replace),
        [&](const std::string& token) {
            std::cout << token << std::flush;
            accumulated += token;
        }
    );

    if (!accumulated.empty()) {
        if (cfg.no_store) {
            std::cout << "\n---\n"
                      << "[--no-store] classification not written; case DB "
                      << "unchanged (" << casedb.case_count() << " cases)\n";
            return 0;
        }
        bool stored = casedb.store_classify_result(file_path, scan_result, accumulated);
        std::cout << "\n---\n"
                  << "Total cases: " << casedb.case_count()
                  << "  " << (stored ? "stored" : "update failed") << "\n";
    } else {
        std::cerr << "\nLLM error: " << resp.error << "\n";
        return 1;
    }
    return 0;
}

// ─── Deobfuscate pipeline (Phase 1-5) ─────────────────────

static int run_deobfuscate(const RunConfig& cfg) {
    // Use bare "node" since it's on PATH; _popen handles quoted paths poorly
    std::string node = "node";
    std::string script_dir = "modules\\deobfuscator";
    std::string out_dir    = cfg.output_dir.empty() ? "temp" : cfg.output_dir;

    // Ensure output dir exists
    fs::create_directories(out_dir);

    fs::path target_p(cfg.file);
    std::string base_name = target_p.stem().string();
    std::string inst_path = out_dir + "\\" + base_name + "_inst.js";
    std::string trace_path = out_dir + "\\" + base_name + "_trace.json";
    std::string unfl_path  = out_dir + "\\" + base_name + "_unflattened.js";

    // ── Phase 1: Instrument ───────────────────────────────
    std::cout << "[Phase 1] Instrumenting " << cfg.file << "...\n";
    std::string cmd1 = node + " \"" + script_dir + "\\instrument.js\""
                     + " --input \"" + cfg.file + "\""
                     + " --output \"" + inst_path + "\" --json 2>&1";
    std::string out1 = exec_cmd(cmd1);
    // Trim trailing non-JSON noise (stderr leaks)
    auto brace_end = out1.find_last_of('}');
    if (brace_end != std::string::npos && brace_end > 0) {
        out1 = out1.substr(0, brace_end + 1);
    }

    try {
        auto j1 = json::parse(out1);
        std::cout << "  patches=" << json_int(j1, "patches")
                  << "  state_machines=" << json_int(j1, "state_machines_detected") << "\n";
    } catch (...) {
        std::cerr << "  Instrument parse error: " << out1.substr(0, 200) << "\n";
    }

    // ── Phase 2-3: Sandbox + Trace ────────────────────────
    std::cout << "[Phase 2+3] Running sandbox with trace capture...\n";
    std::string cmd2 = node + " \"" + script_dir + "\\runner.js\""
                     + " --input \"" + inst_path + "\""
                     + " --entry \"" + cfg.entry_fn + "\""
                     + " --inst --trace-out \"" + trace_path + "\" --json 2>&1";
    std::string out2 = exec_cmd(cmd2);
    // Extract JSON object from possibly mixed stdout/stderr
    // runner.js writes JSON to stdout first, then Node may emit warnings to stderr
    // _popen merges both; we need the first complete JSON object
    auto brace_start2 = out2.find('{');
    // Track brace depth to find matching close
    if (brace_start2 != std::string::npos) {
        int depth = 0;
        size_t i = brace_start2;
        for (; i < out2.size(); ++i) {
            if (out2[i] == '{') depth++;
            else if (out2[i] == '}') { depth--; if (depth == 0) break; }
        }
        if (depth == 0 && i < out2.size()) {
            out2 = out2.substr(brace_start2, i - brace_start2 + 1);
        }
    }

    std::string orig_h5st;
    bool entry_found = false;
    try {
        auto j2 = json::parse(out2);
        std::string status = json_str(j2, "status", "unknown");
        orig_h5st   = json_str(j2, "h5st");
        entry_found = json_bool(j2, "entry_found");
        std::cout << "  status=" << status;
        if (!entry_found) std::cout << "  entry_found=no (" << cfg.entry_fn << ")";
        if (!orig_h5st.empty()) std::cout << "  h5st=" << orig_h5st.substr(0, 60) << "...";
        std::cout << "\n";
    } catch (...) {
        std::cerr << "  Sandbox parse error: " << out2.substr(0, 200) << "\n";
    }

    // ── Phase 4: Native flatten ───────────────────────────
    std::cout << "[Phase 4] Native C++ flatten engine...\n";
    std::ifstream tfile(trace_path);
    if (!tfile.is_open()) {
        std::cerr << "  Error: cannot read trace file: " << trace_path << "\n";
        if (!entry_found) {
            std::cerr << "  Cause: entry '" << cfg.entry_fn << "' was not resolved in the target,\n"
                      << "         so nothing was executed and no trace could be captured.\n"
                      << "         Pass --entry <expr> matching this file's real global entry,\n"
                      << "         e.g. --entry window.MySign.sign or --entry myFunc.\n";
        } else {
            std::cerr << "  Cause: entry ran but emitted no trace - the target may contain no\n"
                      << "         instrumentable state machine (instrument.js reported patches=0).\n";
        }
        return 1;
    }
    json trace_json;
    try { trace_json = json::parse(tfile); }
    catch (const std::exception& e) {
        std::cerr << "  Trace JSON parse error: " << e.what() << "\n";
        return 1;
    }

    auto flatten_result = xcore::flatten::process(trace_json);
    std::cout << "  linearized=" << flatten_result.linearized.size()
              << "  loops=" << flatten_result.loops.size()
              << "  dead=" << flatten_result.dead_cases_removed << "/" << flatten_result.total_cases
              << "  rle_segments=" << flatten_result.rle.size() << "\n";

    // Write flatten output
    std::string flatten_json_path = out_dir + "\\" + base_name + "_flatten.json";
    std::ofstream fout(flatten_json_path);
    fout << flatten_result.to_json().dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
    fout.close();
    std::cout << "  Flatten analysis written to: " << flatten_json_path << "\n";

    // ── Phase 4b: Emit dead-case-eliminated JS ────────────
    std::cout << "[Phase 4b] Emitting unflattened JS...\n";
    std::string cmd3 = node + " \"" + script_dir + "\\emitter.js\""
                     + " --input \"" + cfg.file + "\""
                     + " --flatten \"" + flatten_json_path + "\""
                     + " --output \"" + unfl_path + "\" --json 2>&1";
    std::string out3 = exec_cmd(cmd3);
    try {
        auto j3 = json::parse(out3);
        std::cout << "  status=" << json_str(j3, "status", "unknown")
                  << "  output_size=" << json_int(j3, "output_size")
                  << "  alive_cases=" << json_int(j3, "alive_cases") << "\n";
    } catch (...) {
        std::cerr << "  Emitter parse error: " << out3.substr(0, 200) << "\n";
    }

    // ── Phase 5: Auto-verify (freeze + byte-match) ────────
    std::cout << "[Phase 5] Auto-verifying (freeze mode)...\n";
    {
        xcore::Verifier verifier(node, script_dir + "\\runner.js", cfg.entry_fn);
        auto vres = verifier.verify(cfg.file, unfl_path);
        if (vres.match) {
            std::cout << "  [PASS] 100% Exact Byte-Match\n";
            std::cout << "  h5st: " << vres.original_h5st.substr(0, 80) << "...\n";
        } else {
            std::cout << "  [FAIL] Mismatch detected\n";
            if (!vres.error.empty())
                std::cout << "  Error: " << vres.error << "\n";
        }
    }

    return 0;
}

// ─── Verify subcommand (standalone) ───────────────────────

static int run_verify(const RunConfig& cfg) {

    std::string node = "node";
    std::string runner = "modules\\deobfuscator\\runner.js";

    // With --json, stdout carries the document and the human lines move to
    // stderr -- same contract as scan.
    //
    // The document is written by briefly handing std::cout its real buffer back,
    // rather than by constructing a second std::ostream over it. A local
    // ostream built from the saved streambuf aborted inside this function
    // (0xC0000409, FAST_FAIL_FATAL_APP_EXIT) before printing a byte, and an
    // abort here is a crash the caller cannot diagnose: no output, no message,
    // just a dead process. One stream, swapped, has no such lifetime to get
    // wrong.
    JsonModeRedirect redirect(cfg.json_output);

    xcore::Verifier verifier(node, runner);
    std::cerr << "[MARK v2 verifier constructed]\n";
    auto result = verifier.verify(cfg.file, cfg.rules_path); // file=original, rules_path=flattened
    std::cerr << "[MARK v3 verify returned]\n";

    // First differing byte, computed once for both renderings. Reporting only
    // "mismatch" tells a caller nothing it can act on.
    size_t diff = 0;
    {
        auto& a = result.original_h5st;
        auto& b = result.flattened_h5st;
        while (diff < a.size() && diff < b.size() && a[diff] == b[diff]) diff++;
    }
    const bool has_diff = diff < result.original_h5st.size();

    std::cerr << "[MARK v4 before json branch]\n";
    if (cfg.json_output) {
        std::cerr << "[MARK v5 in json branch]\n";
        json out;
        out["tool"] = "xcore";
        out["version"] = XCORE_VERSION;
        out["verified"] = result.match;
        out["original"] = cfg.file;
        out["flattened"] = cfg.rules_path;
        out["h5st_original"] = result.original_h5st;
        out["h5st_flattened"] = result.flattened_h5st;
        std::cerr << "[MARK v6 json built]\n";
        if (!result.match) {
            if (!result.error.empty()) out["error"] = result.error;
            if (has_diff) out["first_diff_at"] = diff;
        }
        std::cerr << "[MARK v7 before dump]\n";
        std::streambuf* saved = std::cout.rdbuf(redirect.real());
        std::cout << out.dump(2, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
        std::cout.flush();
        std::cout.rdbuf(saved);
        std::cerr << "[MARK v8 printed]\n";
        return result.match ? 0 : 1;
    }

    if (result.match) {
        std::cout << "[PASS] Exact byte-match\n";
        std::cout << "h5st: " << result.original_h5st.substr(0, 100) << "...\n";
        return 0;
    } else {
        std::cout << "[FAIL] Mismatch\n";
        if (!result.error.empty())
            std::cout << "Error: " << result.error << "\n";
        else {
            std::cout << "Original:  " << result.original_h5st.substr(0, 60) << "...\n";
            std::cout << "Flattened: " << result.flattened_h5st.substr(0, 60) << "...\n";
            if (has_diff)
                std::cout << "First diff at byte " << diff << ": '"
                          << result.original_h5st[diff] << "' vs '"
                          << result.flattened_h5st[diff] << "'\n";
        }
        return 1;
    }
}

// ─── Main ─────────────────────────────────────────────────

int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    if (argc < 2) { print_usage(); return 1; }
    std::string cmd = argv[1];

    // ── db stats ──────────────────────────────────────────
    if (cmd == "db") {
        std::string sub = (argc > 2) ? argv[2] : "stats";
        std::string dbp = "tools/cases.db";
        for (int i = 2; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--db" && i + 1 < argc) dbp = argv[++i];
        }
        if (sub == "stats") {
            xcore::CaseDB casedb(dbp);
            if (!casedb.open()) {
                std::cerr << "Cannot open DB: " << dbp << "\n";
                return 1;
            }
            std::cout << casedb.stats().dump(2, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
            return 0;
        }
        print_usage(); return 1;
    }

    // ── help ──────────────────────────────────────────────
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        print_usage(); return 0;
    }

    // ── pipeline ──────────────────────────────────────────
    if (cmd == "pipeline") {
        std::cout << "[Phase 3e] Pipeline not yet integrated. Use individual modules:\n";
        std::cout << "  node modules/deobfuscator/scorer.js <dir>\n";
        std::cout << "  node modules/deobfuscator/slicer.js <input> --entry signSync --max-depth 1\n";
        std::cout << "  node modules/deobfuscator/prep.js --sliced <a> --unflattened <b>\n";
        std::cout << "  node modules/deobfuscator/autoheal.js heal --python <py> --runner <runner> --unflattened <js>\n";
        return 0;
    }

    // ── deobfuscate ───────────────────────────────────────
    if (cmd == "deobfuscate") {
        RunConfig cfg = parse_args(argc, argv);
        return run_deobfuscate(cfg);
    }

    // ── verify ────────────────────────────────────────────
    if (cmd == "verify") {
        RunConfig cfg = parse_args(argc, argv);
        return run_verify(cfg);
    }

    // ── native ───────────────────────────────────────────
    if (cmd == "native") {
        std::string apk_path;
        std::string so_path;
        std::string mode = "active";
        std::string output_dir;
        std::string fingerprints_dir;
        bool json_only = false;
        bool full = false;
        long max_scan_size = 0;
        std::string generate_probe_path;
        std::string generate_probe_out;
        bool generate_probe_spawn = false;
        std::string pipeline_apk;
        std::string pipeline_out;
        bool pipeline_spawn = false;

        for (int i = 2; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--apk" && i + 1 < argc)             apk_path = argv[++i];
            else if (a == "--so" && i + 1 < argc)          so_path = argv[++i];
            else if (a == "--mode" && i + 1 < argc)        mode = argv[++i];
            else if (a == "--output" && i + 1 < argc)      output_dir = argv[++i];
            else if (a == "--fingerprints-dir" && i + 1 < argc) fingerprints_dir = argv[++i];
            else if (a == "--json")                        json_only = true;
            else if (a == "--full")                        full = true;
            else if (a == "--max-scan-size" && i + 1 < argc) max_scan_size = std::atol(argv[++i]);
            else if (a == "--generate-probe" && i + 1 < argc) generate_probe_path = argv[++i];
            else if (a == "--out" && i + 1 < argc)         generate_probe_out = argv[++i];
            else if (a == "--pipeline" && i + 1 < argc)    pipeline_apk = argv[++i];
            else if (a == "--spawn") {
                generate_probe_spawn = true;
                pipeline_spawn = true;
            }
        }

        // Same contract as `scan`: with --json, stdout carries the document and
        // nothing else. Progress from the node scanners goes to stderr.
        JsonModeRedirect redirect(json_only);
        std::ostream doc(redirect.real());

        // ── --generate-probe: Phase 4c probe generation ──
        if (!generate_probe_path.empty()) {
            std::string node = find_node();
            std::string script_path = get_exe_dir() + "\\modules\\native\\probe_generator.js";
            std::string cmd_str = "\"" + node + "\" \"" + script_path + "\""
                                + " --scan-result \"" + generate_probe_path + "\"";
            if (!generate_probe_out.empty())
                cmd_str += " --out \"" + generate_probe_out + "\"";
            if (generate_probe_spawn)
                cmd_str += " --spawn";
            cmd_str += " 2>&1";

            std::string result = exec_cmd(cmd_str);

            std::cout << "\n══════════════════════════════════════════════\n";
            std::cout << " X-Core Phase 4c: Probe Generator\n";
            std::cout << "══════════════════════════════════════════════\n";
            std::cout << " Scan result  : " << generate_probe_path << "\n";

            if (!generate_probe_out.empty())
                std::cout << " Output       : " << generate_probe_out << "\n";

            std::cout << " Spawn mode   : " << (generate_probe_spawn ? "YES" : "NO") << "\n";

            // Display stderr output (stats from probe_generator.js)
            std::cout << result;
            std::cout << "══════════════════════════════════════════════\n";

            return 0;
        }

        // ── --pipeline: Phase 4a→4b→4c full pipeline ─────
        if (!pipeline_apk.empty()) {
            std::string node = find_node();
            std::string script_path = get_exe_dir() + "\\modules\\native\\pipeline_native.js";
            std::string cmd_str = "\"" + node + "\" \"" + script_path + "\""
                                + " --apk \"" + pipeline_apk + "\"";
            if (!pipeline_out.empty() || !output_dir.empty()) {
                std::string od = pipeline_out.empty() ? output_dir : pipeline_out;
                cmd_str += " --output-dir \"" + od + "\"";
            }
            if (pipeline_spawn)
                cmd_str += " --spawn";
            cmd_str += " 2>&1";

            std::cout << "\n══════════════════════════════════════════════\n";
            std::cout << " X-Core Phase 4c: Native Pipeline (4a→4b→4c)\n";
            std::cout << "══════════════════════════════════════════════\n";
            std::cout << " APK          : " << pipeline_apk << "\n";
            std::cout << " Spawn mode   : " << (pipeline_spawn ? "YES" : "NO") << "\n";
            std::cout << " Running...\n";

            std::string result = exec_cmd(cmd_str);

            // Parse final JSON from pipeline output
            try {
                auto brace_start = result.find('{');
                if (brace_start != std::string::npos) {
                    int depth = 0;
                    size_t i = brace_start;
                    for (; i < result.size(); ++i) {
                        if (result[i] == '{') depth++;
                        else if (result[i] == '}') { depth--; if (depth == 0) break; }
                    }
                    if (depth == 0 && i < result.size()) {
                        std::string json_str = result.substr(brace_start, i - brace_start + 1);
                        auto j = json::parse(json_str);
                        std::cout << "\n Status       : " << j.value("status", "unknown") << "\n";
                        std::cout << " Output dir   : " << j.value("output_dir", "") << "\n";
                        std::cout << " Shell        : " << j.value("shell", json::object()).value("name", "?") << "\n";
                        std::cout << " Targets      : " << j.value("targets_scanned", 0) << "\n";
                        std::cout << " Probes       : " << j.value("probes_generated", 0) << "\n";
                        if (j.contains("summary_file"))
                            std::cout << " Summary      : " << j.value("summary_file", "") << "\n";
                    }
                }
            } catch (...) {
                // Not JSON — print raw
                std::cout << result;
            }

            std::cout << "══════════════════════════════════════════════\n";
            return 0;
        }

        // ── --so mode: Phase 4b target scanner ─────────
        if (!so_path.empty()) {
            std::string node = find_node();
            std::string script_path = get_exe_dir() + "\\modules\\native\\target_scanner.js";
            std::string cmd_str = "\"" + node + "\" \"" + script_path + "\""
                                + " --so \"" + so_path + "\"";
            if (!fingerprints_dir.empty())
                cmd_str += " --fingerprints-dir \"" + fingerprints_dir + "\"";
            if (json_only)
                cmd_str += " --json";
            if (max_scan_size > 0)
                cmd_str += " --max-scan-size " + std::to_string(max_scan_size);
            cmd_str += " 2>&1";

            std::string result = exec_cmd(cmd_str);

            // Parse JSON result
            try {
                auto brace_start = result.find('{');
                if (brace_start != std::string::npos) {
                    int depth = 0;
                    size_t i = brace_start;
                    for (; i < result.size(); ++i) {
                        if (result[i] == '{') depth++;
                        else if (result[i] == '}') { depth--; if (depth == 0) break; }
                    }
                    if (depth == 0 && i < result.size()) {
                        std::string json_str = result.substr(brace_start, i - brace_start + 1);
                        auto j = json::parse(json_str);

                        // --json means "emit the scanner's payload". The code below
                        // only renders the parsed object back into a human summary,
                        // which is why `native --so --json` used to print zero JSON
                        // and every machine consumer (bridge, GUI) got nothing.
                        if (json_only) {
                            doc << json_str << "\n";
                            doc.flush();
                            // Exit codes, covering the scanner's whole verdict
                            // vocabulary (the previous mapping knew only
                            // annotate/pending/none, none of which the scanner
                            // emits any more, so everything fell through to 0):
                            //   0 = annotate/flag  something to act on
                            //   1 = clean          nothing found
                            //   2 = note/unknown   signals present, unattributed
                            //   3 = error          scan incomplete, says nothing
                            std::string vj = j.value("verdict", "");
                            if (vj == "annotate" || vj == "flag") return 0;
                            if (vj == "clean")   return 1;
                            if (vj == "note" || vj == "unknown") return 2;
                            if (vj == "error")   return 3;
                            return 2;   // unrecognised verdict is not a success
                        }

                        std::cout << "\n══════════════════════════════════════════════\n";
                        std::cout << " X-Core Native Target Scanner (Phase 4b)\n";
                        std::cout << "══════════════════════════════════════════════\n";
                        std::cout << " Target       : " << j.value("target", "?") << "\n";
                        std::cout << " Arch         : " << j.value("arch", "?") << "\n";
                        std::cout << " Final score  : " << j.value("final_score", 0.0) << "\n";
                        {
                            std::string vj = j.value("verdict", "unknown");
                            std::cout << " Verdict      : " << vj;
                            // `clean` and `unknown` both mean "below the
                            // attribution threshold"; the difference is whether
                            // any layer hit at all. Spell that out, because
                            // reading `clean` as "nothing is protected here" is
                            // exactly the wrong conclusion for a packed target.
                            if (vj == "unknown")
                                std::cout << "   (有信号但不足以归因：不等于干净，需人工判断)";
                            else if (vj == "clean")
                                std::cout << "   (各层均无命中)";
                            else if (vj == "error")
                                std::cout << "   (有子层失败，本次扫描结论不可信)";
                            std::cout << "\n";
                        }

                        if (j.contains("algorithm") && !j.value("algorithm", "").empty())
                            std::cout << " Algorithm    : " << j.value("algorithm", "") << "\n";
                        if (j.contains("library") && j["library"].is_string())
                            std::cout << " Library      : " << j["library"].get<std::string>() << "\n";

                        // Layer breakdown
                        if (j.contains("layers")) {
                            std::cout << "\n Layer scores:\n";
                            for (auto& [name, layer] : j["layers"].items()) {
                                std::cout << "   " << name << ":  score=" << layer.value("score", 0.0);
                                if (layer.contains("hits") && layer["hits"].is_array()) {
                                    std::cout << "  hits=" << layer["hits"].size();
                                    auto& h = layer["hits"];
                                    if (h.size() <= 5) {
                                        std::cout << " [";
                                        for (size_t k = 0; k < h.size(); ++k) {
                                            if (k) std::cout << ", ";
                                            std::cout << render_hit(h[k]);
                                        }
                                        std::cout << "]";
                                    } else {
                                        std::cout << " [";
                                        for (size_t k = 0; k < 3; ++k) {
                                            if (k) std::cout << ", ";
                                            std::cout << render_hit(h[k]);
                                        }
                                        std::cout << ", ... +" << (h.size() - 3) << " more]";
                                    }
                                }
                                std::cout << "\n";
                            }
                        }

                        // Xrefs summary
                        if (j.contains("xrefs") && j["xrefs"].is_array()) {
                            std::cout << "\n String Xrefs: " << j["xrefs"].size() << " entries\n";
                            int shown = 0;
                            for (auto& x : j["xrefs"]) {
                                if (shown >= 5) { std::cout << "   ...\n"; break; }
                                std::cout << "   " << x.value("string", "?")
                                          << " @ " << x.value("at", "?")
                                          << " in " << x.value("func", "?") << "\n";
                                shown++;
                            }
                        }

                        std::cout << "══════════════════════════════════════════════\n";

                        // Same exit-code contract as the --json path above, so a
                        // script behaves identically whether or not it asked for
                        // machine-readable output. This used to return 0
                        // unconditionally, which made `xcore native --so x` look
                        // like a success even when the scan had failed.
                        std::string v = j.value("verdict", "");
                        if (v == "annotate" || v == "flag") return 0;
                        if (v == "clean")  return 1;
                        if (v == "note" || v == "unknown") return 2;
                        if (v == "error")  return 3;
                        return 2;
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Parse error: " << e.what() << "\n";
            }

            std::cout << result << "\n";
            return 0;
        }

        // ── --apk mode: Phase 4a shell classifier ──────
        if (apk_path.empty()) {
            std::cerr << "Error: one of --apk, --so, --generate-probe, --pipeline is required\n";
            std::cerr << "Usage:\n";
            std::cerr << "  xcore native --apk <path> [--mode passive] [--json] [--output <dir>] [--full]\n";
            std::cerr << "  xcore native --so <path> [--fingerprints-dir <dir>] [--json]\n";
            std::cerr << "  xcore native --generate-probe <scan.json> [--out <script.js>] [--spawn]\n";
            std::cerr << "  xcore native --pipeline <apk> [--output <dir>] [--spawn]\n";
            return 1;
        }

        std::string node = find_node();
        std::string script_path = get_exe_dir() + "\\modules\\native\\shell_classifier.js";
        std::string cmd_str = "\"" + node + "\" \"" + script_path + "\""
                            + " --apk \"" + apk_path + "\""
                            + " --mode " + mode;
        if (!output_dir.empty())
            cmd_str += " --output \"" + output_dir + "\"";
        if (json_only)
            cmd_str += " --json";
        cmd_str += " 2>&1";

        std::string result = exec_cmd(cmd_str);

        // Try to parse JSON result
        try {
            // Find JSON object boundaries
            auto brace_start = result.find('{');
            if (brace_start != std::string::npos) {
                int depth = 0;
                size_t i = brace_start;
                for (; i < result.size(); ++i) {
                    if (result[i] == '{') depth++;
                    else if (result[i] == '}') { depth--; if (depth == 0) break; }
                }
                if (depth == 0 && i < result.size()) {
                    std::string json_str = result.substr(brace_start, i - brace_start + 1);
                    auto j = json::parse(json_str);

                    std::string shell_name = j.value("shell", json::object()).value("name", "unknown");
                    std::string confidence = j.value("shell", json::object()).value("confidence", "none");
                    std::string rec = j.value("recommendation", "unknown");
                    std::string next = j.value("next_step", "manual");

                    std::cout << "\n══════════════════════════════════════════════\n";
                    std::cout << " X-Core Native Shell Classifier (Phase 4a)\n";
                    std::cout << "══════════════════════════════════════════════\n";
                    std::cout << " APK          : " << j.value("apk", "?") << "\n";
                    std::cout << " Package      : " << j.value("package_name", "?") << "\n";
                    std::cout << " Shell        : " << shell_name << "\n";
                    std::cout << " Confidence   : " << confidence << "\n";
                    std::cout << " Class        : " << rec << "\n";
                    std::cout << " Next step    : " << next << "\n";

                    if (j.contains("frida_script")) {
                        std::cout << " Frida script : " << j.value("frida_script", "") << "\n";
                        std::cout << " Spawn cmd    : " << j.value("frida_spawn_cmd", "") << "\n";
                        std::cout << " Attach cmd   : " << j.value("frida_attach_cmd", "") << "\n";
                    }

                    // Show evidence
                    if (j.contains("shell") && j["shell"].contains("evidence")) {
                        auto& evidence = j["shell"]["evidence"];
                        if (evidence.is_array() && evidence.size() > 0) {
                            std::cout << "\n Evidence:\n";
                            for (auto& e : evidence) {
                                std::cout << "   [" << e.value("type", "?") << "] "
                                          << e.value("detail", "") << "\n";
                            }
                        }
                    }

                    // --full: auto-proceed to Phase 4b target scan if clean/light_shell
                    if (full && (rec == "clean" || rec == "light_shell")) {
                        std::string lib_path = j.value("native_lib", "");
                        if (!lib_path.empty() && fs::exists(lib_path)) {
                            std::cout << "\n══════════════════════════════════════════════\n";
                            std::cout << " [--full] Auto-proceeding to Phase 4b targeting...\n";
                            std::cout << "══════════════════════════════════════════════\n\n";

                            std::string target_script = get_exe_dir() + "\\modules\\native\\target_scanner.js";
                            std::string target_cmd = "\"" + node + "\" \"" + target_script + "\""
                                                   + " --so \"" + lib_path + "\"";
                            if (!fingerprints_dir.empty())
                                target_cmd += " --fingerprints-dir \"" + fingerprints_dir + "\"";
                            if (json_only)
                                target_cmd += " --json";
                            if (max_scan_size > 0)
                                target_cmd += " --max-scan-size " + std::to_string(max_scan_size);
                            target_cmd += " 2>&1";

                            std::string tresult = exec_cmd(target_cmd);
                            try {
                                auto tbrace = tresult.find('{');
                                if (tbrace != std::string::npos) {
                                    int td = 0;
                                    size_t ti = tbrace;
                                    for (; ti < tresult.size(); ++ti) {
                                        if (tresult[ti] == '{') td++;
                                        else if (tresult[ti] == '}') { td--; if (td == 0) break; }
                                    }
                                    if (td == 0 && ti < tresult.size()) {
                                        auto tj = json::parse(tresult.substr(tbrace, ti - tbrace + 1));
                                        std::cout << "\n══════════════════════════════════════════════\n";
                                        std::cout << " Target: " << tj.value("target", "?")
                                                  << "  Score: " << tj.value("final_score", 0.0)
                                                  << "  Verdict: " << tj.value("verdict", "?") << "\n";
                                        std::cout << "══════════════════════════════════════════════\n";
                                    } else {
                                        std::cout << tresult << "\n";
                                    }
                                } else {
                                    std::cout << tresult << "\n";
                                }
                            } catch (...) {
                                std::cout << tresult << "\n";
                            }
                        }
                    }

                    std::cout << "══════════════════════════════════════════════\n";

                    // Exit code based on recommendation
                    if (rec == "clean") return 0;
                    if (rec == "light_shell") return 2;
                    return 3;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "Parse error: " << e.what() << "\n";
        }

        // Fallback: print raw output
        std::cout << result << "\n";
        return 0;
    }

    RunConfig cfg = parse_args(argc, argv);

    // From here on, with --json, everything written to std::cout goes to stderr;
    // only the document is written to the real stdout, through this.
    JsonModeRedirect redirect(cfg.json_output);
    std::ostream doc(redirect.real());

    // ── pipe ──────────────────────────────────────────────
    if (cmd == "pipe") {
        auto rules = load_rules(cfg.rules_path);
        if (!cfg.fingerprints_dir.empty())
            load_fingerprints(cfg.fingerprints_dir);
        auto result = scan_stream(std::cin, "pipe://stdin");
        // `--brief` was the only way to get the document out of pipe, which is
        // a confusing name for it: --brief reads as "less output", not "JSON".
        // --json is now accepted and means the same thing.
        if (cfg.brief || cfg.json_output) doc << result.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
        return run_pipeline(result, "pipe://stdin", cfg);
    }

    // ── scan / classify ───────────────────────────────────
    auto rules = load_rules(cfg.rules_path);
    if (!cfg.fingerprints_dir.empty())
        load_fingerprints(cfg.fingerprints_dir);

    // Noise gate: skip files too small to contain meaningful crypto
    {
        std::error_code ec;
        auto fsize = fs::file_size(cfg.file, ec);
        if (!ec && (size_t)fsize < MIN_SCAN_SIZE) {
            std::cout << "[noise-gate] Skipping " << cfg.file << " (" << fsize << " bytes < " << MIN_SCAN_SIZE << ")\n";
            return 0;
        }
    }

    json out;
    out["tool"] = "xcore"; out["version"] = XCORE_VERSION;
    out["file"] = cfg.file;

    auto result = scan(cfg.file, rules);
    out["result"] = result;

    if (!cfg.brief) {
        std::cout << "Scanned " << result["size"] << "B  "
                  << result["match_count"] << " rules hit\n";
    }

    if (cfg.json_output) {
        // The one thing that belongs on the real stdout.
        doc << out.dump(2, ' ', false, nlohmann::json::error_handler_t::replace) << "\n";
        doc.flush();
    }

    return run_pipeline(result, cfg.file, cfg);
}
