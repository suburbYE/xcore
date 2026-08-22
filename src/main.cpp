/**
 * X-Core unified CLI v0.18.0
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
};

static void print_usage() {
    std::cout
        << "X-Core v0.18.0   Rule engine + Deobfuscator + Native Targeting\n"
        << "─────────────────────────────────────────────────────────────\n"
        << "  xcore scan        <file> <rules.json> [--fingerprints-dir <dir>] [--model <m>] [--db <path>] [--brief] [--json]\n"
        << "  xcore pipe        <rules.json> [--fingerprints-dir <dir>] [--model <m>] [--db <path>]\n"
        << "  xcore db          stats [--db <path>]\n"
        << "  xcore classify    <file> <rules.json> [--model <m>] [--db <path>]\n"
        << "  xcore deobfuscate <target.js> [--output <dir>] [--entry <fn>] [--verify]\n"
        << "  xcore verify      <original.js> <flattened.js>\n"
        << "  xcore pipeline    --url <url> --entry <fn> --target-python <path>\n"
        << "  xcore native      --apk <path> [--mode passive] [--json] [--output <dir>] [--full]\n"
        << "  xcore native      --so <path> [--fingerprints-dir <dir>] [--json]\n"
        << "  xcore native      --generate-probe <scan.json> [--out <script.js>] [--spawn]\n"
        << "  xcore native      --pipeline <apk> [--output <dir>] [--spawn]\n"
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
                  << " (already known)  " << existing.llm_confidence
                  << "  " << existing.llm_algorithms.dump() << "\n";
    }

    auto similar = casedb.find_similar(scan_result, 3);
    bool llm_needed = true;

    if (!similar.empty() && !cfg.force_llm) {
        if (!cfg.brief) {
            for (auto& s : similar) {
                std::cout << "  #" << s.info.id
                          << "  sim=" << s.similarity
                          << "  w5=" << (s.skip_llm ? "LOCK" : "-")
                          << "  " << s.info.llm_algorithms.dump() << "\n";
            }
        }
        if (similar[0].skip_llm) {
            llm_needed = false;
            if (similar[0].similarity >= 0.40 && similar[0].similarity <= 0.55) {
                std::cout << "[!] BORDERLINE LOCK  sim=" << similar[0].similarity
                          << " -> Case #" << similar[0].info.id << "  "
                          << similar[0].info.llm_algorithms.dump() << "\n";
            } else {
                std::cout << "Hard-lock  sim=" << similar[0].similarity
                          << " -> Case #" << similar[0].info.id << "  "
                          << similar[0].info.llm_algorithms.dump()
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
        scan_result.dump(2),
        [&](const std::string& token) {
            std::cout << token << std::flush;
            accumulated += token;
        }
    );

    if (!accumulated.empty()) {
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
        std::cout << "  patches=" << j1.value("patches", 0)
                  << "  state_machines=" << j1.value("state_machines_detected", 0) << "\n";
    } catch (...) {
        std::cerr << "  Instrument parse error: " << out1.substr(0, 200) << "\n";
    }

    // ── Phase 2-3: Sandbox + Trace ────────────────────────
    std::cout << "[Phase 2+3] Running sandbox with trace capture...\n";
    std::string cmd2 = node + " \"" + script_dir + "\\runner.js\""
                     + " --input \"" + inst_path + "\""
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
    try {
        auto j2 = json::parse(out2);
        std::string status = j2.value("status", "unknown");
        orig_h5st = j2.value("h5st", "");
        std::cout << "  status=" << status;
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
    fout << flatten_result.to_json().dump(2);
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
        std::cout << "  status=" << j3.value("status", "unknown")
                  << "  output_size=" << j3.value("output_size", 0)
                  << "  alive_cases=" << j3.value("alive_cases", 0) << "\n";
    } catch (...) {
        std::cerr << "  Emitter parse error: " << out3.substr(0, 200) << "\n";
    }

    // ── Phase 5: Auto-verify (freeze + byte-match) ────────
    std::cout << "[Phase 5] Auto-verifying (freeze mode)...\n";
    {
        xcore::Verifier verifier(node, script_dir + "\\runner.js");
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

    xcore::Verifier verifier(node, runner);
    auto result = verifier.verify(cfg.file, cfg.rules_path); // file=original, rules_path=flattened

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
            // Show first differing position
            size_t diff = 0;
            auto& a = result.original_h5st;
            auto& b = result.flattened_h5st;
            while (diff < a.size() && diff < b.size() && a[diff] == b[diff]) diff++;
            if (diff < a.size())
                std::cout << "First diff at byte " << diff << ": '" << a[diff] << "' vs '" << b[diff] << "'\n";
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
            std::cout << casedb.stats().dump(2) << "\n";
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
            else if (a == "--generate-probe" && i + 1 < argc) generate_probe_path = argv[++i];
            else if (a == "--out" && i + 1 < argc)         generate_probe_out = argv[++i];
            else if (a == "--pipeline" && i + 1 < argc)    pipeline_apk = argv[++i];
            else if (a == "--spawn") {
                generate_probe_spawn = true;
                pipeline_spawn = true;
            }
        }

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

                        std::cout << "\n══════════════════════════════════════════════\n";
                        std::cout << " X-Core Native Target Scanner (Phase 4b)\n";
                        std::cout << "══════════════════════════════════════════════\n";
                        std::cout << " Target       : " << j.value("target", "?") << "\n";
                        std::cout << " Arch         : " << j.value("arch", "?") << "\n";
                        std::cout << " Final score  : " << j.value("final_score", 0.0) << "\n";
                        std::cout << " Verdict      : " << j.value("verdict", "unknown") << "\n";

                        if (j.contains("algorithm") && !j.value("algorithm", "").empty())
                            std::cout << " Algorithm    : " << j.value("algorithm", "") << "\n";

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
                                            if (h[k].is_string()) std::cout << h[k].get<std::string>();
                                        }
                                        std::cout << "]";
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

                        // Exit code based on verdict
                        std::string v = j.value("verdict", "");
                        if (v == "annotate") return 0;
                        if (v == "pending") return 2;
                        if (v == "none") return 1;
                        return 0;
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

    // ── pipe ──────────────────────────────────────────────
    if (cmd == "pipe") {
        auto rules = load_rules(cfg.rules_path);
        if (!cfg.fingerprints_dir.empty())
            load_fingerprints(cfg.fingerprints_dir);
        auto result = scan_stream(std::cin, "pipe://stdin");
        if (cfg.brief) std::cout << result.dump() << "\n";
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
    out["tool"] = "xcore"; out["version"] = "0.18.0";
    out["file"] = cfg.file;

    auto result = scan(cfg.file, rules);
    out["result"] = result;

    if (!cfg.brief) {
        std::cout << "Scanned " << result["size"] << "B  "
                  << result["match_count"] << " rules hit\n";
    }

    if (cfg.json_output) {
        std::cout << out.dump(2) << "\n";
    }

    return run_pipeline(result, cfg.file, cfg);
}
