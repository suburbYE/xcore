/**
 * xcore verify module — h5st equivalence checker
 *
 * Spawns node runner.js with --freeze on original + flattened JS,
 * extracts h5st, compares byte-exact.
 */

#pragma once
#include <string>
#include <cstdio>
#include <memory>
#include <array>

#ifdef _WIN32
#include <windows.h>
#endif

namespace xcore {

struct VerifyResult {
    bool        match = false;
    std::string original_h5st;
    std::string flattened_h5st;
    std::string error;
};

class Verifier {
    std::string node_path;
    std::string runner_path;

    static std::string exec_cmd(const std::string& cmd) {
        char buf[256];
        std::string result;
#ifdef _WIN32
        FILE* pipe = _popen(cmd.c_str(), "r");
#else
        FILE* pipe = popen(cmd.c_str(), "r");
#endif
        if (!pipe) return "";
        while (fgets(buf, sizeof(buf), pipe) != nullptr)
            result += buf;
#ifdef _WIN32
        _pclose(pipe);
#else
        pclose(pipe);
#endif
        return result;
    }

    static std::string extract_h5st(const std::string& json_str) {
        auto pos = json_str.find("\"h5st\":\"");
        if (pos == std::string::npos) return "";
        pos += 8;
        auto end = json_str.find('"', pos);
        if (end == std::string::npos) return "";
        return json_str.substr(pos, end - pos);
    }

public:
    Verifier(const std::string& node, const std::string& runner)
        : node_path(node), runner_path(runner) {}

    VerifyResult verify(const std::string& original_js,
                        const std::string& flattened_js) {
        VerifyResult r;

        std::string cmd1 = node_path + " \"" + runner_path + "\""
                         + " --input \"" + original_js + "\""
                         + " --freeze --json 2>&1";
        std::string out1 = exec_cmd(cmd1);
        r.original_h5st = extract_h5st(out1);

        std::string cmd2 = node_path + " \"" + runner_path + "\""
                         + " --input \"" + flattened_js + "\""
                         + " --freeze --json 2>&1";
        std::string out2 = exec_cmd(cmd2);
        r.flattened_h5st = extract_h5st(out2);

        if (r.original_h5st.empty() && r.flattened_h5st.empty()) {
            r.error = "Both h5st empty — sandbox failure";
            return r;
        }
        if (r.original_h5st.empty()) { r.error = "Original h5st empty"; return r; }
        if (r.flattened_h5st.empty()) { r.error = "Flattened h5st empty"; return r; }

        r.match = (r.original_h5st == r.flattened_h5st);
        return r;
    }
};

} // namespace xcore
