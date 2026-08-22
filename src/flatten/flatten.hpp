/**
 * xcore flatten engine — Native RLE + Sliding Window + CFG linearization
 *
 * Replaces the JS-based xcore_unflatten.js Phase 4 with native C++.
 *
 * Input:  trace JSON (case_sequence array + case_frequency map)
 * Output: JSON { "linearized": [case_id, ...], "loops": [{start, end, count}], ... }
 */

#pragma once
#include <vector>
#include <map>
#include <set>
#include <string>
#include <algorithm>
#include <cstdint>
#include "nlohmann.json.hpp"

using json = nlohmann::json;
using namespace nlohmann::literals;

namespace xcore {
namespace flatten {

// ─── RLE Compressor ───────────────────────────────────────
struct RleSegment {
    int32_t value;
    size_t  count;
};

inline std::vector<RleSegment> rle_compress(const std::vector<int32_t>& seq) {
    std::vector<RleSegment> out;
    if (seq.empty()) return out;

    int32_t cur = seq[0];
    size_t   cnt = 1;
    for (size_t i = 1; i < seq.size(); ++i) {
        if (seq[i] == cur) {
            cnt++;
        } else {
            out.push_back({cur, cnt});
            cur = seq[i];
            cnt = 1;
        }
    }
    out.push_back({cur, cnt});
    return out;
}

// ─── Repeating pattern (for loop folding) ─────────────────
struct RepeatPattern {
    size_t start_idx;     // index in linearized array where pattern begins
    size_t length;        // number of cases in pattern
    size_t repeats;       // how many times it repeats contiguously
};

// ─── Sliding window repeat detection ──────────────────────
inline std::vector<RepeatPattern> find_repeats(
    const std::vector<int32_t>& linearized,
    size_t min_window = 2,
    size_t max_window = 20,
    size_t min_repeats = 3)
{
    std::vector<RepeatPattern> found;
    size_t N = linearized.size();

    for (size_t w = min_window; w <= max_window && w <= N / min_repeats; ++w) {
        for (size_t i = 0; i + w <= N; ++i) {
            // Count contiguous repeats of pattern starting at i
            size_t rep = 1;
            while (i + rep * w + w <= N) {
                bool match = true;
                for (size_t k = 0; k < w; ++k) {
                    if (linearized[i + k] != linearized[i + rep * w + k]) {
                        match = false;
                        break;
                    }
                }
                if (!match) break;
                rep++;
            }
            if (rep >= min_repeats) {
                found.push_back({i, w, rep});
                i += rep * w - 1; // skip past matched region
                break;
            }
        }
    }
    return found;
}

// ─── Full flatten result ──────────────────────────────────
struct FlattenResult {
    std::vector<int32_t> linearized;   // final case sequence (RLE-expanded)
    std::vector<RleSegment> rle;       // RLE-compressed version
    std::vector<RepeatPattern> loops;  // detected loop patterns
    int32_t  dead_cases_removed;       // count of cases seen 0 times
    int32_t  total_cases;
    int32_t  unique_cases;

    json to_json() const {
        json j;
        j["linearized"] = linearized;
        j["rle"] = json::array();
        for (auto& s : rle)
            j["rle"].push_back({{"case_id", s.value}, {"count", s.count}});
        j["loops"] = json::array();
        for (auto& lp : loops)
            j["loops"].push_back({{"start", lp.start_idx}, {"length", lp.length}, {"repeats", lp.repeats}});
        j["stats"]["total_cases"]      = total_cases;
        j["stats"]["unique_cases"]     = unique_cases;
        j["stats"]["dead_removed"]     = dead_cases_removed;
        j["stats"]["linearized_length"] = linearized.size();
        return j;
    }
};

// ─── Main engine entry point ──────────────────────────────
inline FlattenResult process(const json& trace_input) {
    FlattenResult out;

    // Parse input
    auto& seq = trace_input["case_sequence"];
    int32_t max_case = 0;
    std::set<int32_t> seen_cases;
    std::vector<int32_t> case_list;
    case_list.reserve(seq.size());

    for (auto& v : seq) {
        int32_t cid = v.get<int32_t>();
        case_list.push_back(cid);
        seen_cases.insert(cid);
        if (cid > max_case) max_case = cid;
    }

    out.total_cases = (int32_t)(max_case + 1);
    out.unique_cases = (int32_t)seen_cases.size();
    out.dead_cases_removed = out.total_cases - out.unique_cases;

    // RLE compress
    out.rle = rle_compress(case_list);

    // RLE-expand to original linearized
    out.linearized = case_list;

    // Find repeat patterns
    out.loops = find_repeats(case_list);

    return out;
}

} // namespace flatten
} // namespace xcore
