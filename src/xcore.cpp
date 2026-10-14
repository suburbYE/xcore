/**
 * X-Core Rule Engine v0.5
 * Stream-based scan engine: 10MB chunk + 4KB overlap sliding window.
 * Boyer-Moore hex matching, zero-copy string scanning, global entropy accumulator.
 * Build: via build.bat (MSVC) or: g++ -std=c++17 -O2 xcore.cpp -o xcore
 */
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <sstream>
#include <cstdio>
#include <functional>
#include <unordered_set>
#include "nlohmann.json.hpp"
#include "xcore_api.hpp"
#include "version.h"

#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

using json = nlohmann::json;
using byte = unsigned char;

// ─── Constants ────────────────────────────────────────────
static constexpr size_t CHUNK_SIZE   = 10 * 1024 * 1024;  // 10MB
static constexpr size_t OVERLAP_SIZE = 4 * 1024;          // 4KB
static constexpr size_t GLOBAL_ENTROPY_ID = 18;
static constexpr size_t MIN_HEX_PATTERN_BYTES = 5;       // noise gate: skip hex patterns shorter than 5 bytes

// ─── Unicode helpers ─────────────────────────────────────

static std::string to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
#ifdef _WIN32
    int len = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &s[0], len, nullptr, nullptr);
    return s;
#else
    return std::string(wstr.begin(), wstr.end());
#endif
}

#ifdef _WIN32
static std::wstring to_wstr(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring ws(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], len);
    return ws;
}
#endif

// ─── Hex utility ─────────────────────────────────────────

static std::string hex_decode(const std::string& s) {
    std::string r;
    auto v = [](char x) -> int { return x >= 'a' ? x - 'a' + 10 : x - '0'; };
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        r.push_back((char)((v(s[i]) << 4) | v(s[i + 1])));
    return r;
}

static std::string to_hex(const byte* d, size_t n) {
    std::string r; r.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        static const char h[] = "0123456789abcdef";
        r.push_back(h[d[i] >> 4]); r.push_back(h[d[i] & 0xf]);
    }
    return r;
}

static std::string off(size_t x) { char b[24]; snprintf(b, 24, "0x%zx", x); return b; }

// ─── Shannon entropy ─────────────────────────────────────

static double shannon_global(const uint64_t counts[256], uint64_t total) {
    if (total == 0) return 0.0;
    double e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i]) {
            double p = (double)counts[i] / total;
            e -= p * std::log2(p);
        }
    }
    return e;
}

static double shannon_local(const byte* d, size_t n) {
    int f[256] = {};
    for (size_t i = 0; i < n; ++i) f[d[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (f[i]) { double p = (double)f[i] / n; e -= p * std::log2(p); }
    }
    return e;
}

// ─── Interval merge (for entropy regions) ────────────────

struct Iv { size_t s, e; double max_e; std::string prev; };
static const size_t GAP = 16;

static std::vector<Iv> merge_ivs(std::vector<size_t>& offs, const std::vector<byte>& buf,
                                  size_t win_len, size_t buf_start_offset) {
    if (offs.empty()) return {};
    std::sort(offs.begin(), offs.end());
    std::vector<Iv> r;
    size_t slen = std::min((size_t)32, win_len);
    auto get_prev = [&](size_t o) {
        size_t real = o - buf_start_offset;
        if (real + slen <= buf.size())
            return to_hex(buf.data() + real, slen);
        return std::string("n/a");
    };
    auto ent_at = [&](size_t o) {
        size_t real = o - buf_start_offset;
        if (real + win_len <= buf.size())
            return shannon_local(buf.data() + real, win_len);
        return 0.0;
    };
    Iv cur = {offs[0], offs[0] + win_len, ent_at(offs[0]), get_prev(offs[0])};
    for (size_t i = 1; i < offs.size(); ++i) {
        size_t o = offs[i];
        if (o <= cur.e + GAP) {
            cur.e = o + win_len;
            double e = ent_at(o);
            if (e > cur.max_e) { cur.max_e = e; cur.prev = get_prev(o); }
        } else {
            r.push_back(cur);
            cur = {o, o + win_len, ent_at(o), get_prev(o)};
        }
    }
    r.push_back(cur);
    return r;
}

// ─── Rule Engine (pre-compiled Boyer-Moore, zero-copy strings) ─

struct HexRule {
    std::string id, label;
    int weight, ctx_before, ctx_after;
    std::vector<byte> pattern;
    // Boyer-Moore searcher: compiled once, reused for all chunks
    std::function<const byte*(const byte*, const byte*)> searcher;
};

struct StringRule {
    std::string id, label;
    int weight;
    bool case_sensitive;
    std::vector<std::string> patterns;
};

struct EntropyRule {
    std::string id, label;
    int weight, length, window, max_regions;
    double threshold;
};

// Per-rule collected hits during streaming
struct HexHits {
    std::string id; int weight, cb, ca;
    std::vector<size_t> offsets;  // absolute file offsets
};

struct StringHits {
    std::string id; int weight;
    std::vector<std::pair<size_t, std::string>> hits;  // offset + pattern
};

struct EntropyHits {
    std::string id, label; int weight, length, max_r;
    std::vector<size_t> offsets;
};

// ─── L2 Fingerprint structures ────────────────────────────

struct L2Pattern {
    std::vector<byte> bytes;
    std::function<const byte*(const byte*, const byte*)> searcher;
};

struct L2Fingerprint {
    std::string name;
    std::string algorithm;
    std::string library;
    std::string version;
    std::string output_format;
    std::vector<L2Pattern> patterns;  // OR logic: first pattern hit wins
};

struct L2Hit {
    std::string l1_rule_id;
    std::string fp_name;
    std::string algorithm;
    std::string library;
    std::string version;
    std::string output_format;
    size_t abs_offset;
};

class RuleEngine {
public:
    void load_rules(const json& rules) {
        hex_rules_.clear(); str_rules_.clear(); ent_rules_.clear();
        for (auto& r : rules) {
            std::string type = r.value("type", "");
            int weight = r.value("weight", 1);
            if (type == "hex") {
                HexRule hr;
                hr.id = r["id"]; hr.label = r.value("label", hr.id);
                hr.weight = weight; hr.ctx_before = r.value("context_before", 0);
                hr.ctx_after  = r.value("context_after", 0);
                hr.pattern.clear();
                std::string ph = hex_decode(r["pattern"]);
                hr.pattern.assign((byte*)ph.data(), (byte*)ph.data() + ph.size());

                // Noise gate: skip patterns too short to be specific
                if (hr.pattern.size() < MIN_HEX_PATTERN_BYTES) {
                    std::cerr << "[noise-gate] Skipping hex rule '" << hr.id
                              << "' (" << hr.pattern.size() << " bytes < " << MIN_HEX_PATTERN_BYTES << ")\n";
                    continue;
                }

                // Compile Boyer-Moore once, capture searcher by value for zero-cost reuse
                auto bm = std::boyer_moore_searcher(hr.pattern.data(),
                                                     hr.pattern.data() + hr.pattern.size());
                hr.searcher = [bm](const byte* begin, const byte* end) -> const byte* {
                    auto it = std::search(begin, end, bm);
                    return it == end ? nullptr : it;
                };
                hex_rules_.push_back(std::move(hr));
            } else if (type == "string") {
                StringRule sr;
                sr.id  = r["id"]; sr.label = r.value("label", sr.id);
                sr.weight = weight;
                sr.case_sensitive = r.value("case_sensitive", true);
                for (auto& p : r["patterns"])
                    sr.patterns.push_back(p.get<std::string>());
                str_rules_.push_back(std::move(sr));
            } else if (type == "entropy") {
                EntropyRule er;
                er.id = r["id"]; er.label = r.value("label", er.id);
                er.weight = weight; er.length = r["length"];
                er.window = r.value("window", 1); er.threshold = r["threshold"];
                er.max_regions = r.value("max_regions", 0);
                ent_rules_.push_back(std::move(er));
            }
            // "global_entropy" handled separately at EOF
        }
    }

    // ── L2 fingerprint loading ───────────────────────────
    void load_l2_fingerprints(const std::string& fingerprints_dir) {
        l2_fingerprints_.clear();
        if (fingerprints_dir.empty()) return;

        // Read manifest
        std::string manifest_path = fingerprints_dir + "/manifest.json";
        std::ifstream mf(manifest_path);
        if (!mf) return;  // no fingerprints configured, not an error

        json manifest = json::parse(mf);
        // manifest is { "l1_rule_id": ["rel/path/to/fp.json", ...] }

        for (auto& [l1_rule_id, fp_files] : manifest.items()) {
            if (!fp_files.is_array()) continue;
            std::vector<L2Fingerprint> group;

            for (auto& fp_file : fp_files) {
                std::string full_path = fingerprints_dir + "/" + fp_file.get<std::string>();
                std::ifstream ff(full_path);
                if (!ff) continue;

                json fpj = json::parse(ff);
                L2Fingerprint fp;
                fp.name          = fpj.value("name", "unnamed");
                fp.algorithm     = fpj.value("algorithm", "");
                fp.library       = fpj.value("library", "");
                fp.version       = fpj.value("version", "");
                fp.output_format = fpj.value("output_format", "");

                // patterns: array of hex strings, each gets its own BM searcher (OR logic)
                if (fpj.contains("patterns") && fpj["patterns"].is_array()) {
                    for (auto& ph : fpj["patterns"]) {
                        std::string raw = hex_decode(ph.get<std::string>());
                        if (raw.empty()) continue;
                        L2Pattern lp;
                        lp.bytes.assign((byte*)raw.data(), (byte*)raw.data() + raw.size());
                        auto bm = std::boyer_moore_searcher(lp.bytes.data(),
                                                             lp.bytes.data() + lp.bytes.size());
                        lp.searcher = [bm](const byte* begin, const byte* end) -> const byte* {
                            auto it = std::search(begin, end, bm);
                            return it == end ? nullptr : it;
                        };
                        fp.patterns.push_back(std::move(lp));
                    }
                }

                if (!fp.patterns.empty())
                    group.push_back(std::move(fp));
            }

            if (!group.empty())
                l2_fingerprints_[l1_rule_id] = std::move(group);
        }
    }

    // ── Accessors for global entropy injection ──────────
    bool has_global_entropy_rule() const { return global_entropy_threshold_ > 0.0; }
    double global_entropy_threshold() const { return global_entropy_threshold_; }
    void set_global_entropy_config(double thr, int w, const std::string& lb) {
        global_entropy_threshold_ = thr;
        global_entropy_weight_ = w;
        global_entropy_label_ = lb;
    }
    int    global_entropy_weight() const { return global_entropy_weight_; }
    const std::string& global_entropy_label() const { return global_entropy_label_; }

    // ── Statistics ──────────────────────────────────────
    size_t hex_rule_count()    const { return hex_rules_.size(); }
    size_t str_rule_count()    const { return str_rules_.size(); }
    size_t ent_rule_count()    const { return ent_rules_.size(); }
    size_t total_rule_count()  const { return hex_rules_.size() + str_rules_.size() + ent_rules_.size()
                                           + (has_global_entropy_rule() ? 1 : 0); }

    // ── Stream scan: process chunks, collect hits ───────
    struct ScanResult {
        std::vector<HexHits>    hex;
        std::vector<StringHits> str;
        std::vector<EntropyHits> ent;
        std::vector<L2Hit>      l2_hits;
        uint64_t                byte_counts[256] = {};
        uint64_t                total_bytes = 0;
        size_t                  file_size = 0;
    };

    ScanResult scan_stream(std::istream& in) {
        ScanResult sr;
        sr.hex.resize(hex_rules_.size());
        sr.str.resize(str_rules_.size());
        sr.ent.resize(ent_rules_.size());
        for (size_t i = 0; i < hex_rules_.size(); ++i) {
            sr.hex[i].id = hex_rules_[i].id; sr.hex[i].weight = hex_rules_[i].weight;
            sr.hex[i].cb = hex_rules_[i].ctx_before; sr.hex[i].ca = hex_rules_[i].ctx_after;
        }
        for (size_t i = 0; i < str_rules_.size(); ++i) {
            sr.str[i].id = str_rules_[i].id; sr.str[i].weight = str_rules_[i].weight;
        }
        for (size_t i = 0; i < ent_rules_.size(); ++i) {
            sr.ent[i].id = ent_rules_[i].id; sr.ent[i].label = ent_rules_[i].label;
            sr.ent[i].weight = ent_rules_[i].weight; sr.ent[i].length = ent_rules_[i].length;
            sr.ent[i].max_r = ent_rules_[i].max_regions;
        }

        std::vector<byte> buf(CHUNK_SIZE + OVERLAP_SIZE);
        size_t file_offset = 0;
        bool first_chunk = true;

        while (in) {
            size_t read_start = first_chunk ? 0 : OVERLAP_SIZE;
            in.read((char*)buf.data() + read_start, CHUNK_SIZE);
            size_t bytes_read = in.gcount();
            if (bytes_read == 0) break;

            // Track effective region for this chunk
            const byte* search_start = buf.data();
            size_t search_length = read_start + bytes_read;

            // Absolute offset of byte at buf[0] in the original file
            size_t base_offset = first_chunk ? 0 : (file_offset - OVERLAP_SIZE);

            // ── Hex rules (Boyer-Moore) ─────────────────
            for (size_t ri = 0; ri < hex_rules_.size(); ++ri) {
                auto& hr = hex_rules_[ri];
                if (hr.pattern.empty()) continue;
                const byte* p = search_start;
                const byte* end = search_start + search_length;
                // Check if this L1 rule has L2 fingerprints
                auto l2_it = l2_fingerprints_.find(hr.id);
                bool has_l2 = (l2_it != l2_fingerprints_.end());
                while (p < end) {
                    const byte* found = hr.searcher(p, end);
                    if (!found) break;
                    size_t abs_off = base_offset + (found - search_start);
                    sr.hex[ri].offsets.push_back(abs_off);

                    // ── L2 fingerprint matching (in-stream, ±256B window) ──
                    if (has_l2) {
                        size_t rel_off = found - search_start;
                        size_t win_start = (rel_off > 256) ? (rel_off - 256) : 0;
                        size_t win_end   = (rel_off + 256 < search_length) ? (rel_off + 256) : search_length;
                        size_t win_len   = win_end - win_start;
                        if (win_len > 0) {
                            const byte* wdata = search_start + win_start;
                            for (auto& fp : l2_it->second) {
                                for (auto& l2pat : fp.patterns) {
                                    const byte* l2hit = l2pat.searcher(wdata, wdata + win_len);
                                    if (l2hit) {
                                        L2Hit h;
                                        h.l1_rule_id    = hr.id;
                                        h.fp_name       = fp.name;
                                        h.algorithm     = fp.algorithm;
                                        h.library       = fp.library;
                                        h.version       = fp.version;
                                        h.output_format = fp.output_format;
                                        h.abs_offset    = base_offset + (l2hit - search_start);
                                        sr.l2_hits.push_back(h);
                                        goto next_l2_group;  // OR: first fingerprint match wins
                                    }
                                }
                                next_l2_group:;
                            }
                        }
                    }

                    p = found + 1;  // advance past this match
                }
            }

            // ── String rules ─────────────────────────────
            for (size_t ri = 0; ri < str_rules_.size(); ++ri) {
                auto& sr_rule = str_rules_[ri];
                for (auto& pat : sr_rule.patterns) {
                    if (pat.empty()) continue;
                    // Use memmem-like search on the buffer
                    const byte* p = search_start;
                    const byte* end = search_start + search_length;
                    while (p + pat.size() <= end) {
                        bool ok;
                        if (sr_rule.case_sensitive) {
                            ok = !std::memcmp(p, pat.data(), pat.size());
                        } else {
                            ok = true;
                            for (size_t j = 0; j < pat.size(); ++j)
                                if (::tolower(p[j]) != ::tolower((byte)pat[j])) { ok = false; break; }
                        }
                        if (ok) {
                            size_t abs_off = base_offset + (p - search_start);
                            sr.str[ri].hits.push_back({abs_off, pat});
                            p += pat.size();
                        } else {
                            ++p;
                        }
                    }
                }
            }

            // ── Entropy rules (sliding window) ────────────
            for (size_t ri = 0; ri < ent_rules_.size(); ++ri) {
                auto& er = ent_rules_[ri];
                if (er.length <= 0) continue;
                size_t step = er.window > 0 ? (size_t)er.window : 1;
                for (size_t i = 0; i + er.length <= search_length; i += step) {
                    double e = shannon_local(search_start + i, er.length);
                    if (e >= er.threshold) {
                        sr.ent[ri].offsets.push_back(base_offset + i);
                    }
                }
            }

            // ── Global byte count accumulator ─────────────
            // Count only the new bytes (skip overlap which was counted last chunk)
            const byte* data_start = buf.data() + read_start;
            for (size_t i = 0; i < bytes_read; ++i)
                sr.byte_counts[data_start[i]]++;
            sr.total_bytes += bytes_read;

            // ── Prepare overlap for next chunk ────────────
            if (bytes_read == CHUNK_SIZE) {
                // Copy last OVERLAP_SIZE bytes to beginning of buffer
                std::memcpy(buf.data(), data_start + bytes_read - OVERLAP_SIZE, OVERLAP_SIZE);
            }
            file_offset += bytes_read;
            first_chunk = false;
        }

        sr.file_size = file_offset;
        return sr;
    }

    // ── Build JSON from scan result ─────────────────────
    json build_json(const std::string& file_path, const ScanResult& sr) {
        json j;
        j["file"] = file_path;
        j["size"] = sr.file_size;
        j["rules_loaded"] = total_rule_count();
        j["matches"] = json::array();

        // Hex matches
        for (auto& h : sr.hex) {
            json r;
            r["rule_id"] = h.id; r["label"] = h.id; r["type"] = "hex_match";
            r["count"] = h.offsets.size();
            r["weight"] = h.weight;
            json hits_arr = json::array();
            for (auto o : h.offsets) {
                json hit;
                hit["offset"] = off(o); hit["offset_dec"] = o;
                // Context bytes would require re-reading file; skip for stream mode
                hits_arr.push_back(hit);
            }
            r["hits"] = hits_arr.empty() ? json("not_found") : hits_arr;
            j["matches"].push_back(r);
        }

        // String matches
        for (auto& s : sr.str) {
            json r;
            r["rule_id"] = s.id; r["label"] = s.id; r["type"] = "string_match";
            r["count"] = s.hits.size();
            r["weight"] = s.weight;
            json hits_arr = json::array();
            for (auto& h_pair : s.hits) {
                json hit;
                hit["offset"] = off(h_pair.first); hit["offset_dec"] = h_pair.first;
                hit["pattern"] = h_pair.second;
                hits_arr.push_back(hit);
            }
            r["hits"] = hits_arr;
            j["matches"].push_back(r);
        }

        // Entropy matches
        for (auto& e : sr.ent) {
            json r;
            r["rule_id"] = e.id; r["label"] = e.label; r["type"] = "entropy";
            r["region_count"] = e.offsets.size();
            r["weight"] = e.weight;
            r["regions"] = json::array();
            if (!e.offsets.empty()) {
                auto offs_copy = e.offsets;  // merge_ivs sorts in-place
                auto ivs = merge_ivs(offs_copy, std::vector<byte>(), e.length, 0);
                if (e.max_r > 0 && (int)ivs.size() > e.max_r) ivs.resize(e.max_r);
                for (auto& iv : ivs) {
                    json ir;
                    ir["range"] = off(iv.s) + " - " + off(iv.e);
                    ir["size"] = iv.e - iv.s;
                    ir["max_entropy"] = std::round(iv.max_e * 100) / 100;
                    ir["preview"] = iv.prev;
                    r["regions"].push_back(ir);
                }
            }
            r["region_count"] = (int)r["regions"].size();
            j["matches"].push_back(r);
        }

        // ── L2 fingerprint hits ──────────────────────────
        if (!sr.l2_hits.empty()) {
            json l2j;
            l2j["rule_id"] = "l2_fingerprints";
            l2j["label"]   = "L2 Fingerprint Matches";
            l2j["type"]    = "l2_fingerprint";
            l2j["count"]   = sr.l2_hits.size();
            l2j["weight"]  = 10;
            json hits_arr = json::array();
            for (auto& h : sr.l2_hits) {
                json hit;
                hit["l1_rule"]      = h.l1_rule_id;
                hit["fingerprint"]  = h.fp_name;
                hit["algorithm"]    = h.algorithm;
                hit["library"]      = h.library;
                hit["version"]      = h.version;
                hit["output_format"] = h.output_format;
                hit["offset"]       = off(h.abs_offset);
                hit["offset_dec"]   = h.abs_offset;
                hits_arr.push_back(hit);
            }
            l2j["hits"] = hits_arr;
            j["matches"].push_back(l2j);
        }

        // Global entropy rule (injected at EOF)
        if (has_global_entropy_rule()) {
            double global_e = shannon_global(sr.byte_counts, sr.total_bytes);
            json r;
            r["rule_id"] = "global_high_entropy";
            r["label"] = global_entropy_label_;
            r["type"] = "global_entropy";
            r["weight"] = global_entropy_weight_;
            r["entropy"] = std::round(global_e * 100) / 100;
            r["threshold"] = global_entropy_threshold_;
            r["triggered"] = (global_e >= global_entropy_threshold_);
            j["matches"].push_back(r);
        }

        j["match_count"] = j["matches"].size();
        return j;
    }

private:
    std::vector<HexRule>     hex_rules_;
    std::vector<StringRule>  str_rules_;
    std::vector<EntropyRule> ent_rules_;
    std::unordered_map<std::string, std::vector<L2Fingerprint>> l2_fingerprints_;
    double global_entropy_threshold_ = 0.0;
    int    global_entropy_weight_     = 0;
    std::string global_entropy_label_;
};

// ─── Global engine instance ──────────────────────────────
static RuleEngine g_engine;

// ─── Public API (preserved for classify.cpp compatibility) ─

json load_rules(const std::string& path) {
    json rules;
    {
        std::ifstream f(path);
        if (!f) { std::cerr << "ERROR: cannot open rules " << path << "\n"; exit(1); }
        rules = json::parse(f);
    }
    // Extract global_entropy config before passing to engine
    std::vector<json> non_global_rules;
    for (auto& r : rules) {
        if (r.value("type", "") == "global_entropy") {
            g_engine.set_global_entropy_config(
                r.value("threshold", 7.5),
                r.value("weight", 2),
                r.value("label", "Global file entropy >= 7.5")
            );
        } else {
            non_global_rules.push_back(r);
        }
    }
    g_engine.load_rules(non_global_rules);
    return rules; // return original for backward compat
}

void load_fingerprints(const std::string& dir) {
    g_engine.load_l2_fingerprints(dir);
}

json scan(const std::string& path, const json& /*rules*/) {
    // Open file (Unicode-safe on Windows)
#ifdef _WIN32
    std::wstring wp = to_wstr(path);
    HANDLE h = CreateFileW(wp.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "ERROR: cannot open " << path << " (err " << GetLastError() << ")\n";
        exit(1);
    }
    // Get file size for stream creation
    DWORD hi, lo = GetFileSize(h, &hi);
    CloseHandle(h);
    // Use ifstream (Win32 FILE_FLAG under the hood, but simpler for stream interface)
    // Actually, use CreateFileW + read loop for proper Unicode support in stream
    // For now, rely on ifstream with wide path (MSVC extension)
#endif

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        std::cerr << "ERROR: cannot open " << path << "\n";
        exit(1);
    }

    auto scan_result = g_engine.scan_stream(in);
    return g_engine.build_json(path, scan_result);
}

json scan_stream(std::istream& in, const std::string& virtual_path) {
    auto scan_result = g_engine.scan_stream(in);
    return g_engine.build_json(virtual_path, scan_result);
}

// ─── File listing ────────────────────────────────────────

static std::vector<std::string> list_files(const std::string& path, const std::vector<std::string>& exts) {
    std::vector<std::string> fs;
#ifdef _WIN32
    std::wstring wp = to_wstr(path);
    DWORD a = GetFileAttributesW(wp.c_str());
    if (a == INVALID_FILE_ATTRIBUTES) return fs;
    if (!(a & FILE_ATTRIBUTE_DIRECTORY)) {
        for (auto& e : exts) {
            std::string lo = path; std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);
            if (lo.size() >= e.size() && !lo.compare(lo.size() - e.size(), e.size(), e)) fs.push_back(path);
        }
        return fs;
    }
    WIN32_FIND_DATAW fd;
    HANDLE hnd = FindFirstFileW((wp + L"\\*").c_str(), &fd);
    if (hnd == INVALID_HANDLE_VALUE) return fs;
    do {
        std::wstring nm(fd.cFileName);
        if (nm == L"." || nm == L"..") continue;
        std::string full = to_utf8(wp + L"\\" + nm);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            auto sub = list_files(full, exts); fs.insert(fs.end(), sub.begin(), sub.end());
        } else {
            for (auto& e : exts) {
                std::string lo = to_utf8(nm); std::transform(lo.begin(), lo.end(), lo.begin(), ::tolower);
                if (lo.size() >= e.size() && !lo.compare(lo.size() - e.size(), e.size(), e)) fs.push_back(full);
            }
        }
    } while (FindNextFileW(hnd, &fd));
    FindClose(hnd);
#endif
    return fs;
}

// ─── Main ─────────────────────────────────────────────────

#ifndef XCORE_NO_MAIN
int main(int argc, char* argv[]) {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif
    if (argc < 3) {
        std::cout << "X-Core v" << XCORE_VERSION
                  << "  Usage: xcore <file_or_dir> <rules.json> [--brief] [--stdin]\n";
        return 1;
    }
    std::string tgt = argv[1], rp = argv[2];
    bool brief = false, use_stdin = false;
    for (int i = 3; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--brief") brief = true;
        if (a == "--stdin") use_stdin = true;
    }

    auto rules = load_rules(rp);

    json out;
    out["tool"] = "xcore"; out["version"] = XCORE_VERSION; out["rules"] = rp; out["results"] = json::array();

    if (use_stdin) {
        auto j = scan_stream(std::cin, "pipe://stdin");
        out["results"].push_back(j);
    } else {
        std::vector<std::string> exts = {".wasm", ".bin", ".exe", ".dll", ".so", ".apk", ".dump", ".js", ".ts"};
        auto files = list_files(tgt, exts);
        if (files.empty()) files.push_back(tgt);
        for (auto& f : files)
            out["results"].push_back(scan(f, rules));
    }

    out["files_scanned"] = out["results"].size();
    std::cout << (brief ? out.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace) : out.dump(2, ' ', false, nlohmann::json::error_handler_t::replace)) << "\n";
    return 0;
}
#endif
