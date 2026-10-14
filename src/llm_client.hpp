/**
 * X-Core LLM Client v0.1
 * OpenAI-compatible API wrapper for local/remote LLM inference.
 * Sensitive data isolation: only structured metadata (offsets/entropy/labels)
 * is transmitted; raw bytes never leave the engine.
 */
#pragma once
#include <string>
#include <vector>
#include <functional>
#include "nlohmann.json.hpp"

namespace xcore {

struct LLMConfig {
    std::string endpoint = "http://localhost:11434/v1";  // Ollama default
    std::string model = "qwen2.5:7b";                    // default local model
    std::string api_key;                                  // empty for local
    int max_tokens = 2048;
    float temperature = 0.1;
    int timeout_sec = 120;
};

struct LLMMessage {
    std::string role;    // "system", "user", "assistant"
    std::string content;
};

struct LLMResponse {
    bool success = false;
    std::string content;
    std::string error;
    int tokens_prompt = 0;
    int tokens_completion = 0;
};

// ─── System prompt templates ──────────────────────────────

namespace prompts {
    // Phase 1: classify what was found
    constexpr const char* classifier = R"(
You are a reverse engineering evidence reporter. You are given structured scan
results from a binary. Your job is to report ONLY what the supplied evidence
supports. You are NOT required to identify an algorithm.

DEFAULT ANSWER IS "none". Most binaries contain no identifiable crypto. Reporting
"none" is a correct and expected outcome, not a failure to analyse.

HARD RULES
1. Every algorithm you report MUST cite the specific scan field that justifies it
   (e.g. "l2_constants.hits[3] = 0x9ddfea08eb382d69", "l1_strings.raw_count=7").
   If you cannot name the field, do not report the algorithm.
2. Never report a combination of algorithms you did not observe separately
   (e.g. do not emit "RSA-2048 with AES-128-CBC" unless BOTH were independently
   evidenced by distinct fields).
3. Never report a generic placeholder as an algorithm name. If you cannot name it,
   use "none".
4. Do not infer a library (OpenSSL/BoringSSL/...) from algorithm names alone.
   Library attribution requires a version string or distinctive symbol in the
   evidence. Otherwise set "library":"unattributed".
5. Do NOT output a confidence value. The engine computes confidence from rule
   hits and verification status. Your self-assessed certainty is not evidence.

Respond in JSON only:
{"algorithms":[{"name":"<specific name or none>","evidence":"<exact scan field(s)>"}],
 "library":"<name or unattributed>",
 "insufficient_evidence": true|false,
 "reasoning":"<one paragraph, may say 'no evidence for any crypto primitive'>"}

If the evidence is absent or too weak, respond:
{"algorithms":[],"library":"unattributed","insufficient_evidence":true,
 "reasoning":"no evidence for any crypto primitive in the supplied fields"}

Reference indicators (a hit is necessary but NOT sufficient - always cite the field):
- RSA: public exponent 65537 (0x010001) AND high-entropy 64B+ blocks
- AES: key schedule constants or S-box present in .rdata (not merely high entropy)
- ChaCha20: "expand 32-byte k" literal or 16-byte sigma constant block
- Base64: 64-byte character table at entropy 5.9+
- WASM bindgen: __wbindgen_ markers (indicates Rust->WASM, NOT a cipher)
- ZSTD/LZ4: magic bytes plus matching entropy profile

Note: high entropy alone is far more often compression, packing, or virtualised
code than cryptography. Do not treat entropy as a crypto indicator by itself.
)";

    // Phase 2: suggest next analysis step
    constexpr const char* strategist = R"(
You are a reverse engineering workflow strategist. Given identified algorithms in a binary,
suggest the optimal next step to extract keys or decrypt traffic.

Current findings: %FINDINGS%

Respond in JSON: {"next_step":"...","tool_suggestion":"...","expected_output":"...","risk":"low|medium|high"}
)";

    // Phase 3: analyze specific data region
    constexpr const char* analyst = R"(
You are analyzing ONE specific data region in a binary. You are given metadata only
(offset, size, entropy, byte histogram, nearby strings) — never raw bytes.

Region: %REGION%
Context: %CONTEXT%

Your job is to say what this region most plausibly IS, or to say you cannot tell.

HARD RULES
1. "unknown" is a correct and expected answer. Most regions are ordinary data.
   Answering "unknown" is not a failure.
2. If you name a structure type, cite the specific metadata field that supports it
   (e.g. "entropy=7.94 with flat byte histogram", "size=256 and 256 distinct bytes").
   No field, no claim.
3. Do NOT claim a key or key schedule from entropy alone. High entropy is far more
   often compression, packing, or virtualised code than a key.
4. Do NOT output a confidence value. The engine computes confidence from verified
   evidence. Your self-assessed certainty is not evidence and will be ignored.

Respond in JSON only:
{"type":"<key schedule|lookup table|ciphertext block|padding|compressed|code|unknown>",
 "evidence":"<the exact metadata field(s) that support the type>",
 "detail":"<one sentence; may be 'no distinguishing feature in supplied metadata'>"}
)";
}

// ─── Client ───────────────────────────────────────────────

class LLMClient {
public:
    explicit LLMClient(const LLMConfig& cfg);
    ~LLMClient();

    // Single-turn chat
    LLMResponse chat(const std::string& system_prompt, const std::string& user_prompt);

    // Multi-turn conversation
    LLMResponse chat_multi(const std::vector<LLMMessage>& messages);

    // Convenience: analyze rule engine JSON output
    LLMResponse classify(const nlohmann::json& scan_result);
    LLMResponse strategize(const nlohmann::json& findings);

    // Streaming callback (token by token)
    using StreamCallback = std::function<void(const std::string& token)>;
    LLMResponse chat_stream(const std::string& system_prompt,
                            const std::string& user_prompt,
                            StreamCallback on_token);

    const LLMConfig& config() const { return cfg_; }

private:
    LLMConfig cfg_;
    std::string send_request(const nlohmann::json& body, StreamCallback on_token = nullptr);
    std::string extract_content(const nlohmann::json& response_json);
};

} // namespace xcore
