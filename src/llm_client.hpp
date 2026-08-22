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
You are a reverse engineering analysis engine. Given structured scan results from a binary file,
identify what cryptographic primitives or protocols are likely present.

Respond in JSON only: {"algorithms":["aes-128-cbc","rsa-2048",...],"confidence":"high|medium|low","reasoning":"..."}

Key indicators:
- RSA: public exponent 65537 (0x010001) + high-entropy 64B+ blocks
- AES: high-entropy 32B blocks near key schedule constants
- ChaCha20: "expand 32-byte k" string or 16-byte constant block
- Base64: 64B high-entropy block at entropy 5.9+ (character table)
- WASM bindgen: __wbindgen_ markers indicate Rust→WASM compiled crypto
- ZSTD/LZ4: magic bytes + entropy pattern in data sections
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
You are analyzing a specific data region in a binary. Metadata provided, no raw bytes.

Region: %REGION%
Context: %CONTEXT%

Identify structure type (key schedule, lookup table, ciphertext block, padding, etc).
Respond in JSON: {"type":"...","confidence":"...","detail":"..."}
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
