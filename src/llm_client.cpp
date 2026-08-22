/**
 * X-Core LLM Client v0.1 — WinHTTP implementation
 * Zero external dependencies beyond Windows SDK.
 */
#include "llm_client.hpp"
#include <stdexcept>
#include <sstream>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")
#endif

namespace xcore {

// ─── URL parsing helpers ──────────────────────────────────

struct URLParts {
    std::wstring host;
    int port = 443;
    std::wstring path = L"/v1/chat/completions";
    bool https = true;
};

static URLParts parse_url(const std::string& url) {
    URLParts p;
    std::string s = url;
    if (s.find("https://") == 0) { p.https = true; s = s.substr(8); }
    else if (s.find("http://") == 0) { p.https = false; s = s.substr(7); }

    size_t slash = s.find('/');
    std::string hostpart = (slash != std::string::npos) ? s.substr(0, slash) : s;
    if (slash != std::string::npos) {
        std::string url_path(s.begin() + slash, s.end());
        // OpenAI-compatible: if endpoint ends with /v1, append /chat/completions
        if (url_path.find("/chat/completions") == std::string::npos) {
            while (!url_path.empty() && url_path.back() == '/') url_path.pop_back();
            url_path += "/chat/completions";
        }
        p.path = std::wstring(url_path.begin(), url_path.end());
    }

    size_t colon = hostpart.find(':');
    if (colon != std::string::npos) {
        p.host = std::wstring(hostpart.begin(), hostpart.begin() + colon);
        p.port = std::stoi(hostpart.substr(colon + 1));
    } else {
        p.host = std::wstring(hostpart.begin(), hostpart.end());
        p.port = p.https ? 443 : 80;
    }
    return p;
}

static std::wstring to_wstr(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring ws(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], len);
    return ws;
}

static std::string to_utf8(const std::wstring& ws) {
    if (ws.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), nullptr, 0, nullptr, nullptr);
    std::string s(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), (int)ws.size(), &s[0], len, nullptr, nullptr);
    return s;
}

// ─── Constructor / Destructor ─────────────────────────────

LLMClient::LLMClient(const LLMConfig& cfg) : cfg_(cfg) {}
LLMClient::~LLMClient() = default;

// ─── HTTP request using WinHTTP ──────────────────────────

std::string LLMClient::send_request(const nlohmann::json& body, StreamCallback on_token) {
    auto parts = parse_url(cfg_.endpoint);
    std::string body_str = body.dump();

    HINTERNET hSession = WinHttpOpen(L"X-Core-LLM/0.1",
                                      WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                      nullptr, nullptr, 0);
    if (!hSession) throw std::runtime_error("WinHttpOpen failed");

    HINTERNET hConnect = WinHttpConnect(hSession, parts.host.c_str(),
                                         (INTERNET_PORT)parts.port, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); throw std::runtime_error("WinHttpConnect failed"); }

    DWORD flags = parts.https ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", parts.path.c_str(),
                                             nullptr, nullptr, nullptr, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpOpenRequest failed");
    }

    // Headers
    std::wstring headers = L"Content-Type: application/json\r\n";
    if (!cfg_.api_key.empty()) {
        headers += L"Authorization: Bearer " + to_wstr(cfg_.api_key) + L"\r\n";
    }
    WinHttpAddRequestHeaders(hRequest, headers.c_str(), (DWORD)headers.size(),
                              WINHTTP_ADDREQ_FLAG_ADD);

    // Send
    if (!WinHttpSendRequest(hRequest, nullptr, 0,
                            (LPVOID)body_str.data(), (DWORD)body_str.size(),
                            (DWORD)body_str.size(), 0)) {
        auto err = GetLastError();
        std::string msg = "WinHttpSendRequest failed: " + std::to_string(err);
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error(msg);
    }

    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        throw std::runtime_error("WinHttpReceiveResponse failed");
    }

    // Read response
    std::string response;
    DWORD avail = 0;
    char buf[4096];

    if (on_token) {
        // Streaming mode: accumulate full response, call callback per chunk
        std::string acc;
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            DWORD read = 0;
            DWORD to_read = min(avail, (DWORD)sizeof(buf) - 1);
            if (WinHttpReadData(hRequest, buf, to_read, &read)) {
                buf[read] = 0;
                acc += buf;
                // Try to extract streaming tokens from SSE-like response
                // OpenAI streaming uses "data: " prefix
                size_t pos = 0;
                while ((pos = acc.find("data: ")) != std::string::npos) {
                    size_t end = acc.find("\n", pos);
                    if (end == std::string::npos) break;
                    std::string line = acc.substr(pos + 6, end - pos - 6);
                    acc.erase(0, end + 1);
                    if (line == "[DONE]") continue;
                    try {
                        auto j = nlohmann::json::parse(line);
                        if (j.contains("choices") && j["choices"].size() > 0) {
                            auto& choice = j["choices"][0];
                            if (choice.contains("delta") && choice["delta"].contains("content"))
                                on_token(choice["delta"]["content"].get<std::string>());
                        }
                    } catch (...) {}
                }
            }
        }
        response = acc;  // remaining as full response for extraction
    } else {
        while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
            DWORD read = 0;
            DWORD to_read = min(avail, (DWORD)sizeof(buf) - 1);
            if (WinHttpReadData(hRequest, buf, to_read, &read)) {
                buf[read] = 0;
                response += buf;
            }
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}

std::string LLMClient::extract_content(const nlohmann::json& j) {
    try {
        if (j.contains("choices") && j["choices"].size() > 0) {
            auto& msg = j["choices"][0]["message"];
            return msg["content"].get<std::string>();
        }
    } catch (...) {}
    return "";
}

// ─── Public API ───────────────────────────────────────────

LLMResponse LLMClient::chat(const std::string& system_prompt, const std::string& user_prompt) {
    std::vector<LLMMessage> msgs;
    if (!system_prompt.empty()) msgs.push_back({"system", system_prompt});
    msgs.push_back({"user", user_prompt});
    return chat_multi(msgs);
}

LLMResponse LLMClient::chat_multi(const std::vector<LLMMessage>& messages) {
    LLMResponse resp;

    nlohmann::json body;
    body["model"] = cfg_.model;
    body["max_tokens"] = cfg_.max_tokens;
    body["temperature"] = cfg_.temperature;
    body["messages"] = nlohmann::json::array();
    for (auto& m : messages) {
        nlohmann::json msg;
        msg["role"] = m.role;
        msg["content"] = m.content;
        body["messages"].push_back(msg);
    }

    try {
        std::string raw = send_request(body);
        auto j = nlohmann::json::parse(raw);

        if (j.contains("error")) {
            resp.success = false;
            resp.error = j["error"]["message"].get<std::string>();
            return resp;
        }

        resp.content = extract_content(j);
        resp.success = !resp.content.empty();

        if (j.contains("usage")) {
            resp.tokens_prompt = j["usage"].value("prompt_tokens", 0);
            resp.tokens_completion = j["usage"].value("completion_tokens", 0);
        }
    } catch (const std::exception& e) {
        resp.success = false;
        resp.error = e.what();
    }

    return resp;
}

LLMResponse LLMClient::chat_stream(const std::string& system_prompt,
                                    const std::string& user_prompt,
                                    StreamCallback on_token) {
    LLMResponse resp;

    nlohmann::json body;
    body["model"] = cfg_.model;
    body["max_tokens"] = cfg_.max_tokens;
    body["temperature"] = cfg_.temperature;
    body["stream"] = true;
    body["messages"] = nlohmann::json::array();
    if (!system_prompt.empty()) {
        body["messages"].push_back({{"role", "system"}, {"content", system_prompt}});
    }
    body["messages"].push_back({{"role", "user"}, {"content", user_prompt}});

    try {
        std::string raw = send_request(body, on_token);

        if (!raw.empty()) {
            try {
                auto j = nlohmann::json::parse(raw);
                auto extracted = extract_content(j);
                if (!extracted.empty()) resp.content = extracted;
            } catch (...) {
                // streaming content already captured via callback
            }
        }
        resp.success = !resp.content.empty();

        // Tokens won't be available in stream mode for non-last chunk
        resp.tokens_prompt = -1;
        resp.tokens_completion = -1;
    } catch (const std::exception& e) {
        resp.success = false;
        resp.error = e.what();
    }

    return resp;
}

// ─── Convenience: auto-classify scan results ──────────────

static std::string compact_findings(const nlohmann::json& scan) {
    std::ostringstream ss;
    ss << "File: " << scan.value("file", "?") << " (" << scan.value("size", 0) << " bytes)\n";

    for (auto& m : scan["matches"]) {
        std::string type = m.value("type", "?");
        std::string label = m.value("label", "?");

        if (type == "hex_match") {
            int count = m.value("count", 0);
            ss << "  hex_match [" << label << "]: " << count << " hits\n";
            if (count > 0 && m["hits"].is_array()) {
                for (auto& h : m["hits"])
                    ss << "    offset=" << h.value("offset", "?") << "\n";
            }
        } else if (type == "entropy") {
            int n = m.value("region_count", 0);
            ss << "  entropy [" << label << "]: " << n << " regions\n";
            for (auto& r : m["regions"])
                ss << "    " << r.value("range", "?") << " max_entropy=" << r.value("max_entropy", 0.0) << "\n";
        } else if (type == "string_match") {
            int count = m.value("count", 0);
            ss << "  string_match [" << label << "]: " << count << " hits\n";
        }
    }
    return ss.str();
}

LLMResponse LLMClient::classify(const nlohmann::json& scan_result) {
    std::string sys = prompts::classifier;
    std::string user = "Analyze this binary scan result:\n\n" + compact_findings(scan_result);
    return chat(sys, user);
}

LLMResponse LLMClient::strategize(const nlohmann::json& findings) {
    std::string sys = prompts::strategist;
    std::string prompt_str = sys;
    std::string placeholder = "%FINDINGS%";
    size_t pos = prompt_str.find(placeholder);
    if (pos != std::string::npos)
        prompt_str.replace(pos, placeholder.size(), findings.dump(2));
    return chat("", prompt_str);
}

} // namespace xcore
