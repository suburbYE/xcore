/**
 * X-Core Rule Engine public API (v0.5)
 */
#pragma once
#include <string>
#include <iostream>
#include "nlohmann.json.hpp"

nlohmann::json load_rules(const std::string& path);
void load_fingerprints(const std::string& dir);
nlohmann::json scan(const std::string& path, const nlohmann::json& rules);
nlohmann::json scan_stream(std::istream& in, const std::string& virtual_path = "pipe://stdin");