#pragma once

#include <string>
#include <vector>
#include <map>
#include <regex>
#include <nlohmann/json.hpp>

namespace security {

struct Pattern {
    std::string pattern;
    std::string category;
    std::string severity;
};

struct PatternMatch {
    std::string pattern;
    std::string category;
    std::string severity;
    size_t position;
    std::string matched_content;
};

class PatternManager {
public:
    PatternManager();
    
    void load_patterns_from_file(const std::string& filepath);
    void load_patterns_from_json(const nlohmann::json& json_data);
    void add_pattern(const std::string& pattern, const std::string& category, const std::string& severity);
    std::vector<PatternMatch> scan_content(const std::string& content) const;
    
    const std::vector<Pattern>& get_patterns() const { return patterns; }
    
private:
    std::vector<Pattern> patterns;
    std::map<std::string, std::regex> compiled_patterns;
};

} // namespace security
