#include "security/pattern_manager.hpp"
#include <fstream>
#include <sstream>

namespace security {

PatternManager::PatternManager() {}

void PatternManager::load_patterns_from_file(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file) {
        throw std::runtime_error("Cannot open patterns file: " + filepath);
    }
    
    nlohmann::json json_data;
    file >> json_data;
    load_patterns_from_json(json_data);
}

void PatternManager::load_patterns_from_json(const nlohmann::json& json_data) {
    patterns.clear();
    compiled_patterns.clear();
    
    for (const auto& [category, data] : json_data["patterns"].items()) {
        std::string severity = data["severity"];
        for (const auto& pattern : data["patterns"]) {
            add_pattern(pattern, category, severity);
        }
    }
}

void PatternManager::add_pattern(const std::string& pattern, 
                                const std::string& category,
                                const std::string& severity) {
    patterns.push_back({pattern, category, severity});
    try {
        compiled_patterns[pattern] = std::regex(pattern, 
            std::regex::extended | std::regex::icase);
    } catch (const std::regex_error& e) {
        throw std::runtime_error("Invalid pattern: " + pattern);
    }
}

std::vector<PatternMatch> PatternManager::scan_content(const std::string& content) const {
    std::vector<PatternMatch> matches;
    
    for (const auto& pattern : patterns) {
        std::smatch match;
        std::string::const_iterator search_start(content.cbegin());
        
        while (std::regex_search(search_start, content.cend(), match, 
                               compiled_patterns.at(pattern.pattern))) {
            PatternMatch pm;
            pm.pattern = pattern.pattern;
            pm.category = pattern.category;
            pm.severity = pattern.severity;
            pm.position = match.position();
            
            // Get some context around the match
            size_t context_start = (pm.position > 20) ? pm.position - 20 : 0;
            size_t context_length = match.str().length() + 40;
            if (context_start + context_length > content.length()) {
                context_length = content.length() - context_start;
            }
            pm.matched_content = content.substr(context_start, context_length);
            
            matches.push_back(pm);
            search_start = match.suffix().first;
        }
    }
    
    return matches;
}

} // namespace security
