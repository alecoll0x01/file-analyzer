#include "security/file_analyzer.hpp"
#include <iostream>
#include <iomanip>
#include <map>

void print_file_info(const security::FileAnalyzer::FileInfo& info) {
    std::cout << "\n=== File Analysis Report ===\n";
    std::cout << "Filename: " << info.filename << "\n";
    std::cout << "Size: " << info.filesize << " bytes\n";
    std::cout << "Type: " << info.filetype << "\n";
    std::cout << "SHA256: " << info.sha256 << "\n";
    
    if (!info.detected_patterns.empty()) {
        std::cout << "\nDetected Patterns:\n";
        std::map<std::string, std::vector<security::PatternMatch>> patterns_by_category;
        for (const auto& match : info.detected_patterns) {
            patterns_by_category[match.category].push_back(match);
        }
        for (const auto& [category, matches] : patterns_by_category) {
            std::cout << "\n" << category << " (Severity: " << matches[0].severity << "):\n";
            for (const auto& match : matches) {
                std::cout << "- Pattern: " << match.pattern << "\n";
                std::cout << "  Context: ..." << match.matched_content << "...\n";
            }
        }
    } else {
        std::cout << "\nNo suspicious patterns detected.\n";
    }
    std::cout << "=========================\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <file_or_directory_path> [patterns_file]\n";
        return 1;
    }

    try {
        std::string patterns_file = (argc > 2) ? argv[2] : "config/patterns.json";
        security::FileAnalyzer analyzer(patterns_file);
        
        std::string path = argv[1];
        if (std::filesystem::is_directory(path)) {
            auto results = analyzer.batch_analyze(path);
            for (const auto& info : results) {
                print_file_info(info);
            }
        } else {
            auto info = analyzer.analyze_file(path);
            print_file_info(info);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}
