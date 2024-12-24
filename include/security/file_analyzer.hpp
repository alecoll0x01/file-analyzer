#pragma once

#include "pattern_manager.hpp"
#include <string>
#include <vector>
#include <filesystem>
#include <openssl/sha.h>
#include <magic.h>
#include <fstream>
#include <iostream>

namespace security {

class FileAnalyzer {
public:
    struct FileInfo {
        std::string filename;
        std::string filetype;
        std::string sha256;
        size_t filesize;
        std::vector<PatternMatch> detected_patterns;
    };

    FileAnalyzer(const std::string& patterns_file = "patterns.json");
    ~FileAnalyzer();
    
    FileInfo analyze_file(const std::string& filepath);
    std::vector<FileInfo> batch_analyze(const std::string& directory);
    void load_patterns(const std::string& patterns_file);
    
private:
    std::string calculate_sha256(const std::string& filepath);
    std::string detect_file_type(const std::string& filepath);
    std::vector<PatternMatch> scan_file(const std::string& filepath);
    
    magic_t magic_cookie;
    PatternManager pattern_manager;
};

} // namespace security
