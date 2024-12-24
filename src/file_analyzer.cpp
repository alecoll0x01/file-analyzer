#include "security/file_analyzer.hpp"
#include <iomanip>
#include <sstream>

namespace security {

FileAnalyzer::FileAnalyzer(const std::string& patterns_file) {
    magic_cookie = magic_open(MAGIC_MIME_TYPE);
    if (magic_cookie == nullptr) {
        throw std::runtime_error("Failed to initialize magic library");
    }
    if (magic_load(magic_cookie, nullptr) != 0) {
        magic_close(magic_cookie);
        throw std::runtime_error("Failed to load magic database");
    }
    
    if (!patterns_file.empty()) {
        load_patterns(patterns_file);
    }
}

FileAnalyzer::~FileAnalyzer() {
    if (magic_cookie) {
        magic_close(magic_cookie);
    }
}

void FileAnalyzer::load_patterns(const std::string& patterns_file) {
    try {
        pattern_manager.load_patterns_from_file(patterns_file);
    } catch (const std::exception& e) {
        throw std::runtime_error("Failed to load patterns: " + std::string(e.what()));
    }
}

std::string FileAnalyzer::calculate_sha256(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    char buffer[4096];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    return ss.str();
}

std::string FileAnalyzer::detect_file_type(const std::string& filepath) {
    const char* file_type = magic_file(magic_cookie, filepath.c_str());
    if (file_type == nullptr) {
        return "unknown";
    }
    return std::string(file_type);
}

std::vector<PatternMatch> FileAnalyzer::scan_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + filepath);
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    
    return pattern_manager.scan_content(content);
}

FileAnalyzer::FileInfo FileAnalyzer::analyze_file(const std::string& filepath) {
    FileInfo info;
    info.filename = std::filesystem::path(filepath).filename();
    info.filesize = std::filesystem::file_size(filepath);
    info.sha256 = calculate_sha256(filepath);
    info.filetype = detect_file_type(filepath);
    info.detected_patterns = scan_file(filepath);
    
    return info;
}

std::vector<FileAnalyzer::FileInfo> FileAnalyzer::batch_analyze(const std::string& directory) {
    std::vector<FileInfo> results;
    
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.is_regular_file()) {
            try {
                results.push_back(analyze_file(entry.path()));
            } catch (const std::exception& e) {
                std::cerr << "Error analyzing file " << entry.path() << ": " 
                         << e.what() << std::endl;
            }
        }
    }
    
    return results;
}

} // namespace security
