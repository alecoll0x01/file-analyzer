# Automated File Analysis Tool

A robust C++ tool for automated analysis of potentially suspicious files, providing comprehensive file information including metadata, cryptographic hashes, and malicious pattern detection.

## Features

- Comprehensive file analysis:
  - File metadata extraction (size, type, name)
  - SHA256 hash calculation
  - MIME type detection
  - Suspicious pattern recognition
- Batch processing support for directory analysis
- Modern, exception-safe C++ implementation
- Extensible pattern detection system
- JSON output format support

## Prerequisites

- C++17 or later
- OpenSSL libraries
- libmagic
- CMake 3.12+
- nlohmann-json library

## Installation

### Arch Linux

1. Install dependencies:
```bash
sudo pacman -S openssl file cmake gcc make nlohmann-json
```

2. Clone and build:
```bash
git clone https://github.com/yourusername/file-analyzer
cd file-analyzer
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Other Linux Distributions

Please refer to your distribution's package manager for installing the required dependencies.

## Usage

### Command Line Interface

Basic file analysis:
```bash
./file_analyzer <file_path>
```

Directory analysis with custom patterns:
```bash
./file_analyzer <directory_path> patterns.json
```

### Example Output

```json
{
  "analysis_result": {
    "filename": "test.exe",
    "size_bytes": 45678,
    "mime_type": "application/x-executable",
    "sha256": "a1b2c3d4e5f6...",
    "suspicious": true,
    "detected_patterns": [
      "CreateProcess",
      "WinExec"
    ]
  }
}
```

### C++ API Integration

```cpp
#include "security/file_analyzer.hpp"

int main() {
    security::FileAnalyzer analyzer;
    
    // Configure custom patterns
    analyzer.add_suspicious_pattern("dangerous_function");
    
    // Single file analysis
    auto result = analyzer.analyze_file("suspicious_file.exe");
    
    // Batch directory analysis
    auto batch_results = analyzer.batch_analyze("/path/to/directory");
    
    return 0;
}
```

## Project Structure

```
file-analyzer/
├── CMakeLists.txt
├── include/
│   └── security/
│       ├── pattern_manager.hpp
│       └── file_analyzer.hpp
├── src/
│   ├── file_analyzer.cpp
│   ├── pattern_manager.cpp
│   └── main.cpp
├── tests/
│   └── unit_tests/
├── docs/
│   └── API.md
└── README.md
```

## Security Guidelines

- Always run analysis in an isolated environment
- Do not execute suspicious files
- Follow proper malware handling procedures
- Keep the tool and its dependencies updated
- Review patterns file before usage

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Guidelines

- Follow C++17 best practices
- Include unit tests for new features
- Document public APIs
- Maintain exception safety
- Update relevant documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- OpenSSL project
- libmagic developers
- nlohmann/json library
