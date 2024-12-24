cmake_minimum_required(VERSION 3.10)
project(file_analyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(MAGIC REQUIRED libmagic)

# Add executable
add_executable(file_analyzer
    src/main.cpp
    src/file_analyzer.cpp
)

# Include directories
target_include_directories(file_analyzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
    ${MAGIC_INCLUDE_DIRS}
)

# Link libraries
target_link_libraries(file_analyzer PRIVATE
    OpenSSL::Crypto
    ${MAGIC_LIBRARIES}
)

# Install
install(TARGETS file_analyzer DESTINATION bin)