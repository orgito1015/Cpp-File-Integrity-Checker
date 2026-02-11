
cmake_minimum_required(VERSION 3.10)
project(FileIntegrityChecker)

set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)

add_executable(file_integrity_checker src/main.cpp)
target_link_libraries(file_integrity_checker OpenSSL::Crypto)
