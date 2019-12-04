cmake_minimum_required(VERSION 3.12.0)

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR} ../third_party/spdlog/src)
