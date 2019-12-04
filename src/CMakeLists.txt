cmake_minimum_required(VERSION 3.12.0)

project(RsaEccBenchmark)

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME} RsaEccBenchmark.cpp EccKeyPair/EccKeyPair.cpp RsaKeyPair/RsaKeyPair.cpp)

target_include_directories(${PROJECT_NAME} PUBLIC ${OPENSSL_INCLUDE_DIR} spdlog)
include_directories(EccKeyPair RsaKeyPair)

target_link_libraries(${PROJECT_NAME} PUBLIC ${OPENSSL_LIBRARIES} spdlog)

set_target_properties(${PROJECT_NAME} PROPERTIES
   ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
   LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
   RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)