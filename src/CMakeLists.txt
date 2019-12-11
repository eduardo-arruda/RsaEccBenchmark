cmake_minimum_required(VERSION 3.12.0)

project(RsaEccBenchmark)

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME}
   RsaEccBenchmark.cpp
   Util/Convert.cpp
   Util/Random.cpp
   Util/Base64.cpp
   EccEncrypt/EccKeyPair.cpp
   EccEncrypt/EccSignature.cpp
   RsaEncrypt/RsaKeyPair.cpp
   RsaEncrypt/RsaSignature.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC
  ${OPENSSL_INCLUDE_DIR}
  spdlog
)

include_directories(
  Util
  EccEncrypt
  RsaEncrypt
)

target_link_libraries(${PROJECT_NAME} PUBLIC
  ${OPENSSL_LIBRARIES}
  spdlog
)

set_target_properties(${PROJECT_NAME} PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
