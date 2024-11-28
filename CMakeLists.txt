cmake_minimum_required(VERSION 3.29)
project(crypto_algs_comparison)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.*")

include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(crypto_algs_comparison ${SOURCES})

target_include_directories(crypto_algs_comparison PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(crypto_algs_comparison PRIVATE ${OPENSSL_CRYPTO_LIBRARY} ${OPENSSL_SSL_LIBRARY})