cmake_minimum_required(VERSION 3.5)

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_FLAGS "-O3 ${CMAKE_CXX_FLAGS}")

if (LINUX)
    set(OPENSSL_ROOT_DIR /usr/local/ssl)
    set(OPENSSL_LIBRARIES /usr/local/ssl/lib)
endif(LINUX)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

set(SOURCES main.cpp)
link_libraries(${OPENSSL_CRYPTO_LIBRARY})
add_executable(password_cracker ${SOURCES})
