cmake_minimum_required(VERSION 3.10.2)
project(Cert-test 
        VERSION 1.0
        DESCRIPTION "Certificate Test"
        LANGUAGES C)

add_definitions(-DOPENSSL_API_COMPAT=0x10100000L)

include_directories("${CMAKE_SOURCE_DIR}/src")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")

#======================= BUILD MODE =========================

#set(BUILD_MODE RELEASE)
set(BUILD_MODE DEBUG)

if (${BUILD_MODE} STREQUAL DEBUG)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
        set(CMAKE_BUILD_TYPE Debug)
        add_definitions(-DIS_RELEASE_BUILD=0)
else()
        add_definitions(-DIS_RELEASE_BUILD=1)
endif()

#============================================================


add_executable(client "src/client.c" "src/testlib.c" "src/sock.c" "src/ossl_debug.c")
add_executable(server "src/server.c" "src/testlib.c" "src/sock.c" "src/ossl_debug.c")

find_package(OpenSSL REQUIRED)
find_package(OpenSSL REQUIRED)
target_link_libraries(client OpenSSL::SSL)
target_link_libraries(server OpenSSL::SSL)
target_link_libraries(client OpenSSL::Crypto)
target_link_libraries(server OpenSSL::Crypto)