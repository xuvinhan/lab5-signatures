cmake_minimum_required(VERSION 3.20)

project(Lab5_Digital_Signatures LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)

add_executable(sigtool
    src/main.cpp
)

target_link_libraries(sigtool PRIVATE
    OpenSSL::Crypto
)
