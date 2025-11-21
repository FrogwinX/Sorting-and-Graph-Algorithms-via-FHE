cmake_minimum_required(VERSION 3.15)
project(seal_demo)

set(CMAKE_CXX_STANDARD 17)
find_package(SEAL 4.1.1 REQUIRED)

add_executable(seal_demo main.cpp)
target_link_libraries(seal_demo SEAL::seal)