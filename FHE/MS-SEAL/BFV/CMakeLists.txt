cmake_minimum_required(VERSION 3.15)
project(sort_bfv)

set(CMAKE_CXX_STANDARD 17)
find_package(SEAL 4.1.1 REQUIRED)

add_executable(sort_bfv main.cpp)
target_link_libraries(sort_bfv SEAL::seal)