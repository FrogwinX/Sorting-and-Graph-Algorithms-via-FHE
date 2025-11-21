cmake_minimum_required(VERSION 3.10)
project(ckks-appro)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Xpreprocessor -fopenmp")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L/opt/homebrew/opt/libomp/lib -lomp")
include_directories("/opt/homebrew/opt/libomp/include")

find_package(OpenFHE REQUIRED)

add_executable(ckks-appro ckks-appro.cpp)
target_link_libraries(ckks-appro OPENFHEcore OPENFHEpke OPENFHEbinfhe)

# Set include directories
target_include_directories(ckks-appro PRIVATE 
    /usr/local/include/openfhe
    /usr/local/include/openfhe/core
    /usr/local/include/openfhe/pke
    /usr/local/include/openfhe/binfhe
)
