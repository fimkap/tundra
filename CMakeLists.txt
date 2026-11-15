cmake_minimum_required(VERSION 3.25)
project(tundra LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(TUNDRA_BUILD_TESTS "Build the tests" ON)
option(TUNDRA_BUILD_BENCH "Build the benchmarks" OFF)
option(TUNDRA_FUZZ "Build the libFuzzer targets (clang)" OFF)
set(TUNDRA_SANITIZE "" CACHE STRING "Sanitizers, e.g. address,undefined")

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wnon-virtual-dtor)
if(TUNDRA_SANITIZE)
  add_compile_options(-fsanitize=${TUNDRA_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${TUNDRA_SANITIZE})
endif()

add_library(tundra STATIC
  src/checksum.cpp
  src/wire.cpp
)
target_include_directories(tundra PUBLIC include)

include(FetchContent)

if(TUNDRA_BUILD_TESTS)
  FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
                       DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  enable_testing()
  add_executable(tundra_tests
    tests/checksum_test.cpp
    tests/wire_test.cpp
  )
  target_link_libraries(tundra_tests PRIVATE tundra GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(tundra_tests DISCOVERY_TIMEOUT 60)
endif()
