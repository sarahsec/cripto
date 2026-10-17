cmake_minimum_required(VERSION 3.16)
project(cripto_cli LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_library(cripto_core src/crypto.cpp)
target_include_directories(cripto_core PUBLIC src)
target_link_libraries(cripto_core PUBLIC OpenSSL::Crypto)
target_compile_options(cripto_core PRIVATE -Wall -Wextra -Wpedantic)

add_executable(cripto src/main.cpp)
target_link_libraries(cripto PRIVATE cripto_core)
target_compile_options(cripto PRIVATE -Wall -Wextra -Wpedantic)

enable_testing()
add_executable(cripto_tests tests/test_cripto.cpp)
target_link_libraries(cripto_tests PRIVATE cripto_core)
target_compile_options(cripto_tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME cripto_tests COMMAND cripto_tests)
