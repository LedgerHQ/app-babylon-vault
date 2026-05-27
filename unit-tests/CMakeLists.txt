cmake_minimum_required(VERSION 3.10)

project(unit_tests
  VERSION 0.1
  DESCRIPTION "Unit tests for Babylon Vault app"
  LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Debug")
endif()

include(CTest)
enable_testing()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -Wall -pedantic -g -O0 --coverage")

set(GCC_COVERAGE_LINK_FLAGS "--coverage -lgcov")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GCC_COVERAGE_LINK_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS   "${CMAKE_EXE_LINKER_FLAGS}   ${GCC_COVERAGE_LINK_FLAGS}")

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
  message(FATAL_ERROR "In-source builds are not allowed.")
endif()

# -----------------------------------------------------------------------
# Sources under test (no Ledger SDK needed — pure-C state machine)
# -----------------------------------------------------------------------
set(SRC_DIR ${CMAKE_SOURCE_DIR}/../src)

include_directories(${SRC_DIR})

# -----------------------------------------------------------------------
# test_vault_context
# -----------------------------------------------------------------------
add_executable(test_vault_context
  test_vault_context.c
  ${SRC_DIR}/vault_context.c
  ${SRC_DIR}/globals.c
)

target_compile_definitions(test_vault_context PRIVATE TEST)

find_package(cmocka REQUIRED)
target_link_libraries(test_vault_context cmocka)

add_test(NAME test_vault_context COMMAND test_vault_context)
