cmake_minimum_required(VERSION 3.10)
project(BabylonVaultFuzzers
  VERSION 0.1
  DESCRIPTION "Babylon Vault libFuzzer targets"
  LANGUAGES C)

# ── Enforce Clang (libFuzzer requirement) ────────────────────────────────────
if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    find_program(CLANG_EXECUTABLE clang)
    if(CLANG_EXECUTABLE)
        set(CMAKE_C_COMPILER   ${CLANG_EXECUTABLE} CACHE STRING "C compiler"   FORCE)
        set(CMAKE_CXX_COMPILER clang++             CACHE STRING "C++ compiler" FORCE)
    else()
        message(FATAL_ERROR "Fuzzers must be built with Clang. Install clang.")
    endif()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# ── Sanitizer + libFuzzer flags ───────────────────────────────────────────────
# ClusterFuzzLite sets LIB_FUZZING_ENGINE; local runs default to
# -fsanitize=fuzzer,address,undefined.
if(DEFINED ENV{LIB_FUZZING_ENGINE})
    set(FUZZER_FLAGS "$ENV{LIB_FUZZING_ENGINE} $ENV{CFLAGS}")
    if(DEFINED ENV{SANITIZER})
        if("$ENV{SANITIZER}" STREQUAL "address")
            string(APPEND FUZZER_FLAGS
                " -fsanitize=address -fsanitize-address-use-after-scope")
        elseif("$ENV{SANITIZER}" STREQUAL "memory")
            string(APPEND FUZZER_FLAGS
                " -fsanitize=memory -fsanitize-memory-track-origins=2")
        elseif("$ENV{SANITIZER}" STREQUAL "undefined")
            string(APPEND FUZZER_FLAGS
                " -fsanitize=undefined -fno-sanitize-recover=undefined")
        endif()
        string(APPEND FUZZER_FLAGS
            " -fsanitize-coverage=trace-cmp,indirect-calls,8bit-counters")
    endif()
else()
    set(FUZZER_FLAGS "-O1 -g -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined")
endif()

separate_arguments(FUZZER_FLAGS_LIST NATIVE_COMMAND "${FUZZER_FLAGS}")

# ── Paths ─────────────────────────────────────────────────────────────────────
set(SRC_DIR   ${CMAKE_CURRENT_SOURCE_DIR}/../src)
set(STUBS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/stubs)

# stubs/ must come first to shadow SDK headers (os_utils.h, etc.)
include_directories(${STUBS_DIR} ${SRC_DIR})

# BIP44_COIN_TYPE must be provided; 1 = testnet (matches the test binary)
add_compile_definitions(BIP44_COIN_TYPE=1)

# ── Helper ────────────────────────────────────────────────────────────────────
function(add_fuzz_target TARGET)
    set(EXTRA_SOURCES ${ARGN})
    add_executable(${TARGET}
        src/${TARGET}.c
        ${EXTRA_SOURCES}
    )
    target_compile_options(${TARGET} PRIVATE ${FUZZER_FLAGS_LIST})
    target_link_options(${TARGET}    PRIVATE ${FUZZER_FLAGS_LIST})
endfunction()

# ── Targets ───────────────────────────────────────────────────────────────────

# P1=0x00 TLV scalar parser
add_fuzz_target(fuzz_vault_tlv
    ${SRC_DIR}/vault_tlv.c
)

# P1=0x01 key batch validation (static inline — no extra .c needed)
add_fuzz_target(fuzz_key_batch)
