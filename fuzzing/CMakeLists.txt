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
# In ClusterFuzzLite/OSS-Fuzz, build.sh passes $CFLAGS via -DCMAKE_C_FLAGS
# and $LIB_FUZZING_ENGINE as a cmake variable; each fuzzer target links it
# explicitly via target_link_libraries. No manual ENV handling needed here.
#
# For local development (LIB_FUZZING_ENGINE not set), fall back to a combined
# fuzzer+sanitizer build so run_local.sh works without any extra setup.
if(NOT DEFINED ENV{LIB_FUZZING_ENGINE})
    add_compile_options(
        -O1
        -g
        -fno-omit-frame-pointer
        -fsanitize=fuzzer,address,undefined
    )
    add_link_options(-fsanitize=fuzzer,address,undefined)
endif()

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
    # In CI, link the fuzzer engine explicitly so it isn't part of CMAKE_EXE_LINKER_FLAGS
    # (a global linker flag would conflict with cmake's own int-main() compiler check).
    # For local runs, -fsanitize=fuzzer from add_link_options above provides the runtime.
    if(DEFINED LIB_FUZZING_ENGINE)
        target_link_libraries(${TARGET} PRIVATE ${LIB_FUZZING_ENGINE})
    endif()
endfunction()

# ── Targets ───────────────────────────────────────────────────────────────────

# P1=0x00 TLV scalar parser
add_fuzz_target(fuzz_vault_tlv
    ${SRC_DIR}/vault_tlv.c
)

# P1=0x01 key batch validation (static inline — no extra .c needed)
add_fuzz_target(fuzz_key_batch)
