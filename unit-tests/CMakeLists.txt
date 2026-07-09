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
# Paths
# -----------------------------------------------------------------------
set(SRC_DIR   ${CMAKE_SOURCE_DIR}/../src)
set(MOCKS_DIR ${CMAKE_SOURCE_DIR}/mocks)

# Mock headers override Ledger SDK headers for all test targets.
# MOCKS_DIR must come first so mock cx.h / crypto_helpers.h are found
# before any SDK include path.
include_directories(${MOCKS_DIR} ${SRC_DIR})

find_package(cmocka REQUIRED)

# -----------------------------------------------------------------------
# test_vault_context
# -----------------------------------------------------------------------
add_executable(test_vault_context
  test_vault_context.c
  mock_cx.c
  ${SRC_DIR}/vault_context.c
  ${SRC_DIR}/globals.c
)

target_compile_definitions(test_vault_context PRIVATE TEST BIP44_COIN_TYPE=1 VAULT_TARGET_SIGNET)
target_link_libraries(test_vault_context cmocka)

add_test(NAME test_vault_context COMMAND test_vault_context)

# -----------------------------------------------------------------------
# test_derive_context_hash
# -----------------------------------------------------------------------
add_executable(test_derive_context_hash
  test_derive_context_hash.c
  mock_cx.c
  ${SRC_DIR}/globals.c
)

# BIP44_COIN_TYPE=0 → canonicalNetworkName "bitcoin-mainnet" (matches the §4.2 vector).
target_compile_definitions(test_derive_context_hash PRIVATE TEST BIP44_COIN_TYPE=0)
target_link_libraries(test_derive_context_hash cmocka)

add_test(NAME test_derive_context_hash COMMAND test_derive_context_hash)

# -----------------------------------------------------------------------
# test_derive_vault_secrets
# -----------------------------------------------------------------------
add_executable(test_derive_vault_secrets
  test_derive_vault_secrets.c
  mock_cx.c
)

target_compile_definitions(test_derive_vault_secrets PRIVATE TEST BIP44_COIN_TYPE=0)
target_link_libraries(test_derive_vault_secrets cmocka)

add_test(NAME test_derive_vault_secrets COMMAND test_derive_vault_secrets)

# -----------------------------------------------------------------------
# test_vault_tlv
#
# Tests vault_tlv_parse (src/vault_tlv.c) and the static-inline core
# functions in src/handler/approve_vault_intent_core.h.
# No mock_cx needed — vault_tlv.c only uses os_utils.h (mocked in mocks/).
# BIP44_COIN_TYPE must match VALID_PATH[1] in the test fixture (coin type 1).
# -----------------------------------------------------------------------
add_executable(test_vault_tlv
  test_vault_tlv.c
  ${SRC_DIR}/vault_tlv.c
)

target_compile_definitions(test_vault_tlv PRIVATE
  TEST
  BIP44_COIN_TYPE=1
  VAULT_TARGET_SIGNET
)
target_link_libraries(test_vault_tlv cmocka)

add_test(NAME test_vault_tlv COMMAND test_vault_tlv)

# -----------------------------------------------------------------------
# test_vault_script
#
# Tests vault_script.c leaf builders, taproot primitives, scriptpubkey
# derivation, and PegIn txid computation.
# mock_cx.c provides SHA-256 + taproot tagged-hash + secp256k1 tweak.
# -----------------------------------------------------------------------
add_executable(test_vault_script
  test_vault_script.c
  mock_cx.c
  ${SRC_DIR}/vault_script.c
  ${SRC_DIR}/globals.c
)

target_compile_definitions(test_vault_script PRIVATE
  TEST
  BIP44_COIN_TYPE=1
  VAULT_TARGET_SIGNET
)
target_link_libraries(test_vault_script cmocka)

add_test(NAME test_vault_script COMMAND test_vault_script)

# -----------------------------------------------------------------------
# test_sign_psbt_validate
#
# Tests the three pure helper functions extracted from sign_psbt_validate.c:
#   check_bip86_path, parse_tap_bip32_deriv_value, parse_refund_leaf_script.
# mocks/read.h provides inline read_u32_le; mocks/common/script.h provides
# opcode constants.  No mock_cx needed (no SHA-256 or crypto calls).
# -----------------------------------------------------------------------
add_executable(test_sign_psbt_validate
  test_sign_psbt_validate.c
  ${SRC_DIR}/sign_psbt_validate_helpers.c
)

target_compile_definitions(test_sign_psbt_validate PRIVATE
  TEST
  BIP44_COIN_TYPE=1
  VAULT_TARGET_SIGNET
)
target_link_libraries(test_sign_psbt_validate cmocka)

add_test(NAME test_sign_psbt_validate COMMAND test_sign_psbt_validate)
