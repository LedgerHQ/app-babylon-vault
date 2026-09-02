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
set(SRC_DIR      ${CMAKE_SOURCE_DIR}/../src)
set(BASE_SRC_DIR ${CMAKE_SOURCE_DIR}/../bitcoin_app_base/src)
set(MOCKS_DIR    ${CMAKE_SOURCE_DIR}/mocks)

# libsecp256k1 backs the real BIP-341 output-key tweak in mock_cx.c (V-030). REQUIRED
# rather than optional on purpose: falling back to a hash stub is what made the taproot
# targets unable to serve as an oracle for the output key or the control-block parity bit,
# and an optional dependency would silently restore that. Install with
# `apt-get install libsecp256k1-dev`.
find_library(SECP256K1_LIBRARY NAMES secp256k1 REQUIRED)
find_path(SECP256K1_INCLUDE_DIR NAMES secp256k1.h REQUIRED)

# Mock headers override Ledger SDK headers for all test targets.
# MOCKS_DIR must come first so mock cx.h / crypto_helpers.h are found
# before any SDK include path.
include_directories(${MOCKS_DIR} ${SRC_DIR} ${SECP256K1_INCLUDE_DIR})

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
target_link_libraries(test_vault_context cmocka ${SECP256K1_LIBRARY})

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
target_link_libraries(test_derive_context_hash cmocka ${SECP256K1_LIBRARY})

add_test(NAME test_derive_context_hash COMMAND test_derive_context_hash)

# -----------------------------------------------------------------------
# test_derive_vault_secrets
# -----------------------------------------------------------------------
add_executable(test_derive_vault_secrets
  test_derive_vault_secrets.c
  mock_cx.c
)

target_compile_definitions(test_derive_vault_secrets PRIVATE TEST BIP44_COIN_TYPE=0)
target_link_libraries(test_derive_vault_secrets cmocka ${SECP256K1_LIBRARY})

add_test(NAME test_derive_vault_secrets COMMAND test_derive_vault_secrets)

# -----------------------------------------------------------------------
# test_vault_tlv
#
# Tests vault_tlv_parse (src/vault_tlv.c) and the static-inline core
# functions in src/handler/approve_vault_intent_core.h.
# No mock_cx needed — vault_tlv.c only uses os_utils.h (mocked in mocks/).
# BIP44_COIN_TYPE must match VALID_PATH[1] in the test fixture (coin type 1).
# -----------------------------------------------------------------------
# secp256k1.c is a 23-line constant table with no SDK dependency; linking the real
# one keeps vault_xonly_key_is_canonical tested against the same field prime the
# firmware uses, rather than a copy that could drift.
add_executable(test_vault_tlv
  test_vault_tlv.c
  ${SRC_DIR}/vault_tlv.c
  ${BASE_SRC_DIR}/secp256k1.c
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
# mock_cx.c provides SHA-256 + taproot tagged-hash, and the real libsecp256k1 output-key
# tweak (so this target is a genuine oracle for P2TR keys and control-block parity).
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
target_link_libraries(test_vault_script cmocka ${SECP256K1_LIBRARY})

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

# -----------------------------------------------------------------------
# test_bip322
#
# Tests bip322_parse_pop_message (pure string logic) and
# bip322_compute_to_spend_txid (BIP-322 tagged hash + to_spend txid).
# mock_cx.c provides the software SHA-256 implementation.
# -----------------------------------------------------------------------
add_executable(test_bip322
  test_bip322.c
  mock_cx.c
  ${SRC_DIR}/bip322.c
)

target_compile_definitions(test_bip322 PRIVATE TEST BIP44_COIN_TYPE=1)
target_link_libraries(test_bip322 cmocka ${SECP256K1_LIBRARY})

add_test(NAME test_bip322 COMMAND test_bip322)
