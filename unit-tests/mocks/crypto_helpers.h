#pragma once

/**
 * Mock crypto_helpers.h for unit tests.
 * Provides bip32_derive_init_privkey_256 with a fixed test key (0x42 * 32).
 * Implemented in unit-tests/mock_cx.c.
 */

#include "cx.h"

#define HDW_NORMAL 0

WARN_UNUSED_RESULT cx_err_t bip32_derive_init_privkey_256(cx_curve_t                 curve,
                                                           const uint32_t            *path,
                                                           size_t                     path_len,
                                                           cx_ecfp_256_private_key_t *privkey,
                                                           uint8_t                   *chain_code);
