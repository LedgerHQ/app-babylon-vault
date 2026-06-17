#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "vault_intent.h"

/**
 * Check whether a BIP-32 path is BIP-86 shaped:
 *   m/86'/coin_type'/account'/change/index
 * with account <= 100 and address_index <= 10000.
 */
bool check_bip86_path(const uint32_t *path, int path_len);

/**
 * Parse a TAP_BIP32_DERIVATION value:
 *   [n_hashes (1B)] [n_hashes * 32B leaf hashes] [fingerprint (4B LE)] [path steps (4B LE each)]
 *
 * Skips the leaf hashes, then reads fingerprint and path steps.
 * Returns the number of path steps on success, or -1 on any parse error.
 */
int parse_tap_bip32_deriv_value(const uint8_t *val,
                                int val_len,
                                uint32_t *fingerprint_out,
                                uint32_t *path_out,
                                int max_path_steps);

/**
 * Parse a Refund HTLC leaf script:
 *   <OP_PUSHBYTES_32> <32B key> <OP_CHECKSIGVERIFY> <minimal-push CSV> <OP_CHECKSEQUENCEVERIFY>
 *
 * Extracts the 32-byte x-only public key into leaf_key_out.
 * Returns true if the script has the expected shape, false otherwise.
 */
bool parse_refund_leaf_script(const uint8_t *script,
                              int script_len,
                              uint8_t leaf_key_out[VAULT_XONLY_PUBKEY_LEN]);
