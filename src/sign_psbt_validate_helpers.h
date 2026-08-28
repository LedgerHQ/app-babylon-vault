#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "vault_script.h"

/**
 * Check whether a BIP-32 path is BIP-86 shaped:
 *   m/86'/coin_type'/account'/change/index
 * with account <= 100 and address_index <= 10000.
 */
bool check_bip86_path(const uint32_t *path, int path_len);

/**
 * Parse a TAP_BIP32_DERIVATION value:
 *   [n_hashes (1B)] [n_hashes * 32B leaf hashes] [fingerprint (4B BE)] [path steps (4B LE each)]
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
 * Extracts the 32-byte x-only public key into leaf_key_out and the decoded
 * positive CSV timelock into csv_value_out.
 * Returns true if the script has the expected shape, false otherwise.
 */
bool parse_refund_leaf_script(const uint8_t *script,
                              int script_len,
                              uint8_t leaf_key_out[VAULT_XONLY_PUBKEY_LEN],
                              uint32_t *csv_value_out);

/**
 * Parse a PayoutFinalize (Assert:0 payout) leaf script:
 *   <OP_PUSHBYTES_32> <32B depositor-key> <OP_CHECKSIGVERIFY>
 *   [AppChallengers multisig] [UnivChallengers multisig]
 *   <t2-push> <OP_CHECKSEQUENCEVERIFY>
 *
 * Validates the leaf shape (length > 68, correct opcodes at fixed positions and
 * tail), extracts the 32-byte x-only depositor key into d_key_out, and decodes
 * the t2 CSV timelock into csv_value_out.
 * Returns true if the script has the expected shape, false otherwise.
 */
bool parse_payout_leaf_script(const uint8_t *script,
                              int script_len,
                              uint8_t d_key_out[VAULT_XONLY_PUBKEY_LEN],
                              uint32_t *csv_value_out);

/**
 * Report whether a leaf has the Assert shape: length past the NoPayout leaf, a 32-byte key
 * push closed by OP_CHECKSIG where the first challenger group starts, and a terminal
 * OP_TRUE.
 *
 * Shape only.  It separates the Assert leaf from the app's other leaves, but says nothing
 * about whether the leaf is trustworthy — a hand-crafted leaf can satisfy every byte it
 * reads.  Callers must also require G_leaf_meta.assert_prefix_ok, which is what binds the
 * leaf's signer set to the approved intent.
 *
 * @param script_len  Full script length; only the prefix and last byte are read.
 * @param prefix      At least VAULT_LEAF_PREFIX_LEN captured leading bytes.
 */
bool leaf_has_assert_shape(int script_len, const uint8_t *prefix, uint8_t last_byte);
