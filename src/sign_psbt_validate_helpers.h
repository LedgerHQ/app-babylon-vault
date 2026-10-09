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

/**
 * Parse a Claim/Reclaim leaf script: <OP_PUSHBYTES_32> <32B key D> <OP_CHECKSIG>, exactly
 * VAULT_DEPOSITOR_CLAIM_LEAF_LEN (34) bytes.
 *
 * Claim and Reclaim share this leaf byte-for-byte; the dispatcher tells them apart by
 * output count alone.  Extracts D into d_key_out.
 * Returns true if the script has the expected shape, false otherwise.
 */
bool parse_claim_leaf_script(const uint8_t *script,
                             int script_len,
                             uint8_t d_key_out[VAULT_XONLY_PUBKEY_LEN]);

/**
 * Report whether a Reclaim Input 0 nSequence is exactly the RBF signal RECLAIM_SEQUENCE
 * (0xFFFFFFFD), requiring the PSBT_IN_SEQUENCE field to be present.
 *
 * An absent field decodes as SEQUENCE_FINAL (non-replaceable) per BIP-370, which is not
 * RECLAIM_SEQUENCE — so omitting the field is already rejected by the equality check.
 * `present` is still taken explicitly so callers cannot default a PSBT_FIELD_ERROR read
 * into an accepted comparison value.
 */
bool reclaim_sequence_ok(bool present, uint32_t seq);

/**
 * Compute the Reclaim fee as in_value - out_value with a strictly-positive result.
 *
 * Returns false (fee_out left unset) when out_value >= in_value, covering both the
 * zero-fee case and the case that would otherwise underflow the subtraction.
 */
bool reclaim_fee_ok(uint64_t in_value, uint64_t out_value, uint64_t *fee_out);

/**
 * The optional Pre-PegIn outputs paying P2TR(depositor_pk) accepted so far.  Zero-initialise
 * before the first output and update only through prepegin_depositor_output_accept.
 */
typedef struct {
    bool anchor_seen;
    bool change_seen;
} prepegin_depositor_outputs_t;

/**
 * Accept a Pre-PegIn output whose scriptPubKey is already known to be P2TR(depositor_pk), and
 * record it in `seen`:
 *
 *   value == VAULT_DUST_LIMIT  CPFP anchor; at most one.
 *   value  > VAULT_DUST_LIMIT  depositor change; at most one, and only once the anchor has
 *                              been seen.
 *   value  < VAULT_DUST_LIMIT  rejected.
 *
 * The anchor and the change share one scriptPubKey, so the anchor-first order is the only way
 * for a reader of the transaction to tell them apart.
 *
 * @param change_allowed  Whether the depositor path accepts change (prepegin_change_path_ok).
 *                        The anchor is accepted regardless.
 *
 * Returns false, leaving `seen` unchanged, for any output that is not acceptable in the given
 * state.  change_seen without anchor_seen cannot arise from a caller that updates `seen` only
 * through this function, and is rejected for every value.
 */
bool prepegin_depositor_output_accept(prepegin_depositor_outputs_t *seen,
                                      uint64_t value,
                                      bool change_allowed);

/**
 * Report whether a Pre-PegIn may return change to the key at `path`: the first receive
 * address, m/86'/coin_type'/account'/0/0, of the BIP-86 account the transaction is signed from.
 * That is the address a wallet shows and scans.  The depositor path is chosen by the host and
 * never shown on the device, so change paid anywhere else in the BIP-86 space (the change
 * branch, a high address index, another account) would sit where wallets do not look.
 *
 * @param signing_purpose  BIP-44 purpose of the wallet policy the inputs are signed from; only
 *                         BIP86_PURPOSE qualifies.
 * @param signing_account  Unhardened account index of the wallet policy the inputs are signed
 *                         from, as verified against the device's own key by the base app.
 */
bool prepegin_change_path_ok(const uint32_t *path,
                             int path_len,
                             uint32_t signing_purpose,
                             uint32_t signing_account);
