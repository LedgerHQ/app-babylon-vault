#include <stdbool.h>
#include <string.h>

#include "ledger_assert.h"

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"
#include "../bitcoin_app_base/src/boilerplate/sw.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/common/psbt.h"
#include "../bitcoin_app_base/src/crypto.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map_value.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/handler/sign_psbt/sign_input.h"
#include "../bitcoin_app_base/src/handler/sign_psbt/txhashes.h"

#include "apdu_handler.h"
#include "globals.h"
#include "sign_psbt_validate.h"
#include "sign_psbt_validate_helpers.h"

/* 8B value + 1B varint + 34B P2TR script */
#define _MAX_WITNESS_UTXO_LEN (8 + 1 + 34)
/* 1B n_hashes + up to 2×32B leaf_hashes + 4B fingerprint + 5*4B path */
#define _MAX_TAP_BIP32_DERIV_LEN (1 + 2 * 32 + 4 + 5 * 4)

/*
 * Read PSBT_IN_WITNESS_UTXO for input 0 of `input_map` and require it to be a
 * standard 34-byte P2TR output.  On success copies the scriptPubKey into
 * `spk_out` and returns true.  On failure returns false WITHOUT sending a status
 * word, so each caller decides how to report the error and whether to invalidate
 * the session.
 */
static bool read_p2tr_witness_utxo(dispatcher_context_t *dc,
                                   merkleized_map_commitment_t *input_map,
                                   uint8_t spk_out[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    uint8_t wu[_MAX_WITNESS_UTXO_LEN];
    int wu_len = call_get_merkleized_map_value(dc,
                                               input_map,
                                               (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                               1,
                                               wu,
                                               sizeof(wu));
    if (wu_len < 9 || wu_len != 9 + wu[8] || wu[8] != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
        return false;
    }
    memcpy(spk_out, wu + 9, VAULT_P2TR_SCRIPTPUBKEY_LEN);
    return true;
}

bool sign_custom_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    tx_hashes_t *tx_hashes,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    UNUSED(internal_inputs);

    vault_state_t state = G_vault_context.state;
    const vault_intent_t *const intent = &G_vault_intent;

    /* -----------------------------------------------------------------------
     * PegIn (SESSION2_PEGIN_EXPECTED)
     *
     * Sign HTLC Leaf 0 (input 0) with the depositor key.
     * State advances to PAYOUT_EXPECTED only after signing succeeds, so the
     * host can retry on failure without losing session progress.
     * ----------------------------------------------------------------------- */
    if (state == VAULT_STATE_SESSION2_PEGIN_EXPECTED) {
        merkleized_map_commitment_t input_map;
        if (call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, 0, &input_map) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        int leaf_len = vault_build_htlc_leaf0(intent,
                                              G_vault_context.htlc_hashlock,
                                              G_scratch.script_scratch,
                                              VAULT_SCRIPT_MAX_LEN);
        if (leaf_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t leaf_hash[VAULT_HASH256_LEN];
        vault_taproot_leaf_hash(G_scratch.script_scratch, leaf_len, leaf_hash);

        uint8_t input_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!read_p2tr_witness_utxo(dc, &input_map, input_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t sighash[VAULT_HASH256_LEN];
        if (!compute_sighash_segwitv1(dc,
                                      st,
                                      tx_hashes,
                                      &input_map,
                                      0,
                                      input_spk,
                                      VAULT_P2TR_SCRIPTPUBKEY_LEN,
                                      leaf_hash,
                                      0x00,
                                      sighash)) {
            return false; /* SW already sent by callee */
        }

        if (!sign_sighash_schnorr_and_yield(dc,
                                            st,
                                            0,
                                            intent->depositor_path,
                                            VAULT_DEPOSITOR_PATH_LEN,
                                            NULL,
                                            0,
                                            leaf_hash,
                                            0x00,
                                            sighash)) {
            return false; /* SW already sent by callee */
        }

        LEDGER_ASSERT(vault_context_transition(&G_vault_context,
                                               VAULT_STATE_SESSION2_PEGIN_EXPECTED,
                                               VAULT_STATE_SESSION2_PAYOUT_EXPECTED),
                      "Unreachable: state was confirmed before signing");
        return true;
    }

    /* -----------------------------------------------------------------------
     * Payout (SESSION2_PAYOUT_EXPECTED or SESSION2_COMPLETE)
     *
     * Sign Vault UTXO (input 0) with the depositor key.
     * State and payout_index were already advanced in _validate_payout.
     * SESSION2_COMPLETE is reached after the last Payout's _validate_payout runs.
     * ----------------------------------------------------------------------- */
    if (state == VAULT_STATE_SESSION2_PAYOUT_EXPECTED || state == VAULT_STATE_SESSION2_COMPLETE) {
        merkleized_map_commitment_t input_map;
        if (call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, 0, &input_map) < 0) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        int leaf_len =
            vault_build_vault_utxo_leaf(intent, G_scratch.script_scratch, VAULT_SCRIPT_MAX_LEN);
        if (leaf_len < 0) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t leaf_hash[VAULT_HASH256_LEN];
        vault_taproot_leaf_hash(G_scratch.script_scratch, leaf_len, leaf_hash);

        uint8_t input_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!read_p2tr_witness_utxo(dc, &input_map, input_spk)) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t sighash[VAULT_HASH256_LEN];
        if (!compute_sighash_segwitv1(dc,
                                      st,
                                      tx_hashes,
                                      &input_map,
                                      0,
                                      input_spk,
                                      VAULT_P2TR_SCRIPTPUBKEY_LEN,
                                      leaf_hash,
                                      0x00,
                                      sighash)) {
            vault_context_invalidate(&G_vault_context);
            return false; /* SW already sent by callee */
        }

        if (!sign_sighash_schnorr_and_yield(dc,
                                            st,
                                            0,
                                            intent->depositor_path,
                                            VAULT_DEPOSITOR_PATH_LEN,
                                            NULL,
                                            0,
                                            leaf_hash,
                                            0x00,
                                            sighash)) {
            vault_context_invalidate(&G_vault_context);
            return false; /* SW already sent by callee */
        }

        return true;
    }

    /* -----------------------------------------------------------------------
     * Pre-PegIn (SESSION1_PREPEGIN_EXPECTED, has_no_wallet_policy == false):
     * All inputs are BIP-86 wallet-owned and were already signed by
     * sign_internal_inputs.  Nothing left to sign here.
     * ----------------------------------------------------------------------- */
    if (!st->has_no_wallet_policy) {
        return true;
    }

    /* -----------------------------------------------------------------------
     * Refund (any state, has_no_wallet_policy == true)
     *
     * Re-read PSBT_IN_TAP_LEAF_SCRIPT (fills G_scratch.tls), PSBT_IN_WITNESS_UTXO
     * for the scriptPubKey, and PSBT_IN_TAP_BIP32_DERIVATION for the signing path.
     * The original reads in _validate_display_refund cannot be reused because
     * display_refund_transaction clobbers G_scratch.tls via the display_tx union member.
     * ----------------------------------------------------------------------- */
    {
        merkleized_map_commitment_t input_map;
        if (!vault_read_refund_leaf_script(dc, st, &input_map)) {
            return false;
        }

        uint8_t leaf_hash[VAULT_HASH256_LEN];
        vault_taproot_leaf_hash(G_scratch.tls.leaf_script,
                                G_scratch.tls.leaf_script_len,
                                leaf_hash);

        uint8_t input_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!read_p2tr_witness_utxo(dc, &input_map, input_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t leaf_key[VAULT_XONLY_PUBKEY_LEN];
        uint32_t csv_value;
        if (!parse_refund_leaf_script(G_scratch.tls.leaf_script,
                                      G_scratch.tls.leaf_script_len,
                                      leaf_key,
                                      &csv_value)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t deriv_key[1 + VAULT_XONLY_PUBKEY_LEN];
        deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(deriv_key + 1, leaf_key, VAULT_XONLY_PUBKEY_LEN);

        uint8_t deriv_val[_MAX_TAP_BIP32_DERIV_LEN];
        int deriv_len = call_get_merkleized_map_value(dc,
                                                      &input_map,
                                                      deriv_key,
                                                      sizeof(deriv_key),
                                                      deriv_val,
                                                      sizeof(deriv_val));
        if (deriv_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint32_t fingerprint;
        uint32_t sign_path[5];
        int path_len =
            parse_tap_bip32_deriv_value(deriv_val, deriv_len, &fingerprint, sign_path, 5);
        if (path_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (fingerprint != st->master_key_fingerprint) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Bind the signing key to the script being spent.
         * validate_and_display_transaction already enforces these on the same
         * Merkle-committed PSBT, but signing must not silently rely on that:
         * re-check the BIP-86 path shape and that the derived x-only key equals
         * the leaf_key embedded in the refund script, so a refactor that ever
         * decouples validation from signing cannot turn this into a key-confusion
         * signing oracle. */
        if (!check_bip86_path(sign_path, path_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        serialized_extended_pubkey_t xpub;
        if (get_extended_pubkey_at_path(sign_path,
                                        (uint8_t) path_len,
                                        BIP32_PUBKEY_VERSION,
                                        &xpub) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* compressed_pubkey[0] is 0x02/0x03; x-only key is bytes [1..32] */
        if (memcmp(xpub.compressed_pubkey + 1, leaf_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t sighash[VAULT_HASH256_LEN];
        if (!compute_sighash_segwitv1(dc,
                                      st,
                                      tx_hashes,
                                      &input_map,
                                      0,
                                      input_spk,
                                      VAULT_P2TR_SCRIPTPUBKEY_LEN,
                                      leaf_hash,
                                      0x00,
                                      sighash)) {
            return false; /* SW already sent by callee */
        }

        if (!sign_sighash_schnorr_and_yield(dc,
                                            st,
                                            0,
                                            sign_path,
                                            (size_t) path_len,
                                            NULL,
                                            0,
                                            leaf_hash,
                                            0x00,
                                            sighash)) {
            return false; /* SW already sent by callee */
        }

        return true;
    }
}
