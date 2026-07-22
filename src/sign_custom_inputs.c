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

/* A witness UTXO is serialized as: 8-byte value (LE) | 1-byte compact-size script
 * length | scriptPubKey. A 34-byte P2TR script uses a single-byte length (0x22). */
#define _WU_VALUE_LEN      8                   /* 8-byte little-endian amount */
#define _WU_SCRIPT_LEN_OFF _WU_VALUE_LEN       /* offset of the 1-byte script-length */
#define _WU_SCRIPT_OFF     (_WU_VALUE_LEN + 1) /* offset of the scriptPubKey bytes */

/* 8B value + 1B varint + 34B P2TR script */
#define _MAX_WITNESS_UTXO_LEN (_WU_SCRIPT_OFF + VAULT_P2TR_SCRIPTPUBKEY_LEN)
/* 1B n_hashes + up to 2×32B leaf_hashes + 4B fingerprint + 5*4B path */
#define _MAX_TAP_BIP32_DERIV_LEN (1 + 2 * 32 + 4 + 5 * 4)

/*
 * Read PSBT_IN_WITNESS_UTXO for input 0 of `input_map` and require it to be a
 * standard 34-byte P2TR output.  When `expected_spk` is non-NULL the read
 * scriptPubKey must equal it byte-for-byte — this binds the value that goes
 * into the sighash to a script the device reconstructed from the approved
 * intent, instead of trusting the host's witness UTXO.  On success copies the
 * scriptPubKey into `spk_out` and returns true.  On failure returns false
 * WITHOUT sending a status word, so each caller decides how to report the error
 * and whether to invalidate the session.
 */
static bool read_p2tr_witness_utxo(dispatcher_context_t *dc,
                                   merkleized_map_commitment_t *input_map,
                                   const uint8_t *expected_spk,
                                   uint8_t spk_out[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    uint8_t wu[_MAX_WITNESS_UTXO_LEN];
    int wu_len = call_get_merkleized_map_value(dc,
                                               input_map,
                                               (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                               1,
                                               wu,
                                               sizeof(wu));
    if (wu_len < _WU_SCRIPT_OFF || wu_len != _WU_SCRIPT_OFF + wu[_WU_SCRIPT_LEN_OFF] ||
        wu[_WU_SCRIPT_LEN_OFF] != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
        return false;
    }
    if (expected_spk != NULL &&
        memcmp(wu + _WU_SCRIPT_OFF, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
        return false;
    }
    memcpy(spk_out, wu + _WU_SCRIPT_OFF, VAULT_P2TR_SCRIPTPUBKEY_LEN);
    return true;
}

bool sign_custom_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    tx_hashes_t *tx_hashes,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
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
                                              0,
                                              G_vault_context.htlc_hashlock[0],
                                              G_scratch.script_scratch,
                                              VAULT_SCRIPT_MAX_LEN);
        if (leaf_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t leaf_hash[VAULT_HASH256_LEN];
        vault_taproot_leaf_hash(G_scratch.script_scratch, leaf_len, leaf_hash);

        /* Bind the witness-UTXO scriptPubKey to the HTLC P2TR reconstructed from
         * the approved intent, so the sighash commits to a device-known script. */
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!vault_build_htlc_scriptpubkey(intent,
                                           0,
                                           G_vault_context.htlc_hashlock[0],
                                           expected_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t input_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!read_p2tr_witness_utxo(dc, &input_map, expected_spk, input_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Sighash type SIGHASH_DEFAULT (0x00): the device reconstructs and
         * validates the entire transaction from the approved intent, so the
         * signature must commit to all inputs and outputs. SIGHASH_DEFAULT is
         * the BIP-341 default (equivalent to SIGHASH_ALL, 64-byte signature);
         * the PSBT validation path only accepts SIGHASH_DEFAULT as well. */
        uint8_t sighash[VAULT_HASH256_LEN];
        if (!compute_sighash_segwitv1(dc,
                                      st,
                                      tx_hashes,
                                      &input_map,
                                      0,
                                      input_spk,
                                      VAULT_P2TR_SCRIPTPUBKEY_LEN,
                                      leaf_hash,
                                      SIGHASH_DEFAULT,
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
                                            SIGHASH_DEFAULT,
                                            sighash)) {
            return false; /* SW already sent by callee */
        }

        LEDGER_ASSERT(vault_context_transition(&G_vault_context,
                                               VAULT_STATE_SESSION2_PEGIN_EXPECTED,
                                               VAULT_STATE_SESSION2_PAYOUT_EXPECTED),
                      "Unreachable: state was confirmed before signing");
        /* vault_group_index was used as a group-ingestion cursor during
         * approve_vault_intent and is left at vault_count.  Reset it to 0
         * so _validate_payout can use it as the payout-group cursor. */
        G_vault_context.vault_group_index = 0;
        return true;
    }

    /* -----------------------------------------------------------------------
     * Payout / NoPayout (SESSION2_PAYOUT_EXPECTED or SESSION2_COMPLETE)
     *
     * NoPayout (n_inputs==3): sign Input 0 with the depositor NoPayout leaf.
     * Payout   (n_inputs==2): sign Input 0 with the depositor Vault UTXO leaf.
     * State and indices were already advanced in the corresponding validator.
     * SESSION2_COMPLETE is reached after the last Payout's _validate_payout runs.
     * ----------------------------------------------------------------------- */
    if (state == VAULT_STATE_SESSION2_PAYOUT_EXPECTED || state == VAULT_STATE_SESSION2_COMPLETE) {
        /* -------
         * NoPayout: 3 inputs, 1 output, no wallet policy.
         * Re-read Input 0's TAP_LEAF_SCRIPT (G_scratch.tls clobbered by display).
         * Sign with the depositor path using the reconstructed NoPayout leaf hash.
         * ------- */
        if (st->has_no_wallet_policy && st->n_inputs == 3 && st->n_outputs == 1) {
            merkleized_map_commitment_t input_map;
            if (!vault_read_refund_leaf_script(dc, st, &input_map)) {
                vault_context_invalidate(&G_vault_context);
                return false;
            }

            const uint8_t *leaf    = G_scratch.tls.leaf_script;
            int             leaf_len = G_scratch.tls.leaf_script_len;

            /* Verify NoPayout leaf shape and that the first key matches the approved
             * depositor.  The validator already checked this on the same PSBT, but
             * the signing path must not silently rely on that to remain safe if
             * validation and signing are ever decoupled. */
            if (leaf_len != 68 || leaf[0] != OP_PUSHBYTES_32 || leaf[33] != OP_CHECKSIGVERIFY ||
                leaf[34] != OP_PUSHBYTES_32 || leaf[67] != OP_CHECKSIG ||
                memcmp(leaf + 1, intent->depositor_pk, VAULT_XONLY_PUBKEY_LEN) != 0) {
                vault_context_invalidate(&G_vault_context);
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }

            uint8_t leaf_hash[VAULT_HASH256_LEN];
            vault_taproot_leaf_hash(leaf, leaf_len, leaf_hash);

            uint8_t input_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
            if (!read_p2tr_witness_utxo(dc, &input_map, NULL, input_spk)) {
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
                                          SIGHASH_DEFAULT,
                                          sighash)) {
                vault_context_invalidate(&G_vault_context);
                return false;
            }

            if (!sign_sighash_schnorr_and_yield(dc,
                                                st,
                                                0,
                                                intent->depositor_path,
                                                VAULT_DEPOSITOR_PATH_LEN,
                                                NULL,
                                                0,
                                                leaf_hash,
                                                SIGHASH_DEFAULT,
                                                sighash)) {
                vault_context_invalidate(&G_vault_context);
                return false;
            }

            return true;
        }

        /* Payout */
        merkleized_map_commitment_t input_map;
        if (call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, 0, &input_map) < 0) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* _validate_payout advances vault_group_index after the last claimer of each
         * group and resets payout_index to 0.  Recover the group that was actually
         * validated and is now being signed: if payout_index is 0 and vault_group_index
         * is non-zero, the advance already happened — step back by one. */
        uint8_t sgi = G_vault_context.vault_group_index;
        if (G_vault_context.payout_index == 0 && sgi > 0) {
            sgi--;
        }

        int leaf_len = vault_build_vault_utxo_leaf(intent,
                                                   sgi,
                                                   G_scratch.script_scratch,
                                                   VAULT_SCRIPT_MAX_LEN);
        if (leaf_len < 0) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t leaf_hash[VAULT_HASH256_LEN];
        vault_taproot_leaf_hash(G_scratch.script_scratch, leaf_len, leaf_hash);

        /* Bind the witness-UTXO scriptPubKey to the Vault UTXO P2TR reconstructed
         * from the approved intent (rebuilds G_scratch.script_scratch, which we
         * are done reading from above). */
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!vault_build_vault_utxo_scriptpubkey(intent, sgi, expected_spk)) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t input_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!read_p2tr_witness_utxo(dc, &input_map, expected_spk, input_spk)) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Sighash type SIGHASH_DEFAULT (0x00): see PegIn branch above — the
         * signature must commit to the whole device-reconstructed transaction,
         * and the PSBT validation path only accepts SIGHASH_DEFAULT. */
        uint8_t sighash[VAULT_HASH256_LEN];
        if (!compute_sighash_segwitv1(dc,
                                      st,
                                      tx_hashes,
                                      &input_map,
                                      0,
                                      input_spk,
                                      VAULT_P2TR_SCRIPTPUBKEY_LEN,
                                      leaf_hash,
                                      SIGHASH_DEFAULT,
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
                                            SIGHASH_DEFAULT,
                                            sighash)) {
            vault_context_invalidate(&G_vault_context);
            return false; /* SW already sent by callee */
        }

        return true;
    }

    /* -----------------------------------------------------------------------
     * Pre-PegIn (SESSION1_PREPEGIN_EXPECTED, has_no_wallet_policy == false,
     * Input 0 internal): all inputs are BIP-86 wallet-owned and were already
     * signed by sign_internal_inputs.  Nothing left to sign here.
     * WC-with-wallet (has_no_wallet_policy == false, Input 0 external) falls
     * through to the standalone signing section.
     * ----------------------------------------------------------------------- */
    if (!st->has_no_wallet_policy && bitvector_get(internal_inputs, 0)) {
        return true;
    }

    /* -----------------------------------------------------------------------
     * Standalone flows: Refund, Claim (Screen 4), Assert (Screen 5), WC (Screen 6),
     * and WC-with-wallet (has_no_wallet_policy == false, Input 0 external).
     *
     * All these leaves share the shape <D> OP_PUSHBYTES_32 ... — the depositor's
     * x-only key D is always at leaf[1..32].  Re-read PSBT_IN_TAP_LEAF_SCRIPT
     * (fills G_scratch.tls), PSBT_IN_WITNESS_UTXO for the scriptPubKey, and
     * PSBT_IN_TAP_BIP32_DERIVATION for the signing path.
     * The original reads in the validators cannot be reused because the display
     * functions clobber G_scratch.tls via the display_tx union member.
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

        /* No loaded intent for standalone flows; the validator bound the spk via
         * the taproot control-block commitment (NUMS key + Merkle root), so a
         * structural-only read is sufficient here. */
        uint8_t input_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!read_p2tr_witness_utxo(dc, &input_map, NULL, input_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* All supported leaf types open with OP_PUSHBYTES_32 <D-key>. */
        if (G_scratch.tls.leaf_script_len < 34 || G_scratch.tls.leaf_script[0] != OP_PUSHBYTES_32) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t leaf_key[VAULT_XONLY_PUBKEY_LEN];
        memcpy(leaf_key, G_scratch.tls.leaf_script + 1, VAULT_XONLY_PUBKEY_LEN);

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
                                      SIGHASH_DEFAULT,
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
                                            SIGHASH_DEFAULT,
                                            sighash)) {
            return false; /* SW already sent by callee */
        }

        return true;
    }
}
