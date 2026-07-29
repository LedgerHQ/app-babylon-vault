#include <stdbool.h>
#include <stddef.h>
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
 * Verify sign_standalone_scratch_t layout assumptions used for tls aliasing.
 * If any assert fires, review the field ordering rules in sign_standalone_scratch_t's
 * comment in globals.h.
 */
_Static_assert(offsetof(tap_leaf_script_state_t, leaf_script) == 68,
               "sign_standalone aliasing: tls.leaf_script offset must be 68");
_Static_assert(offsetof(sign_standalone_scratch_t, leaf_hash) == 0,
               "sign_standalone layout changed: leaf_hash must be first");
_Static_assert(offsetof(sign_standalone_scratch_t, leaf_key) == VAULT_HASH256_LEN,
               "sign_standalone layout changed: leaf_key must be at offset 32");
_Static_assert(offsetof(sign_standalone_scratch_t, input_spk) == 2 * VAULT_XONLY_PUBKEY_LEN,
               "sign_standalone layout changed: input_spk must be at offset 64");
/* input_spk must start before tls.leaf_script so writes to input_spk[0..3] only
 * hit dead control_block/control_block_len bytes (offsets 64-67), not leaf_script. */
_Static_assert(offsetof(sign_standalone_scratch_t, input_spk) <
                   offsetof(tap_leaf_script_state_t, leaf_script),
               "sign_standalone aliasing: input_spk must start before tls.leaf_script");
_Static_assert(sizeof(G_scratch.sign_standalone.xpub_bytes) == sizeof(serialized_extended_pubkey_t),
               "sign_standalone.xpub_bytes size must match serialized_extended_pubkey_t");
_Static_assert(sizeof(sign_standalone_scratch_t) <= sizeof(vault_scratch_t),
               "sign_standalone_scratch_t must fit within vault_scratch_t");
_Static_assert(sizeof(sign_standalone_scratch_t) <= sizeof(tap_leaf_script_state_t),
               "sign_standalone aliasing: sign_standalone_scratch_t exceeds "
               "tap_leaf_script_state_t — SDK tls layout changed");

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

            const uint8_t *leaf = G_scratch.tls.leaf_script;
            int leaf_len = G_scratch.tls.leaf_script_len;

            /* Verify NoPayout leaf shape and that the first key matches the approved
             * depositor.  The validator already checked this on the same PSBT, but
             * the signing path must not silently rely on that to remain safe if
             * validation and signing are ever decoupled. */
            if (leaf_len != 68 || leaf[0] != OP_PUSHBYTES_32 ||
                leaf[33] != (uint8_t) OP_CHECKSIGVERIFY || leaf[34] != OP_PUSHBYTES_32 ||
                leaf[67] != (uint8_t) OP_CHECKSIG ||
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
     * PayoutFinalize (Screen 8): standalone flow that signs Input 1, not Input 0.
     *
     * The payout leaf is on Input 1; Input 0 (Assert:0) carries no signing request.
     * Re-read Input 1's TAP_LEAF_SCRIPT via vault_read_payout_leaf_script because
     * display_payout_finalize clobbered G_scratch.tls.  Signing proceeds identically
     * to other standalone flows except the input index is 1.
     * ----------------------------------------------------------------------- */
    if (st->has_no_wallet_policy && st->n_inputs == 2 && st->n_outputs == 2) {
        merkleized_map_commitment_t input1_map;
        if (!vault_read_payout_leaf_script(dc, st, &input1_map)) return false;

        /* Phase 1: consume G_scratch.tls, populate G_scratch.sign_standalone.
         * Aliasing rules are the same as the standalone section below. */
        vault_taproot_leaf_hash(G_scratch.tls.leaf_script,
                                G_scratch.tls.leaf_script_len,
                                G_scratch.sign_standalone.leaf_hash);

        if (G_scratch.tls.leaf_script_len <= 68 ||
            G_scratch.tls.leaf_script[0] != OP_PUSHBYTES_32) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        memcpy(G_scratch.sign_standalone.leaf_key,
               G_scratch.tls.leaf_script + 1,
               VAULT_XONLY_PUBKEY_LEN);

        if (!read_p2tr_witness_utxo(dc, &input1_map, NULL, G_scratch.sign_standalone.input_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Phase 2: BIP-32 derivation + key verification */
        G_scratch.sign_standalone.deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(G_scratch.sign_standalone.deriv_key + 1,
               G_scratch.sign_standalone.leaf_key,
               VAULT_XONLY_PUBKEY_LEN);

        int deriv_len = call_get_merkleized_map_value(dc,
                                                      &input1_map,
                                                      G_scratch.sign_standalone.deriv_key,
                                                      sizeof(G_scratch.sign_standalone.deriv_key),
                                                      G_scratch.sign_standalone.deriv_val,
                                                      sizeof(G_scratch.sign_standalone.deriv_val));
        if (deriv_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint32_t fingerprint;
        int path_len = parse_tap_bip32_deriv_value(G_scratch.sign_standalone.deriv_val,
                                                   deriv_len,
                                                   &fingerprint,
                                                   G_scratch.sign_standalone.sign_path,
                                                   VAULT_STANDALONE_PATH_LEN);
        if (path_len < 0 || fingerprint != st->master_key_fingerprint ||
            !check_bip86_path(G_scratch.sign_standalone.sign_path, path_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        serialized_extended_pubkey_t *xpub =
            (serialized_extended_pubkey_t *) G_scratch.sign_standalone.xpub_bytes;
        if (get_extended_pubkey_at_path(G_scratch.sign_standalone.sign_path,
                                        (uint8_t) path_len,
                                        BIP32_PUBKEY_VERSION,
                                        xpub) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(xpub->compressed_pubkey + 1,
                   G_scratch.sign_standalone.leaf_key,
                   VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (!compute_sighash_segwitv1(dc,
                                      st,
                                      tx_hashes,
                                      &input1_map,
                                      1,
                                      G_scratch.sign_standalone.input_spk,
                                      VAULT_P2TR_SCRIPTPUBKEY_LEN,
                                      G_scratch.sign_standalone.leaf_hash,
                                      SIGHASH_DEFAULT,
                                      G_scratch.sign_standalone.sighash)) {
            return false; /* SW already sent by callee */
        }

        if (!sign_sighash_schnorr_and_yield(dc,
                                            st,
                                            1,
                                            G_scratch.sign_standalone.sign_path,
                                            (size_t) path_len,
                                            NULL,
                                            0,
                                            G_scratch.sign_standalone.leaf_hash,
                                            SIGHASH_DEFAULT,
                                            G_scratch.sign_standalone.sighash)) {
            return false; /* SW already sent by callee */
        }

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
        /* input_map stays on the stack: vault_read_refund_leaf_script() writes
         * both G_scratch.tls and *input_map_out in the same call, so input_map
         * cannot alias any G_scratch union member. */
        merkleized_map_commitment_t input_map;
        if (!vault_read_refund_leaf_script(dc, st, &input_map)) {
            return false;
        }

        /* Phase 1: consume G_scratch.tls and populate G_scratch.sign_standalone.
         * Each write targets bytes already dead in tls — see sign_standalone_scratch_t
         * in globals.h for the byte-by-byte aliasing map. */

        /* leaf_hash [0..31]: clobbers tls.found/ambiguous/control_block[0..29] — dead. */
        vault_taproot_leaf_hash(G_scratch.tls.leaf_script,
                                G_scratch.tls.leaf_script_len,
                                G_scratch.sign_standalone.leaf_hash);

        /* Read tls.leaf_script_len (offset 2628) and tls.leaf_script[0] (offset 68)
         * before any write reaches those offsets. */
        if (G_scratch.tls.leaf_script_len < 34 || G_scratch.tls.leaf_script[0] != OP_PUSHBYTES_32) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* leaf_key [32..63]: clobbers tls.control_block[30..62] — dead.
         * Source tls.leaf_script[1..32] is at offsets [69..100], past dst [32..63]. */
        memcpy(G_scratch.sign_standalone.leaf_key,
               G_scratch.tls.leaf_script + 1,
               VAULT_XONLY_PUBKEY_LEN);

        /* tls is fully consumed.  input_spk [64..97] now clobbers tls.control_block_len
         * (offset 67) and tls.leaf_script[0..29] (offsets 68..97) — all dead. */

        /* No loaded intent for standalone flows; the validator bound the spk via
         * the taproot control-block commitment (NUMS key + Merkle root), so a
         * structural-only read is sufficient here. */
        if (!read_p2tr_witness_utxo(dc, &input_map, NULL, G_scratch.sign_standalone.input_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Phase 2: tls is dead; use G_scratch.sign_standalone for all remaining state. */

        G_scratch.sign_standalone.deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(G_scratch.sign_standalone.deriv_key + 1,
               G_scratch.sign_standalone.leaf_key,
               VAULT_XONLY_PUBKEY_LEN);

        int deriv_len = call_get_merkleized_map_value(dc,
                                                      &input_map,
                                                      G_scratch.sign_standalone.deriv_key,
                                                      sizeof(G_scratch.sign_standalone.deriv_key),
                                                      G_scratch.sign_standalone.deriv_val,
                                                      sizeof(G_scratch.sign_standalone.deriv_val));
        if (deriv_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint32_t fingerprint;
        int path_len = parse_tap_bip32_deriv_value(G_scratch.sign_standalone.deriv_val,
                                                   deriv_len,
                                                   &fingerprint,
                                                   G_scratch.sign_standalone.sign_path,
                                                   VAULT_STANDALONE_PATH_LEN);
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
        if (!check_bip86_path(G_scratch.sign_standalone.sign_path, path_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        serialized_extended_pubkey_t *xpub =
            (serialized_extended_pubkey_t *) G_scratch.sign_standalone.xpub_bytes;
        if (get_extended_pubkey_at_path(G_scratch.sign_standalone.sign_path,
                                        (uint8_t) path_len,
                                        BIP32_PUBKEY_VERSION,
                                        xpub) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* compressed_pubkey[0] is 0x02/0x03; x-only key is bytes [1..32] */
        if (memcmp(xpub->compressed_pubkey + 1,
                   G_scratch.sign_standalone.leaf_key,
                   VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        if (!compute_sighash_segwitv1(dc,
                                      st,
                                      tx_hashes,
                                      &input_map,
                                      0,
                                      G_scratch.sign_standalone.input_spk,
                                      VAULT_P2TR_SCRIPTPUBKEY_LEN,
                                      G_scratch.sign_standalone.leaf_hash,
                                      SIGHASH_DEFAULT,
                                      G_scratch.sign_standalone.sighash)) {
            return false; /* SW already sent by callee */
        }

        if (!sign_sighash_schnorr_and_yield(dc,
                                            st,
                                            0,
                                            G_scratch.sign_standalone.sign_path,
                                            (size_t) path_len,
                                            NULL,
                                            0,
                                            G_scratch.sign_standalone.leaf_hash,
                                            SIGHASH_DEFAULT,
                                            G_scratch.sign_standalone.sighash)) {
            return false; /* SW already sent by callee */
        }

        return true;
    }
}
