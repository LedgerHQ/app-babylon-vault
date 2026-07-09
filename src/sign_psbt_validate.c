#include "sign_psbt_validate.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../bitcoin_app_base/src/boilerplate/sw.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/common/psbt.h"
#include "../bitcoin_app_base/src/common/script.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map.h"
#include "../bitcoin_app_base/src/handler/lib/get_merkleized_map_value.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"

#include "cx.h"
#include "../bitcoin_app_base/src/crypto.h"
#include "display.h"
#include "globals.h"
#include "vault_constants.h"
#include "vault_script.h"
#include "sign_psbt_validate_helpers.h"

/* read_u32_le / read_u64_le come from the SDK's lib_standard_app */
#include "read.h"

/* Maximum length of a TAP_BIP32_DERIVATION value that we'll read:
 * 1B n_hashes + up to 2×32B leaf_hashes + 4B fingerprint + 5*4B path = 89 bytes max */
#define MAX_TAP_BIP32_DERIV_VALUE_LEN (1 + 2 * 32 + 4 + 5 * 4)

/* Maximum WITNESS_UTXO size: 8B value + 1B script_len varint + 34B P2TR script */
#define MAX_WITNESS_UTXO_LEN (8 + 1 + 34)

/* auth-anchor OP_RETURN scriptPubKey: OP_RETURN(0x6A) OP_PUSHBYTES_32(0x20) <32B hash>.
 * Happens to be the same byte length as a P2TR scriptPubKey; the static assert makes
 * this coincidence explicit so _read_output can read both with the same buffer size. */
#define AUTH_ANCHOR_SPK_LEN 34u
_Static_assert(AUTH_ANCHOR_SPK_LEN == VAULT_P2TR_SCRIPTPUBKEY_LEN,
               "AUTH_ANCHOR_SPK_LEN must equal VAULT_P2TR_SCRIPTPUBKEY_LEN for _read_output reuse");

/* Payout fee bound constants (NAPPS-1376) */
#define MAX_PAYOUT_VSIZE_BASE            500u
#define MAX_PAYOUT_VSIZE_PER_PARTICIPANT 55u

/* -------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------- */

/*
 * Read one output's script and amount from the PSBT.
 * Returns true on success.
 */
static bool _read_output(dispatcher_context_t *dc,
                         const uint8_t outputs_root[static 32],
                         unsigned int n_outputs,
                         unsigned int output_idx,
                         uint8_t script_out[VAULT_P2TR_SCRIPTPUBKEY_LEN],
                         uint64_t *amount_out) {
    merkleized_map_commitment_t map;
    if (call_get_merkleized_map(dc, outputs_root, n_outputs, output_idx, &map) < 0) {
        return false;
    }

    /* Amount */
    uint8_t raw8[8];
    if (8 != call_get_merkleized_map_value(dc, &map, (uint8_t[]) {PSBT_OUT_AMOUNT}, 1, raw8, 8)) {
        return false;
    }
    *amount_out = read_u64_le(raw8, 0);

    /* Script */
    int slen = call_get_merkleized_map_value(dc,
                                             &map,
                                             (uint8_t[]) {PSBT_OUT_SCRIPT},
                                             1,
                                             script_out,
                                             VAULT_P2TR_SCRIPTPUBKEY_LEN);
    return slen == VAULT_P2TR_SCRIPTPUBKEY_LEN;
}

/* -------------------------------------------------------------------------
 * Callback for iterating an input map looking for TAP_LEAF_SCRIPT
 * State type is tap_leaf_script_state_t (defined in globals.h, lives in G_scratch.tls)
 * ---------------------------------------------------------------------- */

static void _tap_leaf_script_callback(dispatcher_context_t *dc,
                                      tap_leaf_script_state_t *state,
                                      const merkleized_map_commitment_t *map_commitment,
                                      int index,
                                      buffer_t *data) {
    UNUSED(dc);
    UNUSED(index);

    size_t data_len = data->size - data->offset;
    if (data_len < 1) return;

    uint8_t key_type;
    buffer_read_u8(data, &key_type);
    if (key_type != PSBT_IN_TAP_LEAF_SCRIPT) return;

    if (state->found) {
        state->ambiguous = true;
        return;
    }
    state->found = true;

    /* Remaining key bytes are the control block */
    size_t cb_len = data->size - data->offset;
    if (cb_len > sizeof(state->control_block)) {
        state->ambiguous = true; /* treat oversized as error */
        return;
    }
    state->control_block_len = (uint8_t) cb_len;
    memcpy(state->control_block, data->ptr + data->offset, cb_len);

    /*
     * Read the value: <leaf_script> || <leaf_version (1B)>.
     * The map_commitment has the value Merkle root; look up by position (index).
     * We use call_get_merkleized_map_value on the *value* merkle tree via a
     * temporary full key reconstruction: the full key is key_type || control_block,
     * which is exactly what was in `data` before we read the type byte.
     */
    uint8_t full_key[1 + sizeof(state->control_block)];
    full_key[0] = PSBT_IN_TAP_LEAF_SCRIPT;
    memcpy(full_key + 1, state->control_block, cb_len);
    size_t full_key_len = 1 + cb_len;

    /* Use leaf_check.actual_buf (union offset VAULT_SCRIPT_MAX_LEN) as the read buffer.
     * G_scratch.tls (state) occupies union offsets 0..~2636; actual_buf starts at 2560
     * so it only aliases the tail of tls.leaf_script and tls.leaf_script_len/leaf_version —
     * fields that haven't been set yet.  Write leaf_version/leaf_script_len AFTER the
     * memcpy so we don't corrupt the source before copying it. */
    uint8_t *const value_buf = G_scratch.leaf_check.actual_buf;
    int value_len = call_get_merkleized_map_value(dc,
                                                  map_commitment,
                                                  full_key,
                                                  full_key_len,
                                                  value_buf,
                                                  sizeof(G_scratch.leaf_check.actual_buf));
    if (value_len < 1) {
        state->ambiguous = true; /* failed to read value — treat as ambiguous/error */
        return;
    }
    /* Save leaf_version into a local before writing to tls fields that alias actual_buf. */
    uint8_t leaf_version = value_buf[value_len - 1];
    int leaf_script_len = value_len - 1;
    if (leaf_script_len > (int) VAULT_SCRIPT_MAX_LEN) {
        state->ambiguous = true;
        return;
    }
    if (leaf_script_len > 0) {
        /* tls.leaf_script (union+68) and actual_buf (union+2560) overlap when
         * leaf_script_len > 2492 — use memmove to stay defined in that case. */
        memmove(state->leaf_script, value_buf, leaf_script_len);
    }
    state->leaf_script_len = leaf_script_len;
    state->leaf_version = leaf_version;
}

/* -------------------------------------------------------------------------
 * Pre-PegIn validation + display
 * ---------------------------------------------------------------------- */

static bool _validate_display_prepegin(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)],
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /* State guard: must have intent and a derived hashlock */
    if (G_vault_context.state != VAULT_STATE_INTENT_LOADED) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }
    const uint8_t zeros[VAULT_HASH256_LEN] = {0};
    if (memcmp(G_vault_context.htlc_hashlock, zeros, VAULT_HASH256_LEN) == 0) {
        /* DERIVE_CONTEXT_HASH must be called before Pre-PegIn signing */
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    const vault_intent_t *intent = &G_vault_intent;

    /* 1. All inputs must be wallet-owned (BIP-86 wallet inputs from the loaded policy) */
    for (unsigned int i = 0; i < st->n_inputs; i++) {
        if (!bitvector_get(internal_inputs, i)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 2. Version >= 2 */
    if (st->tx_version < 2) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 3. Sighash check: each input must use DEFAULT (0) or ALL (1) */
    for (unsigned int i = 0; i < st->n_inputs; i++) {
        merkleized_map_commitment_t input_map;
        if (call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &input_map) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint32_t sighash_type = 0;
        int res = call_get_merkleized_map_value_u32_le(dc,
                                                       &input_map,
                                                       (uint8_t[]) {PSBT_IN_SIGHASH_TYPE},
                                                       1,
                                                       &sighash_type);
        if (res >= 0 && res != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (res == 4 && sighash_type != 0 && sighash_type != 1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* res < 0 means absent → SIGHASH_DEFAULT (0) → OK */
    }

    /* 4. htlc_vout is within output range */
    if (intent->htlc_vout >= st->n_outputs) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 5. Read the HTLC output script and amount */
    uint8_t actual_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    uint64_t htlc_value;
    if (!_read_output(dc,
                      st->outputs_root,
                      st->n_outputs,
                      intent->htlc_vout,
                      actual_spk,
                      &htlc_value)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 6-7-8. Reconstruct expected HTLC scriptPubKey and compare */
    uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    if (!vault_build_htlc_scriptpubkey(intent, G_vault_context.htlc_hashlock, expected_spk)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (memcmp(actual_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 9-10. HTLC amount ∈ [V + Dcv, V + Dcv + pegin_max_fee] */
    uint64_t min_htlc = intent->vault_amount + intent->depositor_claim_value;
    if (min_htlc < intent->vault_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t max_htlc = min_htlc + intent->pegin_max_fee;
    if (max_htlc < min_htlc) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (htlc_value < min_htlc || htlc_value > max_htlc) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 11. Every non-HTLC output must be either BIP-86 change (internal) or the single
     * shared auth-anchor OP_RETURN = "OP_RETURN <SHA256(authAnchor)>". The OP_RETURN
     * carries the auth-anchor commitment (derive-vault-secrets); the device binds it to
     * the value expanded from the derived root so a host cannot substitute it.
     *
     * Expected scriptPubKey: 0x6A 0x20 || auth_anchor_hash (AUTH_ANCHOR_SPK_LEN bytes). */
    uint8_t expected_anchor_spk[AUTH_ANCHOR_SPK_LEN];
    expected_anchor_spk[0] = 0x6A;  // OP_RETURN
    expected_anchor_spk[1] = 0x20;  // OP_PUSHBYTES_32
    memcpy(expected_anchor_spk + 2, G_vault_context.auth_anchor_hash, VAULT_HASH256_LEN);

    bool anchor_found = false;
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        if (i == intent->htlc_vout) continue;
        if (bitvector_get(internal_outputs, i)) continue;  // BIP-86 change

        /* Non-internal output: the only one allowed is the auth-anchor OP_RETURN, and it
         * MUST carry zero value. The OP_RETURN is provably unspendable, so any value
         * assigned to it is burned; since neither the OP_RETURN nor the change is shown
         * on the approval screen, a non-zero value would let a malicious host silently
         * burn the depositor's own change (WYSIWYS violation). Require value == 0. */
        uint8_t out_spk[AUTH_ANCHOR_SPK_LEN];
        uint64_t out_value;
        if (!_read_output(dc, st->outputs_root, st->n_outputs, i, out_spk, &out_value) ||
            anchor_found || out_value != 0 ||
            memcmp(out_spk, expected_anchor_spk, AUTH_ANCHOR_SPK_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        anchor_found = true;
    }
    if (!anchor_found) {
        /* The shared auth-anchor OP_RETURN is mandatory on the Pre-PegIn. */
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 12. Fee */
    if (st->outputs.total_amount > st->inputs_total_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    /* 13. Convert HTLC scriptPubKey to address string.
     * Written into G_scratch.display_tx.addr_str — NBGL holds a pointer to it
     * across the blocking io_ui_process() call in display_prepegin_transaction. */
    if (get_script_address(expected_spk,
                           VAULT_P2TR_SCRIPTPUBKEY_LEN,
                           G_scratch.display_tx.addr_str,
                           sizeof(G_scratch.display_tx.addr_str)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 14. Show Screen 2 to the user (SW_DENY already sent by display function on rejection) */
    if (!display_prepegin_transaction(dc,
                                      intent->vault_amount,
                                      intent->depositor_claim_value,
                                      fee,
                                      G_scratch.display_tx.addr_str)) {
        return false;
    }

    /* 15. Advance state: INTENT_LOADED → SESSION1_PREPEGIN_EXPECTED.
     * This is intentionally done after user approval and before signing completes.
     * Pre-PegIn uses only BIP-86 wallet-policy inputs: sign_custom_inputs is never
     * called for them — the base framework signs them atomically within the same APDU.
     * Advancing state here provides replay prevention (same Pre-PegIn cannot be
     * presented to the user twice) without a time-of-check/time-of-use window. */
    if (!vault_context_transition(&G_vault_context,
                                  VAULT_STATE_INTENT_LOADED,
                                  VAULT_STATE_SESSION1_PREPEGIN_EXPECTED)) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * Refund validation + display
 * ---------------------------------------------------------------------- */

/* Verifies the BIP-341 taproot commitment from the control block in G_scratch.tls:
 * internal key is NUMS, merkle root built from leaf + siblings, tweaked key matches htlc_spk. */
static bool _refund_verify_taproot_commitment(dispatcher_context_t *dc,
                                              const uint8_t htlc_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    /* control_block: (leaf_version | parity)(1B) || internal_key(32B) [|| sibling(32B)...] */
    const uint8_t *cb = G_scratch.tls.control_block;
    int cb_len = G_scratch.tls.control_block_len;
    if (cb_len < 1 + VAULT_XONLY_PUBKEY_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    const uint8_t *internal_key = cb + 1;

    /* The HTLC disables key-path spending via a NUMS point — verify this. */
    if (memcmp(internal_key, VAULT_NUMS_XONLY, VAULT_XONLY_PUBKEY_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    uint8_t leaf_hash[VAULT_HASH256_LEN];
    vault_taproot_leaf_hash(G_scratch.tls.leaf_script, G_scratch.tls.leaf_script_len, leaf_hash);

    uint8_t merkle_root[VAULT_HASH256_LEN];
    memcpy(merkle_root, leaf_hash, VAULT_HASH256_LEN);
    int pos = 1 + VAULT_XONLY_PUBKEY_LEN;
    while (pos + VAULT_HASH256_LEN <= cb_len) {
        uint8_t combined[VAULT_HASH256_LEN];
        crypto_tr_combine_taptree_hashes(merkle_root, cb + pos, combined);
        memcpy(merkle_root, combined, VAULT_HASH256_LEN);
        pos += VAULT_HASH256_LEN;
    }

    uint8_t parity;
    uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
    if (crypto_tr_tweak_pubkey(internal_key, merkle_root, VAULT_HASH256_LEN, &parity, tweaked) !=
        0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    /* BIP-341: control block parity bit must match output key parity */
    if ((cb[0] & 1) != parity) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    /* htlc_spk: [0x51, 0x20, tweaked[32]] */
    if (htlc_spk[0] != 0x51 || htlc_spk[1] != 0x20 ||
        memcmp(htlc_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    return true;
}

static bool _validate_display_refund(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    /* State guard: Refund is valid in IDLE, INTENT_LOADED, and
     * SESSION1_PREPEGIN_EXPECTED.  The last case supports abort-before-broadcast:
     * the user signed a Pre-PegIn but hasn't yet published it, so the HTLC is
     * not on-chain yet.  Allowing Refund here lets the wallet recover gracefully.
     * Block it in SESSION2_PAYOUT_EXPECTED and SESSION2_COMPLETE — once the
     * PegIn is settled, only Payout signing makes sense and Refund would sign
     * for funds the protocol has already committed forward. */
    vault_state_t state = G_vault_context.state;
    if (state == VAULT_STATE_SESSION2_PAYOUT_EXPECTED || state == VAULT_STATE_SESSION2_COMPLETE) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    /* 1. Structural requirements */
    if (st->n_inputs != 1 || st->n_outputs != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 2. Version >= 2, locktime == 0 */
    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 3. Get input 0 map and check sighash */
    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 1, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    {
        uint32_t sighash_type = 0;
        int res = call_get_merkleized_map_value_u32_le(dc,
                                                       &input_map,
                                                       (uint8_t[]) {PSBT_IN_SIGHASH_TYPE},
                                                       1,
                                                       &sighash_type);
        if (res >= 0 && res != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* accept DEFAULT (0) and explicit ALL (1) — identical tapscript commitment (BIP-341) */
        if (res == 4 && sighash_type != 0 && sighash_type != 1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 4. Read PSBT_IN_WITNESS_UTXO → htlc_value + htlc_spk */
    uint8_t witness_utxo[MAX_WITNESS_UTXO_LEN];
    int wu_len = call_get_merkleized_map_value(dc,
                                               &input_map,
                                               (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                               1,
                                               witness_utxo,
                                               sizeof(witness_utxo));
    if (wu_len < 9) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t htlc_value = read_u64_le(witness_utxo, 0);
    /* Script length: varint at byte 8 (we require a single-byte varint for P2TR) */
    uint8_t spk_len = witness_utxo[8];
    if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    const uint8_t *htlc_spk = witness_utxo + 9;

    /* 5. Find TAP_LEAF_SCRIPT using the callback — lives in G_scratch.tls (saves 2636 B BSS). */
    memset(&G_scratch.tls, 0, sizeof(G_scratch.tls));
    if (call_get_merkleized_map_with_callback(
            dc,
            &G_scratch.tls,
            st->inputs_root,
            1,
            0,
            (merkle_tree_elements_callback_t) _tap_leaf_script_callback,
            &input_map) < 0 ||
        !G_scratch.tls.found || G_scratch.tls.ambiguous) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (G_scratch.tls.leaf_version != TAPSCRIPT_LEAF_VERSION) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 6. Parse leaf script shape — also extracts the CSV timelock value */
    uint8_t leaf_key[VAULT_XONLY_PUBKEY_LEN];
    uint32_t csv_value;
    if (!parse_refund_leaf_script(G_scratch.tls.leaf_script,
                                  G_scratch.tls.leaf_script_len,
                                  leaf_key,
                                  &csv_value)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 6a. When intent is loaded, the CSV timelock in the leaf must match the
     * approved htlc_refund_timelock — prevents signing a premature refund with
     * an attacker-supplied shorter timelock. */
    if (state == VAULT_STATE_INTENT_LOADED || state == VAULT_STATE_SESSION1_PREPEGIN_EXPECTED) {
        if (csv_value != (uint32_t) G_vault_intent.htlc_refund_timelock) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 7. Read TAP_BIP32_DERIVATION for leaf_key */
    {
        uint8_t deriv_key[1 + VAULT_XONLY_PUBKEY_LEN];
        deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(deriv_key + 1, leaf_key, VAULT_XONLY_PUBKEY_LEN);

        uint8_t deriv_val[MAX_TAP_BIP32_DERIV_VALUE_LEN];
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
        uint32_t path[5];
        int path_len = parse_tap_bip32_deriv_value(deriv_val, deriv_len, &fingerprint, path, 5);
        if (path_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* 8. Fingerprint must match this device's master key */
        if (fingerprint != st->master_key_fingerprint) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* 9. BIP-86 path check */
        if (!check_bip86_path(path, path_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Derive the key and verify it matches leaf_key */
        serialized_extended_pubkey_t xpub;
        if (get_extended_pubkey_at_path(path, (uint8_t) path_len, BIP32_PUBKEY_VERSION, &xpub) !=
            0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* compressed_pubkey[0] is 0x02 or 0x03; x-only is bytes [1..32] */
        if (memcmp(xpub.compressed_pubkey + 1, leaf_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 10. Control block taproot commitment verification */
    if (!_refund_verify_taproot_commitment(dc, htlc_spk)) return false;

    /* 11. Validate PSBT_IN_SEQUENCE against the leaf-script CSV timelock.
     * BIP-68: bit 31 enables/disables sequence, bit 22 selects block vs time. */
    {
        uint32_t nsequence = 0;
        int seq_res = call_get_merkleized_map_value_u32_le(dc,
                                                           &input_map,
                                                           (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                           1,
                                                           &nsequence);
        if (seq_res != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* bit 31 set → relative locktime disabled; bit 22 set → time-based unit */
        if ((nsequence & 0x80000000u) != 0 || (nsequence & 0x00400000u) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if ((nsequence & 0x0000FFFFu) < (csv_value & 0x0000FFFFu)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 12. Read single output and verify P2TR shape + BIP-86 ownership */
    merkleized_map_commitment_t out_map;
    if (call_get_merkleized_map(dc, st->outputs_root, 1, 0, &out_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint8_t out_script[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    int slen = call_get_merkleized_map_value(dc,
                                             &out_map,
                                             (uint8_t[]) {PSBT_OUT_SCRIPT},
                                             1,
                                             out_script,
                                             VAULT_P2TR_SCRIPTPUBKEY_LEN);
    if (slen != VAULT_P2TR_SCRIPTPUBKEY_LEN || out_script[0] != 0x51 || out_script[1] != 0x20) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint8_t raw8[8];
    if (8 !=
        call_get_merkleized_map_value(dc, &out_map, (uint8_t[]) {PSBT_OUT_AMOUNT}, 1, raw8, 8)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t out_value = read_u64_le(raw8, 0);

    /* 13. Output BIP-86 ownership via PSBT_OUT_TAP_BIP32_DERIVATION */
    {
        const uint8_t *out_key = out_script + 2; /* x-only key from scriptPubKey */
        uint8_t deriv_key[1 + VAULT_XONLY_PUBKEY_LEN];
        deriv_key[0] = PSBT_OUT_TAP_BIP32_DERIVATION;
        memcpy(deriv_key + 1, out_key, VAULT_XONLY_PUBKEY_LEN);

        uint8_t deriv_val[MAX_TAP_BIP32_DERIV_VALUE_LEN];
        int deriv_len = call_get_merkleized_map_value(dc,
                                                      &out_map,
                                                      deriv_key,
                                                      sizeof(deriv_key),
                                                      deriv_val,
                                                      sizeof(deriv_val));
        if (deriv_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint32_t fingerprint;
        uint32_t path[5];
        int path_len = parse_tap_bip32_deriv_value(deriv_val, deriv_len, &fingerprint, path, 5);
        if (path_len < 0 || fingerprint != st->master_key_fingerprint) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (!check_bip86_path(path, path_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        serialized_extended_pubkey_t xpub;
        if (get_extended_pubkey_at_path(path, (uint8_t) path_len, BIP32_PUBKEY_VERSION, &xpub) !=
            0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* BIP-86: output key = taproot_tweak(internal_key, H("TapTweak"||internal_key)).
         * get_extended_pubkey_at_path returns the untweaked internal key, so we must apply
         * the key-path-only (empty script tree) tweak before comparing with out_key. */
        uint8_t bip86_parity;
        uint8_t bip86_tweaked[VAULT_XONLY_PUBKEY_LEN];
        if (crypto_tr_tweak_pubkey(xpub.compressed_pubkey + 1,
                                   NULL,
                                   0,
                                   &bip86_parity,
                                   bip86_tweaked) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(bip86_tweaked, out_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 14. Fee */
    if (out_value > htlc_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = htlc_value - out_value;

    /* 15. Convert refund output scriptPubKey to address string.
     * Written into G_scratch.display_tx.addr_str — NBGL holds a pointer to it
     * across the blocking io_ui_process() call in display_refund_transaction. */
    if (get_script_address(out_script,
                           VAULT_P2TR_SCRIPTPUBKEY_LEN,
                           G_scratch.display_tx.addr_str,
                           sizeof(G_scratch.display_tx.addr_str)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 16. Display Screen 3 (SW_DENY already sent by display function on rejection) */
    if (!display_refund_transaction(dc, out_value, fee, G_scratch.display_tx.addr_str)) {
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * PegIn validation (silent — no UX)
 * ---------------------------------------------------------------------- */

/* Verifies that the PSBT TAP_LEAF_SCRIPT entry for Leaf 0 contains the expected
 * htlc_hashlock script, and that the WITNESS_UTXO scriptPubKey matches the
 * reconstructed taproot output key. Uses G_scratch.leaf_check. */
static bool _pegin_check_leaf0_script(dispatcher_context_t *dc,
                                      const merkleized_map_commitment_t *input_map,
                                      const vault_intent_t *intent,
                                      const uint8_t htlc_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    /* Build Leaf 0 into leaf_check.expected_script (= union offset 0 = script_scratch).
     * It stays there for the final comparison — Leaf 1 is built into actual_buf instead
     * so we never overwrite Leaf 0, eliminating a second vault_build_htlc_leaf0 call. */
    memset(G_scratch.leaf_check.expected_script, 0, VAULT_SCRIPT_MAX_LEN);
    int l0_len = vault_build_htlc_leaf0(intent,
                                        G_vault_context.htlc_hashlock,
                                        G_scratch.leaf_check.expected_script,
                                        VAULT_SCRIPT_MAX_LEN);
    if (l0_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint8_t leaf0_hash[VAULT_HASH256_LEN];
    vault_taproot_leaf_hash(G_scratch.leaf_check.expected_script, l0_len, leaf0_hash);

    uint8_t *const actual_buf = G_scratch.leaf_check.actual_buf;
    memset(actual_buf, 0, sizeof(G_scratch.leaf_check.actual_buf));
    int l1_len =
        vault_build_htlc_leaf1(intent, actual_buf, sizeof(G_scratch.leaf_check.actual_buf));
    if (l1_len < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint8_t leaf1_hash[VAULT_HASH256_LEN];
    vault_taproot_leaf_hash(actual_buf, l1_len, leaf1_hash);

    uint8_t merkle_root[VAULT_HASH256_LEN];
    crypto_tr_combine_taptree_hashes(leaf0_hash, leaf1_hash, merkle_root);

    uint8_t parity;
    uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
    if (crypto_tr_tweak_pubkey(VAULT_NUMS_XONLY,
                               merkle_root,
                               VAULT_HASH256_LEN,
                               &parity,
                               tweaked) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (htlc_spk[0] != 0x51 || htlc_spk[1] != 0x20 ||
        memcmp(htlc_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Construct PSBT key for TAP_LEAF_SCRIPT of Leaf 0:
     * key = 0x15 || (0xC0 | parity) || VAULT_NUMS_XONLY || leaf1_hash */
    uint8_t psbt_key[1 + 1 + VAULT_XONLY_PUBKEY_LEN + VAULT_HASH256_LEN];
    psbt_key[0] = PSBT_IN_TAP_LEAF_SCRIPT;
    psbt_key[1] = (uint8_t) (TAPSCRIPT_LEAF_VERSION | parity);
    memcpy(psbt_key + 2, VAULT_NUMS_XONLY, VAULT_XONLY_PUBKEY_LEN);
    memcpy(psbt_key + 2 + VAULT_XONLY_PUBKEY_LEN, leaf1_hash, VAULT_HASH256_LEN);

    /* Value = expected_leaf0_script || 0xC0.  Overwrite actual_buf (leaf1 no longer needed). */
    int value_len = call_get_merkleized_map_value(dc,
                                                  input_map,
                                                  psbt_key,
                                                  sizeof(psbt_key),
                                                  actual_buf,
                                                  sizeof(G_scratch.leaf_check.actual_buf));
    if (value_len != l0_len + 1 || actual_buf[value_len - 1] != TAPSCRIPT_LEAF_VERSION) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (memcmp(actual_buf, G_scratch.leaf_check.expected_script, l0_len) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    return true;
}

/* Validates the single PegIn input: identity (txid/vout/sequence), sighash,
 * WITNESS_UTXO, and full taproot commitment (internal key, merkle root, leaf
 * script).  Returns htlc_value on success via out-param. */
static bool _pegin_validate_input(dispatcher_context_t *dc,
                                  const merkleized_map_commitment_t *input_map,
                                  const vault_intent_t *intent,
                                  uint64_t *htlc_value_out) {
    /* 1. PSBT_IN_PREVIOUS_TXID must match intent->prepegin_txid */
    uint8_t txid[VAULT_HASH256_LEN];
    if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                           input_map,
                                                           (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                           1,
                                                           txid,
                                                           VAULT_HASH256_LEN) ||
        memcmp(txid, intent->prepegin_txid, VAULT_HASH256_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 2. PSBT_IN_OUTPUT_INDEX must match intent->htlc_vout */
    uint32_t vout;
    if (call_get_merkleized_map_value_u32_le(dc,
                                             input_map,
                                             (uint8_t[]) {PSBT_IN_OUTPUT_INDEX},
                                             1,
                                             &vout) != 4 ||
        vout != intent->htlc_vout) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 3. Sequence must be 0xFFFFFFFE */
    uint32_t seq;
    if (call_get_merkleized_map_value_u32_le(dc,
                                             input_map,
                                             (uint8_t[]) {PSBT_IN_SEQUENCE},
                                             1,
                                             &seq) != 4 ||
        seq != 0xFFFFFFFEu) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 4. Accept SIGHASH_DEFAULT (0) or explicit ALL (1) — identical tapscript commitment (BIP-341)
     */
    uint32_t sighash_type = 0;
    int res = call_get_merkleized_map_value_u32_le(dc,
                                                   input_map,
                                                   (uint8_t[]) {PSBT_IN_SIGHASH_TYPE},
                                                   1,
                                                   &sighash_type);
    if ((res >= 0 && res != 4) || (res == 4 && sighash_type != 0 && sighash_type != 1)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 5. WITNESS_UTXO → htlc_value + htlc_spk */
    uint64_t htlc_value;
    uint8_t htlc_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    {
        uint8_t witness_utxo[MAX_WITNESS_UTXO_LEN];
        int wu_len = call_get_merkleized_map_value(dc,
                                                   input_map,
                                                   (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                                   1,
                                                   witness_utxo,
                                                   sizeof(witness_utxo));
        if (wu_len < 9) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        htlc_value = read_u64_le(witness_utxo, 0);
        uint8_t spk_len = witness_utxo[8];
        if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        memcpy(htlc_spk, witness_utxo + 9, VAULT_P2TR_SCRIPTPUBKEY_LEN);
    }

    /* 6. TAP_INTERNAL_KEY must be VAULT_NUMS_XONLY */
    uint8_t int_key[VAULT_XONLY_PUBKEY_LEN];
    if (VAULT_XONLY_PUBKEY_LEN !=
            call_get_merkleized_map_value(dc,
                                          input_map,
                                          (uint8_t[]) {PSBT_IN_TAP_INTERNAL_KEY},
                                          1,
                                          int_key,
                                          VAULT_XONLY_PUBKEY_LEN) ||
        memcmp(int_key, VAULT_NUMS_XONLY, VAULT_XONLY_PUBKEY_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 7. TAP_MERKLE_ROOT must match vault_build_htlc_merkle_root */
    uint8_t expected_root[VAULT_HASH256_LEN];
    if (!vault_build_htlc_merkle_root(intent, G_vault_context.htlc_hashlock, expected_root)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint8_t psbt_root[VAULT_HASH256_LEN];
    if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                           input_map,
                                                           (uint8_t[]) {PSBT_IN_TAP_MERKLE_ROOT},
                                                           1,
                                                           psbt_root,
                                                           VAULT_HASH256_LEN) ||
        memcmp(psbt_root, expected_root, VAULT_HASH256_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 8. TAP_LEAF_SCRIPT must embed the expected Leaf 0 (contains htlc_hashlock) */
    if (!_pegin_check_leaf0_script(dc, input_map, intent, htlc_spk)) return false;

    *htlc_value_out = htlc_value;
    return true;
}

/* Validates both PegIn outputs (Vault UTXO and Depositor Claim) and the fee bound. */
static bool _pegin_validate_outputs(dispatcher_context_t *dc,
                                    sign_psbt_state_t *st,
                                    const vault_intent_t *intent,
                                    uint64_t htlc_value) {
    /* 1. Output 0: Vault UTXO scriptPubKey and amount */
    uint8_t spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    uint64_t amount;
    uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];

    if (!_read_output(dc, st->outputs_root, 3, 0, spk, &amount)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (!vault_build_vault_utxo_scriptpubkey(intent, expected_spk) ||
        memcmp(spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0 ||
        amount != intent->vault_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 2. Output 1: Depositor Claim scriptPubKey and amount */
    if (!_read_output(dc, st->outputs_root, 3, 1, spk, &amount)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (!vault_build_depositor_claim_scriptpubkey(intent, expected_spk) ||
        memcmp(spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0 ||
        amount != intent->depositor_claim_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 3. Output 2: P2A anchor (OP_1 OP_PUSHBYTES_2 0x4e73, intent->pegin_anchor_value sats)
     * P2A script is 4 bytes — _read_output enforces 34-byte P2TR scripts, so read inline. */
    {
        merkleized_map_commitment_t anchor_map;
        if (call_get_merkleized_map(dc, st->outputs_root, 3, 2, &anchor_map) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t raw_amount[8];
        if (8 != call_get_merkleized_map_value(dc,
                                               &anchor_map,
                                               (uint8_t[]) {PSBT_OUT_AMOUNT},
                                               1,
                                               raw_amount,
                                               8)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (read_u64_le(raw_amount, 0) != intent->pegin_anchor_value) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        static const uint8_t P2A_SCRIPT[] = {0x51u, 0x02u, 0x4Eu, 0x73u};
        uint8_t p2a_buf[sizeof(P2A_SCRIPT)];
        if ((int) sizeof(P2A_SCRIPT) != call_get_merkleized_map_value(dc,
                                                                      &anchor_map,
                                                                      (uint8_t[]) {PSBT_OUT_SCRIPT},
                                                                      1,
                                                                      p2a_buf,
                                                                      sizeof(P2A_SCRIPT)) ||
            memcmp(p2a_buf, P2A_SCRIPT, sizeof(P2A_SCRIPT)) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 4. Fee: htlc_value >= vault_amount + depositor_claim_value + anchor, remainder <=
     * pegin_max_fee.  Two-step addition to catch both possible wraps independently. */
    uint64_t outputs_sum = intent->vault_amount + intent->depositor_claim_value;
    if (outputs_sum < intent->vault_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    outputs_sum += intent->pegin_anchor_value;
    if (outputs_sum < intent->pegin_anchor_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (htlc_value < outputs_sum || (htlc_value - outputs_sum) > intent->pegin_max_fee) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    return true;
}

static bool _validate_pegin(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    /* Internal state guard — defence in depth against caller mis-dispatch */
    if (G_vault_context.state != VAULT_STATE_SESSION2_PEGIN_EXPECTED) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    const vault_intent_t *intent = &G_vault_intent;

    /* 1. Version >= 2, locktime == 0 */
    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 2. Exactly 1 input, 3 outputs (Vault UTXO + Depositor Claim + P2A anchor) */
    if (st->n_inputs != 1 || st->n_outputs != 3) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 3. Get input 0 map */
    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 1, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    uint64_t htlc_value;
    if (!_pegin_validate_input(dc, &input_map, intent, &htlc_value)) return false;
    if (!_pegin_validate_outputs(dc, st, intent, htlc_value)) return false;

    /* 4. PegIn is silent — no display needed.
     * State transition SESSION2_PEGIN_EXPECTED → SESSION2_PAYOUT_EXPECTED is deferred
     * to sign_custom_inputs (NAPPS-1377).  Advancing state here would be premature:
     * the HTLC Leaf 0 input is a tap-script custom input, so sign_custom_inputs is
     * called after this function returns.  If signing fails the state must remain
     * SESSION2_PEGIN_EXPECTED so the host can retry. */
    return true;
}

/* -------------------------------------------------------------------------
 * Payout validation (silent — no UX)
 * ---------------------------------------------------------------------- */

/*
 * Verify PSBT_IN_WITNESS_UTXO for an input: expected_value and expected_spk must match.
 * The btcext framework does not cross-check PSBT_IN_WITNESS_UTXO against a reconstructed
 * P2TR address for segwit v1 inputs, so the device must do this explicitly (NAPPS-1376).
 */
static bool _payout_check_witness_utxo(dispatcher_context_t *dc,
                                       const merkleized_map_commitment_t *input_map,
                                       const uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN],
                                       uint64_t expected_value) {
    uint8_t witness_utxo[MAX_WITNESS_UTXO_LEN];
    int wu_len = call_get_merkleized_map_value(dc,
                                               input_map,
                                               (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                               1,
                                               witness_utxo,
                                               sizeof(witness_utxo));
    if (wu_len < 9) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (read_u64_le(witness_utxo, 0) != expected_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint8_t spk_len = witness_utxo[8];
    if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (memcmp(witness_utxo + 9, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    return true;
}

/*
 * Verify PSBT_IN_TAP_LEAF_SCRIPT for a single-leaf taptree (NUMS internal key).
 * The expected leaf must already reside in G_scratch.leaf_check.expected_script,
 * with its byte count in expected_leaf_len.  Parity is derived from the leaf hash.
 * Uses G_scratch.leaf_check.actual_buf as read buffer — must not overlap with
 * expected_script (guaranteed: actual_buf starts at offset VAULT_SCRIPT_MAX_LEN).
 */
static bool _payout_check_single_leaf_script(dispatcher_context_t *dc,
                                             const merkleized_map_commitment_t *input_map,
                                             int expected_leaf_len,
                                             uint8_t parity) {
    /* PSBT key: 0x15 || (0xC0 | parity) || VAULT_NUMS_XONLY */
    uint8_t psbt_key[1 + 1 + VAULT_XONLY_PUBKEY_LEN];
    psbt_key[0] = PSBT_IN_TAP_LEAF_SCRIPT;
    psbt_key[1] = (uint8_t) (TAPSCRIPT_LEAF_VERSION | parity);
    memcpy(psbt_key + 2, VAULT_NUMS_XONLY, VAULT_XONLY_PUBKEY_LEN);

    /* Value = <leaf_script> || <leaf_version(1B)> */
    int value_len = call_get_merkleized_map_value(dc,
                                                  input_map,
                                                  psbt_key,
                                                  sizeof(psbt_key),
                                                  G_scratch.leaf_check.actual_buf,
                                                  sizeof(G_scratch.leaf_check.actual_buf));
    if (value_len != expected_leaf_len + 1 ||
        G_scratch.leaf_check.actual_buf[value_len - 1] != TAPSCRIPT_LEAF_VERSION) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (memcmp(G_scratch.leaf_check.actual_buf,
               G_scratch.leaf_check.expected_script,
               expected_leaf_len) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    return true;
}

/*
 * Build a BIP-86 key-path-only P2TR scriptPubKey from an x-only public key:
 *   output_key = taproot_tweak(xonly_key, H("TapTweak"||xonly_key))
 *   spk = OP_1 OP_PUSHBYTES_32 output_key
 */
static bool _bip86_p2tr_spk(const uint8_t xonly_key[VAULT_XONLY_PUBKEY_LEN],
                            uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    uint8_t parity;
    uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
    if (crypto_tr_tweak_pubkey(xonly_key, NULL, 0, &parity, tweaked) != 0) return false;
    out[0] = 0x51;
    out[1] = 0x20;
    memcpy(out + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);
    return true;
}

static bool _validate_payout(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    if (G_vault_context.state != VAULT_STATE_SESSION2_PAYOUT_EXPECTED) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    const vault_intent_t *intent = &G_vault_intent;
    const uint8_t claimer_idx = G_vault_context.payout_index;

    /* Claimer ordering guard: payout_index must be in [0, keeper_count] */
    if (claimer_idx > intent->keeper_count) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    /* 1. Version >= 2, locktime == 0 */
    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 2. Exactly 2 inputs */
    if (st->n_inputs != 2) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 3. Output count: 3 for VP claimer (claimer_idx==0), 2 for VK */
    const unsigned int expected_n_outputs = (claimer_idx == 0) ? 3u : 2u;
    if (st->n_outputs != expected_n_outputs) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 4. Validate Input 0 (Vault UTXO) -------------------------------------- */
    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 2, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 4a. PSBT_IN_PREVIOUS_TXID must equal vault_compute_pegin_txid.
     * vault_compute_pegin_txid uses G_scratch.script_scratch — call before
     * any use of G_scratch.leaf_check.expected_script (same memory). */
    uint8_t computed_pegin_txid[VAULT_HASH256_LEN];
    if (!vault_compute_pegin_txid(intent, computed_pegin_txid)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    {
        uint8_t txid[VAULT_HASH256_LEN];
        if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                               &input_map,
                                                               (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                               1,
                                                               txid,
                                                               VAULT_HASH256_LEN) ||
            memcmp(txid, computed_pegin_txid, VAULT_HASH256_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 4b. PSBT_IN_OUTPUT_INDEX must be 0 (Vault UTXO = output 0 of PegIn) */
    {
        uint32_t vout;
        if (call_get_merkleized_map_value_u32_le(dc,
                                                 &input_map,
                                                 (uint8_t[]) {PSBT_IN_OUTPUT_INDEX},
                                                 1,
                                                 &vout) != 4 ||
            vout != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 4c. PSBT_IN_SEQUENCE must equal pegin_csv_timelock */
    {
        uint32_t seq;
        if (call_get_merkleized_map_value_u32_le(dc,
                                                 &input_map,
                                                 (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                 1,
                                                 &seq) != 4 ||
            seq != (uint32_t) intent->pegin_csv_timelock) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 4d. Sighash: SIGHASH_DEFAULT only (absent or 0; 1=ALL rejected) */
    {
        uint32_t sighash = 0;
        int res = call_get_merkleized_map_value_u32_le(dc,
                                                       &input_map,
                                                       (uint8_t[]) {PSBT_IN_SIGHASH_TYPE},
                                                       1,
                                                       &sighash);
        if ((res >= 0 && res != 4) || (res == 4 && sighash != 0)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 4e-f. Build Vault UTXO leaf, derive spk, verify WITNESS_UTXO and TAP_LEAF_SCRIPT.
     * vault_build_vault_utxo_leaf writes directly to buf without touching G_scratch. */
    {
        int leaf_len = vault_build_vault_utxo_leaf(intent,
                                                   G_scratch.leaf_check.expected_script,
                                                   VAULT_SCRIPT_MAX_LEN);
        if (leaf_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t leaf_hash[VAULT_HASH256_LEN];
        vault_taproot_leaf_hash(G_scratch.leaf_check.expected_script, leaf_len, leaf_hash);

        uint8_t parity;
        uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
        if (crypto_tr_tweak_pubkey(VAULT_NUMS_XONLY,
                                   leaf_hash,
                                   VAULT_HASH256_LEN,
                                   &parity,
                                   tweaked) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        expected_spk[0] = 0x51;
        expected_spk[1] = 0x20;
        memcpy(expected_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);

        if (!_payout_check_witness_utxo(dc, &input_map, expected_spk, intent->vault_amount))
            return false;
        if (!_payout_check_single_leaf_script(dc, &input_map, leaf_len, parity)) return false;
    }

    /* 5. Validate Input 1 (Assert:0 Payout for claimer_idx) ----------------- */
    if (call_get_merkleized_map(dc, st->inputs_root, 2, 1, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 5a. PSBT_IN_SEQUENCE must equal payout_timelock */
    {
        uint32_t seq;
        if (call_get_merkleized_map_value_u32_le(dc,
                                                 &input_map,
                                                 (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                 1,
                                                 &seq) != 4 ||
            seq != (uint32_t) intent->payout_timelock) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 5b-c. Build Assert:0 Payout leaf for claimer_idx, verify WITNESS_UTXO and
     * TAP_LEAF_SCRIPT.  This overwrites G_scratch.leaf_check.expected_script (safe:
     * Input 0 checks are complete). */
    {
        int leaf_len = vault_build_assert0_payout_leaf(intent,
                                                       claimer_idx,
                                                       G_scratch.leaf_check.expected_script,
                                                       VAULT_SCRIPT_MAX_LEN);
        if (leaf_len < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t leaf_hash[VAULT_HASH256_LEN];
        vault_taproot_leaf_hash(G_scratch.leaf_check.expected_script, leaf_len, leaf_hash);

        uint8_t parity;
        uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
        if (crypto_tr_tweak_pubkey(VAULT_NUMS_XONLY,
                                   leaf_hash,
                                   VAULT_HASH256_LEN,
                                   &parity,
                                   tweaked) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        expected_spk[0] = 0x51;
        expected_spk[1] = 0x20;
        memcpy(expected_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);

        if (!_payout_check_witness_utxo(dc, &input_map, expected_spk, VAULT_DUST_LIMIT))
            return false;
        if (!_payout_check_single_leaf_script(dc, &input_map, leaf_len, parity)) return false;
    }

    /* 6. Validate outputs --------------------------------------------------- */
    uint8_t out_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    uint64_t out_value;

    /* 6a. Read Out0:
     *   VP claimer: BIP-86 P2TR(depositor)        — depositor receives V - fee - Fc
     *   VK claimer: BIP-86 P2TR(keeper[i])        — VaultKeeper receives V - fee */
    if (!_read_output(dc, st->outputs_root, st->n_outputs, 0, out_spk, &out_value)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    {
        const uint8_t *out0_pk =
            (claimer_idx == 0) ? intent->depositor_pk : intent->keeper_pks[claimer_idx - 1];
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!_bip86_p2tr_spk(out0_pk, expected_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(out_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }
    uint64_t total_out = out_value; /* out0: bounded by out_value; no overflow risk yet */

    /* 6b. Read Out1:
     *   VP: amount == commission_fee, script == BIP-86 P2TR(vault_provider_pk)
     *   VK: amount == VAULT_DUST_LIMIT (CPFP anchor), script == BIP-86 P2TR(keeper[i]) */
    if (!_read_output(dc, st->outputs_root, st->n_outputs, 1, out_spk, &out_value)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    {
        const uint8_t *out1_pk;
        uint64_t expected_out1_value;
        if (claimer_idx == 0) {
            out1_pk = intent->vault_provider_pk;
            expected_out1_value = intent->commission_fee;
        } else {
            out1_pk = intent->keeper_pks[claimer_idx - 1]; /* CPFP anchor to claimer */
            expected_out1_value = VAULT_DUST_LIMIT;
        }
        if (out_value != expected_out1_value) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!_bip86_p2tr_spk(out1_pk, expected_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(out_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }
    if (total_out + out_value < total_out) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    total_out += out_value;

    /* 6c. VP only: Out2 = CPFP anchor (VAULT_DUST_LIMIT) to Claimer (vault_provider_pk) */
    if (claimer_idx == 0) {
        if (!_read_output(dc, st->outputs_root, st->n_outputs, 2, out_spk, &out_value)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (out_value != VAULT_DUST_LIMIT) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!_bip86_p2tr_spk(intent->vault_provider_pk, expected_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(out_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (total_out + out_value < total_out) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        total_out += out_value;
    }

    /* 6d. Fee bound: fee = (vault_amount + VAULT_DUST_LIMIT) - total_out
     *   fee <= base_fee_rate * (MAX_PAYOUT_VSIZE_BASE + MAX_PAYOUT_VSIZE_PER_PARTICIPANT*(N+M)) */
    uint64_t total_in = intent->vault_amount + VAULT_DUST_LIMIT;
    if (total_out > total_in) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = total_in - total_out;
    uint64_t participants = (uint64_t) intent->keeper_count + intent->challenger_count;
    uint64_t max_fee = intent->base_fee_rate *
                       (MAX_PAYOUT_VSIZE_BASE + MAX_PAYOUT_VSIZE_PER_PARTICIPANT * participants);
    if (fee > max_fee) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Advance the payout cursor now that this claimer validated.  Ordering is
     * enforced via claimer_idx == payout_index above; the matching signature is
     * produced afterwards in sign_custom_inputs.  A signing failure there calls
     * vault_context_invalidate(), so advancing here cannot leave a half-signed
     * session behind.  After the last claimer (index == keeper_count) the
     * session moves to SESSION2_COMPLETE; the final payout's signing runs in
     * that state, which is expected.  SESSION2_COMPLETE is terminal — under the
     * realigned spec the host already holds the derived root, so there is no
     * on-device secret-release step. */
    G_vault_context.payout_index++;
    if (G_vault_context.payout_index > intent->keeper_count) {
        if (!vault_context_transition(&G_vault_context,
                                      VAULT_STATE_SESSION2_PAYOUT_EXPECTED,
                                      VAULT_STATE_SESSION2_COMPLETE)) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_BAD_STATE);
            return false;
        }
    }

    return true;
}

/* -------------------------------------------------------------------------
 * Public helpers for sign_custom_inputs
 * ---------------------------------------------------------------------- */

bool vault_read_refund_leaf_script(dispatcher_context_t *dc,
                                   sign_psbt_state_t *st,
                                   merkleized_map_commitment_t *input_map_out) {
    memset(&G_scratch.tls, 0, sizeof(G_scratch.tls));
    if (call_get_merkleized_map_with_callback(
            dc,
            &G_scratch.tls,
            st->inputs_root,
            st->n_inputs,
            0,
            (merkle_tree_elements_callback_t) _tap_leaf_script_callback,
            input_map_out) < 0 ||
        !G_scratch.tls.found || G_scratch.tls.ambiguous) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (G_scratch.tls.leaf_version != TAPSCRIPT_LEAF_VERSION) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * Public dispatch function
 * ---------------------------------------------------------------------- */

bool validate_and_display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)],
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /* PegIn: strictly state-gated */
    if (G_vault_context.state == VAULT_STATE_SESSION2_PEGIN_EXPECTED) {
        return _validate_pegin(dc, st);
    }

    /* Payout: strictly state-gated */
    if (G_vault_context.state == VAULT_STATE_SESSION2_PAYOUT_EXPECTED) {
        return _validate_payout(dc, st);
    }

    /* Pre-PegIn: host provides a wallet policy (BIP-86 wallet inputs) */
    if (!st->has_no_wallet_policy) {
        return _validate_display_prepegin(dc, st, internal_inputs, internal_outputs);
    }

    /* No wallet policy → Refund */
    return _validate_display_refund(dc, st);
}
