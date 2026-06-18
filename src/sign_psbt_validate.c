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
#include "vault_script.h"
#include "sign_psbt_validate_helpers.h"

/* read_u32_le / read_u64_le come from the SDK's lib_standard_app */
#include "read.h"

/* NUMS internal key — same constant as in vault_script.c */
static const uint8_t NUMS_XONLY[VAULT_XONLY_PUBKEY_LEN] = {
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
};

/* Tapscript leaf version */
#define TAPSCRIPT_LEAF_VERSION 0xC0u

/* Maximum length of a TAP_BIP32_DERIVATION value that we'll read:
 * 1B n_hashes + 32B leaf_hash + 4B fingerprint + 5*4B path = 57 bytes max */
#define MAX_TAP_BIP32_DERIV_VALUE_LEN (1 + 32 + 4 + 5 * 4)

/* Maximum WITNESS_UTXO size: 8B value + 1B script_len varint + 34B P2TR script */
#define MAX_WITNESS_UTXO_LEN (8 + 1 + 34)

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
    bool hashlock_set = false;
    for (int i = 0; i < VAULT_HASH256_LEN; i++) {
        if (G_vault_context.htlc_hashlock[i] != 0) {
            hashlock_set = true;
            break;
        }
    }
    if (!hashlock_set) {
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

    /* 11. All outputs other than htlc_vout must be BIP-86 change (internal) */
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        if (i == intent->htlc_vout) continue;
        if (!bitvector_get(internal_outputs, i)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 12. Fee */
    if (st->outputs.total_amount > st->inputs_total_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    /* 13. Convert HTLC scriptPubKey to address string.
     * Static lifetime required: NBGL stores a pointer to this buffer that must
     * remain valid through the blocking io_ui_process() call in display_prepegin_transaction. */
    static char htlc_addr[MAX_ADDRESS_LENGTH_STR + 1];
    if (get_script_address(expected_spk,
                           VAULT_P2TR_SCRIPTPUBKEY_LEN,
                           htlc_addr,
                           sizeof(htlc_addr)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 14. Show Screen 2 to the user (SW_DENY already sent by display function on rejection) */
    if (!display_prepegin_transaction(dc, intent->vault_amount, fee, htlc_addr)) {
        return false;
    }

    /* 15. Advance state: INTENT_LOADED → SESSION1_PREPEGIN_EXPECTED.
     * This prevents the same Pre-PegIn PSBT from being signed more than once. */
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

/* check_bip86_path, parse_tap_bip32_deriv_value, parse_refund_leaf_script
 * live in sign_psbt_validate_helpers.c (included via sign_psbt_validate_helpers.h). */

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
    {
        /* control_block: (leaf_version | parity)(1B) || internal_key(32B) [|| sibling(32B)...] */
        const uint8_t *cb = G_scratch.tls.control_block;
        int cb_len = G_scratch.tls.control_block_len;
        if (cb_len < 1 + VAULT_XONLY_PUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        const uint8_t *internal_key = cb + 1;

        /* The HTLC disables key-path spending via a NUMS point — verify this. */
        if (memcmp(internal_key, NUMS_XONLY, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Compute the leaf hash */
        uint8_t leaf_hash[VAULT_HASH256_LEN];
        vault_taproot_leaf_hash(G_scratch.tls.leaf_script,
                                G_scratch.tls.leaf_script_len,
                                leaf_hash);

        /* Build the merkle root from the leaf hash and any sibling hashes in the control block */
        uint8_t merkle_root[VAULT_HASH256_LEN];
        memcpy(merkle_root, leaf_hash, VAULT_HASH256_LEN);
        int pos = 1 + VAULT_XONLY_PUBKEY_LEN;
        while (pos + VAULT_HASH256_LEN <= cb_len) {
            uint8_t combined[VAULT_HASH256_LEN];
            crypto_tr_combine_taptree_hashes(merkle_root, cb + pos, combined);
            memcpy(merkle_root, combined, VAULT_HASH256_LEN);
            pos += VAULT_HASH256_LEN;
        }

        /* Tweak the internal key and compare with htlc_spk output key */
        uint8_t parity;
        uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
        if (crypto_tr_tweak_pubkey(internal_key,
                                   merkle_root,
                                   VAULT_HASH256_LEN,
                                   &parity,
                                   tweaked) != 0) {
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
    }

    /* 10.5 Validate PSBT_IN_SEQUENCE against the leaf-script CSV timelock.
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

    /* 11. Read single output and verify P2TR shape + BIP-86 ownership */
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

    /* 12. Output BIP-86 ownership via PSBT_OUT_TAP_BIP32_DERIVATION */
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

    /* 13. Fee */
    if (out_value > htlc_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = htlc_value - out_value;

    /* 14. Convert refund output scriptPubKey to address string */
    static char refund_addr[MAX_ADDRESS_LENGTH_STR + 1];
    if (get_script_address(out_script,
                           VAULT_P2TR_SCRIPTPUBKEY_LEN,
                           refund_addr,
                           sizeof(refund_addr)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 15. Display Screen 3 (SW_DENY already sent by display function on rejection) */
    if (!display_refund_transaction(dc, out_value, fee, refund_addr)) {
        return false;
    }
    return true;
}

/* -------------------------------------------------------------------------
 * PegIn validation (silent — no UX)
 * ---------------------------------------------------------------------- */

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

    /* 2. Exactly 1 input, 2 outputs */
    if (st->n_inputs != 1 || st->n_outputs != 2) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 3. Get input 0 map */
    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 1, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* 4. PSBT_IN_PREVIOUS_TXID must match intent->prepegin_txid */
    {
        uint8_t txid[VAULT_HASH256_LEN];
        if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                               &input_map,
                                                               (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                               1,
                                                               txid,
                                                               VAULT_HASH256_LEN)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(txid, intent->prepegin_txid, VAULT_HASH256_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 5. PSBT_IN_OUTPUT_INDEX must match intent->htlc_vout */
    {
        uint32_t vout;
        if (call_get_merkleized_map_value_u32_le(dc,
                                                 &input_map,
                                                 (uint8_t[]) {PSBT_IN_OUTPUT_INDEX},
                                                 1,
                                                 &vout) != 4 ||
            vout != intent->htlc_vout) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 6. Sequence must be 0xFFFFFFFE */
    {
        uint32_t seq;
        if (call_get_merkleized_map_value_u32_le(dc,
                                                 &input_map,
                                                 (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                 1,
                                                 &seq) != 4 ||
            seq != 0xFFFFFFFEu) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 7. Accept SIGHASH_DEFAULT (0) or explicit ALL (1) — identical tapscript commitment (BIP-341)
     */
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
        if (res == 4 && sighash_type != 0 && sighash_type != 1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 8. WITNESS_UTXO → htlc_value + htlc_spk (spk verified against reconstructed key in step 11)
     */
    uint64_t htlc_value;
    uint8_t htlc_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    {
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
        htlc_value = read_u64_le(witness_utxo, 0);
        uint8_t spk_len = witness_utxo[8];
        if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        memcpy(htlc_spk, witness_utxo + 9, VAULT_P2TR_SCRIPTPUBKEY_LEN);
    }

    /* 9. TAP_INTERNAL_KEY must be NUMS_XONLY */
    {
        uint8_t int_key[VAULT_XONLY_PUBKEY_LEN];
        if (VAULT_XONLY_PUBKEY_LEN !=
                call_get_merkleized_map_value(dc,
                                              &input_map,
                                              (uint8_t[]) {PSBT_IN_TAP_INTERNAL_KEY},
                                              1,
                                              int_key,
                                              VAULT_XONLY_PUBKEY_LEN) ||
            memcmp(int_key, NUMS_XONLY, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 10. TAP_MERKLE_ROOT must match vault_build_htlc_merkle_root */
    {
        uint8_t expected_root[VAULT_HASH256_LEN];
        if (!vault_build_htlc_merkle_root(intent, G_vault_context.htlc_hashlock, expected_root)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t psbt_root[VAULT_HASH256_LEN];
        if (VAULT_HASH256_LEN !=
                call_get_merkleized_map_value(dc,
                                              &input_map,
                                              (uint8_t[]) {PSBT_IN_TAP_MERKLE_ROOT},
                                              1,
                                              psbt_root,
                                              VAULT_HASH256_LEN) ||
            memcmp(psbt_root, expected_root, VAULT_HASH256_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 11. TAP_LEAF_SCRIPT must embed the expected Leaf 0 (contains htlc_hashlock) */
    {
        /* Build Leaf 0 into leaf_check.expected_script (= union offset 0 = script_scratch).
         * It stays there for the final comparison — leaf1 is built into actual_buf instead
         * so we never overwrite leaf0, eliminating a second vault_build_htlc_leaf0 call. */
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

        /* Build Leaf 1 into actual_buf (union offset 2560) — disjoint from expected_script. */
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

        /* Recompute merkle root (needed for tweak parity) */
        uint8_t merkle_root[VAULT_HASH256_LEN];
        crypto_tr_combine_taptree_hashes(leaf0_hash, leaf1_hash, merkle_root);

        /* Tweak to get output key parity */
        uint8_t parity;
        uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
        if (crypto_tr_tweak_pubkey(NUMS_XONLY, merkle_root, VAULT_HASH256_LEN, &parity, tweaked) !=
            0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Verify WITNESS_UTXO scriptPubKey matches the reconstructed output key */
        if (htlc_spk[0] != 0x51 || htlc_spk[1] != 0x20 ||
            memcmp(htlc_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        /* Construct PSBT key for TAP_LEAF_SCRIPT of Leaf 0:
         * key = 0x15 || (0xC0 | parity) || NUMS_XONLY || leaf1_hash */
        uint8_t psbt_key[1 + 1 + VAULT_XONLY_PUBKEY_LEN + VAULT_HASH256_LEN];
        psbt_key[0] = PSBT_IN_TAP_LEAF_SCRIPT;
        psbt_key[1] = (uint8_t) (TAPSCRIPT_LEAF_VERSION | parity);
        memcpy(psbt_key + 2, NUMS_XONLY, VAULT_XONLY_PUBKEY_LEN);
        memcpy(psbt_key + 2 + VAULT_XONLY_PUBKEY_LEN, leaf1_hash, VAULT_HASH256_LEN);
        size_t psbt_key_len = sizeof(psbt_key);

        /* Value = expected_leaf0_script || 0xC0.  Overwrite actual_buf with the PSBT value
         * (leaf1 bytes are no longer needed — only leaf1_hash matters from here). */
        int value_len = call_get_merkleized_map_value(dc,
                                                      &input_map,
                                                      psbt_key,
                                                      psbt_key_len,
                                                      actual_buf,
                                                      sizeof(G_scratch.leaf_check.actual_buf));
        if (value_len != l0_len + 1) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* Last byte is leaf version */
        if (actual_buf[value_len - 1] != TAPSCRIPT_LEAF_VERSION) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* Compare PSBT script against expected_script (leaf0 still in place at offset 0) */
        if (memcmp(actual_buf, G_scratch.leaf_check.expected_script, l0_len) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 12. Output 0: Vault UTXO scriptPubKey and amount */
    {
        uint8_t spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        uint64_t amount;
        if (!_read_output(dc, st->outputs_root, 2, 0, spk, &amount)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!vault_build_vault_utxo_scriptpubkey(intent, expected_spk) ||
            memcmp(spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (amount != intent->vault_amount) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 13. Output 1: Depositor Claim scriptPubKey and amount */
    {
        uint8_t spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        uint64_t amount;
        if (!_read_output(dc, st->outputs_root, 2, 1, spk, &amount)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!vault_build_depositor_claim_scriptpubkey(intent, expected_spk) ||
            memcmp(spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (amount != intent->depositor_claim_value) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 14. Fee check: htlc_value >= vault_amount + depositor_claim_value (no overflow) */
    {
        uint64_t outputs_sum = intent->vault_amount + intent->depositor_claim_value;
        if (outputs_sum < intent->vault_amount) {
            /* overflow */
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (htlc_value < outputs_sum) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint64_t fee = htlc_value - outputs_sum;
        if (fee > intent->pegin_max_fee) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* 15. PegIn is silent — no display needed.
     * Advance state: SESSION2_PEGIN_EXPECTED → SESSION2_PAYOUT_EXPECTED so the same
     * PSBT cannot be validated a second time before NAPPS-1377 implements signing. */
    if (!vault_context_transition(&G_vault_context,
                                  VAULT_STATE_SESSION2_PEGIN_EXPECTED,
                                  VAULT_STATE_SESSION2_PAYOUT_EXPECTED)) {
        SEND_SW(dc, SW_BAD_STATE);
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

    /* Pre-PegIn: host provides a wallet policy (BIP-86 wallet inputs) */
    if (!st->has_no_wallet_policy) {
        return _validate_display_prepegin(dc, st, internal_inputs, internal_outputs);
    }

    /* No wallet policy → Refund */
    return _validate_display_refund(dc, st);
}
