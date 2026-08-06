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
#include "bip322.h"
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

_Static_assert(
    VAULT_MAX_VAULTS *(VAULT_MAX_KEEPERS + 2) <= UINT16_MAX,
    "payout cap overflows uint16_t — reduce VAULT_MAX_VAULTS or VAULT_MAX_KEEPERS");
_Static_assert(VAULT_MAX_VAULTS *(VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS) <= UINT16_MAX,
               "nopayout cap overflows uint16_t — reduce VAULT_MAX_VAULTS, VAULT_MAX_KEEPERS, or "
               "VAULT_MAX_CHALLENGERS");

/* Maximum WITNESS_UTXO size: 8B value + 1B script_len varint + 34B P2TR script */
#define MAX_WITNESS_UTXO_LEN (8 + 1 + 34)

/* auth-anchor OP_RETURN scriptPubKey: OP_RETURN(0x6A) OP_PUSHBYTES_32(0x20) <32B hash>.
 * Happens to be the same byte length as a P2TR scriptPubKey; the static assert makes
 * this coincidence explicit so _read_output can read both with the same buffer size. */
#define AUTH_ANCHOR_SPK_LEN 34u
_Static_assert(AUTH_ANCHOR_SPK_LEN == VAULT_P2TR_SCRIPTPUBKEY_LEN,
               "AUTH_ANCHOR_SPK_LEN must equal VAULT_P2TR_SCRIPTPUBKEY_LEN for _read_output reuse");

/* Distinct status word for CPFP anchor output scriptPubKey mismatch in payout */
#define SW_BAD_CPFP_ANCHOR 0xB009u
/* Returned when a per-type signature cap is exceeded; intent is nullified on this path */
#define SW_CAP_EXCEEDED 0xB00Au

/* Payout fee bound constants (NAPPS-1376) */
#define MAX_PAYOUT_VSIZE_BASE            500u
#define MAX_PAYOUT_VSIZE_PER_PARTICIPANT 55u

/* Bounds guard for functions that receive group_idx as a parameter and index
 * htlc_hashlock[] or intent->groups[].  vault_count ∈ [1, VAULT_MAX_VAULTS]
 * is enforced at parse time, so the upper check also implies gi < VAULT_MAX_VAULTS. */
#define ASSERT_GROUP_IDX(dc, intent, gi)                                \
    do {                                                                \
        if ((gi) < 0 || (unsigned int) (gi) >= (intent)->vault_count) { \
            SEND_SW((dc), SW_INCORRECT_DATA);                           \
            return false;                                               \
        }                                                               \
    } while (0)

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
 * Pre-PegIn validation
 * ---------------------------------------------------------------------- */

/* Computes the double-SHA256 txid of the Pre-PegIn transaction from PSBT fields.
 * All Pre-PegIn inputs are SegWit (no scriptSig), so the serialisation is:
 *   version_le4 | n_inputs | (prev_txid | vout_le4 | 0x00 | seq_le4) * n_inputs |
 *   n_outputs | (value_le8 | script_len | script) * n_outputs | locktime_le4.
 * All Pre-PegIn output scripts are 34 bytes (P2TR or OP_RETURN); prior validation
 * ensures this, so the script buffer is bounded to VAULT_P2TR_SCRIPTPUBKEY_LEN.
 * Returns false and sends SW on any PSBT read or crypto failure. */
static bool _compute_prepegin_txid(dispatcher_context_t *dc,
                                   sign_psbt_state_t *st,
                                   uint8_t txid_out[VAULT_HASH256_LEN]) {
    cx_sha256_t sha;
    cx_sha256_init_no_throw(&sha);
    uint8_t tmp[8];

    /* version (4 bytes LE) */
    write_u32_le(tmp, 0, (uint32_t) st->tx_version);
    if (cx_hash_no_throw(&sha.header, 0, tmp, 4, NULL, 0) != CX_OK) return false;

    /* input count */
    if (crypto_hash_update_varint(&sha.header, st->n_inputs) != CX_OK) return false;

    for (unsigned int i = 0; i < st->n_inputs; i++) {
        merkleized_map_commitment_t in_map;
        if (call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, i, &in_map) < 0) {
            return false;
        }
        uint8_t prev_txid[VAULT_HASH256_LEN];
        if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                               &in_map,
                                                               (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                               1,
                                                               prev_txid,
                                                               VAULT_HASH256_LEN)) {
            return false;
        }
        if (cx_hash_no_throw(&sha.header, 0, prev_txid, VAULT_HASH256_LEN, NULL, 0) != CX_OK)
            return false;

        uint32_t vout;
        if (call_get_merkleized_map_value_u32_le(dc,
                                                 &in_map,
                                                 (uint8_t[]) {PSBT_IN_OUTPUT_INDEX},
                                                 1,
                                                 &vout) != 4) {
            return false;
        }
        write_u32_le(tmp, 0, vout);
        if (cx_hash_no_throw(&sha.header, 0, tmp, 4, NULL, 0) != CX_OK) return false;

        /* scriptSig: empty (varint 0x00) */
        tmp[0] = 0x00;
        if (cx_hash_no_throw(&sha.header, 0, tmp, 1, NULL, 0) != CX_OK) return false;

        /* nSequence (4 bytes LE); absent PSBT_IN_SEQUENCE defaults to SEQUENCE_FINAL */
        uint32_t seq = SEQUENCE_FINAL;
        int seq_rc = call_get_merkleized_map_value_u32_le(dc,
                                                          &in_map,
                                                          (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                          1,
                                                          &seq);
        if (seq_rc >= 0 && seq_rc != 4) return false;
        write_u32_le(tmp, 0, seq);
        if (cx_hash_no_throw(&sha.header, 0, tmp, 4, NULL, 0) != CX_OK) return false;
    }

    /* output count */
    if (crypto_hash_update_varint(&sha.header, st->n_outputs) != CX_OK) return false;

    for (unsigned int i = 0; i < st->n_outputs; i++) {
        uint8_t spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        uint64_t value;
        if (!_read_output(dc, st->outputs_root, st->n_outputs, i, spk, &value)) {
            return false;
        }
        write_u64_le(tmp, 0, value);
        if (cx_hash_no_throw(&sha.header, 0, tmp, 8, NULL, 0) != CX_OK) return false;
        if (crypto_hash_update_varint(&sha.header, VAULT_P2TR_SCRIPTPUBKEY_LEN) != CX_OK)
            return false;
        if (cx_hash_no_throw(&sha.header, 0, spk, VAULT_P2TR_SCRIPTPUBKEY_LEN, NULL, 0) != CX_OK)
            return false;
    }

    /* locktime (4 bytes LE) */
    write_u32_le(tmp, 0, st->locktime);
    if (cx_hash_no_throw(&sha.header, 0, tmp, 4, NULL, 0) != CX_OK) return false;

    /* Finalise first SHA256 */
    uint8_t inner[VAULT_HASH256_LEN];
    if (cx_hash_no_throw(&sha.header, CX_LAST, NULL, 0, inner, VAULT_HASH256_LEN) != CX_OK)
        return false;

    /* SHA256(inner) = txid */
    cx_sha256_init_no_throw(&sha);
    return cx_hash_no_throw(&sha.header,
                            CX_LAST,
                            inner,
                            VAULT_HASH256_LEN,
                            txid_out,
                            VAULT_HASH256_LEN) == CX_OK;
}

static bool _validate_prepegin(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)],
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]) {
    /* State guard: must have intent and a derived hashlock */
    if (G_vault_context.state != VAULT_STATE_INTENT_LOADED) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }
    const vault_intent_t *intent = &G_vault_intent;
    const uint8_t zeros[VAULT_HASH256_LEN] = {0};
    for (uint8_t gi = 0; gi < intent->vault_count; gi++) {
        if (memcmp(G_vault_context.htlc_hashlock[gi], zeros, VAULT_HASH256_LEN) == 0) {
            /* DERIVE_CONTEXT_HASH must be called before Pre-PegIn signing */
            SEND_SW(dc, SW_BAD_STATE);
            return false;
        }
    }

    for (unsigned int i = 0; i < st->n_inputs; i++) {
        if (!bitvector_get(internal_inputs, i)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

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
        if (res == 4 && sighash_type != SIGHASH_DEFAULT && sighash_type != SIGHASH_ALL) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* res < 0 means absent → SIGHASH_DEFAULT (0) → OK */
    }

    /* Per vault group: verify htlc_vout range, HTLC scriptPubKey, and amount. */
    for (unsigned int gi = 0; gi < intent->vault_count; gi++) {
        if (intent->groups[gi].htlc_vout >= st->n_outputs) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t actual_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        uint64_t htlc_value;
        if (!_read_output(dc,
                          st->outputs_root,
                          st->n_outputs,
                          intent->groups[gi].htlc_vout,
                          actual_spk,
                          &htlc_value)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!vault_build_htlc_scriptpubkey(intent,
                                           gi,
                                           G_vault_context.htlc_hashlock[gi],
                                           expected_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(actual_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

        uint64_t min_htlc =
            intent->groups[gi].vault_amount + intent->groups[gi].depositor_claim_value;
        if (min_htlc < intent->groups[gi].vault_amount) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* Include P2A anchor: the PegIn funds this output from the HTLC value. */
        min_htlc += P2A_ANCHOR_VALUE;
        if (min_htlc < P2A_ANCHOR_VALUE) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint64_t max_htlc = min_htlc + intent->groups[gi].pegin_max_fee;
        if (max_htlc < min_htlc) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (htlc_value < min_htlc || htlc_value > max_htlc) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Every non-HTLC output must be either BIP-86 change (internal) or the single
     * shared auth-anchor OP_RETURN = "OP_RETURN <SHA256(authAnchor)>". The OP_RETURN
     * must be positioned strictly after all HTLC outputs.
     *
     * Expected scriptPubKey: 0x6A 0x20 || auth_anchor_hash (AUTH_ANCHOR_SPK_LEN bytes).
     * groups are in ascending htlc_vout order, so the last group has the highest htlc_vout. */
    uint8_t expected_anchor_spk[AUTH_ANCHOR_SPK_LEN];
    expected_anchor_spk[0] = 0x6A;  // OP_RETURN
    expected_anchor_spk[1] = OP_PUSHBYTES_32;
    memcpy(expected_anchor_spk + 2, G_vault_context.auth_anchor_hash, VAULT_HASH256_LEN);

    /* Assert vault_count ∈ [1, VAULT_MAX_VAULTS] enforced at parse time.
     * Guards against a false-positive [security.ArrayBound] warning: the analyzer cannot
     * prove the invariant across the parse/validate boundary and flags the -1 index path. */
    LEDGER_ASSERT(intent->vault_count >= 1 && intent->vault_count <= VAULT_MAX_VAULTS,
                  "vault_count out of range");
    const unsigned int max_htlc_vout = intent->groups[intent->vault_count - 1].htlc_vout;

    bool anchor_found = false;
    for (unsigned int i = 0; i < st->n_outputs; i++) {
        bool is_htlc_output = false;
        for (unsigned int gi = 0; gi < intent->vault_count; gi++) {
            if (intent->groups[gi].htlc_vout == i) {
                is_htlc_output = true;
                break;
            }
        }
        if (is_htlc_output) continue;
        if (bitvector_get(internal_outputs, i)) continue;  // BIP-86 change

        /* Non-internal, non-HTLC output: the only one allowed is the auth-anchor OP_RETURN,
         * positioned strictly after all HTLC outputs. MUST carry zero value — the OP_RETURN
         * is provably unspendable, so any non-zero value silently burns the depositor's
         * change (WYSIWYS violation). */
        if (i <= max_htlc_vout) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
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
    /* v22: OP_RETURN anchor is optional — presence is not enforced.
     * anchor_found enforces at-most-one anchor within the loop; its final
     * value is intentionally not checked here. */
    (void) anchor_found;

    if (st->outputs.total_amount > st->inputs_total_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Enforce Pre-PegIn fee bound. prepegin_max_fee is a mandatory intent field (v22). */
    uint64_t prepegin_fee = st->inputs_total_amount - st->outputs.total_amount;
    if (prepegin_fee > intent->prepegin_max_fee) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Verify the PSBT will produce the txid committed in the intent. */
    {
        uint8_t computed_txid[VAULT_HASH256_LEN];
        if (!_compute_prepegin_txid(dc, st, computed_txid) ||
            memcmp(computed_txid, intent->prepegin_txid, VAULT_HASH256_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    if (G_vault_context.pre_pegin_signed >= 1u) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_CAP_EXCEEDED);
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
    if (htlc_spk[0] != OP_1 || htlc_spk[1] != OP_PUSHBYTES_32 ||
        memcmp(htlc_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    return true;
}

static bool _validate_display_refund(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    vault_state_t state = G_vault_context.state;

    if (st->n_inputs != 1 || st->n_outputs != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

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
        /* HLD mandates SIGHASH_DEFAULT only; explicit SIGHASH_ALL is rejected even
         * though BIP-341 defines it as equivalent for tapscript, to enforce strict
         * canonical encoding per the protocol spec. */
        if (res == 4 && sighash_type != SIGHASH_DEFAULT) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

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

    /* Find TAP_LEAF_SCRIPT using the callback — lives in G_scratch.tls (saves 2636 B BSS). */
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

    /* Parse leaf script shape — also extracts the CSV timelock value */
    uint8_t leaf_key[VAULT_XONLY_PUBKEY_LEN];
    uint32_t csv_value;
    if (!parse_refund_leaf_script(G_scratch.tls.leaf_script,
                                  G_scratch.tls.leaf_script_len,
                                  leaf_key,
                                  &csv_value)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* CSV timelock validation:
     *   INTENT_LOADED: must equal the approved htlc_refund_timelock exactly.
     *   IDLE/HASH_DERIVED: no approved value to compare against, but enforce the
     *     protocol minimum so a short-CSV UTXO (e.g. 1 block) cannot be signed. */
    if (state == VAULT_STATE_INTENT_LOADED) {
        if (csv_value != (uint32_t) G_vault_intent.htlc_refund_timelock) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    } else {
        if (csv_value < VAULT_TIMELOCK_MIN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

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

        if (fingerprint != st->master_key_fingerprint) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }

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

    if (!_refund_verify_taproot_commitment(dc, htlc_spk)) return false;

    /* Validate PSBT_IN_SEQUENCE against the leaf-script CSV timelock.
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
        if ((nsequence & BIP68_DISABLE_FLAG) != 0 || (nsequence & BIP68_TIME_BASED_FLAG) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* Canonical: sequence must encode exactly the CSV timelock, not just satisfy it. */
        if ((nsequence & BIP68_SEQUENCE_MASK) != (csv_value & BIP68_SEQUENCE_MASK)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

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
    if (slen != VAULT_P2TR_SCRIPTPUBKEY_LEN || out_script[0] != OP_1 ||
        out_script[1] != OP_PUSHBYTES_32) {
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

    if (out_value > htlc_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = htlc_value - out_value;

    /* Read the Pre-PegIn txid (Input 0 prevout) for Screen 3 display. */
    uint8_t prepegin_txid[VAULT_HASH256_LEN];
    if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                           &input_map,
                                                           (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                           1,
                                                           prepegin_txid,
                                                           VAULT_HASH256_LEN)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    /* When an intent is loaded, the displayed txid must match the intent-bound Pre-PegIn. */
    if (G_vault_context.state == VAULT_STATE_INTENT_LOADED &&
        memcmp(prepegin_txid, G_vault_intent.prepegin_txid, VAULT_HASH256_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Convert refund output scriptPubKey to address string.
     * Written into G_scratch.display_tx.addr_str — NBGL holds a pointer to it
     * across the blocking io_ui_process() call in display_refund_transaction. */
    if (get_script_address(out_script,
                           VAULT_P2TR_SCRIPTPUBKEY_LEN,
                           G_scratch.display_tx.addr_str,
                           sizeof(G_scratch.display_tx.addr_str)) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* SW_DENY already sent by display function on rejection */
    if (!display_refund_transaction(dc,
                                    out_value,
                                    fee,
                                    csv_value,
                                    prepegin_txid,
                                    G_scratch.display_tx.addr_str)) {
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
                                      int group_idx,
                                      const uint8_t htlc_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    ASSERT_GROUP_IDX(dc, intent, group_idx);
    /* Build Leaf 0 into leaf_check.expected_script (= union offset 0 = script_scratch).
     * It stays there for the final comparison — Leaf 1 is built into actual_buf instead
     * so we never overwrite Leaf 0, eliminating a second vault_build_htlc_leaf0 call. */
    memset(G_scratch.leaf_check.expected_script, 0, VAULT_SCRIPT_MAX_LEN);
    int l0_len = vault_build_htlc_leaf0(intent,
                                        group_idx,
                                        G_vault_context.htlc_hashlock[group_idx],
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

    if (htlc_spk[0] != OP_1 || htlc_spk[1] != OP_PUSHBYTES_32 ||
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
                                  int group_idx,
                                  uint64_t *htlc_value_out) {
    ASSERT_GROUP_IDX(dc, intent, group_idx);
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

    uint32_t vout;
    if (call_get_merkleized_map_value_u32_le(dc,
                                             input_map,
                                             (uint8_t[]) {PSBT_IN_OUTPUT_INDEX},
                                             1,
                                             &vout) != 4 ||
        vout != intent->groups[group_idx].htlc_vout) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    uint32_t seq;
    if (call_get_merkleized_map_value_u32_le(dc,
                                             input_map,
                                             (uint8_t[]) {PSBT_IN_SEQUENCE},
                                             1,
                                             &seq) != 4 ||
        seq != PEGIN_TX_SEQUENCE) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* SIGHASH_DEFAULT only (spec: absent or explicit 0; SIGHASH_ALL rejected). */
    uint32_t sighash_type = 0;
    int res = call_get_merkleized_map_value_u32_le(dc,
                                                   input_map,
                                                   (uint8_t[]) {PSBT_IN_SIGHASH_TYPE},
                                                   1,
                                                   &sighash_type);
    if ((res >= 0 && res != 4) || (res == 4 && sighash_type != SIGHASH_DEFAULT)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

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

    uint8_t expected_root[VAULT_HASH256_LEN];
    if (!vault_build_htlc_merkle_root(intent,
                                      group_idx,
                                      G_vault_context.htlc_hashlock[group_idx],
                                      expected_root)) {
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

    if (!_pegin_check_leaf0_script(dc, input_map, intent, group_idx, htlc_spk)) return false;

    *htlc_value_out = htlc_value;
    return true;
}

/* Validates both PegIn outputs (Vault UTXO and Depositor Claim) and the fee bound. */
static bool _pegin_validate_outputs(dispatcher_context_t *dc,
                                    sign_psbt_state_t *st,
                                    const vault_intent_t *intent,
                                    int group_idx,
                                    uint64_t htlc_value) {
    uint8_t spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    uint64_t amount;
    uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];

    if (!_read_output(dc, st->outputs_root, 3, 0, spk, &amount)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (!vault_build_vault_utxo_scriptpubkey(intent, group_idx, expected_spk) ||
        memcmp(spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0 ||
        amount != intent->groups[group_idx].vault_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (!_read_output(dc, st->outputs_root, 3, 1, spk, &amount)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (!vault_build_depositor_claim_scriptpubkey(intent, expected_spk) ||
        memcmp(spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0 ||
        amount != intent->groups[group_idx].depositor_claim_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Output 2: P2A anchor (OP_1 OP_PUSHBYTES_2 0x4e73, P2A_ANCHOR_VALUE sats).
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
        if (read_u64_le(raw_amount, 0) != P2A_ANCHOR_VALUE) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        static const uint8_t P2A_SCRIPT[] = {OP_1,
                                             OP_PUSHBYTES_2,
                                             P2A_WITNESS_PROG_BYTE0,
                                             P2A_WITNESS_PROG_BYTE1};
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

    /* Fee: htlc_value >= vault_amount + depositor_claim_value + anchor, remainder <=
     * pegin_max_fee.  Two-step addition to catch both possible wraps independently. */
    uint64_t outputs_sum =
        intent->groups[group_idx].vault_amount + intent->groups[group_idx].depositor_claim_value;
    if (outputs_sum < intent->groups[group_idx].vault_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    outputs_sum += P2A_ANCHOR_VALUE;
    if (outputs_sum < P2A_ANCHOR_VALUE) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (htlc_value < outputs_sum ||
        (htlc_value - outputs_sum) > intent->groups[group_idx].pegin_max_fee) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    return true;
}

static bool _validate_pegin(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    if (G_vault_context.state != VAULT_STATE_INTENT_LOADED) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    const vault_intent_t *intent = &G_vault_intent;

    /* PegIn must be a TRUC transaction (BIP-431 version 3) with locktime 0. */
    if (st->tx_version != PEGIN_TX_VERSION || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->n_inputs != 1 || st->n_outputs != 3) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 1, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Auto-detect group_idx: find the vault group whose htlc_vout matches
     * Input 0's PSBT_IN_OUTPUT_INDEX.  This enables multi-vault PegIn signing. */
    uint32_t htlc_vout;
    if (call_get_merkleized_map_value_u32_le(dc,
                                             &input_map,
                                             (uint8_t[]) {PSBT_IN_OUTPUT_INDEX},
                                             1,
                                             &htlc_vout) != 4) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    /* intent->groups[g].htlc_vout is uint8_t; reject any PSBT vout > 255 before
     * comparing, so the narrowing cast below cannot silently alias a wrong group. */
    if (htlc_vout > 0xFFu) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    int group_idx = -1;
    for (uint8_t g = 0; g < intent->vault_count; g++) {
        if (intent->groups[g].htlc_vout == (uint8_t) htlc_vout) {
            group_idx = (int) g;
            break;
        }
    }
    if (group_idx < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Store the detected group index in context for sign_custom_inputs. */
    G_vault_context.vault_group_index = (uint8_t) group_idx;

    uint64_t htlc_value;
    if (!_pegin_validate_input(dc, &input_map, intent, group_idx, &htlc_value)) return false;
    if (!_pegin_validate_outputs(dc, st, intent, group_idx, htlc_value)) return false;

    if (G_vault_context.pegin_signed >= (uint16_t) G_vault_intent.vault_count) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_CAP_EXCEEDED);
        return false;
    }
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
    out[0] = OP_1;
    out[1] = OP_PUSHBYTES_32;
    memcpy(out + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);
    return true;
}

static bool _validate_payout(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    if (G_vault_context.state != VAULT_STATE_INTENT_LOADED) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    const vault_intent_t *intent = &G_vault_intent;

    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->n_inputs != 2) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* --- Input 0: open and detect gi from PREVIOUS_TXID ---
     * vault_compute_pegin_txid uses G_scratch.script_scratch; call before any
     * use of G_scratch.leaf_check.expected_script (same memory union). */
    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 2, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    int gi = -1;
    {
        uint8_t psbt_txid[VAULT_HASH256_LEN];
        if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                               &input_map,
                                                               (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                               1,
                                                               psbt_txid,
                                                               VAULT_HASH256_LEN)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t computed_txid[VAULT_HASH256_LEN];
        for (uint8_t g = 0; g < intent->vault_count; g++) {
            if (vault_compute_pegin_txid(intent, (int) g, computed_txid) &&
                memcmp(psbt_txid, computed_txid, VAULT_HASH256_LEN) == 0) {
                gi = (int) g;
                break;
            }
        }
    }
    if (gi < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    ASSERT_GROUP_IDX(dc, intent, gi);

    /* --- Input 1: open and detect claimer_idx from Assert:0 Payout leaf spk ---
     * Try each claimer_idx; the first whose computed P2TR scriptPubKey matches
     * Input 1's PSBT_IN_WITNESS_UTXO script is the valid claimer. */
    merkleized_map_commitment_t input1_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 2, 1, &input1_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    int claimer_idx = -1;
    {
        uint8_t wu1[8 + 1 + VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (call_get_merkleized_map_value(dc,
                                          &input1_map,
                                          (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                          1,
                                          wu1,
                                          sizeof(wu1)) != (int) sizeof(wu1) ||
            wu1[8] != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        const uint8_t *input1_spk = wu1 + 9;
        for (int ci = 0; ci <= (int) intent->keeper_count + 1; ci++) {
            int leaf_len = vault_build_assert0_payout_leaf(intent,
                                                           gi,
                                                           ci,
                                                           G_scratch.leaf_check.expected_script,
                                                           VAULT_SCRIPT_MAX_LEN);
            if (leaf_len < 0) continue;
            uint8_t lh[VAULT_HASH256_LEN];
            vault_taproot_leaf_hash(G_scratch.leaf_check.expected_script, leaf_len, lh);
            uint8_t parity;
            uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
            if (crypto_tr_tweak_pubkey(VAULT_NUMS_XONLY, lh, VAULT_HASH256_LEN, &parity, tweaked) !=
                0)
                continue;
            uint8_t cand_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
            cand_spk[0] = OP_1;
            cand_spk[1] = OP_PUSHBYTES_32;
            memcpy(cand_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);
            if (memcmp(input1_spk, cand_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) == 0) {
                claimer_idx = ci;
                break;
            }
        }
    }
    if (claimer_idx < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Store detected indices for sign_custom_inputs. */
    G_vault_context.vault_group_index = (uint8_t) gi;
    G_vault_context.payout_index = (uint8_t) claimer_idx;

    /* n_outputs: 3 for VP, 2 for all other claimers */
    const unsigned int expected_n_outputs = (claimer_idx == 0) ? 3u : 2u;
    if (st->n_outputs != expected_n_outputs) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* PSBT_IN_OUTPUT_INDEX must be 0 (Vault UTXO = output 0 of PegIn) */
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

    /* PSBT_IN_SEQUENCE must equal pegin_csv_timelock */
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

    /* Sighash: SIGHASH_DEFAULT only (absent or 0; 1=ALL rejected) */
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

    /* Build Vault UTXO leaf, derive spk, verify WITNESS_UTXO and TAP_LEAF_SCRIPT.
     * vault_build_vault_utxo_leaf writes directly to buf without touching G_scratch. */
    {
        int leaf_len = vault_build_vault_utxo_leaf(intent,
                                                   gi,
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
        expected_spk[0] = OP_1;
        expected_spk[1] = OP_PUSHBYTES_32;
        memcpy(expected_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);

        if (!_payout_check_witness_utxo(dc,
                                        &input_map,
                                        expected_spk,
                                        intent->groups[gi].vault_amount))
            return false;
        if (!_payout_check_single_leaf_script(dc, &input_map, leaf_len, parity)) return false;
    }

    /* --- Input 1: Assert:0 Payout (map opened above for claimer detection) --- */

    /* PSBT_IN_SEQUENCE must equal payout_timelock */
    {
        uint32_t seq;
        if (call_get_merkleized_map_value_u32_le(dc,
                                                 &input1_map,
                                                 (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                 1,
                                                 &seq) != 4 ||
            seq != (uint32_t) intent->payout_timelock) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Build Assert:0 Payout leaf for claimer_idx, verify WITNESS_UTXO and
     * TAP_LEAF_SCRIPT.  Overwrites G_scratch.leaf_check.expected_script (safe:
     * Input 0 checks are complete). */
    {
        int leaf_len = vault_build_assert0_payout_leaf(intent,
                                                       gi,
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
        expected_spk[0] = OP_1;
        expected_spk[1] = OP_PUSHBYTES_32;
        memcpy(expected_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);

        if (!_payout_check_witness_utxo(dc, &input1_map, expected_spk, VAULT_DUST_LIMIT))
            return false;
        if (!_payout_check_single_leaf_script(dc, &input1_map, leaf_len, parity)) return false;
    }

    /* --- Outputs --- */
    uint8_t out_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    uint64_t out_value;

    /* Out0:
     *   VP or Depositor claimer: depositor receives V - fee (± Fc) — BIP-86 P2TR(depositor).
     *   VK claimer: VaultKeeper receives V - fee — VK's registered address, value only (v22). */
    if (!_read_output(dc, st->outputs_root, st->n_outputs, 0, out_spk, &out_value)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (claimer_idx == 0 || claimer_idx == (uint8_t) (intent->keeper_count + 1u)) {
        /* VP or Depositor claimer: Output 0 must be BIP-86 P2TR(depositor_pk). */
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!_bip86_p2tr_spk(intent->depositor_pk, expected_spk)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(out_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    } else {
        /* VK claimer: Output 0 must be key-path P2TR(keeper_pks[claimer_idx - 1]). */
        uint8_t parity;
        uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
        if (crypto_tr_tweak_pubkey(intent->keeper_pks[claimer_idx - 1],
                                   NULL,
                                   0,
                                   &parity,
                                   tweaked) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        expected_spk[0] = OP_1;
        expected_spk[1] = OP_PUSHBYTES_32;
        memcpy(expected_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);
        if (memcmp(out_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }
    if (out_value <= VAULT_DUST_LIMIT) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t total_out = out_value; /* out0: bounded by out_value; no overflow risk yet */

    /* Out1:
     *   VP claimer: commission_fee to VP's registered address — value only (v22).
     *   Depositor claimer: CPFP anchor (DUST) to depositor — BIP-86 P2TR(depositor), verified.
     *   VK claimer: CPFP anchor (DUST) to VK's registered address — value only (v22). */
    if (!_read_output(dc, st->outputs_root, st->n_outputs, 1, out_spk, &out_value)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    {
        if (claimer_idx == 0) {
            /* Spec: VP Out1 must be exactly commission_fee (Fc). */
            if (out_value != intent->groups[gi].commission_fee) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
        } else {
            /* Non-VP Out1 must be exactly DUST. */
            if (out_value != VAULT_DUST_LIMIT) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
        }
        /* Only the Depositor claimer's CPFP anchor is script-verified (BIP-86 P2TR). */
        if (claimer_idx == (uint8_t) (intent->keeper_count + 1u)) {
            uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
            if (!_bip86_p2tr_spk(intent->depositor_pk, expected_spk)) {
                SEND_SW(dc, SW_INCORRECT_DATA);
                return false;
            }
            if (memcmp(out_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
                SEND_SW(dc, SW_BAD_CPFP_ANCHOR);
                return false;
            }
        }
    }
    if (total_out + out_value < total_out) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    total_out += out_value;

    /* VP only: Out2 = CPFP anchor (VAULT_DUST_LIMIT) to VP's registered address — value only (v22).
     */
    if (claimer_idx == 0) {
        if (!_read_output(dc, st->outputs_root, st->n_outputs, 2, out_spk, &out_value)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (out_value != VAULT_DUST_LIMIT) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (total_out + out_value < total_out) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        total_out += out_value;
    }

    /* Fee bound: fee = (vault_amount + Assert:0_amount) - total_out.
     * Assert:0_amount was already validated as VAULT_DUST_LIMIT by _payout_check_witness_utxo
     * above, so the two are equivalent.
     *   fee <= base_fee_rate * (MAX_PAYOUT_VSIZE_BASE + MAX_PAYOUT_VSIZE_PER_PARTICIPANT*(N+M)) */
    uint64_t total_in = intent->groups[gi].vault_amount + VAULT_DUST_LIMIT;
    if (total_out > total_in) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = total_in - total_out;
    if (fee == 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t participants = (uint64_t) intent->keeper_count + intent->challenger_count;
    uint64_t vsize = MAX_PAYOUT_VSIZE_BASE + MAX_PAYOUT_VSIZE_PER_PARTICIPANT * participants;
    /* Overflow check before multiplying: vsize is bounded (~28k max), base_fee_rate is u64. */
    if (vsize > UINT64_MAX / intent->base_fee_rate) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t max_fee = intent->base_fee_rate * vsize;
    if (fee > max_fee) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Payout cap: vault_count × (keeper_count + 2) — VP + N VK claimers + Depositor */
    {
        uint16_t payout_cap =
            (uint16_t) intent->vault_count * ((uint16_t) intent->keeper_count + 2u);
        if (G_vault_context.payout_signed >= payout_cap) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_CAP_EXCEEDED);
            return false;
        }
    }

    G_vault_context.is_payout_signing = true;
    return true;
}

/* -------------------------------------------------------------------------
 * NoPayout validation (intent-bound, silent)
 *
 * Input 0: Assert:0 UTXO (depositor graph), Assert:0 leaf, value DUST.
 * Inputs 1, 2: ChallengeAssert connectors (not signed by device).
 * Output: pays challenger.
 * ---------------------------------------------------------------------- */

static bool _validate_nopayout(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    if (G_vault_context.state != VAULT_STATE_INTENT_LOADED) {
        SEND_SW(dc, SW_BAD_STATE);
        return false;
    }

    const vault_intent_t *intent = &G_vault_intent;

    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Exactly 3 inputs (Assert:0 + 2 ChallengeAssert connectors) and 1 output. */
    if (st->n_inputs != 3 || st->n_outputs != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    merkleized_map_commitment_t input_map;
    if (!vault_read_refund_leaf_script(dc, st, &input_map)) return false;

    const uint8_t *leaf = G_scratch.tls.leaf_script;
    int leaf_len = G_scratch.tls.leaf_script_len;

    /* Assert:0 leaf: <D>(33B) OP_CHECKSIGVERIFY <Cj>(33B) OP_CHECKSIG = 68 bytes */
    if (leaf_len != VAULT_NOPAYOUT_LEAF_LEN || leaf[0] != OP_PUSHBYTES_32 ||
        leaf[33] != (uint8_t) OP_CHECKSIGVERIFY || leaf[34] != OP_PUSHBYTES_32 ||
        leaf[67] != (uint8_t) OP_CHECKSIG) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* D key at leaf[1..32] must match intent depositor key */
    if (memcmp(leaf + 1, intent->depositor_pk, VAULT_XONLY_PUBKEY_LEN) != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Identify the depositor-graph challenger at leaf[35..66].  The role can be
     * a VaultKeeper (indices 0..keeper_count-1) or a UniversalChallenger
     * (indices keeper_count..keeper_count+challenger_count-1). */
    const uint8_t *leaf_challenger = leaf + 35;
    int challenger_idx = -1;
    for (int i = 0; i < (int) intent->keeper_count && challenger_idx < 0; i++) {
        if (memcmp(intent->keeper_pks[i], leaf_challenger, VAULT_XONLY_PUBKEY_LEN) == 0)
            challenger_idx = i;
    }
    for (int i = 0; i < (int) intent->challenger_count && challenger_idx < 0; i++) {
        if (memcmp(intent->challenger_pks[i], leaf_challenger, VAULT_XONLY_PUBKEY_LEN) == 0)
            challenger_idx = (int) intent->keeper_count + i;
    }
    if (challenger_idx < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Save challenger key before _refund_verify_taproot_commitment clobbers G_scratch.tls. */
    uint8_t challenger_xonly[VAULT_XONLY_PUBKEY_LEN];
    memcpy(challenger_xonly, leaf_challenger, VAULT_XONLY_PUBKEY_LEN);

    /* Reconstruct the leaf and compare to prevent parameter substitution */
    {
        uint8_t expected[VAULT_NOPAYOUT_LEAF_LEN];
        if (vault_build_nopayout_leaf(intent, challenger_idx, expected, sizeof(expected)) !=
                VAULT_NOPAYOUT_LEAF_LEN ||
            memcmp(expected, leaf, VAULT_NOPAYOUT_LEAF_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Sighash must be SIGHASH_DEFAULT (absent or 0) */
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

    /* Input 0 WITNESS_UTXO: value must be ≤ VAULT_DUST_LIMIT; verify taproot commitment */
    {
        uint8_t witness_utxo[MAX_WITNESS_UTXO_LEN];
        int wu_len = call_get_merkleized_map_value(dc,
                                                   &input_map,
                                                   (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                                   1,
                                                   witness_utxo,
                                                   sizeof(witness_utxo));
        if (wu_len < 9 || read_u64_le(witness_utxo, 0) > VAULT_DUST_LIMIT) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t spk_len = witness_utxo[8];
        if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (!_refund_verify_taproot_commitment(dc, witness_utxo + 9)) return false;
    }

    /* Inputs 1 and 2 (ChallengeAssert connectors): WITNESS_UTXO value must be <= DUST. */
    for (unsigned int ci = 1; ci <= 2; ci++) {
        merkleized_map_commitment_t conn_map;
        if (call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, ci, &conn_map) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t wu[MAX_WITNESS_UTXO_LEN];
        int wu_len = call_get_merkleized_map_value(dc,
                                                   &conn_map,
                                                   (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                                   1,
                                                   wu,
                                                   sizeof(wu));
        if (wu_len < 8 || read_u64_le(wu, 0) > VAULT_DUST_LIMIT) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Output 0: must pay P2TR(Challenger_j) — key-path spend with empty script tree. */
    {
        uint8_t parity;
        uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
        if (crypto_tr_tweak_pubkey(challenger_xonly, NULL, 0, &parity, tweaked) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t expected_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        expected_spk[0] = OP_1;
        expected_spk[1] = OP_PUSHBYTES_32;
        memcpy(expected_spk + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);
        uint8_t out_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        uint64_t out_value;
        if (!_read_output(dc, st->outputs_root, st->n_outputs, 0, out_spk, &out_value) ||
            memcmp(out_spk, expected_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Cap: vault_count × (keeper_count + challenger_count) */
    uint16_t cap =
        (uint16_t) ((uint16_t) intent->vault_count *
                    ((uint16_t) intent->keeper_count + (uint16_t) intent->challenger_count));
    if (G_vault_context.nopayout_signed >= cap) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_CAP_EXCEEDED);
        return false;
    }

    if (!display_nopayout_transaction(dc, (uint8_t) challenger_idx)) return false;
    return true;
}

/* -------------------------------------------------------------------------
 * Standalone Claim validation + display (Screen 4)
 *
 * Precondition: G_scratch.tls is populated by the leaf-based dispatcher.
 * Input 0: Depositor Claim UTXO, leaf <D> OP_CHECKSIG, key BIP-86.
 * Output 0: ClaimAssertConnector (host-provided, not reconstructed).
 * Output 1: BIP-86 P2TR(D), value DUST (CPFP anchor).
 * ---------------------------------------------------------------------- */

/* Verify Input 0 nSequence == SEQUENCE_FINAL (RBF-disabled, no CSV).
 * Absent PSBT_IN_SEQUENCE is treated as the spec-default SEQUENCE_FINAL. */
static bool _require_sequence_final(dispatcher_context_t *dc,
                                    merkleized_map_commitment_t *input_map) {
    uint32_t seq = SEQUENCE_FINAL;
    int seq_rc = call_get_merkleized_map_value_u32_le(dc,
                                                      input_map,
                                                      (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                      1,
                                                      &seq);
    if ((seq_rc >= 0 && seq_rc != 4) || seq != SEQUENCE_FINAL) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    return true;
}

static bool _validate_display_claim(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    if (st->n_inputs != 1 || st->n_outputs != 2) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* G_scratch.tls already populated; dispatcher guarantees leaf is 34 bytes <D> OP_CHECKSIG */
    LEDGER_ASSERT(G_scratch.tls.leaf_script_len == VAULT_DEPOSITOR_CLAIM_LEAF_LEN,
                  "unexpected claim leaf length");
    const uint8_t *leaf = G_scratch.tls.leaf_script;
    /* Extract D key into a local copy before any use of G_scratch.leaf_check */
    uint8_t d_key[VAULT_XONLY_PUBKEY_LEN];
    memcpy(d_key, leaf + 1, VAULT_XONLY_PUBKEY_LEN);

    /* Open Input 0 map */
    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 1, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Input 0 sequence must be SEQUENCE_FINAL (RBF-disabled, no CSV). */
    if (!_require_sequence_final(dc, &input_map)) return false;

    /* Sighash must be SIGHASH_DEFAULT */
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

    /* WITNESS_UTXO: read value and verify taproot commitment first.
     * _refund_verify_taproot_commitment reads G_scratch.tls.control_block and
     * .leaf_script, fully consuming tls.  After this block, G_scratch.sign_standalone
     * is free for the BIP32 locals (xpub, deriv_val) to save ~200 B of stack. */
    uint64_t input_value;
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
        input_value = read_u64_le(witness_utxo, 0);
        uint8_t spk_len = witness_utxo[8];
        if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (!_refund_verify_taproot_commitment(dc, witness_utxo + 9)) return false;
    }

    /* Verify D key via BIP-32 derivation path in Input 0.
     * G_scratch.tls is consumed above; use G_scratch.sign_standalone for the large
     * buffers (xpub 78 B, deriv_val 89 B) to keep them off the call stack. */
    uint8_t bip86_out_key[VAULT_XONLY_PUBKEY_LEN]; /* BIP-86 P2TR(D) for output check */
    {
        G_scratch.sign_standalone.deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(G_scratch.sign_standalone.deriv_key + 1, d_key, VAULT_XONLY_PUBKEY_LEN);
        int deriv_len = call_get_merkleized_map_value(dc,
                                                      &input_map,
                                                      G_scratch.sign_standalone.deriv_key,
                                                      1 + VAULT_XONLY_PUBKEY_LEN,
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
        if (memcmp(xpub->compressed_pubkey + 1, d_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t bip86_parity;
        if (crypto_tr_tweak_pubkey(d_key, NULL, 0, &bip86_parity, bip86_out_key) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Output 1: value == VAULT_DUST_LIMIT, script == BIP-86 P2TR(D) */
    {
        uint8_t out_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        uint64_t out1_value;
        if (!_read_output(dc, st->outputs_root, 2, 1, out_spk, &out1_value)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (out1_value != VAULT_DUST_LIMIT) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (out_spk[0] != OP_1 || out_spk[1] != OP_PUSHBYTES_32 ||
            memcmp(out_spk + 2, bip86_out_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    if (st->outputs.total_amount >= input_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = input_value - st->outputs.total_amount;

    /* connector_amount = Out0 value = total outputs minus the VAULT_DUST_LIMIT CPFP anchor */
    uint64_t connector_amount = st->outputs.total_amount - VAULT_DUST_LIMIT;

    /* Read PegIn txid (Input 0 prevout) — vault reference shown on Screen 4. */
    uint8_t pegin_txid[VAULT_HASH256_LEN];
    if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                           &input_map,
                                                           (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                           1,
                                                           pegin_txid,
                                                           VAULT_HASH256_LEN)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (!display_claim_transaction(dc, input_value, connector_amount, fee, pegin_txid))
        return false;
    return true;
}

/* -------------------------------------------------------------------------
 * Standalone Assert validation + display (Screen 5)
 *
 * Precondition: G_scratch.tls is populated by the leaf-based dispatcher.
 * Input 0: ClaimAssertConnector (leaf not reconstructed; D verified at prefix).
 * Outputs: not enforced (host-provided connector tree).
 * ---------------------------------------------------------------------- */

static bool _validate_display_assert(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    if (st->n_inputs != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* G_scratch.tls already populated; extract D key before any use of leaf_check.
     * Leaf shape: <D>(32B) OP_CHECKSIGVERIFY <key>(32B) OP_CSV (68 bytes).
     * <key> at leaf[35..66] is not verified against the vault intent — per spec this is
     * "parameter insulation": the Assert leaf is host-provided (the WOTS chain tips are
     * outside the device's knowledge), and the signature only commits the depositor key. */
    const uint8_t *leaf = G_scratch.tls.leaf_script;
    uint8_t d_key[VAULT_XONLY_PUBKEY_LEN];
    memcpy(d_key, leaf + 1, VAULT_XONLY_PUBKEY_LEN);

    /* Open Input 0 map */
    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 1, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Input 0 sequence must be SEQUENCE_FINAL (RBF-disabled, no CSV). */
    if (!_require_sequence_final(dc, &input_map)) return false;

    /* Sighash must be SIGHASH_DEFAULT */
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

    /* WITNESS_UTXO: verify taproot commitment and extract amount_carried.
     * Must execute before the BIP-32 block below, which clobbers G_scratch.tls via
     * G_scratch.sign_standalone.  G_scratch.tls (populated by the dispatcher) is
     * still intact here, so _refund_verify_taproot_commitment can read the control
     * block and leaf script it needs. */
    uint64_t amount_carried;
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
        uint8_t spk_len = witness_utxo[8];
        if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (!_refund_verify_taproot_commitment(dc, witness_utxo + 9)) return false;
        amount_carried = read_u64_le(witness_utxo, 0);
    }

    /* Verify D key via BIP-32 derivation in Input 0.
     * tls is consumed after the WITNESS_UTXO block above; use G_scratch.sign_standalone
     * for the large buffers (xpub 78 B, deriv_val 89 B) to keep them off the stack. */
    {
        G_scratch.sign_standalone.deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(G_scratch.sign_standalone.deriv_key + 1, d_key, VAULT_XONLY_PUBKEY_LEN);
        int deriv_len = call_get_merkleized_map_value(dc,
                                                      &input_map,
                                                      G_scratch.sign_standalone.deriv_key,
                                                      1 + VAULT_XONLY_PUBKEY_LEN,
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
        if (memcmp(xpub->compressed_pubkey + 1, d_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Read Claim txid (= Input 0 prevout txid) for Screen 5 display */
    uint8_t claim_txid[VAULT_HASH256_LEN];
    if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                           &input_map,
                                                           (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                           1,
                                                           claim_txid,
                                                           VAULT_HASH256_LEN)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    if (st->inputs_total_amount < st->outputs.total_amount) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = st->inputs_total_amount - st->outputs.total_amount;

    if (!display_assert_transaction(dc, claim_txid, amount_carried, fee)) return false;
    return true;
}

/* -------------------------------------------------------------------------
 * Standalone WC (WronglyChallenged) validation + display (Screen 6)
 *
 * Input 0: ChallengeAssert output connector, leaf <D> OP_CHECKSIGVERIFY OP_SIZE ...
 * Inputs 1+ (optional): BIP-86 wallet inputs for fees.
 * Output 0: BIP-86 P2TR(D).
 * ---------------------------------------------------------------------- */

static bool _validate_display_wc(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    if (st->n_inputs < 1 || st->n_outputs != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Always re-read leaf so WC works both from wallet-policy and leaf-dispatch paths */
    merkleized_map_commitment_t input_map;
    if (!vault_read_refund_leaf_script(dc, st, &input_map)) return false;

    const uint8_t *leaf = G_scratch.tls.leaf_script;
    int leaf_len = G_scratch.tls.leaf_script_len;

    /* WC leaf (exact 73 bytes):
     *   <D>(32B) OP_CHECKSIGVERIFY OP_SIZE OP_PUSHBYTES_1 32 OP_EQUALVERIFY
     *   OP_SHA256 OP_PUSHBYTES_32 <output_label_hash>(32B) OP_EQUAL.
     * The output_label_hash at [40..71] is read as-is; not reconstructed from intent. */
    if (leaf_len != 73 || leaf[0] != OP_PUSHBYTES_32 || leaf[33] != (uint8_t) OP_CHECKSIGVERIFY ||
        leaf[34] != (uint8_t) OP_SIZE || leaf[35] != OP_PUSHBYTES_1 ||
        leaf[36] != VAULT_HASH256_LEN || leaf[37] != (uint8_t) OP_EQUALVERIFY ||
        leaf[38] != (uint8_t) OP_SHA256 || leaf[39] != OP_PUSHBYTES_32 ||
        leaf[72] != (uint8_t) OP_EQUAL) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Extract D key before any use of leaf_check */
    uint8_t d_key[VAULT_XONLY_PUBKEY_LEN];
    memcpy(d_key, leaf + 1, VAULT_XONLY_PUBKEY_LEN);

    /* Input 0 sequence must be SEQUENCE_FINAL (RBF-disabled, no CSV). */
    if (!_require_sequence_final(dc, &input_map)) return false;

    /* Sighash must be SIGHASH_DEFAULT */
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

    /* Verify D key via BIP-32 derivation in Input 0 */
    uint8_t bip86_out_key[VAULT_XONLY_PUBKEY_LEN];
    {
        uint8_t deriv_key[1 + VAULT_XONLY_PUBKEY_LEN];
        deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(deriv_key + 1, d_key, VAULT_XONLY_PUBKEY_LEN);
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
        if (path_len < 0 || fingerprint != st->master_key_fingerprint ||
            !check_bip86_path(path, path_len)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        serialized_extended_pubkey_t xpub;
        if (get_extended_pubkey_at_path(path, (uint8_t) path_len, BIP32_PUBKEY_VERSION, &xpub) !=
            0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(xpub.compressed_pubkey + 1, d_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t bip86_parity;
        if (crypto_tr_tweak_pubkey(d_key, NULL, 0, &bip86_parity, bip86_out_key) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* WITNESS_UTXO: verify taproot commitment and extract the WC UTXO value. */
    uint64_t wc_utxo_value;
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
        uint8_t spk_len = witness_utxo[8];
        if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        wc_utxo_value = read_u64_le(witness_utxo, 0);
        if (!_refund_verify_taproot_commitment(dc, witness_utxo + 9)) return false;
    }

    /* Output 0: BIP-86 P2TR(D) — also convert to address for display. */
    uint64_t out0_value;
    {
        uint8_t out_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!_read_output(dc, st->outputs_root, 1, 0, out_spk, &out0_value)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (out_spk[0] != OP_1 || out_spk[1] != OP_PUSHBYTES_32 ||
            memcmp(out_spk + 2, bip86_out_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* Convert verified output to bech32m address for display.
         * NBGL holds the pointer across io_ui_process in display_wc_transaction. */
        if (get_script_address(out_spk,
                               VAULT_P2TR_SCRIPTPUBKEY_LEN,
                               G_scratch.display_tx.addr_str,
                               sizeof(G_scratch.display_tx.addr_str)) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    if (st->inputs_total_amount < out0_value) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    uint64_t fee = st->inputs_total_amount - out0_value;

    /* Wallet inputs are any counted inputs beyond the WC UTXO itself. */
    uint64_t wallet_inputs_amount =
        (st->inputs_total_amount > wc_utxo_value) ? st->inputs_total_amount - wc_utxo_value : 0;

    if (!display_wc_transaction(dc,
                                out0_value,
                                wallet_inputs_amount,
                                fee,
                                G_scratch.display_tx.addr_str))
        return false;
    return true;
}

/* -------------------------------------------------------------------------
 * PoP (BIP-322 proof-of-possession) validation + display (Screen 7)
 *
 * Discriminator: tx_version == 0 is unique to PoP across all protocol PSBTs.
 * Input 0: P2TR key-path (BIP-86 depositor), SIGHASH_DEFAULT, sequence 0.
 * Output 0: value 0, scriptPubKey OP_RETURN (0x6A).
 * Global proprietary field (BIP322_PSBT_PROP_POP_MSG_KEY) carries the PoP message.
 * ---------------------------------------------------------------------- */

static bool _validate_display_pop(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    LEDGER_ASSERT(st->tx_version == 0, "pop handler called for non-PoP tx");
    memset(&G_scratch.sign_standalone, 0, sizeof(G_scratch.sign_standalone));
    if (st->n_inputs != 1 || st->n_outputs != 1) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Read PoP message from PSBT global proprietary field */
    uint8_t msg_buf[BIP322_POP_MSG_MAX_LEN];
    int msg_len = call_get_merkleized_map_value(dc,
                                                &st->global_map,
                                                BIP322_PSBT_PROP_POP_MSG_KEY,
                                                BIP322_PSBT_PROP_KEY_LEN,
                                                msg_buf,
                                                BIP322_POP_MSG_MAX_LEN);
    /* call_get_merkleized_map_value returns at most the buffer size (bytes read, capped),
     * so msg_len > BIP322_POP_MSG_MAX_LEN is structurally unreachable — kept as explicit
     * documentation of the intended upper-bound rejection. */
    if (msg_len <= 0 || msg_len > BIP322_POP_MSG_MAX_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Validate message grammar */
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];
    if (!bip322_parse_pop_message(msg_buf, msg_len, eth_addr, chain_id, registry)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Open Input 0 map */
    merkleized_map_commitment_t input_map;
    if (call_get_merkleized_map(dc, st->inputs_root, 1, 0, &input_map) < 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Sighash: absent (SIGHASH_DEFAULT) or explicit 0 only */
    {
        uint32_t sighash = 0;
        int res = call_get_merkleized_map_value_u32_le(dc,
                                                       &input_map,
                                                       (uint8_t[]) {PSBT_IN_SIGHASH_TYPE},
                                                       1,
                                                       &sighash);
        if (res >= 0 && res != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (res == 4 && sighash != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* WITNESS_UTXO: P2TR scriptPubKey (OP_1 PUSHBYTES_32 <tweaked_key>) */
    uint8_t tweaked_key[VAULT_XONLY_PUBKEY_LEN];
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
        /* BIP-322 to_spend output value must be 0 */
        if (read_u64_le(witness_utxo, 0) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t spk_len = witness_utxo[8];
        if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN ||
            witness_utxo[9] != BIP322_OP_1 || witness_utxo[10] != BIP322_PUSHBYTES_32) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        memcpy(tweaked_key, witness_utxo + 11, VAULT_XONLY_PUBKEY_LEN);
    }

    /* TAP_INTERNAL_KEY: x-only BIP-86 internal key */
    uint8_t internal_key[VAULT_XONLY_PUBKEY_LEN];
    if (VAULT_XONLY_PUBKEY_LEN !=
        call_get_merkleized_map_value(dc,
                                      &input_map,
                                      (uint8_t[]) {PSBT_IN_TAP_INTERNAL_KEY},
                                      1,
                                      internal_key,
                                      VAULT_XONLY_PUBKEY_LEN)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* PoP is a BIP-86 key-path spend — TAP_MERKLE_ROOT must be absent.
     * TAP_LEAF_SCRIPT absence is enforced structurally: the BIP-86 tweak uses
     * no scripts, and we verify the tweaked key against WITNESS_UTXO below —
     * a script-derived alternative SPK would fail that check. */
    {
        uint8_t dummy[32];
        if (call_get_merkleized_map_value(dc,
                                          &input_map,
                                          (uint8_t[]) {PSBT_IN_TAP_MERKLE_ROOT},
                                          1,
                                          dummy,
                                          sizeof(dummy)) >= 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Verify internal key via BIP-32 derivation + BIP-86 tweak.
     * Uses G_scratch.sign_standalone for large buffers (xpub 78B, deriv_val 89B). */
    {
        G_scratch.sign_standalone.deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(G_scratch.sign_standalone.deriv_key + 1, internal_key, VAULT_XONLY_PUBKEY_LEN);
        int deriv_len = call_get_merkleized_map_value(dc,
                                                      &input_map,
                                                      G_scratch.sign_standalone.deriv_key,
                                                      1 + VAULT_XONLY_PUBKEY_LEN,
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
        /* The derived x-only key must match the PSBT TAP_INTERNAL_KEY */
        if (memcmp(xpub->compressed_pubkey + 1, internal_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* BIP-86: key-path-only tweak must match the tweaked key in WITNESS_UTXO */
        uint8_t bip86_parity;
        uint8_t bip86_tweaked[VAULT_XONLY_PUBKEY_LEN];
        if (crypto_tr_tweak_pubkey(internal_key, NULL, 0, &bip86_parity, bip86_tweaked) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (memcmp(bip86_tweaked, tweaked_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Verify PSBT_IN_PREVIOUS_TXID against the computed to_spend txid */
    {
        uint8_t computed_txid[VAULT_HASH256_LEN];
        if (!bip322_compute_to_spend_txid(msg_buf, msg_len, tweaked_key, computed_txid)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t psbt_txid[VAULT_HASH256_LEN];
        if (VAULT_HASH256_LEN != call_get_merkleized_map_value(dc,
                                                               &input_map,
                                                               (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                               1,
                                                               psbt_txid,
                                                               VAULT_HASH256_LEN) ||
            memcmp(psbt_txid, computed_txid, VAULT_HASH256_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* PSBT_IN_OUTPUT_INDEX must be 0 */
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

    /* PSBT_IN_SEQUENCE must be 0 (BIP-322 to_sign nSequence = 0) */
    {
        uint32_t seq;
        if (call_get_merkleized_map_value_u32_le(dc,
                                                 &input_map,
                                                 (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                 1,
                                                 &seq) != 4 ||
            seq != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Output 0: value == 0, scriptPubKey == OP_RETURN (0x6A, single byte) */
    {
        merkleized_map_commitment_t out_map;
        if (call_get_merkleized_map(dc, st->outputs_root, 1, 0, &out_map) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t raw8[8];
        if (8 != call_get_merkleized_map_value(dc,
                                               &out_map,
                                               (uint8_t[]) {PSBT_OUT_AMOUNT},
                                               1,
                                               raw8,
                                               8) ||
            read_u64_le(raw8, 0) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        /* BIP-322: to_sign output 0 must be a bare single-byte OP_RETURN */
        uint8_t out_script[2];
        if (call_get_merkleized_map_value(dc,
                                          &out_map,
                                          (uint8_t[]) {PSBT_OUT_SCRIPT},
                                          1,
                                          out_script,
                                          sizeof(out_script)) != 1 ||
            out_script[0] != BIP322_OP_RETURN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    if (G_vault_context.pop_signed >= VAULT_POP_CAP) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_CAP_EXCEEDED);
        return false;
    }

    if (!display_pop_transaction(dc, eth_addr, chain_id, registry)) return false;
    return true;
}

/* -------------------------------------------------------------------------
 * PayoutFinalize validation + display (Screen 8)
 *
 * Input 0: Assert:0 output — no signing request permitted.
 * Input 1: P2TR script-path spend; payout leaf
 *          <D> OP_CHECKSIGVERIFY [AppChallengers] [UnivChallengers] <t2> OP_CSV.
 * Output 0: P2TR(D) BIP-86 — depositor receives these funds.
 * Output 1: VAULT_DUST_LIMIT, P2TR(D) BIP-86 — CPFP anchor.
 * ---------------------------------------------------------------------- */

static bool _validate_display_payout_finalize(dispatcher_context_t *dc, sign_psbt_state_t *st) {
    G_vault_context.is_payout_signing = false;
    if (st->tx_version < 2 || st->locktime != 0) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Read Input 1 TAP_LEAF_SCRIPT into G_scratch.tls */
    merkleized_map_commitment_t input1_map;
    if (!vault_read_payout_leaf_script(dc, st, &input1_map)) return false;

    uint8_t d_key[VAULT_XONLY_PUBKEY_LEN];
    uint32_t csv_value;
    if (!parse_payout_leaf_script(G_scratch.tls.leaf_script,
                                  G_scratch.tls.leaf_script_len,
                                  d_key,
                                  &csv_value)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Sighash must be SIGHASH_DEFAULT */
    {
        uint32_t sighash = 0;
        int res = call_get_merkleized_map_value_u32_le(dc,
                                                       &input1_map,
                                                       (uint8_t[]) {PSBT_IN_SIGHASH_TYPE},
                                                       1,
                                                       &sighash);
        if ((res >= 0 && res != 4) || (res == 4 && sighash != 0)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* WITNESS_UTXO for Input 1: record the input value, verify P2TR size, then taproot commitment.
     * _refund_verify_taproot_commitment reads G_scratch.tls, which is still intact here. */
    uint64_t input1_value;
    {
        uint8_t witness_utxo[MAX_WITNESS_UTXO_LEN];
        int wu_len = call_get_merkleized_map_value(dc,
                                                   &input1_map,
                                                   (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                                   1,
                                                   witness_utxo,
                                                   sizeof(witness_utxo));
        if (wu_len < 9) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        input1_value = read_u64_le(witness_utxo, 0);
        uint8_t spk_len = witness_utxo[8];
        if (wu_len != 9 + spk_len || spk_len != VAULT_P2TR_SCRIPTPUBKEY_LEN) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (!_refund_verify_taproot_commitment(dc, witness_utxo + 9)) return false;
    }

    /* Verify D key via BIP-32 derivation in Input 1.
     * G_scratch.tls is consumed above; use G_scratch.sign_standalone for large buffers. */
    uint8_t bip86_out_key[VAULT_XONLY_PUBKEY_LEN];
    {
        G_scratch.sign_standalone.deriv_key[0] = PSBT_IN_TAP_BIP32_DERIVATION;
        memcpy(G_scratch.sign_standalone.deriv_key + 1, d_key, VAULT_XONLY_PUBKEY_LEN);
        int deriv_len = call_get_merkleized_map_value(dc,
                                                      &input1_map,
                                                      G_scratch.sign_standalone.deriv_key,
                                                      1 + VAULT_XONLY_PUBKEY_LEN,
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
        if (memcmp(xpub->compressed_pubkey + 1, d_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        uint8_t bip86_parity;
        if (crypto_tr_tweak_pubkey(d_key, NULL, 0, &bip86_parity, bip86_out_key) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Validate Input 1 PSBT_IN_SEQUENCE against the payout leaf CSV timelock.
     * BIP-68: bit 31 enables/disables sequence, bit 22 selects block vs time.
     * nSequence must be block-based and satisfy nSequence >= t2 (not exact match). */
    {
        uint32_t nsequence = 0;
        int seq_res = call_get_merkleized_map_value_u32_le(dc,
                                                           &input1_map,
                                                           (uint8_t[]) {PSBT_IN_SEQUENCE},
                                                           1,
                                                           &nsequence);
        if (seq_res != 4) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if ((nsequence & BIP68_DISABLE_FLAG) != 0 || (nsequence & BIP68_TIME_BASED_FLAG) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if ((nsequence & BIP68_SEQUENCE_MASK) < (csv_value & BIP68_SEQUENCE_MASK)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Output 0: P2TR(D) BIP-86 — amount received by depositor.
     * Encode SPK as bech32m address here; addr_str stays valid across io_ui_process()
     * because it lives in global scratch storage. */
    uint64_t amount_received;
    {
        uint8_t out0_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        if (!_read_output(dc, st->outputs_root, 2, 0, out0_spk, &amount_received)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (out0_spk[0] != OP_1 || out0_spk[1] != OP_PUSHBYTES_32 ||
            memcmp(out0_spk + 2, bip86_out_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (get_script_address(out0_spk,
                               VAULT_P2TR_SCRIPTPUBKEY_LEN,
                               G_scratch.display_tx.addr_str,
                               sizeof(G_scratch.display_tx.addr_str)) < 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Output 1: CPFP anchor — VAULT_DUST_LIMIT, P2TR(D) BIP-86 */
    {
        uint8_t out1_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
        uint64_t out1_value;
        if (!_read_output(dc, st->outputs_root, 2, 1, out1_spk, &out1_value)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        if (out1_value != VAULT_DUST_LIMIT || out1_spk[0] != OP_1 ||
            out1_spk[1] != OP_PUSHBYTES_32 ||
            memcmp(out1_spk + 2, bip86_out_key, VAULT_XONLY_PUBKEY_LEN) != 0) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
    }

    /* Outputs must not exceed Input 1 — guards against fabricated witness_utxo values. */
    if (amount_received > input1_value || VAULT_DUST_LIMIT > input1_value - amount_received) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }
    if (!display_payout_finalize(dc, amount_received, G_scratch.display_tx.addr_str)) return false;
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

bool vault_read_payout_leaf_script(dispatcher_context_t *dc,
                                   sign_psbt_state_t *st,
                                   merkleized_map_commitment_t *input_map_out) {
    memset(&G_scratch.tls, 0, sizeof(G_scratch.tls));
    if (call_get_merkleized_map_with_callback(
            dc,
            &G_scratch.tls,
            st->inputs_root,
            st->n_inputs,
            1,
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
    /* PoP BIP-322: tx_version == 0 uniquely identifies PoP across all protocol PSBTs.
     * PoP is intentionally state-independent: it may be signed at any time, with or
     * without a loaded intent. A pegin request may be re-submitted after the deposit
     * ceremony, so PoP is never constrained by the vault session state machine.
     * Scratch safety: all other handlers in this function complete within a single APDU
     * and do not leave live data in G_scratch across APDU boundaries, so dispatching PoP
     * at any point does not clobber in-progress state. _validate_display_pop zeroes
     * G_scratch.sign_standalone before use. */
    if (st->tx_version == 0) return _validate_display_pop(dc, st);

    vault_state_t state = G_vault_context.state;

    /* PegIn: 1 input, 3 outputs, no wallet policy.
     * Routed before the INTENT_LOADED gate so _validate_pegin can return SW_BAD_STATE
     * when called without an active session, rather than falling through to the standalone
     * leaf dispatcher which would return SW_INCORRECT_DATA for the HTLC leaf shape. */
    if (st->has_no_wallet_policy && st->n_inputs == 1 && st->n_outputs == 3)
        return _validate_pegin(dc, st);

    /* NoPayout: 3 inputs, 1 output, no wallet policy.
     * Routed before the INTENT_LOADED gate so _validate_nopayout can return SW_BAD_STATE
     * when invoked without an active session rather than falling through to the leaf dispatcher. */
    if (st->has_no_wallet_policy && st->n_inputs == 3 && st->n_outputs == 1)
        return _validate_nopayout(dc, st);

    /* Intent-bound flows (no wallet policy, INTENT_LOADED):
     *   Payout (all)      — 2 inputs; VP=3 outputs, VK/Depositor=2 outputs
     *   PayoutFinalize    — 2 inputs, 2 outputs, Input 0 external (routed after the block below)
     * Any other no-wallet-policy PSBT in INTENT_LOADED falls through to the
     * standalone leaf dispatch (Refund/Claim/Assert/WC also valid from this state). */
    if (state == VAULT_STATE_INTENT_LOADED && st->has_no_wallet_policy) {
        /* Payout: 2 inputs, VP=3 outputs / VK+Depositor=2 outputs.
         * VP (n_outputs==3) is unambiguous.
         * VK/Depositor (n_outputs==2) is distinguished from PayoutFinalize (also 2+2) by
         * Input 0 PREVIOUS_TXID matching a vault_compute_pegin_txid for some group.
         * bitvector_get(internal_inputs, 0) cannot be used because internal_inputs is
         * always zero for no-wallet-policy flows (preprocess_inputs only sets bits for
         * wallet-policy inputs). */
        if (st->n_inputs == 2) {
            if (st->n_outputs != 2) {
                return _validate_payout(dc, st);
            }
            /* n_outputs==2: peek at Input 0 PREVIOUS_TXID to distinguish Payout from
             * PayoutFinalize.  vault_compute_pegin_txid uses G_scratch.script_scratch
             * transiently; _validate_payout repeats the computation internally. */
            {
                merkleized_map_commitment_t peek_map;
                uint8_t psbt_txid[VAULT_HASH256_LEN];
                if (call_get_merkleized_map(dc, st->inputs_root, 2, 0, &peek_map) >= 0 &&
                    VAULT_HASH256_LEN ==
                        call_get_merkleized_map_value(dc,
                                                      &peek_map,
                                                      (uint8_t[]) {PSBT_IN_PREVIOUS_TXID},
                                                      1,
                                                      psbt_txid,
                                                      VAULT_HASH256_LEN)) {
                    uint8_t computed[VAULT_HASH256_LEN];
                    for (uint8_t g = 0; g < G_vault_intent.vault_count; g++) {
                        if (vault_compute_pegin_txid(&G_vault_intent, g, computed) &&
                            memcmp(psbt_txid, computed, VAULT_HASH256_LEN) == 0)
                            return _validate_payout(dc, st);
                    }
                }
            }
            /* TXID mismatch: Input 0 is not a Vault UTXO → PayoutFinalize, fall through */
        }

        /* PegIn detection: check Input 0 witness UTXO against all HTLC scriptpubkeys.
         * vault_build_htlc_scriptpubkey uses G_scratch.script_scratch transiently;
         * results are captured in htlc_spk before any subsequent G_scratch use. */
        merkleized_map_commitment_t pegin_map;
        if (call_get_merkleized_map(dc, st->inputs_root, st->n_inputs, 0, &pegin_map) >= 0) {
            uint8_t wu[8 + 1 + VAULT_P2TR_SCRIPTPUBKEY_LEN];
            if (call_get_merkleized_map_value(dc,
                                              &pegin_map,
                                              (uint8_t[]) {PSBT_IN_WITNESS_UTXO},
                                              1,
                                              wu,
                                              sizeof(wu)) == (int) sizeof(wu) &&
                wu[8] == VAULT_P2TR_SCRIPTPUBKEY_LEN) {
                /* PegIn has exactly 3 outputs; Refund also spends an HTLC UTXO but
                 * has 1 output — the n_outputs guard prevents Refund from being
                 * misrouted here. */
                if (st->n_outputs == 3) {
                    for (uint8_t g = 0; g < G_vault_intent.vault_count; g++) {
                        uint8_t htlc_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
                        if (vault_build_htlc_scriptpubkey(&G_vault_intent,
                                                          g,
                                                          G_vault_context.htlc_hashlock[g],
                                                          htlc_spk) &&
                            memcmp(wu + 9, htlc_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN) == 0) {
                            return _validate_pegin(dc, st);
                        }
                    }
                }
            }
        }
        /* Not a PegIn: fall through to standalone leaf dispatch */
    }

    /* Pre-PegIn: wallet policy present, Input 0 is internal (BIP-86) */
    if (!st->has_no_wallet_policy) {
        if (bitvector_get(internal_inputs, 0))
            return _validate_prepegin(dc, st, internal_inputs, internal_outputs);
        /* Input 0 external → WC with optional wallet inputs */
        return _validate_display_wc(dc, st);
    }

    /* PayoutFinalize: 2 inputs, 2 outputs, Input 0 external (device signs Input 1).
     * VK/Depositor Payout (also 2+2) was already routed above via the internal_inputs[0]
     * check; only PayoutFinalize reaches here, so Input 0 being internal is a host error. */
    if (st->has_no_wallet_policy && st->n_inputs == 2 && st->n_outputs == 2) {
        if (bitvector_get(internal_inputs, 0)) {
            SEND_SW(dc, SW_INCORRECT_DATA);
            return false;
        }
        return _validate_display_payout_finalize(dc, st);
    }

    /* No wallet policy: read Input 0 leaf and dispatch by shape */
    merkleized_map_commitment_t dispatch_map;
    if (!vault_read_refund_leaf_script(dc, st, &dispatch_map)) return false;

    const uint8_t *leaf = G_scratch.tls.leaf_script;
    int leaf_len = G_scratch.tls.leaf_script_len;

    if (leaf_len < (int) VAULT_DEPOSITOR_CLAIM_LEAF_LEN || leaf[0] != OP_PUSHBYTES_32) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return false;
    }

    /* Claim: <D> OP_CHECKSIG */
    if (leaf_len == VAULT_DEPOSITOR_CLAIM_LEAF_LEN && leaf[33] == (uint8_t) OP_CHECKSIG)
        return _validate_display_claim(dc, st);

    if (leaf_len > (int) VAULT_DEPOSITOR_CLAIM_LEAF_LEN &&
        leaf[33] == (uint8_t) OP_CHECKSIGVERIFY) {
        /* WC: <D> OP_CHECKSIGVERIFY OP_SIZE ... */
        if (leaf[34] == (uint8_t) OP_SIZE) return _validate_display_wc(dc, st);
        /* Assert: exactly 68 bytes, <D> OP_CHECKSIGVERIFY <key>(32B) OP_CSV */
        if (leaf_len == VAULT_NOPAYOUT_LEAF_LEN && leaf[34] == OP_PUSHBYTES_32 &&
            (uint8_t) leaf[leaf_len - 1] == (uint8_t) OP_CSV)
            return _validate_display_assert(dc, st);
        /* Refund: <D> OP_CHECKSIGVERIFY <T> OP_CSV */
        if ((uint8_t) leaf[leaf_len - 1] == (uint8_t) OP_CSV)
            return _validate_display_refund(dc, st);
    }

    SEND_SW(dc, SW_INCORRECT_DATA);
    return false;
}
