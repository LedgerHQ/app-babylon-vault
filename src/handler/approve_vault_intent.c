#include "approve_vault_intent.h"
#include "approve_vault_intent_core.h"
#include "derive_vault_secrets_core.h"

#include "../display.h"
#include "../globals.h"
#include "../vault_context.h"
#include "../vault_tlv.h"

#include "../../bitcoin_app_base/src/boilerplate/sw.h"
#include "../../bitcoin_app_base/src/crypto.h"

#include <string.h>

#define P1_SCALARS   0x00
#define P1_GROUP     0x02
#define P1_KEY_BATCH 0x01

/* Spec-defined SW for BIP-32 depositor key derivation failure (see docs/apdu.md). */
#define SW_BIP32_FAIL ((uint16_t) 0x6F00)

static uint16_t tlv_err_to_sw(vault_tlv_err_t err) {
    switch (err) {
        case VAULT_TLV_OK:
            return SW_OK;
        case VAULT_TLV_ERR_OVERFLOW:
        case VAULT_TLV_ERR_WRONG_LENGTH:
        case VAULT_TLV_ERR_UNKNOWN_TAG:
        case VAULT_TLV_ERR_DUPLICATE_TAG:
        case VAULT_TLV_ERR_MISSING_FIELD:
        case VAULT_TLV_ERR_VALIDATION:
            return SW_INCORRECT_DATA;
    }
    return SW_INCORRECT_DATA;
}

/* -------------------------------------------------------------------------
 * P1=0x00 — scalar TLV payload
 * ---------------------------------------------------------------------- */

static void handle_scalar_payload(dispatcher_context_t *dc, const command_t *cmd) {
    /* If DERIVE_CONTEXT_HASH completed, preserve the root and derivation path across
     * the reset. The per-vault commitments (htlc_hashlock, auth_anchor_hash) are
     * recomputed from the root once htlc_vout is known (see handle_key_batch).
     * derivation_path must survive so the F2 check in handle_key_batch can compare
     * it against the intent's depositor path. */
    uint8_t saved_root[VAULT_HASH256_LEN];
    uint32_t saved_path[VAULT_MAX_PATH_DEPTH];
    uint8_t saved_path_len = 0;
    bool preserve_root = (G_vault_context.state == VAULT_STATE_HASH_DERIVED);
    if (preserve_root) {
        memcpy(saved_root, G_vault_context.root, VAULT_HASH256_LEN);
        saved_path_len = G_vault_context.derivation_path_len;
        memcpy(saved_path, G_vault_context.derivation_path, saved_path_len * sizeof(uint32_t));
    }

    vault_context_invalidate(&G_vault_context);
    explicit_bzero(&G_scratch, sizeof(G_scratch));

    if (preserve_root) {
        memcpy(G_vault_context.root, saved_root, VAULT_HASH256_LEN);
        explicit_bzero(saved_root, sizeof(saved_root));
        G_vault_context.derivation_path_len = saved_path_len;
        memcpy(G_vault_context.derivation_path, saved_path, saved_path_len * sizeof(uint32_t));
        explicit_bzero(saved_path, sizeof(saved_path));
        // Restore state to HASH_DERIVED so handle_key_batch can transition
        // HASH_DERIVED → INTENT_LOADED; without this the transition would fail
        // because vault_context_invalidate() left state at IDLE.
        if (!vault_context_transition(&G_vault_context,
                                      VAULT_STATE_IDLE,
                                      VAULT_STATE_HASH_DERIVED)) {
            explicit_bzero(G_vault_context.root, sizeof(G_vault_context.root));
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
    }

    vault_tlv_err_t err = vault_tlv_parse(cmd->data, cmd->lc, &G_vault_intent);
    if (err != VAULT_TLV_OK) {
        explicit_bzero(&G_vault_intent, sizeof(G_vault_intent));
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, tlv_err_to_sw(err));
        return;
    }

    /* vault_provider_pk validation (secp256k1 lift_x) moves to the P1=0x02 group
     * handler (NAPPS-1442) since the key is now per-vault, not a P1=0x00 scalar. */

    G_approve_intent_state.scalars_loaded = true;
    SEND_SW(dc, SW_OK);
}

/* -------------------------------------------------------------------------
 * P1=0x02 — per-vault group TLV (one APDU per vault)
 * ---------------------------------------------------------------------- */

static void handle_group_payload(dispatcher_context_t *dc, const command_t *cmd) {
    if (!G_approve_intent_state.scalars_loaded) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }
    uint8_t idx = G_vault_context.vault_group_index;
    if (idx >= G_vault_intent.vault_count) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    vault_tlv_err_t err =
        vault_tlv_parse_group(cmd->data, (size_t) cmd->lc, &G_vault_intent.groups[idx]);
    if (err != VAULT_TLV_OK) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, tlv_err_to_sw(err));
        return;
    }
    /* Enforce strictly-ascending htlc_vout order across groups. */
    if (idx > 0 &&
        G_vault_intent.groups[idx].htlc_vout <= G_vault_intent.groups[idx - 1].htlc_vout) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    /* Propagate the global pegin_anchor_value (parked in groups[0] by the P1=0x00
     * parser) to each subsequent group.  Full multi-vault loop in NAPPS-1442. */
    if (idx > 0) {
        G_vault_intent.groups[idx].pegin_anchor_value = G_vault_intent.groups[0].pegin_anchor_value;
    }
    G_vault_context.vault_group_index++;
    SEND_SW(dc, SW_OK);
}

/* -------------------------------------------------------------------------
 * P1=0x01 — key batch streaming
 * ---------------------------------------------------------------------- */

static void handle_key_batch(dispatcher_context_t *dc, const command_t *cmd) {
    if (!G_approve_intent_state.scalars_loaded) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    /* F1: all P1=0x02 group APDUs must have arrived before key batching starts. */
    if (G_vault_context.vault_group_index != G_vault_intent.vault_count) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    if (cmd->lc == 0 || cmd->lc % VAULT_XONLY_PUBKEY_LEN != 0) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    /* Enforce DERIVE_CONTEXT_HASH ordering on every batch, not just the last.
     * Without this check, a host in the wrong state would receive SW_OK for all
     * intermediate batches, getting implicit per-batch confirmation before the
     * final batch rejects.  Placing the check here short-circuits that. */
    if (G_vault_context.state != VAULT_STATE_HASH_DERIVED) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    uint8_t n_keys = cmd->lc / VAULT_XONLY_PUBKEY_LEN;
    uint8_t total_expected = G_vault_intent.keeper_count + G_vault_intent.challenger_count;

    if ((uint16_t) G_approve_intent_state.keys_received + n_keys > total_expected) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    for (uint8_t i = 0; i < n_keys; i++) {
        const uint8_t *key = cmd->data + i * VAULT_XONLY_PUBKEY_LEN;

        /* Reject keys that are not valid secp256k1 x-only points. */
        uint8_t tmp_point[65];
        int lift_rc = crypto_tr_lift_x(key, tmp_point);
        explicit_bzero(tmp_point, sizeof(tmp_point));
        if (lift_rc != 0) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        vault_key_err_t err = vault_validate_and_store_key(&G_vault_intent,
                                                           G_approve_intent_state.keys_received,
                                                           key);
        if (err != VAULT_KEY_OK) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        G_approve_intent_state.keys_received++;
    }

    if (G_approve_intent_state.keys_received < total_expected) {
        SEND_SW(dc, SW_OK);
        return;
    }

    /* All keys received — verify depositor key is disjoint from all roles. */

    /* F2: reject if the path supplied to DERIVE_CONTEXT_HASH does not match the
     * depositor path in the intent.  Prevents a host from pairing a root derived
     * at one path with an intent that claims a different depositor path. */
    if (G_vault_context.derivation_path_len != VAULT_DEPOSITOR_PATH_LEN ||
        memcmp(G_vault_context.derivation_path,
               G_vault_intent.depositor_path,
               VAULT_DEPOSITOR_PATH_LEN * sizeof(uint32_t)) != 0) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    uint8_t depositor_compressed[33];
    if (crypto_get_compressed_pubkey_at_path(G_vault_intent.depositor_path,
                                             VAULT_DEPOSITOR_PATH_LEN,
                                             depositor_compressed,
                                             NULL) != CX_OK) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BIP32_FAIL);
        return;
    }

    if (!vault_check_depositor_uniqueness(&G_vault_intent, depositor_compressed + 1)) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    /* Store the x-only depositor key so vault_build_* script builders can embed it. */
    memcpy(G_vault_intent.depositor_pk, depositor_compressed + 1, VAULT_XONLY_PUBKEY_LEN);

    /* Compute the on-chain commitments from the HKDF root now that htlc_vout is known.
     * DERIVE_CONTEXT_HASH is required before this point (enforced by the state machine).
     * F3: treat an all-zero root as a protocol violation — do not silently skip. */
    const uint8_t zeros32[VAULT_HASH256_LEN] = {0};
    if (memcmp(G_vault_context.root, zeros32, VAULT_HASH256_LEN) == 0) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }
    if (!vault_derive_hashlock_commitment(G_vault_context.root,
                                          G_vault_intent.groups[0].htlc_vout,
                                          G_vault_context.htlc_hashlock[0]) ||
        !vault_derive_auth_anchor_commitment(G_vault_context.root,
                                             G_vault_context.auth_anchor_hash)) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }
    // Root is no longer needed — both commitments are stored in G_vault_context.
    // Zero it now rather than waiting for session end to minimise exposure window.
    explicit_bzero(G_vault_context.root, sizeof(G_vault_context.root));

    /* Intent fully loaded — show approval screen before committing the transition. */
    explicit_bzero(&G_approve_intent_state, sizeof(G_approve_intent_state));
    if (!display_vault_intent(dc)) {
        vault_context_invalidate(&G_vault_context);
        return;
    }
    if (!vault_context_transition(&G_vault_context,
                                  VAULT_STATE_HASH_DERIVED,
                                  VAULT_STATE_INTENT_LOADED)) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }
    /* Session 2: advance immediately to SESSION2_PEGIN_EXPECTED when the device
     * already holds a derived hashlock (set by DERIVE_CONTEXT_HASH before this call)
     * AND the intent carries a non-zero prepegin_txid.  Without this transition the
     * sign_psbt dispatch can never reach _validate_pegin. */
    const uint8_t zeros[VAULT_HASH256_LEN] = {0};
    if (memcmp(G_vault_context.htlc_hashlock[0], zeros, VAULT_HASH256_LEN) != 0 &&
        memcmp(G_vault_intent.prepegin_txid, zeros, VAULT_HASH256_LEN) != 0) {
        if (!vault_context_transition(&G_vault_context,
                                      VAULT_STATE_INTENT_LOADED,
                                      VAULT_STATE_SESSION2_PEGIN_EXPECTED)) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
    }
    SEND_SW(dc, SW_OK);
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

void handler_approve_vault_intent(dispatcher_context_t *dc, const command_t *cmd) {
    switch (cmd->p1) {
        case P1_SCALARS:
            handle_scalar_payload(dc, cmd);
            return;
        case P1_GROUP:
            handle_group_payload(dc, cmd);
            return;
        case P1_KEY_BATCH:
            handle_key_batch(dc, cmd);
            return;
        default:
            SEND_SW(dc, SW_WRONG_P1P2);
            return;
    }
}
