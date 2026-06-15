#include "approve_vault_intent.h"
#include "approve_vault_intent_core.h"

#include "../display.h"
#include "../globals.h"
#include "../vault_context.h"
#include "../vault_tlv.h"

#include "../../bitcoin_app_base/src/boilerplate/sw.h"
#include "../../bitcoin_app_base/src/crypto.h"

#include <string.h>

#define P1_SCALARS   0x00
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
    /* If DERIVE_CONTEXT_HASH completed (Session 2), preserve preimage/hashlock across the reset. */
    uint8_t saved_preimage[VAULT_HASH256_LEN];
    uint8_t saved_hashlock[VAULT_HASH256_LEN];
    bool preserve_htlc = (G_vault_context.state == VAULT_STATE_HASH_DERIVED);
    if (preserve_htlc) {
        memcpy(saved_preimage, G_vault_context.htlc_preimage, VAULT_HASH256_LEN);
        memcpy(saved_hashlock, G_vault_context.htlc_hashlock, VAULT_HASH256_LEN);
    }

    vault_context_invalidate(&G_vault_context);
    explicit_bzero(&G_scratch.hkdf, sizeof(G_scratch.hkdf));

    if (preserve_htlc) {
        memcpy(G_vault_context.htlc_preimage, saved_preimage, VAULT_HASH256_LEN);
        memcpy(G_vault_context.htlc_hashlock, saved_hashlock, VAULT_HASH256_LEN);
        explicit_bzero(saved_preimage, sizeof(saved_preimage));
        explicit_bzero(saved_hashlock, sizeof(saved_hashlock));
    }

    vault_tlv_err_t err = vault_tlv_parse(cmd->data, cmd->lc, &G_vault_intent);
    if (err != VAULT_TLV_OK) {
        explicit_bzero(&G_vault_intent, sizeof(G_vault_intent));
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, tlv_err_to_sw(err));
        return;
    }

    /* Verify vault_provider_pk is a valid secp256k1 x-only point.
     * vault_tlv_parse stores it as raw bytes without an EC validity check;
     * reject invalid points here before they can reach taproot key derivation. */
    uint8_t tmp_point[65];
    if (crypto_tr_lift_x(G_vault_intent.vault_provider_pk, tmp_point) != 0) {
        explicit_bzero(&G_vault_intent, sizeof(G_vault_intent));
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    explicit_bzero(tmp_point, sizeof(tmp_point));

    G_scratch.approve.scalars_loaded = true;
    SEND_SW(dc, SW_OK);
}

/* -------------------------------------------------------------------------
 * P1=0x01 — key batch streaming
 * ---------------------------------------------------------------------- */

static void handle_key_batch(dispatcher_context_t *dc, const command_t *cmd) {
    if (!G_scratch.approve.scalars_loaded) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    if (cmd->lc == 0 || cmd->lc % VAULT_XONLY_PUBKEY_LEN != 0) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t n_keys = cmd->lc / VAULT_XONLY_PUBKEY_LEN;
    uint8_t total_expected = G_vault_intent.keeper_count + G_vault_intent.challenger_count;

    if ((uint16_t) G_scratch.approve.keys_received + n_keys > total_expected) {
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
                                                           G_scratch.approve.keys_received,
                                                           key);
        if (err != VAULT_KEY_OK) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        G_scratch.approve.keys_received++;
    }

    if (G_scratch.approve.keys_received < total_expected) {
        SEND_SW(dc, SW_OK);
        return;
    }

    /* All keys received — verify depositor key is disjoint from all roles. */
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

    /* Intent fully loaded — show approval screen before committing the transition. */
    explicit_bzero(&G_scratch.approve, sizeof(G_scratch.approve));
    if (!display_vault_intent(dc)) {
        vault_context_invalidate(&G_vault_context);
        return;
    }
    if (!vault_context_transition(&G_vault_context, VAULT_STATE_IDLE, VAULT_STATE_INTENT_LOADED)) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
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
        case P1_KEY_BATCH:
            handle_key_batch(dc, cmd);
            return;
        default:
            SEND_SW(dc, SW_WRONG_P1P2);
            return;
    }
}
