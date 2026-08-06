#include "approve_vault_intent.h"
#include "approve_vault_intent_core.h"
#include "derive_vault_secrets_core.h"

#include "../display.h"
#include "../globals.h"
#include "../vault_context.h"
#include "../vault_intent_tags.h"
#include "../vault_tlv.h"

#include "../../bitcoin_app_base/src/boilerplate/sw.h"
#include "../../bitcoin_app_base/src/crypto.h"

#include <string.h>

#define P1_SCALARS   0x00
#define P1_GROUP     0x01
#define P1_KEY_BATCH 0x02

/* Spec-defined SW for BIP-32 depositor key derivation failure (see docs/apdu.md). */
#define SW_BIP32_FAIL ((uint16_t) 0x6F00)

/* No default: -Wswitch-enum/-Werror will catch any new vault_tlv_err_t value that
 * is not explicitly handled here.  The post-switch return satisfies -Wreturn-type. */
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
    return SW_INCORRECT_DATA; /* unreachable */
}

/* -------------------------------------------------------------------------
 * P1=0x00 — scalar TLV payload
 * ---------------------------------------------------------------------- */

static void handle_scalar_payload(dispatcher_context_t *dc, const command_t *cmd) {
    if (G_vault_context.state != VAULT_STATE_HASH_DERIVED) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    /* Preserve the root and derivation path across the context reset.
     * The per-vault commitments (htlc_hashlock, auth_anchor_hash) are recomputed
     * from the root once htlc_vout is known (see handle_key_batch).
     * derivation_path must survive so the F2 check in handle_key_batch can compare
     * it against the intent's depositor path. */
    uint8_t saved_root[VAULT_HASH256_LEN];
    uint32_t saved_path[VAULT_MAX_PATH_DEPTH];
    uint8_t saved_app_name[VAULT_APP_NAME_MAX_LEN];
    uint8_t saved_path_len = G_vault_context.derivation_path_len;
    uint8_t saved_app_name_len = G_vault_context.app_name_len;
    memcpy(saved_root, G_vault_context.root, VAULT_HASH256_LEN);
    memcpy(saved_path, G_vault_context.derivation_path, saved_path_len * sizeof(uint32_t));
    memcpy(saved_app_name, G_vault_context.app_name, saved_app_name_len);

    vault_context_invalidate(&G_vault_context);
    explicit_bzero(&G_scratch, sizeof(G_scratch));

    memcpy(G_vault_context.root, saved_root, VAULT_HASH256_LEN);
    explicit_bzero(saved_root, sizeof(saved_root));
    G_vault_context.derivation_path_len = saved_path_len;
    memcpy(G_vault_context.derivation_path, saved_path, saved_path_len * sizeof(uint32_t));
    explicit_bzero(saved_path, sizeof(saved_path));
    G_vault_context.app_name_len = saved_app_name_len;
    memcpy(G_vault_context.app_name, saved_app_name, saved_app_name_len);
    /* Restore state to HASH_DERIVED so handle_key_batch can transition
     * HASH_DERIVED → INTENT_LOADED; without this the transition would fail
     * because vault_context_invalidate() left state at IDLE. */
    if (!vault_context_transition(&G_vault_context, VAULT_STATE_IDLE, VAULT_STATE_HASH_DERIVED)) {
        explicit_bzero(G_vault_context.root, sizeof(G_vault_context.root));
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    vault_tlv_err_t err = vault_tlv_parse(cmd->data, cmd->lc, &G_vault_intent);
    if (err != VAULT_TLV_OK) {
        explicit_bzero(&G_vault_intent, sizeof(G_vault_intent));
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, tlv_err_to_sw(err));
        return;
    }

    G_approve_intent_state.scalars_loaded = true;
    SEND_SW(dc, SW_OK);
}

/* -------------------------------------------------------------------------
 * P1=0x01 — per-vault group TLV
 * One APDU may carry multiple back-to-back group records (as many as fit in
 * 255 bytes, ~3 per APDU at ~83 bytes each).  Process all of them.
 * ---------------------------------------------------------------------- */

static void handle_group_payload(dispatcher_context_t *dc, const command_t *cmd) {
    if (!G_approve_intent_state.scalars_loaded) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    size_t pos = 0;
    while (pos < (size_t) cmd->lc) {
        uint8_t idx = G_vault_context.vault_group_index;
        if (idx >= G_vault_intent.vault_count) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        size_t consumed = 0;
        vault_tlv_err_t err = vault_tlv_parse_group(cmd->data + pos,
                                                    (size_t) cmd->lc - pos,
                                                    &G_vault_intent.groups[idx],
                                                    &consumed);
        if (err != VAULT_TLV_OK) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, tlv_err_to_sw(err));
            return;
        }

        /* Reject vault_provider_pk that is not a valid secp256k1 x-only point. */
        uint8_t tmp_point[65];
        int lift_rc = crypto_tr_lift_x(G_vault_intent.groups[idx].vault_provider_pk, tmp_point);
        explicit_bzero(tmp_point, sizeof(tmp_point));
        if (lift_rc != 0) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        /* Enforce strictly-ascending htlc_vout order across groups. */
        if (idx > 0 &&
            G_vault_intent.groups[idx].htlc_vout <= G_vault_intent.groups[idx - 1].htlc_vout) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        G_vault_context.vault_group_index++;
        pos += consumed;
    }

    SEND_SW(dc, SW_OK);
}

/* -------------------------------------------------------------------------
 * P1=0x02 — key batch TLV streaming
 * Each entry: tag[2] len=0x20[1] key[32].  TAG_KEEPER_PK entries precede
 * TAG_CHALLENGER_PK entries (tag-enforced ordering).
 * ---------------------------------------------------------------------- */

static void handle_key_batch(dispatcher_context_t *dc, const command_t *cmd) {
    if (!G_approve_intent_state.scalars_loaded) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    /* F1: all P1=0x01 group APDUs must have arrived before key batching starts. */
    if (G_vault_context.vault_group_index != G_vault_intent.vault_count) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BAD_STATE);
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

    uint8_t total_expected = G_vault_intent.keeper_count + G_vault_intent.challenger_count;

    /* Parse TLV key entries from this APDU. Each entry: 2B tag | 1B len | 32B key. */
    size_t pos = 0;
    while (pos < (size_t) cmd->lc) {
        /* Need at least 3 bytes for tag (2B) + length (1B). */
        if (pos + 3 > (size_t) cmd->lc) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint16_t tag = (uint16_t) (((uint16_t) cmd->data[pos] << 8) | cmd->data[pos + 1]);
        pos += 2;
        uint8_t klen = cmd->data[pos++];

        if (klen != VAULT_XONLY_PUBKEY_LEN || pos + klen > (size_t) cmd->lc) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        uint8_t keys_rx = G_approve_intent_state.keys_received;
        if (keys_rx >= total_expected) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        /* Tag must match current phase: keepers first, then challengers. */
        bool expect_keeper = (keys_rx < G_vault_intent.keeper_count);
        if (expect_keeper && tag != TAG_KEEPER_PK) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }
        if (!expect_keeper && tag != TAG_CHALLENGER_PK) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_INCORRECT_DATA);
            return;
        }

        const uint8_t *key = cmd->data + pos;

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
        pos += klen;
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

    uint8_t depositor_compressed[VAULT_COMPRESSED_PUBKEY_LEN];
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
    for (uint8_t gi = 0; gi < G_vault_intent.vault_count; gi++) {
        if (!vault_derive_hashlock_commitment(G_vault_context.root,
                                              G_vault_intent.groups[gi].htlc_vout,
                                              G_vault_context.htlc_hashlock[gi])) {
            vault_context_invalidate(&G_vault_context);
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
    }
    if (!vault_derive_auth_anchor_commitment(G_vault_context.root,
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
    SEND_SW(dc, SW_OK);
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

void handler_approve_vault_intent(dispatcher_context_t *dc, const command_t *cmd) {
    if (cmd->p2 != 0x00) {
        SEND_SW(dc, SW_WRONG_P1P2);
        return;
    }
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
