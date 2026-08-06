#include "derive_context_hash.h"
#include "derive_context_hash_core.h"

#include "../display.h"
#include "../globals.h"
#include "../vault_context.h"
#include "../../bitcoin_app_base/src/boilerplate/sw.h"
#include "../../bitcoin_app_base/src/crypto.h"

#define P1_INITIAL  0x00
#define P1_CONTINUE 0x01

#define P2_RETURN_ROOT 0x00
#define P2_SILENT      0x01

/* SW for BIP-32 / connected-pubkey derivation failure (mirrors approve handler). */
#define SW_BIP32_FAIL ((uint16_t) 0x6F00)

/* -------------------------------------------------------------------------
 * Shared finalization helper — called once all context bytes are received
 * ---------------------------------------------------------------------- */

static void _finalize(dispatcher_context_t *dc) {
    G_scratch.derive_ctx.streaming_in_progress = false;

    /* Derive the 33-byte compressed connected public key at the host-supplied path.
     * path[] and connected_pubkey[] live in G_scratch (not on the stack) so that
     * the combined stack depth during the blocking display call stays within budget. */
    uint8_t *const connected_pubkey = G_scratch.derive_ctx.connected_pubkey;
    if (crypto_get_compressed_pubkey_at_path(G_scratch.derive_ctx.path,
                                             G_scratch.derive_ctx.path_len,
                                             connected_pubkey,
                                             NULL) != CX_OK) {
        explicit_bzero(connected_pubkey, VAULT_COMPRESSED_PUBKEY_LEN);
        explicit_bzero(G_scratch.derive_ctx.context_buf, sizeof(G_scratch.derive_ctx.context_buf));
        SEND_SW(dc, SW_BIP32_FAIL);
        return;
    }

    if (G_scratch.derive_ctx.p2_mode == P2_RETURN_ROOT) {
        /* P2=0x00: show Screen 1 and wait for user approval. */
        if (!display_derive_context_hash(dc,
                                         G_scratch.derive_ctx.app_name_buf,
                                         G_scratch.derive_ctx.app_name_len)) {
            explicit_bzero(connected_pubkey, VAULT_COMPRESSED_PUBKEY_LEN);
            explicit_bzero(G_scratch.derive_ctx.context_buf,
                           sizeof(G_scratch.derive_ctx.context_buf));
            return; /* SW_DENY already sent */
        }
    }

    bool ok = hkdf_derive_root(G_scratch.derive_ctx.app_name_buf,
                               G_scratch.derive_ctx.app_name_len,
                               connected_pubkey,
                               G_scratch.derive_ctx.context_buf,
                               G_scratch.derive_ctx.context_total_len,
                               G_vault_context.root);
    explicit_bzero(connected_pubkey, VAULT_COMPRESSED_PUBKEY_LEN);
    explicit_bzero(G_scratch.derive_ctx.context_buf, sizeof(G_scratch.derive_ctx.context_buf));
    if (!ok) {
        vault_context_invalidate(&G_vault_context);
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    if (!vault_context_transition(&G_vault_context, VAULT_STATE_IDLE, VAULT_STATE_HASH_DERIVED)) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    /* F2: persist the BIP-32 path so APPROVE_VAULT_INTENT can verify it matches
     * the depositor derivation path in the intent. */
    memcpy(G_vault_context.derivation_path,
           G_scratch.derive_ctx.path,
           G_scratch.derive_ctx.path_len * sizeof(uint32_t));
    G_vault_context.derivation_path_len = G_scratch.derive_ctx.path_len;

    /* Persist appName so display_vault_intent can show it during APPROVE_VAULT_INTENT,
     * binding the user confirmation to this specific HKDF domain — even for P2=0x01. */
    memcpy(G_vault_context.app_name,
           G_scratch.derive_ctx.app_name_buf,
           G_scratch.derive_ctx.app_name_len);
    G_vault_context.app_name_len = G_scratch.derive_ctx.app_name_len;

    if (G_scratch.derive_ctx.p2_mode == P2_RETURN_ROOT) {
        /* Return the 32-byte root (the host expands it into per-vault secrets). */
        SEND_RESPONSE(dc, G_vault_context.root, VAULT_HASH256_LEN, SW_OK);
    } else {
        /* P2=0x01: silent — SW_OK only, no root in response.
         * The app_name is persisted in G_vault_context.app_name so that
         * display_vault_intent() can present it during APPROVE_VAULT_INTENT,
         * binding the user's approval to this HKDF domain even when Screen 1
         * was skipped. */
        SEND_SW(dc, SW_OK);
    }
}

/* -------------------------------------------------------------------------
 * P1=0x00 — initial chunk
 * ---------------------------------------------------------------------- */

static void handle_initial_chunk(dispatcher_context_t *dc, const command_t *cmd) {
    if (cmd->p2 != P2_RETURN_ROOT && cmd->p2 != P2_SILENT) {
        SEND_SW(dc, SW_WRONG_P1P2);
        return;
    }

    /* Re-deriving cancels any in-flight session or prior streaming. */
    if (G_vault_context.state != VAULT_STATE_IDLE) {
        vault_context_invalidate(&G_vault_context);
    }
    explicit_bzero(&G_scratch, sizeof(G_scratch));
    explicit_bzero(&G_approve_intent_state, sizeof(G_approve_intent_state));

    const uint8_t *data = cmd->data;
    const size_t lc = cmd->lc;
    size_t off = 0;

    /* app_name_len | app_name */
    if (lc < 1u) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    uint8_t app_name_len = data[off++];
    if (app_name_len == 0u || app_name_len > VAULT_APP_NAME_MAX_LEN || off + app_name_len > lc) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    const uint8_t *app_name = data + off;
    off += app_name_len;

    if (!app_name_charset_valid(app_name, app_name_len)) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    /* path_len | path (u32 big-endian per level) */
    if (off + 1u > lc) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    uint8_t path_len = data[off++];
    if (path_len == 0u || path_len > VAULT_MAX_PATH_DEPTH || off + (size_t) path_len * 4u > lc) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    uint32_t *const path = G_scratch.derive_ctx.path;
    for (uint8_t i = 0; i < path_len; i++) {
        path[i] = ((uint32_t) data[off] << 24) | ((uint32_t) data[off + 1] << 16) |
                  ((uint32_t) data[off + 2] << 8) | (uint32_t) data[off + 3];
        off += 4u;
    }

    /* context_total_len (2-byte big-endian) */
    if (off + 2u > lc) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    uint16_t context_total_len = ((uint16_t) data[off] << 8) | (uint16_t) data[off + 1];
    off += 2u;

    if (context_total_len == 0u || context_total_len > VAULT_CONTEXT_MAX_LEN) {
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    /* First context chunk (rest of the APDU). */
    const uint8_t *first_chunk = data + off;
    size_t first_chunk_len = lc - off;

    if (first_chunk_len > context_total_len) {
        /* Host sent more bytes than the declared total — reject. */
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    /* Store all parsed fields in scratch. */
    memcpy(G_scratch.derive_ctx.app_name_buf, app_name, app_name_len);
    G_scratch.derive_ctx.app_name_len = app_name_len;
    G_scratch.derive_ctx.path_len = path_len;
    G_scratch.derive_ctx.p2_mode = cmd->p2;
    G_scratch.derive_ctx.context_total_len = context_total_len;
    G_scratch.derive_ctx.context_received_len = (uint16_t) first_chunk_len;

    if (first_chunk_len > 0u) {
        memcpy(G_scratch.derive_ctx.context_buf, first_chunk, first_chunk_len);
    }

    if (G_scratch.derive_ctx.context_received_len < context_total_len) {
        /* More chunks expected — enter streaming mode. */
        G_scratch.derive_ctx.streaming_in_progress = true;
        SEND_SW(dc, SW_OK);
        return;
    }

    /* All context in the initial APDU — finalize immediately. */
    _finalize(dc);
}

/* -------------------------------------------------------------------------
 * P1=0x01 — continuation chunk
 * ---------------------------------------------------------------------- */

static void handle_continuation_chunk(dispatcher_context_t *dc, const command_t *cmd) {
    if (!G_scratch.derive_ctx.streaming_in_progress) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    /* P2 must match the value recorded from the initial chunk. */
    if (cmd->p2 != G_scratch.derive_ctx.p2_mode) {
        SEND_SW(dc, SW_WRONG_P1P2);
        return;
    }

    const uint8_t *data = cmd->data;
    const size_t lc = cmd->lc;

    if (lc == 0u) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    uint16_t remaining =
        G_scratch.derive_ctx.context_total_len - G_scratch.derive_ctx.context_received_len;

    if (lc > remaining) {
        /* Host sent more context bytes than declared — zero and reject. */
        explicit_bzero(G_scratch.derive_ctx.context_buf, sizeof(G_scratch.derive_ctx.context_buf));
        vault_context_invalidate(&G_vault_context);
        G_scratch.derive_ctx.streaming_in_progress = false;
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    memcpy(G_scratch.derive_ctx.context_buf + G_scratch.derive_ctx.context_received_len, data, lc);
    G_scratch.derive_ctx.context_received_len += (uint16_t) lc;

    if (G_scratch.derive_ctx.context_received_len < G_scratch.derive_ctx.context_total_len) {
        /* More chunks expected. */
        SEND_SW(dc, SW_OK);
        return;
    }

    /* All context received — finalize. */
    _finalize(dc);
}

/* -------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------- */

void handler_derive_context_hash(dispatcher_context_t *dc, const command_t *cmd) {
    switch (cmd->p1) {
        case P1_INITIAL:
            handle_initial_chunk(dc, cmd);
            return;
        case P1_CONTINUE:
            handle_continuation_chunk(dc, cmd);
            return;
        default:
            SEND_SW(dc, SW_WRONG_P1P2);
            return;
    }
}
