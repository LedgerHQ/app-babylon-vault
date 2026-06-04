#include "derive_context_hash.h"
#include "derive_context_hash_core.h"

#include "../globals.h"
#include "../vault_context.h"
#include "../../bitcoin_app_base/src/boilerplate/sw.h"

#define P1_INITIAL  0x00
#define P1_CONTINUE 0x01

// ---------------------------------------------------------------------------
// APDU-layer helpers
// ---------------------------------------------------------------------------

static inline void abort_stream(void) {
    vault_context_invalidate(&G_vault_context);
    explicit_bzero(&G_hkdf_stream, sizeof(G_hkdf_stream));
}

static inline void send_hashlock(dispatcher_context_t *dc) {
    SEND_RESPONSE(dc, G_vault_context.htlc_hashlock, VAULT_HASH256_LEN, SW_OK);
}

// ---------------------------------------------------------------------------
// P1 branch handlers
// ---------------------------------------------------------------------------

static void handle_initial_chunk(dispatcher_context_t *dc, const command_t *cmd) {
    if (G_vault_context.state != VAULT_STATE_IDLE) {
        vault_context_invalidate(&G_vault_context);
    }
    explicit_bzero(&G_hkdf_stream, sizeof(G_hkdf_stream));

    // Parse: app_name_len(1B) | app_name(≤64B) | context_total_len(2B BE)
    if (cmd->lc < 3u) {
        abort_stream();
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }
    uint8_t app_name_len = cmd->data[0];
    if (app_name_len > 64u || cmd->lc < (uint8_t) (1u + app_name_len + 2u)) {
        abort_stream();
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }
    const uint8_t *app_name = &cmd->data[1];
    uint16_t context_total_len =
        ((uint16_t) cmd->data[1u + app_name_len] << 8) | (uint16_t) cmd->data[2u + app_name_len];

    if (!hkdf_stream_begin(&G_hkdf_stream, app_name, app_name_len, context_total_len)) {
        abort_stream();
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    if (context_total_len == 0u) {
        if (!hkdf_stream_finalize(&G_hkdf_stream,
                                  G_vault_context.htlc_preimage,
                                  G_vault_context.htlc_hashlock)) {
            abort_stream();
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
        explicit_bzero(&G_hkdf_stream, sizeof(G_hkdf_stream));
        if (!vault_context_transition(&G_vault_context, VAULT_STATE_IDLE, VAULT_STATE_HASH_DERIVED)) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
        send_hashlock(dc);
        return;
    }

    G_hkdf_stream.active = true;
    SEND_SW(dc, SW_OK);
}

static void handle_context_chunk(dispatcher_context_t *dc, const command_t *cmd) {
    if (!G_hkdf_stream.active) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    uint16_t remaining = G_hkdf_stream.context_total_len - G_hkdf_stream.context_received_len;
    if (cmd->lc > remaining) {
        abort_stream();
        SEND_SW(dc, SW_INCORRECT_DATA);
        return;
    }

    if (!hkdf_stream_feed(&G_hkdf_stream, cmd->data, cmd->lc)) {
        abort_stream();
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    G_hkdf_stream.context_received_len += cmd->lc;

    bool all_context_received =
        (G_hkdf_stream.context_received_len == G_hkdf_stream.context_total_len);
    if (all_context_received) {
        if (!hkdf_stream_finalize(&G_hkdf_stream,
                                  G_vault_context.htlc_preimage,
                                  G_vault_context.htlc_hashlock)) {
            abort_stream();
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
        explicit_bzero(&G_hkdf_stream, sizeof(G_hkdf_stream));
        if (!vault_context_transition(&G_vault_context, VAULT_STATE_IDLE, VAULT_STATE_HASH_DERIVED)) {
            SEND_SW(dc, SW_BAD_STATE);
            return;
        }
        send_hashlock(dc);
    } else {
        SEND_SW(dc, SW_OK);
    }
}

// ---------------------------------------------------------------------------
// Handler — dispatch only
// ---------------------------------------------------------------------------

void handler_derive_context_hash(dispatcher_context_t *dc, const command_t *cmd) {
    switch (cmd->p1) {
        case P1_INITIAL:
            handle_initial_chunk(dc, cmd);
            return;
        case P1_CONTINUE:
            handle_context_chunk(dc, cmd);
            return;
        default:
            SEND_SW(dc, SW_WRONG_P1P2);
            return;
    }
}
