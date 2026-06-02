#pragma once

#include "../../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Handler for DERIVE_CONTEXT_HASH (INS 0x81).
 *
 * Chunked streaming APDU — no user display.
 *
 * P1=0x00  Initial chunk: app_name_len(1B) | app_name(≤64B) | context_total_len(2B BE).
 *          Derives the HTLC preimage via HKDF-SHA-256 at m/73681862'.  If
 *          context_total_len == 0 the derivation completes immediately and
 *          htlc_hashlock = SHA256(htlc_preimage) is returned in the response.
 *
 * P1=0x01  Continuation chunk: raw context bytes (up to 255 per APDU).
 *          On the final chunk the derivation completes and htlc_hashlock is returned.
 *
 * On success: htlc_preimage stored in G_vault_context, htlc_hashlock (32 B) returned.
 * Calling while state != IDLE invalidates the current session before proceeding.
 *
 * Core crypto logic lives in derive_context_hash_core.h (static inline, unit-testable).
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 */
void handler_derive_context_hash(dispatcher_context_t *dc, const command_t *cmd);
