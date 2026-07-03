#pragma once

#include "../../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Handler for DERIVE_CONTEXT_HASH (INS 0x81).
 *
 * Single APDU — no user display.
 *
 * P1=0x00  CData: app_name_len(1B) | app_name(≤VAULT_APP_NAME_MAX_LEN B) | path_len(1B)
 *          | path(path_len×4B u32 BE) | context(remaining bytes, 1–VAULT_CONTEXT_MAX_LEN B).
 *          Derives the 33-byte compressed connected pubkey at `path`, then
 *          root = HKDF-SHA-256(privkey@m/73681862', "derive-context-hash",
 *                 SHA256(app_name)||SHA256(canonicalNetworkName)||pubkey||context, 32).
 *
 * On success: root stored in G_vault_context, advances to HASH_DERIVED, and the
 * 32-byte root (NOT a hashlock) is returned. The host expands the root into the
 * per-vault secrets; the device retains no preimage and has no release step.
 * Calling while state != IDLE invalidates the current session before proceeding.
 *
 * Core crypto logic lives in derive_context_hash_core.h (static inline, unit-testable).
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 */
void handler_derive_context_hash(dispatcher_context_t *dc, const command_t *cmd);
