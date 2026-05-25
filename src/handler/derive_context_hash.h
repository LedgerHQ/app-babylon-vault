#pragma once

#include "../../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Stub handler for DERIVE_CONTEXT_HASH (INS 0x81).
 *
 * Full implementation: NAPPS-1367.
 * Derives session secret s via HKDF-SHA-256 at m/73681862', stores s in
 * vault_context_t, and returns h = SHA256(s).  No user display.
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command (P1 selects chunk phase: 0x00 initial, 0x01 continuation).
 */
void handler_derive_context_hash(dispatcher_context_t *dc, const command_t *cmd);
