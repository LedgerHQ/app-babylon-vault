#pragma once

#include "../../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Handler for DERIVE_CONTEXT_HASH (INS 0x81) — multi-chunk streaming.
 *
 * P1=0x00 — initial chunk:
 *   app_name_len(1B) | app_name(≤64B) | path_len(1B) | path(path_len×4B BE)
 *   | context_total_len(2B BE) | first_context_chunk.
 *   Returns SW_OK with no data if more chunks follow; finalizes on last chunk.
 *
 * P1=0x01 — continuation chunk: raw context bytes appended until
 *   context_received_len == context_total_len. Returns SW_OK with no data
 *   (intermediate) or finalizes (last chunk). Must be preceded by P1=0x00.
 *
 * P2=0x00: show Screen 1 (app_name) and return the 32-byte root on the final chunk.
 * P2=0x01: silent re-derivation; return SW_OK with no data on the final chunk.
 *
 * Both modes store the derivation path in G_vault_context for NAPPS-1442.
 * Calling while state != IDLE invalidates the current session before proceeding.
 *
 * Core crypto logic lives in derive_context_hash_core.h (static inline, unit-testable).
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 */
void handler_derive_context_hash(dispatcher_context_t *dc, const command_t *cmd);
