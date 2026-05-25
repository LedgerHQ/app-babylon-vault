#pragma once

#include "../../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Stub handler for APPROVE_VAULT_INTENT (INS 0x80).
 *
 * Full implementation: NAPPS-1372.
 * Two-phase APDU:
 *   P1=0x00 — TLV scalar parsing (17 fields, tag 1B + len 1B).
 *   P1=0x01 — Key batch streaming (keeper_count + challenger_count x-only keys).
 * On completion shows approval screen; on confirmation transitions to INTENT_LOADED.
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 */
void handler_approve_vault_intent(dispatcher_context_t *dc, const command_t *cmd);
