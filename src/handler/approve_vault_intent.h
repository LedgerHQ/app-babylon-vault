#pragma once

#include "../../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Handler for APPROVE_VAULT_INTENT (INS 0x80).
 *
 * Three-phase APDU (2-byte tags, 1-byte lengths):
 *   P1=0x00 — TLV scalar payload (13 mandatory fields).
 *   P1=0x01 — Per-vault group TLV (vault_count groups, multiple groups per APDU allowed).
 *   P1=0x02 — Key batch (keeper_count + challenger_count x-only keys).
 * On completion shows approval screen; on confirmation transitions to INTENT_LOADED.
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 */
void handler_approve_vault_intent(dispatcher_context_t *dc, const command_t *cmd);
