#pragma once

#include "../../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Handler for RELEASE_CONTEXT_SECRET (INS 0x82).
 *
 * Returns the 32-byte session secret s only when state == SESSION2_COMPLETE.
 * After returning: explicit_bzero(s), reset state to IDLE.
 * Rejected in all other states with SW_BAD_STATE.
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 */
void handler_release_context_secret(dispatcher_context_t *dc, const command_t *cmd);
