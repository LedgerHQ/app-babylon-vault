#pragma once

#include <stdbool.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"

// Babylon Vault custom APDU INS codes (>= 0x80 to avoid conflicts with base app)
#define INS_APPROVE_VAULT_INTENT   0x80
#define INS_DERIVE_CONTEXT_HASH    0x81
#define INS_RELEASE_CONTEXT_SECRET 0x82

/**
 * @brief Dispatches Babylon Vault custom APDUs.
 *
 * Called by the base app dispatcher for every APDU before the base app
 * processes it.  Returns true if the INS was claimed and a response was sent;
 * returns false to fall through to the base app.
 *
 * @param dc   Dispatcher context.
 * @param cmd  Parsed APDU command.
 * @return true if handled, false otherwise.
 */
bool custom_apdu_handler(dispatcher_context_t *dc, const command_t *cmd);
