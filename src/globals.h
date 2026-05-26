#pragma once

#include "vault_intent.h"
#include "vault_context.h"

/** Loaded vault intent. Valid only when G_vault_context.state != VAULT_STATE_IDLE. */
extern vault_intent_t  G_vault_intent;

/** Active session context. Always valid; state == VAULT_STATE_IDLE when no session is running. */
extern vault_context_t G_vault_context;
