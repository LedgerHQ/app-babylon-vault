#include "approve_vault_intent.h"

#include "../../bitcoin_app_base/src/boilerplate/sw.h"

// Stub — full implementation in NAPPS-1372.
void handler_approve_vault_intent(dispatcher_context_t *dc, const command_t *cmd) {
    UNUSED(cmd);
    SEND_SW(dc, SW_INS_NOT_SUPPORTED);
}
