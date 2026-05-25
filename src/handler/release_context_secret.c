#include "release_context_secret.h"

#include "../../bitcoin_app_base/src/boilerplate/sw.h"

// Stub — full implementation in NAPPS-1373.
void handler_release_context_secret(dispatcher_context_t *dc, const command_t *cmd) {
    UNUSED(cmd);
    SEND_SW(dc, SW_INS_NOT_SUPPORTED);
}
