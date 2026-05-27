#include "derive_context_hash.h"

#include "../../bitcoin_app_base/src/boilerplate/sw.h"

// Stub — full implementation in NAPPS-1367.
void handler_derive_context_hash(dispatcher_context_t *dc, const command_t *cmd) {
    UNUSED(cmd);
    SEND_SW(dc, SW_INS_NOT_SUPPORTED);
}
