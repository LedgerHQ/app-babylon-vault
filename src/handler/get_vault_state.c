#include "get_vault_state.h"

#include "../globals.h"
#include "../vault_context.h"
#include "../../bitcoin_app_base/src/boilerplate/sw.h"

void handler_get_vault_state(dispatcher_context_t *dc, const command_t *cmd) {
    if (cmd->p1 != 0x00 || cmd->p2 != 0x00) {
        SEND_SW(dc, SW_WRONG_P1P2);
        return;
    }
    if (cmd->lc != 0u) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    uint8_t response[VAULT_STATE_RESPONSE_MAX_LEN];
    size_t len = vault_context_encode_state(&G_vault_context, response);
    if (len == 0u) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }
    SEND_RESPONSE(dc, response, len, SW_OK);
}
