#include "release_context_secret.h"

#include "../globals.h"
#include "../vault_context.h"
#include "../../bitcoin_app_base/src/boilerplate/sw.h"

void handler_release_context_secret(dispatcher_context_t *dc, const command_t *cmd) {
    if (cmd->p1 != 0x00 || cmd->p2 != 0x00) {
        SEND_SW(dc, SW_WRONG_P1P2);
        return;
    }
    if (cmd->lc != 0) {
        SEND_SW(dc, SW_WRONG_DATA_LENGTH);
        return;
    }

    if (G_vault_context.state != VAULT_STATE_SESSION2_COMPLETE) {
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    // copy before transition; success path leaves htlc_preimage intact (we zero it below)
    uint8_t preimage_copy[VAULT_HASH256_LEN];
    memcpy(preimage_copy, G_vault_context.htlc_preimage, sizeof(preimage_copy));

    if (!vault_context_transition(&G_vault_context,
                                  VAULT_STATE_SESSION2_COMPLETE,
                                  VAULT_STATE_IDLE)) {
        explicit_bzero(preimage_copy, sizeof(preimage_copy));
        SEND_SW(dc, SW_BAD_STATE);
        return;
    }

    explicit_bzero(G_vault_context.htlc_preimage, VAULT_HASH256_LEN);

    dc->add_to_response(preimage_copy, VAULT_HASH256_LEN);
    explicit_bzero(preimage_copy, sizeof(preimage_copy));
    dc->finalize_response(SW_OK);
    dc->send_response();
}
