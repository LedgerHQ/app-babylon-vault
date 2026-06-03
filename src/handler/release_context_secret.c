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

    // Copy the secret into the APDU staging buffer before zeroing it.
    // add_to_response makes a copy, so the transition below (which calls
    // vault_context_invalidate → explicit_bzero(htlc_preimage)) does not
    // corrupt the staged bytes.
    dc->add_to_response(G_vault_context.htlc_preimage, VAULT_HASH256_LEN);

    // Transition SESSION2_COMPLETE → IDLE.  Internally calls
    // vault_context_invalidate, which explicit_bzero's htlc_preimage.
    // Secret is zeroed in device RAM before the packet leaves the device.
    vault_context_transition(&G_vault_context, VAULT_STATE_SESSION2_COMPLETE, VAULT_STATE_IDLE);

    dc->finalize_response(SW_OK);
    dc->send_response();
}
