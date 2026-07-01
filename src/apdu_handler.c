#include "apdu_handler.h"

#include "../bitcoin_app_base/src/constants.h"

#include "handler/approve_vault_intent.h"
#include "handler/derive_context_hash.h"

/**
 * @brief Babylon Vault APDU dispatcher.
 *
 * Overrides the weak `custom_apdu_handler` symbol declared in
 * bitcoin_app_base/src/boilerplate/dispatcher.h.  Called by the base app
 * dispatcher before it processes any APDU, giving the vault app first pick.
 *
 * Returns true (and sends a response) if the INS belongs to the vault;
 * returns false to let the base app handle it as a standard Bitcoin APDU.
 */
bool custom_apdu_handler(dispatcher_context_t *dc, const command_t *cmd) {
    if (cmd->cla != CLA_APP) {
        return false;
    }

    switch (cmd->ins) {
        case INS_APPROVE_VAULT_INTENT:
            handler_approve_vault_intent(dc, cmd);
            return true;

        case INS_DERIVE_CONTEXT_HASH:
            handler_derive_context_hash(dc, cmd);
            return true;

        default:
            return false;
    }
}
