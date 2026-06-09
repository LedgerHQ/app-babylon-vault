#pragma once

#include <stdbool.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"

bool display_transaction(dispatcher_context_t *dc,
                         int64_t value_spent,
                         uint64_t magic_input_value,
                         uint64_t fee);

/**
 * @brief Display the loaded vault intent for user review and approval.
 *
 * Shows vault provider key, amounts, fee rate,
 * timelocks, and all keeper / challenger public keys.
 *
 * @return true   User approved; caller may proceed.
 * @return false  User rejected; SW_DENY has already been sent to the host.
 */
bool display_vault_intent(dispatcher_context_t *dc);
