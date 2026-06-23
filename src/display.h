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

/**
 * @brief Screen 2 — Pre-PegIn transaction review.
 *
 * Shows vault amount, fee, and HTLC output address.
 * Approval gates signing; rejection returns SW_DENY.
 *
 * @param vault_amount    Vault amount in satoshis.
 * @param fee             Transaction fee in satoshis.
 * @param htlc_address    NUL-terminated bech32 address string; caller must keep
 *                        the pointer valid until this function returns.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_prepegin_transaction(dispatcher_context_t *dc,
                                  uint64_t vault_amount,
                                  uint64_t fee,
                                  const char *htlc_address);

/**
 * @brief Screen 3 — Refund transaction review.
 *
 * Shows the amount reclaimed, transaction fee, and the destination (reclaim) address.
 * Approval gates signing; rejection returns SW_DENY.
 *
 * @param amount_reclaimed  Amount returned to the depositor in satoshis.
 * @param fee               Transaction fee in satoshis.
 * @param refund_address    NUL-terminated bech32m address string; caller must keep
 *                          the pointer valid until this function returns.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_refund_transaction(dispatcher_context_t *dc,
                                uint64_t amount_reclaimed,
                                uint64_t fee,
                                const char *refund_address);
