#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief DERIVE_CONTEXT_HASH approval screen.
 *
 * Shows appName and a truncated hex preview of the context bytes, then asks
 * the user to confirm before the device computes and returns the HKDF root.
 *
 * @param app_name      ASCII appName bytes (validated [a-z0-9\-], no NUL).
 * @param app_name_len  Length (1–64).
 * @param context       Raw context bytes (vaultContext APDU field).
 * @param context_len   Length of @p context (non-zero).
 * @return true   User approved; caller may proceed with derivation.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_derive_context_hash(dispatcher_context_t *dc,
                                 const uint8_t *app_name,
                                 uint8_t app_name_len,
                                 const uint8_t *context,
                                 size_t context_len);

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
 * Shows vault amount, depositor claim value, fee, and HTLC output address.
 * Approval gates signing; rejection returns SW_DENY.
 *
 * @param vault_amount          Vault amount in satoshis.
 * @param depositor_claim_value Depositor claim value in satoshis (shown so the user
 *                              sees the full funds committed to the HTLC).
 * @param fee                   Transaction fee in satoshis.
 * @param htlc_address          NUL-terminated bech32 address string; caller must keep
 *                              the pointer valid until this function returns.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_prepegin_transaction(dispatcher_context_t *dc,
                                  uint64_t vault_amount,
                                  uint64_t depositor_claim_value,
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
