#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"

/**
 * @brief Screen 1 — DERIVE_CONTEXT_HASH approval (P2=0x00 only).
 *
 * Shows appName and asks the user to confirm before the device derives and
 * returns the HKDF root.  Called only for P2=0x00; P2=0x01 (silent) skips display.
 *
 * @param app_name      ASCII appName bytes (validated [a-z0-9\-], no NUL).
 * @param app_name_len  Length (1–64).
 * @return true   User approved; caller may proceed with derivation.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_derive_context_hash(dispatcher_context_t *dc,
                                 const uint8_t *app_name,
                                 uint8_t app_name_len);

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
 * @param amount_reclaimed   Amount returned to the depositor in satoshis.
 * @param fee                Transaction fee in satoshis.
 * @param timelock_blocks    Refund timelock from the leaf script (block count).
 * @param prepegin_txid      32-byte Pre-PegIn txid (shown as hex); caller must keep valid.
 * @param refund_address     NUL-terminated bech32m address; caller must keep valid.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_refund_transaction(dispatcher_context_t *dc,
                                uint64_t amount_reclaimed,
                                uint64_t fee,
                                uint32_t timelock_blocks,
                                const uint8_t *prepegin_txid,
                                const char *refund_address);

/**
 * @brief Screen 4 — Claim transaction review (depositor-as-claimer).
 *
 * @param amount_spent       PegIn UTXO value consumed (Dcv) in satoshis.
 * @param connector_amount   Output 0 value locked into the ClaimAssertConnector, satoshis.
 * @param fee                Transaction fee in satoshis.
 * @param pegin_txid         32-byte PegIn txid (vault reference, shown as hex); caller keeps valid.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_claim_transaction(dispatcher_context_t *dc,
                               uint64_t amount_spent,
                               uint64_t connector_amount,
                               uint64_t fee,
                               const uint8_t *pegin_txid);

/**
 * @brief Screen 5 — Assert transaction review.
 *
 * @param claim_txid      32-byte Claim txid (shown as hex); caller must keep valid.
 * @param amount_carried  Amount carried into the Assert output in satoshis.
 * @param n_outputs       Number of outputs in the Assert transaction.
 * @param fee             Transaction fee in satoshis.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_assert_transaction(dispatcher_context_t *dc,
                                const uint8_t *claim_txid,
                                uint64_t amount_carried,
                                uint32_t n_outputs,
                                uint64_t fee);

/**
 * @brief Screen 6 — Wrongly Challenged (WC) transaction review.
 *
 * @param amount_reclaimed     Amount reclaimed to the depositor in satoshis.
 * @param wallet_inputs_amount Extra wallet input value contributed for fees (0 if none).
 * @param fee                  Transaction fee in satoshis.
 * @param wc_address           NUL-terminated bech32m reclaim address; caller keeps valid.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_wc_transaction(dispatcher_context_t *dc,
                            uint64_t amount_reclaimed,
                            uint64_t wallet_inputs_amount,
                            uint64_t fee,
                            const char *wc_address);

/**
 * @brief Screen 7 — Payout transaction review.
 *
 * Shows the amount paid out and the transaction fee.
 * Approval gates signing; rejection returns SW_DENY.
 *
 * @param payout_amount  Amount paid to the claimer in satoshis (Out0 value).
 * @param fee            Transaction fee in satoshis.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_payout_transaction(dispatcher_context_t *dc, uint64_t payout_amount, uint64_t fee);

/**
 * @brief Screen 8 — Payout finalize review (NAPPS-1464).
 *
 * Confirmation screen presented once all payout transactions in a vault group
 * have been signed, before the host proceeds with broadcast.
 *
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_payout_finalize(dispatcher_context_t *dc);
