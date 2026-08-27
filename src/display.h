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
 * Shows vault provider key, amounts, fee rate, timelocks, and all keeper /
 * challenger public keys.  MUST also display G_vault_context.app_name so the user
 * can confirm which HKDF appName domain this intent is bound to — this is the only
 * user-visible confirmation when DERIVE_CONTEXT_HASH was invoked with P2=0x01 (silent).
 *
 * @return true   User approved; caller may proceed.
 * @return false  User rejected; SW_DENY has already been sent to the host.
 */
bool display_vault_intent(dispatcher_context_t *dc);

/**
 * @brief Screen 3 — Refund transaction review.
 *
 * @param amount_reclaimed   Amount returned to the depositor in satoshis.
 * @param fee                Transaction fee in satoshis.
 * @param timelock_blocks    Refund timelock from the leaf script (block count), rendered in
 *                           the same form as the intent's timelocks on Screen 2 so the two
 *                           can be compared by eye.
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
 * @param out0_address       NUL-terminated bech32m address for Output 0 (ClaimAssertConnector);
 *                           caller must keep valid across the blocking io_ui_process call.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_claim_transaction(dispatcher_context_t *dc,
                               uint64_t amount_spent,
                               uint64_t connector_amount,
                               uint64_t fee,
                               const uint8_t *pegin_txid,
                               const char *out0_address);

/**
 * @brief Screen 5 — Assert transaction review.
 *
 * @param claim_txid      32-byte Claim txid (shown as hex); caller must keep valid.
 * @param amount_carried  Amount carried into the Assert output in satoshis.
 * @param fee             Transaction fee in satoshis.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_assert_transaction(dispatcher_context_t *dc,
                                const uint8_t *claim_txid,
                                uint64_t amount_carried,
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
 * @brief Screen 7 — PoP (BIP-322 proof-of-possession) review.
 *
 * Shows the three human-readable fields from the PoP message and the depositor's
 * Bitcoin address, then asks the user to confirm before the device signs the to_sign PSBT.
 *
 * @param eth_addr       NUL-terminated Ethereum address ("0x" + 40 lowercase hex).
 * @param chain_id       NUL-terminated decimal chain ID string.
 * @param registry       NUL-terminated registry contract address ("0x" + 40 lowercase hex).
 * @param btc_address    NUL-terminated bech32m P2TR address of the depositor key being bound.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_pop_transaction(dispatcher_context_t *dc,
                             const char *eth_addr,
                             const char *chain_id,
                             const char *registry,
                             const char *btc_address);

/**
 * @brief Screen 8 — Payout finalize review.
 *
 * Shown when the depositor self-claims after a successful Claim + Assert chain.
 * Displays the vault UTXO txid (Input 0), the amount received, transaction fee,
 * and both output addresses so the user can verify both outputs pay their own
 * BIP-86 address.
 *
 * @param amount_received     Output 0 value in satoshis (funds going to depositor).
 * @param address             NUL-terminated bech32m address for Output 0; caller keeps valid.
 * @param cpfp_address        NUL-terminated bech32m address for Output 1 (CPFP anchor);
 *                            caller keeps valid.
 * @param fee                 Transaction fee in satoshis, as stated by the PSBT: the sum of
 *                            all input prevout values minus the sum of all output values.
 *                            Always displayed, including when it is zero.
 * @param vault_prevout_txid  NUL-terminated 64-char hex string of Input 0's prevout txid —
 *                            the Vault UTXO the funds leave from.  Caller must keep it valid
 *                            across the blocking io_ui_process call.
 * @return true   User approved.
 * @return false  User rejected (SW_DENY already sent).
 */
bool display_payout_finalize(dispatcher_context_t *dc,
                             uint64_t amount_received,
                             const char *address,
                             const char *cpfp_address,
                             uint64_t fee,
                             const char *vault_prevout_txid);
