#pragma once

#include <stdbool.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"
#include "../bitcoin_app_base/src/constants.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"

/**
 * @brief Validates and displays the transaction for user approval.
 *
 * Dispatches to one of three sub-validators based on session state and PSBT structure:
 *   - Pre-PegIn  (state == INTENT_LOADED, has wallet policy)
 *   - Refund     (any state, no wallet policy, 1 input / 1 output)
 *   - PegIn      (state == SESSION2_PEGIN_EXPECTED, silent)
 *
 * Overrides the weak default in bitcoin_app_base/src/handler/sign_psbt/sign_input.h.
 */
bool validate_and_display_transaction(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)],
    const uint8_t internal_outputs[static BITVECTOR_REAL_SIZE(MAX_N_OUTPUTS_CAN_SIGN)]);

/**
 * @brief Re-read the PSBT_IN_TAP_LEAF_SCRIPT entry for a Refund input (Input 0).
 *
 * Fills G_scratch.tls with the leaf script found in the PSBT input map.
 * Also fills *input_map_out with the input's merkleized map commitment so
 * the caller can do further PSBT reads (WITNESS_UTXO, TAP_BIP32_DERIVATION).
 *
 * @return true on success; sends SW_INCORRECT_DATA and returns false on any error.
 */
bool vault_read_refund_leaf_script(dispatcher_context_t *dc,
                                   sign_psbt_state_t *st,
                                   merkleized_map_commitment_t *input_map_out);

/**
 * @brief Re-read the PSBT_IN_TAP_LEAF_SCRIPT entry for a PayoutFinalize input (Input 1).
 *
 * Identical to vault_read_refund_leaf_script but targets Input 1 instead of Input 0.
 *
 * @return true on success; sends SW_INCORRECT_DATA and returns false on any error.
 */
bool vault_read_payout_leaf_script(dispatcher_context_t *dc,
                                   sign_psbt_state_t *st,
                                   merkleized_map_commitment_t *input_map_out);
