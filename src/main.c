#include <stdbool.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"
#include "../bitcoin_app_base/src/boilerplate/sw.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/handler/sign_psbt/txhashes.h"

#include "display.h"
#include "apdu_handler.h"

/**
 * @brief Validates and displays the transaction for user approval.
 *
 * Stub — full implementation in NAPPS-1375 (Pre-PegIn / Refund / PegIn)
 * and NAPPS-1376 (Payout).
 */
bool validate_and_display_transaction(dispatcher_context_t *dc,
                                      sign_psbt_state_t *st,
                                      const uint8_t internal_inputs[64],
                                      const uint8_t internal_outputs[64]) {
    UNUSED(st);
    UNUSED(internal_inputs);
    UNUSED(internal_outputs);

    SEND_SW(dc, SW_INS_NOT_SUPPORTED);
    return false;
}

/**
 * @brief Signs custom (non-wallet-policy) inputs.
 *
 * Stub — full implementation in NAPPS-1377.
 */
bool sign_custom_inputs(
    dispatcher_context_t *dc,
    sign_psbt_state_t *st,
    tx_hashes_t *tx_hashes,
    const uint8_t internal_inputs[static BITVECTOR_REAL_SIZE(MAX_N_INPUTS_CAN_SIGN)]) {
    UNUSED(dc);
    UNUSED(st);
    UNUSED(tx_hashes);
    UNUSED(internal_inputs);

    return false;
}
