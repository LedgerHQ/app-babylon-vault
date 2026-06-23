#include <stdbool.h>

#include "../bitcoin_app_base/src/boilerplate/dispatcher.h"
#include "../bitcoin_app_base/src/boilerplate/sw.h"
#include "../bitcoin_app_base/src/common/bitvector.h"
#include "../bitcoin_app_base/src/handler/sign_psbt.h"
#include "../bitcoin_app_base/src/handler/sign_psbt/txhashes.h"

#include "apdu_handler.h"
#include "sign_psbt_validate.h"

/**
 * @brief Signs custom (non-wallet-policy) inputs.
 *
 * Stub — full implementation in NAPPS-1377.
 *
 * When implemented, this function must perform the following state transitions
 * (intentionally deferred from validate_and_display_transaction so state only
 * advances when signing actually succeeds):
 *
 *   PegIn   (state == SESSION2_PEGIN_EXPECTED):
 *     After signing the HTLC Leaf 0 input:
 *       SESSION2_PEGIN_EXPECTED → SESSION2_PAYOUT_EXPECTED
 *
 *   Payout  (state == SESSION2_PAYOUT_EXPECTED):
 *     After signing both Vault UTXO + Assert:0 Payout inputs:
 *       advance payout_index; when payout_index > keeper_count:
 *       SESSION2_PAYOUT_EXPECTED → SESSION2_COMPLETE
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
