#pragma once

#include <stddef.h>
#include <stdint.h>

#include "vault_intent.h"

/**
 * Error codes returned by vault_tlv_parse.
 * Map to APDU status words via vault_tlv_err_to_sw.
 */
typedef enum {
    VAULT_TLV_OK = 0,
    VAULT_TLV_ERR_OVERFLOW,      /**< TLV field extends past end of buffer */
    VAULT_TLV_ERR_UNKNOWN_TAG,   /**< tag not in [0x01, 0x11]              */
    VAULT_TLV_ERR_DUPLICATE_TAG, /**< same tag appears more than once      */
    VAULT_TLV_ERR_WRONG_LENGTH,  /**< field_len != expected fixed size      */
    VAULT_TLV_ERR_MISSING_FIELD, /**< one or more mandatory tags absent     */
    VAULT_TLV_ERR_VALIDATION,    /**< value out of range or cross-field constraint violated */
} vault_tlv_err_t;

/**
 * Parse and validate the APPROVE_VAULT_INTENT P1=0x00 TLV payload.
 *
 * On success (VAULT_TLV_OK) all 17 scalar fields of @p out are populated.
 * On any error @p out is left in an indeterminate state; the caller must
 * discard it (vault_context_invalidate zeros G_vault_intent).
 *
 * @param data  Pointer to the raw TLV bytes (cmd->data).
 * @param len   Number of bytes in the buffer (cmd->lc).
 * @param out   Destination intent struct to fill.
 */
vault_tlv_err_t vault_tlv_parse(const uint8_t *data, size_t len, vault_intent_t *out);
