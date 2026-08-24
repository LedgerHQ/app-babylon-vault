#pragma once

#include <stddef.h>
#include <stdint.h>

#include "vault_intent.h"

/**
 * Error codes returned by vault_tlv_parse and vault_tlv_parse_group.
 * Map to APDU status words via the handler's tlv_err_to_sw helper.
 */
typedef enum {
    VAULT_TLV_OK = 0,
    VAULT_TLV_ERR_OVERFLOW,      /**< TLV field extends past end of buffer                */
    VAULT_TLV_ERR_UNKNOWN_TAG,   /**< tag not in the valid set for this phase              */
    VAULT_TLV_ERR_DUPLICATE_TAG, /**< same tag appears more than once                     */
    VAULT_TLV_ERR_WRONG_LENGTH,  /**< field_len != expected fixed size                    */
    VAULT_TLV_ERR_MISSING_FIELD, /**< one or more mandatory tags absent                   */
    VAULT_TLV_ERR_VALIDATION,    /**< value out of range or cross-field constraint violated */
} vault_tlv_err_t;

/**
 * Parse and validate the APPROVE_VAULT_INTENT P1=0x00 TLV scalar payload.
 *
 * Accepts the 13 mandatory scalar tags (2-byte tags).  Unknown tags are
 * rejected with VAULT_TLV_ERR_UNKNOWN_TAG.
 *
 * On success (VAULT_TLV_OK) all 13 scalar fields of @p out are populated.
 *
 * On any error @p out is left in an indeterminate state; the caller must
 * discard it (vault_context_invalidate zeros G_vault_intent).
 *
 * @param data  Pointer to the raw TLV bytes (cmd->data).
 * @param len   Number of bytes in the buffer (cmd->lc).
 * @param out   Destination intent struct to fill.
 */
vault_tlv_err_t vault_tlv_parse(const uint8_t *data, size_t len, vault_intent_t *out);

/**
 * Parse and validate one APPROVE_VAULT_INTENT P1=0x01 per-vault group TLV record.
 *
 * A single APDU may carry multiple back-to-back group records; call this function
 * in a loop, advancing @p data by @p *consumed bytes after each successful return.
 *
 * Accepts the 6 mandatory per-vault group tags (TAG_GRP_* namespace, 2-byte tags).
 * Stops as soon as all 6 fields have been seen; remaining bytes in the buffer are
 * left for the next call.  All 6 fields must be present, in strictly ascending order;
 * duplicate and unknown tags are rejected (canonical encoding, as for vault_tlv_parse).
 *
 * On success (VAULT_TLV_OK) all 6 wire fields of @p out are populated and
 * @p *consumed holds the number of bytes consumed from @p data.
 *
 * On any error @p out and @p *consumed are left in an indeterminate state.
 *
 * @param data      Pointer to the raw TLV bytes (start of a group record).
 * @param len       Number of bytes available from @p data.
 * @param out       Destination group struct to fill.
 * @param consumed  Set to the number of bytes consumed on success.
 */
vault_tlv_err_t vault_tlv_parse_group(const uint8_t *data,
                                      size_t len,
                                      vault_group_t *out,
                                      size_t *consumed);
