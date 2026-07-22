#include "vault_tlv.h"
#include "vault_intent_tags.h"
#include "vault_constants.h"

#include <stdint.h>
#include <string.h>

#include "os_utils.h" /* U2BE, U4BE, U8BE */

/* BIP-32 hardened-child bit */
#define HARDENED 0x80000000u

/* -------------------------------------------------------------------------
 * vault_tlv_parse — P1=0x00 scalar payload (12 mandatory fields)
 * ---------------------------------------------------------------------- */

vault_tlv_err_t vault_tlv_parse(const uint8_t *data, size_t len, vault_intent_t *out) {
    uint16_t seen_mask = 0;
    size_t pos = 0;

    while (pos < len) {
        /* Need at least 3 bytes for 2-byte tag + 1-byte length. */
        if (pos + 3 > len) return VAULT_TLV_ERR_OVERFLOW;

        uint16_t tag = U2BE(data, pos);
        pos += 2;
        uint8_t field_len = data[pos++];

        /* Reject if value bytes extend past buffer end. */
        if (pos + field_len > len) return VAULT_TLV_ERR_OVERFLOW;

        const uint8_t *v = data + pos;
        uint8_t field_idx;

        switch (tag) {
            case TAG_STRUCTURE_TYPE:
                field_idx = 0;
                if (field_len != 1) return VAULT_TLV_ERR_WRONG_LENGTH;
                if (v[0] != VAULT_STRUCTURE_TYPE) return VAULT_TLV_ERR_VALIDATION;
                out->structure_type = v[0];
                break;

            case TAG_VERSION:
                field_idx = 1;
                if (field_len != 1) return VAULT_TLV_ERR_WRONG_LENGTH;
                if (v[0] != VAULT_PROTOCOL_VERSION) return VAULT_TLV_ERR_VALIDATION;
                out->version = v[0];
                break;

            case TAG_COIN_TYPE: {
                field_idx = 2;
                if (field_len != 4) return VAULT_TLV_ERR_WRONG_LENGTH;
                uint32_t val = U4BE(v, 0);
                if (val != BIP44_COIN_TYPE) return VAULT_TLV_ERR_VALIDATION;
                out->coin_type = val;
                break;
            }

            case TAG_BASE_FEE_RATE: {
                field_idx = 3;
                if (field_len != 8) return VAULT_TLV_ERR_WRONG_LENGTH;
                uint64_t rate = U8BE(v, 0);
                if (rate > UINT32_MAX) return VAULT_TLV_ERR_VALIDATION;
                out->base_fee_rate = rate;
                break;
            }

            case TAG_PEGIN_CSV_TIMELOCK: {
                field_idx = 4;
                if (field_len != 4) return VAULT_TLV_ERR_WRONG_LENGTH;
                uint32_t val = U4BE(v, 0);
                if (val < VAULT_TIMELOCK_MIN || val > VAULT_TIMELOCK_MAX)
                    return VAULT_TLV_ERR_VALIDATION;
                out->pegin_csv_timelock = (uint16_t) val;
                break;
            }

            case TAG_PAYOUT_TIMELOCK: {
                field_idx = 5;
                if (field_len != 4) return VAULT_TLV_ERR_WRONG_LENGTH;
                uint32_t val = U4BE(v, 0);
                if (val <= VAULT_PAYOUT_TIMELOCK_MIN || val >= VAULT_PAYOUT_TIMELOCK_MAX) {
                    return VAULT_TLV_ERR_VALIDATION;
                }
                out->payout_timelock = (uint16_t) val;
                break;
            }

            case TAG_PREPEGIN_TXID:
                field_idx = 6;
                if (field_len != VAULT_HASH256_LEN) return VAULT_TLV_ERR_WRONG_LENGTH;
                memcpy(out->prepegin_txid, v, VAULT_HASH256_LEN);
                break;

            case TAG_HTLC_REFUND_TIMELOCK: {
                field_idx = 7;
                if (field_len != 4) return VAULT_TLV_ERR_WRONG_LENGTH;
                uint32_t val = U4BE(v, 0);
                if (val < VAULT_TIMELOCK_MIN || val > VAULT_TIMELOCK_MAX)
                    return VAULT_TLV_ERR_VALIDATION;
                out->htlc_refund_timelock = (uint16_t) val;
                break;
            }

            case TAG_DEPOSITOR_DERIVATION_PATH: {
                field_idx = 8;
                /* Exactly 5 levels, 4 bytes each = 20 bytes. */
                if (field_len != VAULT_DEPOSITOR_PATH_LEN * sizeof(uint32_t)) {
                    return VAULT_TLV_ERR_WRONG_LENGTH;
                }
                for (int i = 0; i < VAULT_DEPOSITOR_PATH_LEN; i++) {
                    out->depositor_path[i] = U4BE(v, (size_t) i * 4);
                }
                /* BIP-86: purpose must be 86' */
                if (out->depositor_path[0] != (86u | HARDENED)) return VAULT_TLV_ERR_VALIDATION;
                /* coin_type level must be hardened; exact match vs coin_type field deferred
                 * to post-loop cross-field check (coin_type tag may arrive after this one). */
                if (!(out->depositor_path[1] & HARDENED)) return VAULT_TLV_ERR_VALIDATION;
                /* account must be hardened */
                if (!(out->depositor_path[2] & HARDENED)) return VAULT_TLV_ERR_VALIDATION;
                /* change and index must not be hardened */
                if (out->depositor_path[3] & HARDENED) return VAULT_TLV_ERR_VALIDATION;
                if (out->depositor_path[4] & HARDENED) return VAULT_TLV_ERR_VALIDATION;
                break;
            }

            case TAG_KEEPER_COUNT:
                field_idx = 9;
                if (field_len != 1) return VAULT_TLV_ERR_WRONG_LENGTH;
                if (v[0] < 1 || v[0] > VAULT_MAX_KEEPERS) return VAULT_TLV_ERR_VALIDATION;
                out->keeper_count = v[0];
                break;

            case TAG_CHALLENGER_COUNT:
                field_idx = 10;
                if (field_len != 1) return VAULT_TLV_ERR_WRONG_LENGTH;
                if (v[0] < 1 || v[0] > VAULT_MAX_CHALLENGERS) return VAULT_TLV_ERR_VALIDATION;
                out->challenger_count = v[0];
                break;

            case TAG_VAULT_COUNT:
                field_idx = 11;
                if (field_len != 1) return VAULT_TLV_ERR_WRONG_LENGTH;
                if (v[0] < 1 || v[0] > VAULT_MAX_VAULTS) return VAULT_TLV_ERR_VALIDATION;
                out->vault_count = v[0];
                break;

            default:
                return VAULT_TLV_ERR_UNKNOWN_TAG;
        }

        uint16_t bit = (uint16_t) (1u << field_idx);
        if (seen_mask & bit) return VAULT_TLV_ERR_DUPLICATE_TAG;
        seen_mask |= bit;
        pos += field_len;
    }

    /* All 12 mandatory scalar fields must be present. */
    if (seen_mask != (uint16_t) ((1u << VAULT_INTENT_TAG_COUNT) - 1u))
        return VAULT_TLV_ERR_MISSING_FIELD;

    /* Cross-field: depositor_path[1] must equal coin_type | HARDENED. */
    if (out->depositor_path[1] != (out->coin_type | HARDENED)) return VAULT_TLV_ERR_VALIDATION;

    return VAULT_TLV_OK;
}

/* -------------------------------------------------------------------------
 * vault_tlv_parse_group — P1=0x01 per-vault group payload (6 mandatory fields)
 * ---------------------------------------------------------------------- */

vault_tlv_err_t vault_tlv_parse_group(const uint8_t *data, size_t len, vault_group_t *out) {
    uint8_t seen_mask = 0;
    size_t pos = 0;

    while (pos < len) {
        /* Need at least 3 bytes for 2-byte tag + 1-byte length. */
        if (pos + 3 > len) return VAULT_TLV_ERR_OVERFLOW;

        uint16_t tag = U2BE(data, pos);
        pos += 2;
        uint8_t field_len = data[pos++];

        /* Reject if value bytes extend past buffer end. */
        if (pos + field_len > len) return VAULT_TLV_ERR_OVERFLOW;

        const uint8_t *v = data + pos;
        uint8_t field_idx;

        switch (tag) {
            case TAG_GRP_HTLC_VOUT:
                field_idx = 0;
                if (field_len != 1) return VAULT_TLV_ERR_WRONG_LENGTH;
                out->htlc_vout = v[0];
                break;

            case TAG_GRP_VAULT_PROVIDER_PK:
                field_idx = 1;
                if (field_len != VAULT_XONLY_PUBKEY_LEN) return VAULT_TLV_ERR_WRONG_LENGTH;
                memcpy(out->vault_provider_pk, v, VAULT_XONLY_PUBKEY_LEN);
                break;

            case TAG_GRP_VAULT_AMOUNT:
                field_idx = 2;
                if (field_len != 8) return VAULT_TLV_ERR_WRONG_LENGTH;
                out->vault_amount = U8BE(v, 0);
                break;

            case TAG_GRP_COMMISSION_FEE: {
                field_idx = 3;
                if (field_len != 8) return VAULT_TLV_ERR_WRONG_LENGTH;
                uint64_t val = U8BE(v, 0);
                /* The VP commission output must stay above the relay dust limit. */
                if (val < VAULT_DUST_LIMIT) return VAULT_TLV_ERR_VALIDATION;
                out->commission_fee = val;
                break;
            }

            case TAG_GRP_DEPOSITOR_CLAIM_VALUE: {
                field_idx = 4;
                if (field_len != 8) return VAULT_TLV_ERR_WRONG_LENGTH;
                uint64_t val = U8BE(v, 0);
                /* The depositor reclaim output must stay above the relay dust limit. */
                if (val < VAULT_DUST_LIMIT) return VAULT_TLV_ERR_VALIDATION;
                out->depositor_claim_value = val;
                break;
            }

            case TAG_GRP_PEGIN_MAX_FEE:
                field_idx = 5;
                if (field_len != 8) return VAULT_TLV_ERR_WRONG_LENGTH;
                out->pegin_max_fee = U8BE(v, 0);
                break;

            default:
                return VAULT_TLV_ERR_UNKNOWN_TAG;
        }

        uint8_t bit = (uint8_t) (1u << field_idx);
        if (seen_mask & bit) return VAULT_TLV_ERR_DUPLICATE_TAG;
        seen_mask |= bit;
        pos += field_len;
    }

    /* All 6 mandatory group fields must be present. */
    if (seen_mask != (uint8_t) ((1u << VAULT_GROUP_TAG_COUNT) - 1u))
        return VAULT_TLV_ERR_MISSING_FIELD;

    /* Cross-field: vault_amount > commission_fee + 2*VAULT_DUST_LIMIT (overflow-safe).
     * Both the commission output and the depositor reclaim output must be fundable
     * from the vault UTXO without going below the relay dust limit. */
    const uint64_t two_dust = 2u * VAULT_DUST_LIMIT;
    if (out->commission_fee > UINT64_MAX - two_dust ||
        out->vault_amount <= out->commission_fee + two_dust) {
        return VAULT_TLV_ERR_VALIDATION;
    }

    return VAULT_TLV_OK;
}
