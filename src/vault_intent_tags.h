#pragma once

/**
 * TLV tag byte assignments for APPROVE_VAULT_INTENT (INS 0x80).
 *
 * P1=0x00 payload — 17 scalar fields encoded as: tag (1 B) | length (1 B) | value (length B).
 * Tags are assigned sequentially in spec-table order.
 * Duplicate tags, unknown tags, and non-canonical encodings are all rejected.
 *
 * P1=0x01 payload — raw packed 32-byte x-only keys (no TLV wrapper):
 *   keeper_count × 32 bytes, then challenger_count × 32 bytes.
 * Tags 0x12/0x13 below are defined for documentation purposes only;
 * they do not appear on the wire in P1=0x01.
 *
 * Wire size vs struct notes (parser handles conversion):
 *   pegin_csv_timelock / payout_timelock / htlc_refund_timelock:
 *     wire = 4 B u32 BE, struct = uint32_t (range-validated to [72, 1008] or (90, 4032))
 *   htlc_vout:
 *     wire = 1 B u8, struct = uint32_t (zero-extended)
 *   depositor_derivation_path:
 *     wire = 4n B (variable, n uint32_t BE), struct = uint32_t[5] (validated n == 5)
 */

/* --- P1=0x00 scalar tags (17) ------------------------------------------- */

#define TAG_STRUCTURE_TYPE 0x01 /**< u8    — protocol structure type constant          (1 B)  */
#define TAG_VERSION        0x02 /**< u8    — protocol version constant                 (1 B)  */
#define TAG_COIN_TYPE      0x03 /**< u32   — SLIP-44 coin type                         (4 B BE) */
#define TAG_VAULT_PROVIDER_PK \
    0x04                      /**< bytes — vault provider x-only pubkey              (32 B)   */
#define TAG_VAULT_AMOUNT 0x05 /**< u64   — total vault amount in satoshis             (8 B BE) */
#define TAG_COMMISSION_FEE                                                  \
    0x06 /**< u64   — vault provider commission (Fc)             (8 B BE) \
          */
#define TAG_DEPOSITOR_CLAIM_VALUE \
    0x07                       /**< u64 — depositor claim UTXO value (Dcv)          (8 B BE) */
#define TAG_BASE_FEE_RATE 0x08 /**< u64   — base fee rate in sat/vbyte                 (8 B BE) */
#define TAG_PEGIN_MAX_FEE 0x09 /**< u64   — max acceptable PegIn fee                   (8 B BE) */
#define TAG_PEGIN_CSV_TIMELOCK \
    0x0A /**< u32   — vault UTXO CSV timelock P [72, 1008]       (4 B BE) */
#define TAG_PAYOUT_TIMELOCK                                                                       \
    0x0B                       /**< u32   — Assert:0 payout timelock t2 (90, 4032)     (4 B BE) \
                                */
#define TAG_PREPEGIN_TXID 0x0C /**< bytes — Pre-PegIn txid (little-endian)             (32 B) */
#define TAG_HTLC_VOUT     0x0D /**< u8    — HTLC output index in Pre-PegIn tx          (1 B)  */
#define TAG_HTLC_REFUND_TIMELOCK \
    0x0E /**< u32   — HTLC refund timelock T_refund [72, 1008]   (4 B BE) */
#define TAG_DEPOSITOR_DERIVATION_PATH \
    0x0F /**< u32[] — BIP-86 derivation path, exactly 5 levels  (20 B BE) */
#define TAG_KEEPER_COUNT     0x10 /**< u8    — number of keeper keys [1, 32]              (1 B)  */
#define TAG_CHALLENGER_COUNT 0x11 /**< u8    — number of challenger keys [1, 32]          (1 B) */

/* --- P1=0x01 documentation tags (not on wire) ---------------------------- */

#define TAG_KEEPER_PKS     0x12 /**< (doc) keeper x-only keys, 32 B each, lex-sorted   */
#define TAG_CHALLENGER_PKS 0x13 /**< (doc) challenger x-only keys, 32 B each, lex-sorted */

/* --- Helpers for the P1=0x00 parser -------------------------------------- */

/** Highest tag value used in P1=0x00 scalar payload. */
#define VAULT_INTENT_TAG_MAX TAG_CHALLENGER_COUNT /* 0x11 */

/** Number of mandatory scalar tags. */
#define VAULT_INTENT_TAG_COUNT 17

/**
 * Bitmask over all valid scalar tags.
 * Bit i corresponds to tag (i + 1), i.e. TAG_STRUCTURE_TYPE sets bit 0.
 * All 17 bits must be set after a complete P1=0x00 parse.
 */
#define VAULT_INTENT_ALL_TAGS_MASK ((1u << VAULT_INTENT_TAG_COUNT) - 1u)

/** Convert a tag byte to its bitmask bit (tag must be in [0x01, 0x11]). */
#define VAULT_TAG_BIT(tag) (1u << ((tag) - 1u))
