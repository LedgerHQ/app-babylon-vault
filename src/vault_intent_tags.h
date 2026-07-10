#pragma once

/**
 * TLV tag byte assignments for APPROVE_VAULT_INTENT (INS 0x80).
 *
 * Three-phase loading (v19):
 *
 *   P1=0x00  Scalar payload — 13 mandatory fields encoded as:
 *              tag (1 B) | length (1 B) | value (length B)
 *            Unknown tags are rejected.
 *
 *   P1=0x02  Per-vault group payload — vault_count groups, each with 6 fields
 *            in the TAG_GRP_* namespace (independent tag space from P1=0x00).
 *            Groups must arrive in strictly ascending htlc_vout order.
 *
 *   P1=0x01  Raw packed x-only keys (no TLV wrapper):
 *              keeper_count × 32 bytes, then challenger_count × 32 bytes.
 *            Tags 0x14/0x15 below are defined for documentation purposes only.
 *
 * Wire size notes:
 *   timelocks: wire = 4 B u32 BE, struct = uint16_t (range-validated)
 *   depositor_derivation_path: wire = 20 B (5 × u32 BE), validated n == 5
 */

/* --- P1=0x00 scalar tags (13) ------------------------------------------- */

#define TAG_STRUCTURE_TYPE 0x01 /**< u8    — protocol structure type constant         (1 B)    */
#define TAG_VERSION        0x02 /**< u8    — protocol version constant                (1 B)    */
#define TAG_COIN_TYPE      0x03 /**< u32   — SLIP-44 coin type                        (4 B BE) */
#define TAG_BASE_FEE_RATE 0x08 /**< u64   — base fee rate in sat/vbyte               (8 B BE) */
#define TAG_PEGIN_CSV_TIMELOCK \
    0x0A                         /**< u32   — vault UTXO CSV timelock P [72, 1008]      (4 B BE) */
#define TAG_PAYOUT_TIMELOCK 0x0B /**< u32   — Assert:0 payout timelock t2 (90, 4032)    (4 B BE) \
                                  */
#define TAG_PREPEGIN_TXID 0x0C   /**< bytes — Pre-PegIn txid (little-endian)            (32 B)   */
#define TAG_HTLC_REFUND_TIMELOCK \
    0x0E /**< u32   — HTLC refund timelock T_refund [72, 1008]   (4 B BE) */
#define TAG_DEPOSITOR_DERIVATION_PATH \
    0x0F /**< u32[] — BIP-86 derivation path, exactly 5 levels  (20 B BE) */
#define TAG_KEEPER_COUNT     0x10 /**< u8    — number of keeper keys [1, 32]             (1 B)    */
#define TAG_CHALLENGER_COUNT 0x11 /**< u8    — number of challenger keys [1, 32]         (1 B) */
#define TAG_PEGIN_ANCHOR_VALUE \
    0x12                     /**< u64   — P2A anchor output value in satoshis (global)(8 B BE) */
#define TAG_VAULT_COUNT 0x13 /**< u8    — number of vault groups [1, 10]             (1 B)    */

/* --- P1=0x02 per-vault group tags (6) ------------------------------------ */
/* Independent tag namespace from P1=0x00; parsed by vault_tlv_parse_group.  */

#define TAG_GRP_HTLC_VOUT 0x01 /**< u8    — HTLC output index in Pre-PegIn tx         (1 B)    */
#define TAG_GRP_VAULT_PROVIDER_PK \
    0x02                          /**< bytes — vault provider x-only pubkey            (32 B)   */
#define TAG_GRP_VAULT_AMOUNT 0x03 /**< u64   — total vault amount in satoshis           (8 B BE) \
                                   */
#define TAG_GRP_COMMISSION_FEE \
    0x04 /**< u64   — vault provider commission (Fc)           (8 B BE) */
#define TAG_GRP_DEPOSITOR_CLAIM_VALUE \
    0x05 /**< u64   — depositor claim UTXO value (Dcv)          (8 B BE) */
#define TAG_GRP_PEGIN_MAX_FEE 0x06 /**< u64   — max acceptable PegIn fee                 (8 B BE) \
                                    */

/* --- P1=0x01 documentation tags (not on wire) ---------------------------- */

#define TAG_KEEPER_PKS     0x14 /**< (doc) keeper x-only keys, 32 B each, lex-sorted   */
#define TAG_CHALLENGER_PKS 0x15 /**< (doc) challenger x-only keys, 32 B each, lex-sorted */

/* --- Field counts for the parsers ---------------------------------------- */

/** Number of mandatory scalar tags in P1=0x00. */
#define VAULT_INTENT_TAG_COUNT 13

/** Number of mandatory per-vault group fields in P1=0x02. */
#define VAULT_GROUP_TAG_COUNT 6
