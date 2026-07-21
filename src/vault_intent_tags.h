#pragma once

/**
 * TLV tag assignments for APPROVE_VAULT_INTENT (INS 0x80), v21 2-byte scheme.
 *
 * All tags are 2 bytes (uint16_t, big-endian on wire). Wire encoding:
 *   tag_hi (1 B) | tag_lo (1 B) | length (1 B) | value (length B)
 *
 * Three-phase loading:
 *
 *   P1=0x00  Scalar payload — 12 mandatory fields.
 *            Unknown tags are rejected.
 *
 *   P1=0x01  Per-vault group payload — vault_count groups, each with 6 fields
 *            in the TAG_GRP_* namespace (independent tag space from P1=0x00).
 *            Groups must arrive in strictly ascending htlc_vout order.
 *
 *   P1=0x02  Key batch TLV — keeper_count × TAG_KEEPER_PK entries, then
 *            challenger_count × TAG_CHALLENGER_PK entries. Keepers must all
 *            arrive before challengers (tag-enforced ordering).
 *
 * Wire size notes:
 *   timelocks: wire = 4 B u32 BE, struct = uint16_t (range-validated)
 *   depositor_derivation_path: wire = 20 B (5 × u32 BE), validated n == 5
 */

/* --- P1=0x00 scalar tags (12) ------------------------------------------- */

#define TAG_STRUCTURE_TYPE ((uint16_t) 0x0001) /**< u8    — protocol structure type constant         (1 B)    */
#define TAG_VERSION        ((uint16_t) 0x0002) /**< u8    — protocol version constant                (1 B)    */
#define TAG_COIN_TYPE      ((uint16_t) 0x0021) /**< u32   — SLIP-44 coin type                        (4 B BE) */
#define TAG_BASE_FEE_RATE  ((uint16_t) 0x0100) /**< u64   — base fee rate in sat/vbyte               (8 B BE) */
#define TAG_PEGIN_CSV_TIMELOCK \
    ((uint16_t) 0x0101) /**< u32   — vault UTXO CSV timelock P [72, 1008]      (4 B BE) */
#define TAG_PAYOUT_TIMELOCK \
    ((uint16_t) 0x0102) /**< u32   — Assert:0 payout timelock t2 (90, 4032)    (4 B BE) */
#define TAG_PREPEGIN_TXID \
    ((uint16_t) 0x0027) /**< bytes — Pre-PegIn txid (little-endian)            (32 B)   */
#define TAG_HTLC_REFUND_TIMELOCK \
    ((uint16_t) 0x0103) /**< u32   — HTLC refund timelock T_refund [72, 1008]   (4 B BE) */
#define TAG_DEPOSITOR_DERIVATION_PATH \
    ((uint16_t) 0x0069) /**< u32[] — BIP-86 derivation path, exactly 5 levels  (20 B BE) */
#define TAG_KEEPER_COUNT     ((uint16_t) 0x0104) /**< u8    — number of keeper keys [1, 32]             (1 B)    */
#define TAG_CHALLENGER_COUNT ((uint16_t) 0x0105) /**< u8    — number of challenger keys [1, 32]         (1 B)    */
#define TAG_VAULT_COUNT      ((uint16_t) 0x0106) /**< u8    — number of vault groups [1, 10]            (1 B)    */

/* --- P1=0x01 per-vault group tags (6) ------------------------------------ */
/* Independent tag namespace from P1=0x00; parsed by vault_tlv_parse_group.  */

#define TAG_GRP_HTLC_VOUT \
    ((uint16_t) 0x0109) /**< u8    — HTLC output index in Pre-PegIn tx         (1 B)    */
#define TAG_GRP_VAULT_PROVIDER_PK \
    ((uint16_t) 0x010A) /**< bytes — vault provider x-only pubkey              (32 B)   */
#define TAG_GRP_VAULT_AMOUNT \
    ((uint16_t) 0x010B) /**< u64   — total vault amount in satoshis            (8 B BE) */
#define TAG_GRP_COMMISSION_FEE \
    ((uint16_t) 0x010C) /**< u64   — vault provider commission (Fc)            (8 B BE) */
#define TAG_GRP_DEPOSITOR_CLAIM_VALUE \
    ((uint16_t) 0x010D) /**< u64   — depositor claim UTXO value (Dcv)          (8 B BE) */
#define TAG_GRP_PEGIN_MAX_FEE \
    ((uint16_t) 0x010E) /**< u64   — max acceptable PegIn fee                  (8 B BE) */

/* --- P1=0x02 key batch tags (on wire) ------------------------------------ */

#define TAG_KEEPER_PK \
    ((uint16_t) 0x0107) /**< bytes — keeper x-only key, 32 B each, lex-sorted  (32 B)   */
#define TAG_CHALLENGER_PK \
    ((uint16_t) 0x0108) /**< bytes — challenger x-only key, 32 B each, lex-sorted (32 B) */

/* --- Field counts for the parsers ---------------------------------------- */

/** Number of mandatory scalar tags in P1=0x00. */
#define VAULT_INTENT_TAG_COUNT 12

/** Number of mandatory per-vault group fields in P1=0x01. */
#define VAULT_GROUP_TAG_COUNT 6
