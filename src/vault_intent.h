#pragma once

#include <stdint.h>

#include "vault_constants.h"

// Maximum number of keepers / challengers supported by the protocol.
#define VAULT_MAX_KEEPERS     32
#define VAULT_MAX_CHALLENGERS 32

// BIP-32 derivation path length for the depositor key (BIP-86, exactly 5 levels).
#define VAULT_DEPOSITOR_PATH_LEN 5

// Size of an x-only Schnorr public key (BIP-340).
#define VAULT_XONLY_PUBKEY_LEN 32
// Buffer size for a hex-encoded x-only public key (64 chars + NUL).
#define VAULT_HEX_KEY_STR_SIZE (2 * VAULT_XONLY_PUBKEY_LEN + 1)
// Buffer size for "Challenger 32\0", the longest possible keeper/challenger label.
#define VAULT_KEY_LABEL_SIZE 14

// Size of a SHA-256 hash or Bitcoin txid.
#define VAULT_HASH256_LEN 32

/**
 * @brief Per-vault group — fields specific to one vault in a batch Pre-PegIn.
 *
 * Populated from the P1=0x01 TLV group payload (6 wire fields).
 *
 * Stored in vault_intent_t.groups[0..vault_count-1], indexed by htlc_vout order.
 */
typedef struct {
    /** Output index of the HTLC in the Pre-PegIn transaction. */
    uint8_t htlc_vout;

    /**
     * Vault provider x-only public key.
     * Validated as a valid secp256k1 point at P1=0x02 processing time.
     */
    uint8_t vault_provider_pk[VAULT_XONLY_PUBKEY_LEN];

    /** Total vault amount in satoshis. Must be > commission_fee + 2*DUST. */
    uint64_t vault_amount;

    /** Vault provider commission fee in satoshis. */
    uint64_t commission_fee;

    /** Depositor claim value in satoshis (Depositor Claim UTXO). */
    uint64_t depositor_claim_value;

    /** Maximum acceptable PegIn transaction fee in satoshis. */
    uint64_t pegin_max_fee;
} vault_group_t;

/**
 * @brief Vault intent — all parameters received via APPROVE_VAULT_INTENT (INS 0x80).
 *
 * Populated in three phases:
 *   P1=0x00  TLV scalar parsing  (12 mandatory fields, tag 2B + len 1B)
 *   P1=0x01  Per-vault TLV group parsing (vault_count groups, 6 fields each)
 *   P1=0x02  Key batch TLV (keeper_count keepers, then challenger_count challengers)
 *
 * Valid only while session state != VAULT_STATE_IDLE.
 * Must be zeroed (explicit_bzero) on any session invalidation.
 */
typedef struct {
    // -------------------------------------------------------------------------
    // Scalar fields (12) — parsed from TLV P1=0x00
    // -------------------------------------------------------------------------

    /** Protocol structure type — must equal the vault structure type constant. */
    uint8_t structure_type;

    /** Protocol version — must equal the current protocol version constant. */
    uint8_t version;

    /** BIP-44 coin type — must equal BIP44_COIN_TYPE for the active network. */
    uint32_t coin_type;

    /** PegIn CSV timelock P in blocks. Range: [72, 1008] inclusive. */
    uint16_t pegin_csv_timelock;

    /** HTLC refund timelock T_refund in blocks. Range: [72, 1008] inclusive. */
    uint16_t htlc_refund_timelock;

    /** Payout timelock t2 in blocks. Range: (90, 4032) exclusive. */
    uint16_t payout_timelock;

    /** Number of keeper keys. Range: [1, VAULT_MAX_KEEPERS] inclusive. */
    uint8_t keeper_count;

    /** Number of challenger keys. Range: [1, VAULT_MAX_CHALLENGERS] inclusive. */
    uint8_t challenger_count;

    /** Number of vault groups in this Pre-PegIn. Range: [1, VAULT_MAX_VAULTS] inclusive. */
    uint8_t vault_count;

    /** Depositor BIP-32 derivation path: m/86'/coin_type'/account'/change/index. */
    uint32_t depositor_path[VAULT_DEPOSITOR_PATH_LEN];

    /** Depositor x-only public key. Derived from depositor_path at APPROVE_VAULT_INTENT time. */
    uint8_t depositor_pk[VAULT_XONLY_PUBKEY_LEN];

    /** Base fee rate in sat/vbyte (used to bound Payout transaction fees). */
    uint64_t base_fee_rate;

    /** Pre-PegIn transaction ID (little-endian). */
    uint8_t prepegin_txid[VAULT_HASH256_LEN];

    // -------------------------------------------------------------------------
    // Per-vault groups — parsed from TLV P1=0x01
    // -------------------------------------------------------------------------

    /** Per-vault groups, indexed [0..vault_count-1] in ascending htlc_vout order. */
    vault_group_t groups[VAULT_MAX_VAULTS];

    // -------------------------------------------------------------------------
    // Key arrays — loaded via TLV P1=0x02
    // -------------------------------------------------------------------------

    /** Keeper x-only public keys, sorted ascending lexicographically. */
    uint8_t keeper_pks[VAULT_MAX_KEEPERS][VAULT_XONLY_PUBKEY_LEN];

    /** Challenger x-only public keys, sorted ascending lexicographically. */
    uint8_t challenger_pks[VAULT_MAX_CHALLENGERS][VAULT_XONLY_PUBKEY_LEN];
} vault_intent_t;
