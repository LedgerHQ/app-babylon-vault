#pragma once

#include <stdint.h>

// Maximum number of keepers / challengers supported by the protocol.
#define VAULT_MAX_KEEPERS     32
#define VAULT_MAX_CHALLENGERS 32

// BIP-32 derivation path length for the depositor key (BIP-86, exactly 5 levels).
#define VAULT_DEPOSITOR_PATH_LEN 5

// Size of an x-only Schnorr public key (BIP-340).
#define VAULT_XONLY_PUBKEY_LEN 32

// Size of a SHA-256 hash or Bitcoin txid.
#define VAULT_HASH256_LEN 32

/**
 * @brief Vault intent — all parameters received via APPROVE_VAULT_INTENT (INS 0x80).
 *
 * Populated in two phases:
 *   P1=0x00  TLV scalar parsing  (17 mandatory fields, tag 1B + len 1B)
 *   P1=0x01  Key batch streaming (keeper_count + challenger_count x-only keys)
 *
 * Valid only while session state != VAULT_STATE_IDLE.
 * Must be zeroed (explicit_bzero) on any session invalidation.
 */
typedef struct {
    // -------------------------------------------------------------------------
    // Scalar fields (17) — parsed from TLV P1=0x00
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

    /** Depositor BIP-32 derivation path: m/86'/coin_type'/account'/change/index. */
    uint32_t depositor_path[VAULT_DEPOSITOR_PATH_LEN];

    /** Total vault amount in satoshis. Must be > commission_fee + 2*DUST. */
    uint64_t vault_amount;

    /** Vault provider commission fee in satoshis. */
    uint64_t commission_fee;

    /** Depositor claim value in satoshis (Depositor Claim UTXO). */
    uint64_t depositor_claim_value;

    /** Base fee rate in sat/vbyte (used to bound Payout transaction fees). */
    uint64_t base_fee_rate;

    /** Maximum acceptable PegIn transaction fee in satoshis. */
    uint64_t pegin_max_fee;

    /** Vault provider x-only public key. */
    uint8_t vault_provider_pk[VAULT_XONLY_PUBKEY_LEN];

    /** Output index of the HTLC in the Pre-PegIn transaction. */
    uint32_t htlc_vout;

    /** Pre-PegIn transaction ID (little-endian). */
    uint8_t prepegin_txid[VAULT_HASH256_LEN];

    // -------------------------------------------------------------------------
    // Key arrays — streamed via TLV P1=0x01
    // -------------------------------------------------------------------------

    /** Keeper x-only public keys, sorted ascending lexicographically. */
    uint8_t keeper_pks[VAULT_MAX_KEEPERS][VAULT_XONLY_PUBKEY_LEN];

    /** Challenger x-only public keys, sorted ascending lexicographically. */
    uint8_t challenger_pks[VAULT_MAX_CHALLENGERS][VAULT_XONLY_PUBKEY_LEN];
} vault_intent_t;
