#pragma once

#include <stdint.h>

/**
 * Protocol constants for the Babylon Vault application.
 */

/*
 * BIP44_COIN_TYPE must be supplied by the build system via -DBIP44_COIN_TYPE=<n>
 * in the Makefile (e.g. APP_LOAD_PARAMS / TARGET_FLAGS).
 * It is NOT defined here so that mainnet and testnet builds stay distinct.
 */
#ifndef BIP44_COIN_TYPE
#error "BIP44_COIN_TYPE is not defined. Pass -DBIP44_COIN_TYPE=<n> via the Makefile."
#endif

/**
 * Expected value of the structure_type TLV field.
 *
 * TODO: confirm exact value with protocol authors before shipping.
 * Placeholder: 0x01.
 */
#define VAULT_STRUCTURE_TYPE ((uint8_t) 0x01)

/**
 * Expected value of the version TLV field.
 * Spec: "MUST BE equal to 0x01".
 */
#define VAULT_PROTOCOL_VERSION ((uint8_t) 0x01)

/**
 * Canonical network name fed (as SHA-256) into the DERIVE_CONTEXT_HASH HKDF `info`,
 * per babylon-toolkit derive-context-hash spec v2.x §2.2. Selected at build time from
 * the coin type: mainnet (SLIP-44 0) → "bitcoin-mainnet"; the testnet build targets
 * Bitcoin signet (see Makefile) → "bitcoin-signet".
 */
#if BIP44_COIN_TYPE == 0
#define VAULT_CANONICAL_NETWORK_NAME "bitcoin-mainnet"
#else
#define VAULT_CANONICAL_NETWORK_NAME "bitcoin-signet"
#endif

/**
 * P2TR dust threshold in satoshis.
 *
 * Outputs below this value are uneconomic to spend and rejected by node relay
 * policy. All Babylon Vault outputs are P2TR, so 330 sat applies throughout.
 *
 * Used to enforce: vault_amount > commission_fee + 2 * VAULT_DUST_LIMIT,
 * guaranteeing the Vault UTXO and Depositor Claim UTXO are both above dust.
 */
#define VAULT_DUST_LIMIT ((uint64_t) 330u)

/* Timelock range bounds (block counts). */

/** Minimum inclusive bound for pegin_csv_timelock and htlc_refund_timelock. */
#define VAULT_TIMELOCK_MIN 72u

/** Maximum inclusive bound for pegin_csv_timelock and htlc_refund_timelock. */
#define VAULT_TIMELOCK_MAX 1008u

/** Exclusive lower bound for payout_timelock. */
#define VAULT_PAYOUT_TIMELOCK_MIN 90u

/** Exclusive upper bound for payout_timelock. */
#define VAULT_PAYOUT_TIMELOCK_MAX 4032u
