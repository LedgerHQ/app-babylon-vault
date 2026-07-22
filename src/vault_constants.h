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
#elif BIP44_COIN_TYPE == 1
/* coin_type 1 covers both Bitcoin signet and testnet3/testnet4, which the spec maps to
 * distinct canonicalNetworkNames ("bitcoin-signet" vs "bitcoin-testnet").  Require an
 * explicit -DVAULT_TARGET_SIGNET sentinel so a testnet3/4 build fails loudly rather than
 * silently producing the wrong network name and an incompatible HKDF root. */
#ifndef VAULT_TARGET_SIGNET
#error \
    "BIP44_COIN_TYPE=1 covers both signet and testnet3/4. " \
    "Define VAULT_TARGET_SIGNET to confirm this build targets Bitcoin signet. " \
    "Add a separate #elif guarded by VAULT_TARGET_TESTNET for a testnet3/4 build."
#endif
#define VAULT_CANONICAL_NETWORK_NAME "bitcoin-signet"
#else
#error \
    "BIP44_COIN_TYPE has no mapped canonicalNetworkName — add an explicit entry or use 0 (mainnet) or 1 (signet)."
#endif

/**
 * P2TR CPFP anchor value in satoshis (546 sat; chosen >= the 330-sat P2TR relay
 * dust limit so every anchor output stays above dust).
 *
 * Used as the value of the last payout output (CPFP anchor to the Claimer)
 * and as the Assert:0 UTXO input value in fee calculations.
 *
 * Used to enforce: vault_amount > commission_fee + 2 * VAULT_DUST_LIMIT,
 * guaranteeing all payout outputs are above the relay dust limit.
 */
#define VAULT_DUST_LIMIT ((uint64_t) 546u)

/* DERIVE_CONTEXT_HASH input limits (spec §2.1). */

/** Maximum byte length of the appName field. */
#define VAULT_APP_NAME_MAX_LEN 64u

/** Maximum byte length of the context field (spec §2.1: 1024 bytes / 2048 hex chars). */
#define VAULT_CONTEXT_MAX_LEN 1024u

/** Maximum depth of a BIP-32 derivation path (number of levels). */
#define VAULT_MAX_PATH_DEPTH 10u

/** Compressed SEC1 public key length: 1-byte parity prefix + 32-byte x-coordinate. */
#define VAULT_COMPRESSED_PUBKEY_LEN 33u

/**
 * Maximum byte length of a BIP-32 path string including NUL terminator.
 * Worst case: "m/" + VAULT_MAX_PATH_DEPTH components of up to 11 chars
 * ("2147483647'") separated by "/" + NUL = 2 + 10×11 + 9 + 1 = 122 bytes.
 * Rounded up to 128 for alignment.
 */
#define VAULT_PATH_STR_SIZE 128u

/** Maximum number of vault groups per Pre-PegIn batch (spec §3). */
#define VAULT_MAX_VAULTS 10u

/* Timelock range bounds (block counts). */

/** Minimum inclusive bound for pegin_csv_timelock and htlc_refund_timelock. */
#define VAULT_TIMELOCK_MIN 72u

/** Maximum inclusive bound for pegin_csv_timelock. */
#define VAULT_TIMELOCK_MAX 1008u

/** Maximum inclusive bound for htlc_refund_timelock (v22: ~1 month). */
#define VAULT_HTLC_REFUND_TIMELOCK_MAX 4320u

/** Exclusive lower bound for payout_timelock. */
#define VAULT_PAYOUT_TIMELOCK_MIN 90u

/** Exclusive upper bound for payout_timelock. */
#define VAULT_PAYOUT_TIMELOCK_MAX 4032u

/** P2A anchor output value in satoshis (PegIn Output 2). Floored at relay-dust. */
#define P2A_ANCHOR_VALUE ((uint64_t) 240u)
