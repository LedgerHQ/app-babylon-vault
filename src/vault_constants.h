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

/* Timelock range bounds (block counts). */

/** Minimum inclusive bound for pegin_csv_timelock and htlc_refund_timelock. */
#define VAULT_TIMELOCK_MIN 72u

/** Maximum inclusive bound for pegin_csv_timelock and htlc_refund_timelock. */
#define VAULT_TIMELOCK_MAX 1008u

/** Exclusive lower bound for payout_timelock. */
#define VAULT_PAYOUT_TIMELOCK_MIN 90u

/** Exclusive upper bound for payout_timelock. */
#define VAULT_PAYOUT_TIMELOCK_MAX 4032u
