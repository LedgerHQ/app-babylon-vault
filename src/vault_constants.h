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

/** Expected value of the structure_type TLV field (spec §3.1: MUST BE 0x01). */
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
/* Note: the HLD uses the label "bitcoin-testnet"; this app targets Bitcoin signet, so the
 * correct canonicalNetworkName per the protocol spec is "bitcoin-signet". */
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

/** BIP-86 path depth for standalone signing (m/86'/coin_type'/0'/change/index). */
#define VAULT_STANDALONE_PATH_LEN 5u

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

/**
 * Absolute upper bound on the Pre-PegIn maximum fee in satoshis.
 * No legitimate Pre-PegIn should consume more than 1 BTC in network fees.
 */
#define PREPEGIN_MAX_FEE_LIMIT ((uint64_t) 100000000u)

/* Timelock range bounds (block counts). */

/** Minimum inclusive bound for pegin_csv_timelock and htlc_refund_timelock. */
#define VAULT_TIMELOCK_MIN 72u

/** Maximum inclusive bound for pegin_csv_timelock. */
#define VAULT_TIMELOCK_MAX 1008u

/** Maximum inclusive bound for htlc_refund_timelock (v22: ~1 month). */
#define VAULT_HTLC_REFUND_TIMELOCK_MAX 4320u

/** Minimum valid value for payout t2 CSV timelock (inclusive). */
#define VAULT_PAYOUT_TIMELOCK_MIN 90u

/** Maximum valid value for payout t2 CSV timelock (inclusive). */
#define VAULT_PAYOUT_TIMELOCK_MAX 4032u

/** P2A anchor output value in satoshis (PegIn Output 2). Floored at relay-dust. */
#define P2A_ANCHOR_VALUE ((uint64_t) 240u)

/** Two-byte witness program of a P2A (pay-to-anchor / ephemeral anchor) output.
 *  Full script: OP_1 OP_PUSHBYTES_2 P2A_WITNESS_PROG_BYTE0 P2A_WITNESS_PROG_BYTE1 */
#define P2A_WITNESS_PROG_BYTE0 0x4Eu
#define P2A_WITNESS_PROG_BYTE1 0x73u

/* BIP-68 nSequence control bits (§3). */
#define BIP68_DISABLE_FLAG    0x80000000u /* disables relative-locktime interpretation */
#define BIP68_TIME_BASED_FLAG 0x00400000u /* 0 = block count; 1 = 512-second units */
#define BIP68_SEQUENCE_MASK   0x0000FFFFu /* 16-bit block / time-count field */

/* BIP-86 key derivation purpose level (m/86'/…). */
#define BIP86_PURPOSE 86u

/* PegIn transaction fields (TRUC v3, nLockTime-enabled sequence). */
#define PEGIN_TX_VERSION  3u          /* TRUC (BIP-431) v3; satisfies CSV (BIP-68) v>=2 */
#define PEGIN_TX_SEQUENCE 0xFFFFFFFEu /* enables nLockTime; one below SEQUENCE_FINAL */
#define SEQUENCE_FINAL    0xFFFFFFFFu /* RBF-disabled, no CSV, no nLockTime */

/* Maximum taptree depth for host-provided connector UTXOs.
 * A Huffman tree over 2 + (VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS) = 66 leaves
 * has max depth ceil(log2(66)) = 7. */
#define VAULT_MAX_TAPTREE_DEPTH 7u

/** Bytes of a standalone leaf script captured verbatim for shape discrimination.
 *  The widest discriminator reads VAULT_LEAF_GROUP0_OP_OFF (byte 67), the opcode closing
 *  the first key of the Assert challenger multisig, so 68 bytes are needed.  Capturing
 *  the whole first signer group rather than only its opening push costs 33 bytes of BSS
 *  and is what keeps the Assert pattern from matching a leaf whose middle is a no-op. */
#define VAULT_LEAF_PREFIX_LEN 68u

/** Upper bound on a leaf script the device will hash by streaming.
 *
 *  Only the Assert leaf exceeds VAULT_SCRIPT_MAX_LEN.  Its size is fixed at compile
 *  time in btc-vault by BIG_BLOCK_DIGIT_COUNTS = [64, 64] and
 *  ASSERT_WOTS_NUM_STREAMS = 1; only the signer prefix varies with the challenger
 *  counts, giving 11,526 B at 1/1 and 13,636 B at the 32/32 maximum.  16 KB leaves
 *  headroom for the prefix.
 *
 *  Scope of the cap: it bounds what the device will *process*.  A value declaring
 *  more than this is refused before any byte of it is hashed or buffered, and the
 *  read is failed once it returns.  It does NOT bound the exchange itself: the base
 *  app's call_stream_preimage takes a length callback returning void, so the app has
 *  no way to abort a read the host has already started, and the host still drives one
 *  CCMD_GET_MORE_ELEMENTS round-trip per chunk of whatever length it declared.
 *  Bounding the round-trips requires an abort channel in the base app — see
 *  docs/upstream-stream-preimage-abort.md. */
#define VAULT_ASSERT_SCRIPT_MAX_LEN 16384u
