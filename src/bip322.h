#pragma once

#include <stdbool.h>
#include <stdint.h>

/*
 * BIP-322 proof-of-possession helpers for the Babylon Vault application.
 *
 * The PoP flow accepts only the strict grammar
 *   <eth_address>:<chain_id>:pegin:<registry_address>
 * and builds the BIP-322 "to_spend" virtual transaction from the validated
 * message and the depositor's BIP-86 output key.
 */

/* String buffer sizes (include NUL terminator). */
#define BIP322_ETH_ADDR_STR_LEN 43 /* "0x" + 40 lowercase hex + NUL */
#define BIP322_CHAIN_ID_STR_LEN 21 /* up to 20 decimal digits + NUL */

/* Maximum raw byte length of the complete PoP message string. */
#define BIP322_POP_MSG_MAX_LEN 112 /* eth(42) + ':' + chain_id(20) + ":pegin:" + registry(42) */

/*
 * PSBT global proprietary key carrying the PoP message.
 * Format: 0xFC || 0x06 || "bvault" || 0x00
 *   0xFC = PSBT_GLOBAL_PROPRIETARY
 *   0x06 = identifier length
 *   "bvault" = namespace identifier
 *   0x00 = subtype (POP_MESSAGE)
 */
/* Script opcode constants used in BIP-322 to_spend/to_sign construction and validation. */
#define BIP322_OP_0          0x00u /* OP_0 */
#define BIP322_OP_1          0x51u /* OP_1 */
#define BIP322_OP_RETURN     0x6Au /* OP_RETURN */
#define BIP322_PUSHBYTES_32  0x20u /* PUSHBYTES_32 */
#define BIP322_SCRIPT_LEN_34 0x22u /* varint for 34-byte script */

#define BIP322_PSBT_PROP_KEY_LEN 9
extern const uint8_t BIP322_PSBT_PROP_POP_MSG_KEY[BIP322_PSBT_PROP_KEY_LEN];

/*
 * Parse and validate the PoP message grammar.
 *
 * Accepts exactly four colon-delimited fields:
 *   field 0: "0x" + 40 lowercase hex chars (Ethereum address)
 *   field 1: decimal chain_id, no leading zeros unless "0"
 *   field 2: literal "pegin"
 *   field 3: "0x" + 40 lowercase hex chars (registry address)
 *
 * Returns true and fills the three output buffers on success; returns false on
 * any grammar violation. Output buffers may be partially written on failure;
 * callers must discard them when the return value is false.
 */
bool bip322_parse_pop_message(const uint8_t *msg,
                              int msg_len,
                              char eth_addr[BIP322_ETH_ADDR_STR_LEN],
                              char chain_id[BIP322_CHAIN_ID_STR_LEN],
                              char registry[BIP322_ETH_ADDR_STR_LEN]);

/*
 * Compute the BIP-322 "to_spend" virtual transaction txid.
 *
 * Reconstructs the virtual transaction from the validated message and the
 * depositor's BIP-86 tweaked output key (32-byte x-only, as it appears in the
 * P2TR scriptPubKey "OP_1 PUSHBYTES_32 <key>").  The txid is the double-SHA256
 * of the legacy serialization, reversed to Bitcoin wire format.
 *
 * Returns true and writes 32 bytes to txid_out on success; returns false if
 * the hash computation fails.
 */
bool bip322_compute_to_spend_txid(const uint8_t *message,
                                  int msg_len,
                                  const uint8_t tweaked_key[32],
                                  uint8_t txid_out[32]);
