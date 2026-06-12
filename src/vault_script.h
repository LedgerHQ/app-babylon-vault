#pragma once

#include <stdint.h>
#include "vault_intent.h"

/**
 * Maximum byte length of any single vault leaf script.
 *
 * Worst case: HTLC Leaf 0 with VAULT_MAX_KEEPERS=32 keepers and
 * VAULT_MAX_CHALLENGERS=32 challengers (~2289 bytes).  2560 provides headroom.
 *
 * Callers that pass a local stack buffer must be aware of device RAM limits;
 * prefer a static or global buffer for the largest leaves.
 */
#define VAULT_SCRIPT_MAX_LEN 2560

/* --------------------------------------------------------------------------
 * Taproot primitive
 * ----------------------------------------------------------------------- */

/**
 * Compute the BIP-341 TapLeaf hash for a tapscript.
 *
 * @param script      Raw tapscript bytes.
 * @param script_len  Length of the script in bytes.
 * @param out         32-byte output buffer for the leaf hash.
 */
void vault_taproot_leaf_hash(const uint8_t *script, int script_len, uint8_t out[32]);

/* --------------------------------------------------------------------------
 * Per-leaf raw script builders
 *
 * Each function writes the raw tapscript bytes into buf[0..buf_max-1] and
 * returns the byte count written, or -1 if buf_max is too small.
 *
 * Precondition: intent->keeper_pks and intent->challenger_pks are pre-sorted
 * ascending (enforced by APPROVE_VAULT_INTENT / NAPPS-1372).
 * Precondition for htlc_leaf0: intent->depositor_pk is pre-populated.
 * ----------------------------------------------------------------------- */

int vault_build_htlc_leaf0(const vault_intent_t *intent,
                           const uint8_t h[32],
                           uint8_t *buf,
                           int buf_max);

int vault_build_htlc_leaf1(const vault_intent_t *intent, uint8_t *buf, int buf_max);

int vault_build_vault_utxo_leaf(const vault_intent_t *intent, uint8_t *buf, int buf_max);

int vault_build_depositor_claim_leaf(const vault_intent_t *intent, uint8_t *buf, int buf_max);

/**
 * @param claimer_idx  0 = VP is claimer; 1..keeper_count = VK_i is claimer.
 */
int vault_build_assert0_payout_leaf(const vault_intent_t *intent,
                                    int claimer_idx,
                                    uint8_t *buf,
                                    int buf_max);

/* --------------------------------------------------------------------------
 * Derived outputs
 * ----------------------------------------------------------------------- */

void vault_build_htlc_merkle_root(const vault_intent_t *intent,
                                  const uint8_t h[32],
                                  uint8_t out[32]);

void vault_build_htlc_scriptpubkey(const vault_intent_t *intent,
                                   const uint8_t h[32],
                                   uint8_t out[34]);

void vault_build_vault_utxo_scriptpubkey(const vault_intent_t *intent, uint8_t out[34]);

void vault_build_depositor_claim_scriptpubkey(const vault_intent_t *intent, uint8_t out[34]);

/**
 * @param claimer_idx  0 = VP; 1..keeper_count = VK_i.
 */
void vault_build_assert0_payout_scriptpubkey(const vault_intent_t *intent,
                                             int claimer_idx,
                                             uint8_t out[34]);

/**
 * Compute the SegWit txid of the PegIn transaction from the loaded intent.
 *
 * Valid only in Session 2: uses prepegin_txid and htlc_vout from the intent.
 */
void vault_compute_pegin_txid(const vault_intent_t *intent, uint8_t out[32]);
