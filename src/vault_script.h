#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "vault_intent.h"
#include "../bitcoin_app_base/src/common/script.h"

/**
 * Maximum byte length of any single vault leaf script.
 *
 * Worst case: HTLC Leaf 0 with VAULT_MAX_KEEPERS=32 keepers and
 * VAULT_MAX_CHALLENGERS=32 challengers (~2289 bytes).  2560 provides headroom.
 *
 * Callers that pass a local stack buffer must be aware of device RAM limits;
 * prefer a static or global buffer for the largest leaves.
 */
/* Direct-push pseudo-opcodes (0x01..0x4b): implicit in Bitcoin script encoding,
 * absent from the upstream opcodetype enum.  Bitcoin consensus constants —
 * these values are immutable (changing them would be a hard fork). */
#define OP_PUSHBYTES_1  0x01u
#define OP_PUSHBYTES_2  0x02u
#define OP_PUSHBYTES_32 0x20u
#define OP_PUSHBYTES_33 0x21u
#define OP_PUSHBYTES_75 0x4bu

#define TAPSCRIPT_LEAF_VERSION      0xC0u /* BIP-341 tapscript leaf version */
#define VAULT_SCRIPT_MAX_LEN        2560
#define VAULT_P2TR_SCRIPTPUBKEY_LEN (2 + VAULT_XONLY_PUBKEY_LEN) /* OP_1 OP_PUSHBYTES_32 <key> */

/* --------------------------------------------------------------------------
 * Low-level taproot crypto primitives (implemented in vault_script.c)
 * ----------------------------------------------------------------------- */

/**
 * Compute the BIP-341 output key: output_key = taproot_tweak(pubkey, h[0..h_len]).
 * Returns 0 on success, non-zero on failure.
 */
int crypto_tr_tweak_pubkey(const uint8_t pubkey[VAULT_XONLY_PUBKEY_LEN],
                           const uint8_t *h,
                           size_t h_len,
                           uint8_t *y_parity,
                           uint8_t out[VAULT_XONLY_PUBKEY_LEN]);

/**
 * NUMS x-only public key used as the internal key for all vault P2TR outputs,
 * disabling key-path spending.  Value: SHA256("nothing_up_my_sleeve").
 */
extern const uint8_t VAULT_NUMS_XONLY[VAULT_XONLY_PUBKEY_LEN];

/** BIP-341 TapBranch: sort-and-hash the two child hashes into out. */
void crypto_tr_combine_taptree_hashes(const uint8_t left[VAULT_HASH256_LEN],
                                      const uint8_t right[VAULT_HASH256_LEN],
                                      uint8_t out[VAULT_HASH256_LEN]);

/* --------------------------------------------------------------------------
 * Taproot leaf hash
 * ----------------------------------------------------------------------- */

/**
 * Compute the BIP-341 TapLeaf hash for a tapscript.
 *
 * @param script      Raw tapscript bytes.
 * @param script_len  Length of the script in bytes.
 * @param out         Output buffer for the leaf hash (VAULT_HASH256_LEN bytes).
 */
void vault_taproot_leaf_hash(const uint8_t *script, int script_len, uint8_t out[VAULT_HASH256_LEN]);

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

/**
 * @param group_idx    Index into intent->groups[]; selects which vault's VP key is used.
 */
int vault_build_htlc_leaf0(const vault_intent_t *intent,
                           int group_idx,
                           const uint8_t h[VAULT_HASH256_LEN],
                           uint8_t *buf,
                           int buf_max);

int vault_build_htlc_leaf1(const vault_intent_t *intent, uint8_t *buf, int buf_max);

/**
 * @param group_idx    Index into intent->groups[]; selects which vault's VP key is used.
 */
int vault_build_vault_utxo_leaf(const vault_intent_t *intent,
                                int group_idx,
                                uint8_t *buf,
                                int buf_max);

int vault_build_depositor_claim_leaf(const vault_intent_t *intent, uint8_t *buf, int buf_max);

/**
 * @param group_idx    Index into intent->groups[]; selects which vault's VP key is used.
 * @param claimer_idx  0 = VP is claimer; 1..keeper_count = VK_i is claimer.
 */
int vault_build_assert0_payout_leaf(const vault_intent_t *intent,
                                    int group_idx,
                                    int claimer_idx,
                                    uint8_t *buf,
                                    int buf_max);

/* --------------------------------------------------------------------------
 * Derived outputs
 * ----------------------------------------------------------------------- */

/**
 * @param group_idx    Index into intent->groups[]; selects which vault's VP key is used.
 */
bool vault_build_htlc_merkle_root(const vault_intent_t *intent,
                                  int group_idx,
                                  const uint8_t h[VAULT_HASH256_LEN],
                                  uint8_t out[VAULT_HASH256_LEN]);

/**
 * @param group_idx    Index into intent->groups[]; selects which vault's VP key is used.
 */
bool vault_build_htlc_scriptpubkey(const vault_intent_t *intent,
                                   int group_idx,
                                   const uint8_t h[VAULT_HASH256_LEN],
                                   uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]);

/**
 * @param group_idx    Index into intent->groups[]; selects which vault's VP key is used.
 */
bool vault_build_vault_utxo_scriptpubkey(const vault_intent_t *intent,
                                         int group_idx,
                                         uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]);

bool vault_build_depositor_claim_scriptpubkey(const vault_intent_t *intent,
                                              uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]);

/**
 * @param group_idx    Index into intent->groups[]; selects which vault's VP key is used.
 * @param claimer_idx  0 = VP; 1..keeper_count = VK_i.
 */
bool vault_build_assert0_payout_scriptpubkey(const vault_intent_t *intent,
                                             int group_idx,
                                             int claimer_idx,
                                             uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]);

/**
 * Compute the SegWit txid of the PegIn transaction from the loaded intent.
 *
 * @param group_idx    Index into intent->groups[]; selects per-vault amounts and htlc_vout.
 * Valid only in Session 2: uses prepegin_txid and htlc_vout from the group.
 * Returns false if key derivation fails (clears out to zero).
 */
bool vault_compute_pegin_txid(const vault_intent_t *intent,
                              int group_idx,
                              uint8_t out[VAULT_HASH256_LEN]);
