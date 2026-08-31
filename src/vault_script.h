#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "cx.h"
#include "vault_intent.h"
#include "../bitcoin_app_base/src/common/script.h"

/**
 * Maximum byte length of any single vault leaf script.
 *
 * Dominant leaves (K = VAULT_MAX_KEEPERS = 32, M = VAULT_MAX_CHALLENGERS = 32):
 *   HTLC Leaf 0:           ~2289 bytes  (<D> OP_CSV || <VP> || VK K-of-K || UC M-of-M)
 *   Assert:0 Payout leaf:  ~2228 bytes  (<Claimer> OP_CSV || AppChall K-of-K || UC M-of-M)
 *   Vault UTXO leaf:       ~2228 bytes  (<D> || <VP> || VK K-of-K || UC M-of-M || <t1> OP_CSV)
 *
 * All are below 2560.  The HTLC Leaf 0 is the actual worst case.
 *
 * Callers that pass a local stack buffer must be aware of device RAM limits;
 * prefer a static or global buffer for the largest leaves.
 */
/* Direct-push pseudo-opcodes (0x01..0x4b): implicit in Bitcoin script encoding,
 * absent from the upstream opcodetype enum.  Bitcoin consensus constants —
 * these values are immutable (changing them would be a hard fork). */
#define OP_1            0x51u /* SegWit version 1 (first byte of every P2TR scriptPubKey) */
#define OP_RETURN       0x6Au /* marks an output provably unspendable */
#define OP_PUSHBYTES_1  0x01u
#define OP_PUSHBYTES_2  0x02u
#define OP_PUSHBYTES_32 0x20u
#define OP_PUSHBYTES_33 0x21u
#define OP_PUSHBYTES_75 0x4bu

#define TAPSCRIPT_LEAF_VERSION      0xC0u /* BIP-341 tapscript leaf version */
#define VAULT_SCRIPT_MAX_LEN        2560
#define VAULT_P2TR_SCRIPTPUBKEY_LEN (2 + VAULT_XONLY_PUBKEY_LEN) /* OP_1 OP_PUSHBYTES_32 <key> */

/* Lower bound on a host-provided payout scriptPubKey — a VaultProvider or VaultKeeper
 * address registered in the vault contract, which the device cannot derive and so accepts
 * as-is.  P2WPKH is the shortest standard output script: the HLD admits "any standard
 * address type", and anything shorter is non-standard and unspendable, so it is refused
 * rather than signed over.  The upper bound lives in sign_psbt_validate.c, where the
 * base app's sighash constraint that sets it is in scope. */
#define VAULT_PAYOUT_SPK_MIN_LEN 22u

/** Byte length of the depositor-claim leaf: OP_PUSHBYTES_32 <D[32]> OP_CHECKSIG */
#define VAULT_DEPOSITOR_CLAIM_LEAF_LEN (1u + VAULT_XONLY_PUBKEY_LEN + 1u)
/** Byte length of the NoPayout / Assert:0 leaf: OP_PUSHBYTES_32 <D> OP_CHECKSIGVERIFY
 * OP_PUSHBYTES_32 <C> OP_CHECKSIG */
#define VAULT_NOPAYOUT_LEAF_LEN \
    (1u + VAULT_XONLY_PUBKEY_LEN + 1u + 1u + VAULT_XONLY_PUBKEY_LEN + 1u)

/* Offsets of the first signer group that follows the leading OP_PUSHBYTES_32 <key[32]>
 * OP_CHECKSIGVERIFY in every depositor-signed leaf.  Together the two bytes they name
 * separate the leaves whose leading 34 bytes are otherwise identical:
 *
 *   Assert:0 payout / Assert   <Claimer> OP_CHECKSIGVERIFY <challenger multisig> ...
 *   Vault UTXO                 <D> OP_CHECKSIGVERIFY <VaultProvider> OP_CHECKSIGVERIFY ...
 *
 * A multisig group always opens with a 32-byte key push terminated by OP_CHECKSIG, so
 * OP_CHECKSIG at VAULT_LEAF_GROUP0_OP_OFF means "a signer group starts here" and
 * OP_CHECKSIGVERIFY means "another single required signer follows".  Reading these
 * offsets requires a script strictly longer than VAULT_LEAF_GROUP0_OP_OFF. */

/** Offset of the first signer group's key-push opcode. */
#define VAULT_LEAF_GROUP0_PUSH_OFF (1u + VAULT_XONLY_PUBKEY_LEN + 1u)
/** Offset of the opcode that terminates that group's first key. */
#define VAULT_LEAF_GROUP0_OP_OFF (VAULT_LEAF_GROUP0_PUSH_OFF + 1u + VAULT_XONLY_PUBKEY_LEN)

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
 * disabling key-path spending.  Value: BIP-341 lift_x(0x50929b74c1a04954
 * b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0).
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

/**
 * Incremental TapLeaf hash, for scripts too large to buffer (real Assert leaves are
 * 11.5-13.6 KB against a VAULT_SCRIPT_MAX_LEN read buffer).
 *
 * @p script_len must be the FULL script length and is required at init, because the
 * BIP-341 preimage puts varint(script_len) ahead of the script bytes.  Feed the script
 * with successive _update calls (excluding the PSBT value's trailing leaf-version byte),
 * then _final.  Equivalent to vault_taproot_leaf_hash over the same bytes.
 */
void vault_taproot_leaf_hash_stream_init(cx_sha256_t *ctx, uint32_t script_len);
void vault_taproot_leaf_hash_stream_update(cx_sha256_t *ctx, const uint8_t *data, size_t len);
void vault_taproot_leaf_hash_stream_final(cx_sha256_t *ctx, uint8_t out[VAULT_HASH256_LEN]);

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
 * @param claimer_idx  0 = VP; 1..keeper_count = VK_i; keeper_count+1 = Depositor.
 */
int vault_build_assert0_payout_leaf(const vault_intent_t *intent,
                                    int group_idx,
                                    int claimer_idx,
                                    uint8_t *buf,
                                    int buf_max);

/**
 * Build the Assert:0 leaf: <Depositor> OP_CHECKSIGVERIFY <Challenger_j> OP_CHECKSIG.
 *
 * The Depositor key comes from intent->depositor_pk.
 * Challengers are indexed 0..keeper_count-1 (VaultKeepers) then
 * keeper_count..keeper_count+challenger_count-1 (UniversalChallengers).
 *
 * @param challenger_idx  Index into the combined keeper+challenger list.
 * Returns byte count (68) on success, -1 on error.
 */
int vault_build_nopayout_leaf(const vault_intent_t *intent,
                              int challenger_idx,
                              uint8_t *buf,
                              int buf_max);

/* --------------------------------------------------------------------------
 * Assert leaf prefix (intent-bound)
 *
 * The Assert leaf's spending conditions live entirely in its prefix:
 *
 *   <Depositor> OP_CHECKSIGVERIFY
 *   <VaultKeepers N-of-N>          (intermediate, OP_NUMEQUALVERIFY)
 *   <UniversalChallengers M-of-M>  (intermediate, OP_NUMEQUALVERIFY)
 *
 * Everything after it is the WOTS verifier body, whose ~11 KB of host-chosen chain tips
 * the device cannot derive.  It does not need to: OP_CHECKSIGVERIFY and
 * OP_NUMEQUALVERIFY fail hard, so a leaf whose prefix matches the approved intent cannot
 * be spent without every keeper and challenger signature, whatever the body contains.
 * Verifying the prefix is therefore what makes the unverifiable remainder safe to sign
 * over; the taproot commitment alone only binds the leaf to the output being spent.
 *
 * The first group is the VaultKeepers because of btc-vault's dedicated depositor branch in
 * transactions/claim.rs derive_full_challengers: a depositor claimer takes the VaultKeepers
 * alone, with the VaultProvider excluded.  Not by set subtraction — the depositor is never a
 * VaultKeeper, so {VP, VK_1..VK_N} \ {Claimer} would retain VP.  That subtraction is the
 * VP/VK-claimer branch, which this device never signs: it holds only the depositor key.
 *
 * Real leaves are far past VAULT_SCRIPT_MAX_LEN and are never buffered, so the prefix is
 * compared while the leaf streams.  These two functions describe the expected bytes
 * without materialising them — at the 32/32 maximum the prefix is ~2.2 KB, which no
 * buffer available during a streaming read can hold.
 * ----------------------------------------------------------------------- */

/** Byte length of the expected Assert prefix, or -1 if the intent's key counts are unset. */
int vault_assert_prefix_len(const vault_intent_t *intent);

/** Expected Assert prefix byte at @p off, or -1 when @p off is at or past its end. */
int vault_assert_prefix_byte(const vault_intent_t *intent, uint32_t off);

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
 * Compute the SegWit txid of the PegIn transaction from the loaded intent.
 *
 * @param group_idx    Index into intent->groups[]; selects per-vault amounts and htlc_vout.
 * Valid only in Session 2: uses prepegin_txid and htlc_vout from the group.
 * Returns false if key derivation fails (clears out to zero).
 */
bool vault_compute_pegin_txid(const vault_intent_t *intent,
                              int group_idx,
                              uint8_t out[VAULT_HASH256_LEN]);
