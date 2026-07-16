#include "vault_script.h"
#include "vault_intent.h"
#include "vault_constants.h"
#include "globals.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * Crypto API — provided by:
 *   Device build : Ledger SDK (cx.h) + btcext bitcoin_app_base (crypto.c)
 *   Unit tests   : unit-tests/mocks/cx.h + unit-tests/mock_cx.c
 */
#include "cx.h"
#include "../bitcoin_app_base/src/common/script.h"

#define OP_PUSHBYTES_32 0x20u /* push exactly 32 bytes (x-only pubkey or hash) */

/* Bitcoin compact-size (varint) prefix bytes */
#define VARINT_PREFIX_2BYTE 0xFDu
#define VARINT_PREFIX_4BYTE 0xFEu
#define VARINT_PREFIX_8BYTE 0xFFu

/* PegIn transaction serialization constants */
#define PEGIN_TX_VERSION  3u          /* TRUC (BIP-431) v3; satisfies CSV (BIP-68) v>=2 */
#define PEGIN_TX_SEQUENCE 0xFFFFFFFEu /* enables nLockTime; one below SEQUENCE_FINAL */
#define PEGIN_TX_LOCKTIME 0u
/* 4(ver) + 1(in_cnt) + 41(input) + 1(out_cnt) + 43(vault) + 43(claim) + 13(P2A) + 4(lock) */
#define PEGIN_TX_SIZE 150u /* exact non-witness serialization length */

/* Forward-declare the three btcext taproot functions vault_script.c uses.
 * On device these are implemented in bitcoin_app_base/src/crypto.c and
 * linked via the btcext base; in tests they come from mock_cx.c. */
void crypto_tr_tapleaf_hash_init(cx_sha256_t *ctx);
void crypto_tr_combine_taptree_hashes(const uint8_t left[VAULT_HASH256_LEN],
                                      const uint8_t right[VAULT_HASH256_LEN],
                                      uint8_t out[VAULT_HASH256_LEN]);
int crypto_tr_tweak_pubkey(const uint8_t pubkey[VAULT_XONLY_PUBKEY_LEN],
                           const uint8_t *h,
                           size_t h_len,
                           uint8_t *y_parity,
                           uint8_t out[VAULT_XONLY_PUBKEY_LEN]);

/* --------------------------------------------------------------------------
 * Local streaming-hash helpers — thin wrappers around cx_hash_no_throw.
 * ----------------------------------------------------------------------- */

static inline void _hash_update(cx_hash_t *ctx, const void *data, size_t n) {
    (void) cx_hash_no_throw(ctx, 0, (const uint8_t *) data, n, NULL, 0);
}

static inline void _hash_update_u8(cx_hash_t *ctx, uint8_t b) {
    (void) cx_hash_no_throw(ctx, 0, &b, 1u, NULL, 0);
}

static inline void _hash_final(cx_hash_t *ctx, uint8_t out[VAULT_HASH256_LEN]) {
    (void) cx_hash_no_throw(ctx, (int) CX_LAST, NULL, 0, out, VAULT_HASH256_LEN);
}

/* --------------------------------------------------------------------------
 * Bitcoin compact-size (varint) encoder — used for script-length prefix in
 * the TapLeaf hash construction.
 * Returns the number of bytes written into buf (1, 3, 5, or 9).
 * ----------------------------------------------------------------------- */

static int _varint_write(uint8_t *buf, uint64_t v) {
    if (v < VARINT_PREFIX_2BYTE) {
        buf[0] = (uint8_t) v;
        return 1;
    }
    if (v <= 0xFFFFu) {
        buf[0] = VARINT_PREFIX_2BYTE;
        buf[1] = (uint8_t) (v);
        buf[2] = (uint8_t) (v >> 8);
        return 3;
    }
    if (v <= 0xFFFFFFFFu) {
        buf[0] = VARINT_PREFIX_4BYTE;
        for (int i = 1; i <= 4; i++) buf[i] = (uint8_t) (v >> ((i - 1) * 8));
        return 5;
    }
    buf[0] = VARINT_PREFIX_8BYTE;
    for (int i = 1; i <= 8; i++) buf[i] = (uint8_t) (v >> ((i - 1) * 8));
    return 9;
}

/* --------------------------------------------------------------------------
 * NUMS internal key — lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f
 *                            28ec96d547bfee9ace803ac0)
 * All vault P2TR outputs use this x-only key so no key-path spend is possible.
 * ----------------------------------------------------------------------- */

const uint8_t VAULT_NUMS_XONLY[VAULT_XONLY_PUBKEY_LEN] = {
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
};

/* --------------------------------------------------------------------------
 * _push_number  (static)
 *
 * Emits a complete Bitcoin Script number push into buf and returns the byte
 * count written (opcode + any data bytes included).
 *
 *   value == 0        → OP_0  (0x00), 1 byte
 *   1 <= value <= 16  → OP_1..OP_16 (0x51..0x60), 1 byte
 *   value > 16        → OP_PUSHBYTES_N + N little-endian data bytes; no sign
 *                        byte needed (all values are non-negative timelocks or
 *                        key counts in [1, 4032])
 *
 * Used for CSV timelock operands and N-of-N multisig threshold pushes.
 * ----------------------------------------------------------------------- */

static int _push_number(uint32_t value, uint8_t *buf) {
    if (value == 0u) {
        buf[0] = OP_0;
        return 1;
    }
    if (value <= 16u) {
        buf[0] = (uint8_t) (OP_1 - 1u + value);
        return 1;
    }
    uint8_t tmp[5]; /* 4 data bytes + 1 possible sign-byte extension */
    int n = 0;
    uint32_t v = value;
    while (v) {
        tmp[n++] = (uint8_t) (v & 0xFFu);
        v >>= 8;
    }
    if (tmp[n - 1] & 0x80u) tmp[n++] = 0x00u;
    buf[0] = (uint8_t) n;
    memcpy(buf + 1, tmp, (size_t) n);
    return 1 + n;
}

/* --------------------------------------------------------------------------
 * vault_taproot_leaf_hash
 *
 * BIP-341 TapLeaf hash: tagged_hash("TapLeaf", 0xC0 || varint(len) || script)
 * where 0xC0 is the tapscript leaf version.
 * ----------------------------------------------------------------------- */

void vault_taproot_leaf_hash(const uint8_t *script,
                             int script_len,
                             uint8_t out[VAULT_HASH256_LEN]) {
    if (script_len < 0) {
        memset(out, 0, VAULT_HASH256_LEN);
        return;
    }
    cx_sha256_t ctx;
    crypto_tr_tapleaf_hash_init(&ctx);
    _hash_update_u8(&ctx.header, TAPSCRIPT_LEAF_VERSION);
    /* VAULT_SCRIPT_MAX_LEN ≤ 0xFFFF → varint fits in 3 bytes; vbuf[5] is sufficient. */
    _Static_assert(VAULT_SCRIPT_MAX_LEN <= 0xFFFFu,
                   "varint buffer vbuf[5] assumes script length fits in 2 bytes; update if scripts "
                   "can exceed 64 KB");
    uint8_t vbuf[5];
    int vlen = _varint_write(vbuf, (uint64_t) script_len);
    _hash_update(&ctx.header, vbuf, (size_t) vlen);
    _hash_update(&ctx.header, script, (size_t) script_len);
    _hash_final(&ctx.header, out);
}

/* --------------------------------------------------------------------------
 * vault_taproot_tweak_scriptpubkey  (static)
 *
 * Computes the P2TR scriptPubKey (34 bytes: OP_1 OP_PUSHBYTES_32 <key>)
 * by tweaking the NUMS internal key with the given merkle root.
 * ----------------------------------------------------------------------- */

/* parity_out may be NULL when the caller does not need the parity bit.
 * NAPPS-1377 (signing) will pass a non-NULL pointer for the control block. */
static bool vault_taproot_tweak_scriptpubkey(const uint8_t merkle_root[VAULT_HASH256_LEN],
                                             uint8_t *parity_out,
                                             uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    uint8_t parity;
    uint8_t tweaked[VAULT_XONLY_PUBKEY_LEN];
    if (crypto_tr_tweak_pubkey(VAULT_NUMS_XONLY,
                               merkle_root,
                               VAULT_HASH256_LEN,
                               &parity,
                               tweaked) != 0) {
        memset(out, 0, VAULT_P2TR_SCRIPTPUBKEY_LEN);
        return false;
    }
    if (parity_out) *parity_out = parity;
    out[0] = OP_1;
    out[1] = OP_PUSHBYTES_32;
    memcpy(out + 2, tweaked, VAULT_XONLY_PUBKEY_LEN);
    return true;
}

/* --------------------------------------------------------------------------
 * encode_multisig_group  (static)
 *
 * Emits a tapscript N-of-N multisig fragment for the given key array.
 *
 *   is_final == 0 (intermediate): result is consumed by the next opcode.
 *     N=1 → <key> OP_CHECKSIGVERIFY
 *     N>1 → <key[0]> OP_CHECKSIG  <key[i]>… OP_CHECKSIGADD  N OP_NUMEQUALVERIFY
 *
 *   is_final != 0 (final): the boolean result stays on the stack.
 *     N=1 → <key> OP_CHECKSIG
 *     N>1 → <key[0]> OP_CHECKSIG  <key[i]>… OP_CHECKSIGADD  N OP_NUMEQUAL
 *
 * Each x-only key is pushed as 0x20 <32-byte key> (OP_PUSHBYTES_32).
 * Returns bytes written, or -1 if buf_max is too small.
 * ----------------------------------------------------------------------- */

static int encode_multisig_group(const uint8_t keys[][VAULT_XONLY_PUBKEY_LEN],
                                 int key_count,
                                 int is_final,
                                 uint8_t *buf,
                                 int buf_max) {
    /* Upper bound: key_count * (1 + 32 + 1) + 5 (number push) + 1 (opcode) */
    if (key_count <= 0 || (key_count * 34 + 6) > buf_max) return -1;

    int off = 0;

    if (key_count == 1) {
        buf[off++] = OP_PUSHBYTES_32;
        memcpy(buf + off, keys[0], VAULT_XONLY_PUBKEY_LEN);
        off += 32;
        buf[off++] = is_final ? OP_CHECKSIG : OP_CHECKSIGVERIFY;
    } else {
        buf[off++] = OP_PUSHBYTES_32;
        memcpy(buf + off, keys[0], VAULT_XONLY_PUBKEY_LEN);
        off += 32;
        buf[off++] = OP_CHECKSIG;

        for (int i = 1; i < key_count; i++) {
            buf[off++] = OP_PUSHBYTES_32;
            memcpy(buf + off, keys[i], VAULT_XONLY_PUBKEY_LEN);
            off += 32;
            buf[off++] = OP_CHECKSIGADD;
        }

        int n_len = _push_number((uint32_t) key_count, buf + off);
        off += n_len;
        buf[off++] = is_final ? OP_NUMEQUAL : OP_NUMEQUALVERIFY;
    }

    return off;
}

/* ==========================================================================
 * Leaf script builders
 * ========================================================================== */

/* --------------------------------------------------------------------------
 * vault_build_depositor_claim_leaf
 *
 * Script: <D> OP_CHECKSIG
 * Fixed 34 bytes.
 * ----------------------------------------------------------------------- */

int vault_build_depositor_claim_leaf(const vault_intent_t *intent, uint8_t *buf, int buf_max) {
    if (buf_max < 34) return -1;
    buf[0] = OP_PUSHBYTES_32;
    memcpy(buf + 1, intent->depositor_pk, VAULT_XONLY_PUBKEY_LEN);
    buf[33] = OP_CHECKSIG;
    return 34;
}

/* --------------------------------------------------------------------------
 * vault_build_htlc_leaf1
 *
 * Script: <D> OP_CHECKSIGVERIFY <T_refund> OP_CSV
 * ----------------------------------------------------------------------- */

int vault_build_htlc_leaf1(const vault_intent_t *intent, uint8_t *buf, int buf_max) {
    /* Max output: 1 + 32 + 1 + _push_number(VAULT_TIMELOCK_MAX=1008)=3 + 1 = 38 bytes */
    if (buf_max < 38) return -1;
    int off = 0;
    buf[off++] = OP_PUSHBYTES_32;
    memcpy(buf + off, intent->depositor_pk, VAULT_XONLY_PUBKEY_LEN);
    off += 32;
    buf[off++] = OP_CHECKSIGVERIFY;
    off += _push_number(intent->htlc_refund_timelock, buf + off);
    buf[off++] = OP_CSV;
    return off;
}

/* --------------------------------------------------------------------------
 * vault_build_vault_utxo_leaf
 *
 * Script: <D> OP_CHECKSIGVERIFY
 *         <VP> OP_CHECKSIGVERIFY
 *         <VK N-of-N>
 *         <UC M-of-M>
 *         <P> OP_CSV
 * ----------------------------------------------------------------------- */

int vault_build_vault_utxo_leaf(const vault_intent_t *intent,
                                int group_idx,
                                uint8_t *buf,
                                int buf_max) {
    if (group_idx < 0 || group_idx >= (int) intent->vault_count) return -1;
    int off = 0, r;

    if (off + 34 > buf_max) return -1;
    buf[off++] = OP_PUSHBYTES_32;
    memcpy(buf + off, intent->depositor_pk, VAULT_XONLY_PUBKEY_LEN);
    off += 32;
    buf[off++] = OP_CHECKSIGVERIFY;

    if (off + 34 > buf_max) return -1;
    buf[off++] = OP_PUSHBYTES_32;
    memcpy(buf + off, intent->groups[group_idx].vault_provider_pk, VAULT_XONLY_PUBKEY_LEN);
    off += 32;
    buf[off++] = OP_CHECKSIGVERIFY;

    r = encode_multisig_group(intent->keeper_pks,
                              (int) intent->keeper_count,
                              0,
                              buf + off,
                              buf_max - off);
    if (r < 0) return -1;
    off += r;

    r = encode_multisig_group(intent->challenger_pks,
                              (int) intent->challenger_count,
                              0,
                              buf + off,
                              buf_max - off);
    if (r < 0) return -1;
    off += r;

    if (off + 6 > buf_max) return -1;
    off += _push_number(intent->pegin_csv_timelock, buf + off);
    buf[off++] = OP_CSV;

    return off;
}

/* --------------------------------------------------------------------------
 * vault_build_htlc_leaf0
 *
 * Script: OP_SIZE <32> OP_EQUALVERIFY
 *         OP_SHA256 <h> OP_EQUALVERIFY
 *         <D> OP_CHECKSIGVERIFY
 *         <VP> OP_CHECKSIGVERIFY
 *         <VK N-of-N>          (intermediate)
 *         <UC M-of-M>          (final — leaves result on stack)
 * ----------------------------------------------------------------------- */

int vault_build_htlc_leaf0(const vault_intent_t *intent,
                           int group_idx,
                           const uint8_t h[VAULT_HASH256_LEN],
                           uint8_t *buf,
                           int buf_max) {
    if (group_idx < 0 || group_idx >= (int) intent->vault_count) return -1;
    int off = 0, r;

    /* OP_SIZE <32> OP_EQUALVERIFY */
    if (off + 4 > buf_max) return -1;
    buf[off++] = OP_SIZE;
    off += _push_number(VAULT_XONLY_PUBKEY_LEN, buf + off);
    buf[off++] = OP_EQUALVERIFY;

    /* OP_SHA256 <h> OP_EQUALVERIFY */
    if (off + 35 > buf_max) return -1;
    buf[off++] = OP_SHA256;
    buf[off++] = OP_PUSHBYTES_32;
    memcpy(buf + off, h, VAULT_HASH256_LEN);
    off += 32;
    buf[off++] = OP_EQUALVERIFY;

    /* <D> OP_CHECKSIGVERIFY */
    if (off + 34 > buf_max) return -1;
    buf[off++] = OP_PUSHBYTES_32;
    memcpy(buf + off, intent->depositor_pk, VAULT_XONLY_PUBKEY_LEN);
    off += 32;
    buf[off++] = OP_CHECKSIGVERIFY;

    /* <VP> OP_CHECKSIGVERIFY */
    if (off + 34 > buf_max) return -1;
    buf[off++] = OP_PUSHBYTES_32;
    memcpy(buf + off, intent->groups[group_idx].vault_provider_pk, VAULT_XONLY_PUBKEY_LEN);
    off += 32;
    buf[off++] = OP_CHECKSIGVERIFY;

    /* <VK N-of-N> intermediate */
    r = encode_multisig_group(intent->keeper_pks,
                              (int) intent->keeper_count,
                              0,
                              buf + off,
                              buf_max - off);
    if (r < 0) return -1;
    off += r;

    /* <UC M-of-M> final */
    r = encode_multisig_group(intent->challenger_pks,
                              (int) intent->challenger_count,
                              1,
                              buf + off,
                              buf_max - off);
    if (r < 0) return -1;
    off += r;

    return off;
}

/* --------------------------------------------------------------------------
 * build_app_challengers  (static helper for vault_build_assert0_payout_leaf)
 *
 * Builds the sorted AppChallengers list: {VP, VK_1..VK_N} \ {Claimer}.
 *
 *   claimer_idx == 0       → Claimer is VP; result is all VK keys (already sorted)
 *   claimer_idx == i > 0   → Claimer is VK_{i-1}; result is VP merged into
 *                             remaining VK keys at its lexicographic position
 *
 * Returns the number of keys written, which always equals intent->keeper_count.
 * ----------------------------------------------------------------------- */

static int build_app_challengers(const vault_intent_t *intent,
                                 int group_idx,
                                 int claimer_idx,
                                 uint8_t out[][VAULT_XONLY_PUBKEY_LEN]) {
    int k = 0;
    if (claimer_idx == 0) {
        for (int i = 0; i < (int) intent->keeper_count; i++) {
            memcpy(out[k++], intent->keeper_pks[i], VAULT_XONLY_PUBKEY_LEN);
        }
    } else {
        int vp_inserted = 0;
        for (int i = 0; i < (int) intent->keeper_count; i++) {
            if (i == claimer_idx - 1) continue;
            if (!vp_inserted && memcmp(intent->groups[group_idx].vault_provider_pk,
                                       intent->keeper_pks[i],
                                       VAULT_XONLY_PUBKEY_LEN) < 0) {
                memcpy(out[k++],
                       intent->groups[group_idx].vault_provider_pk,
                       VAULT_XONLY_PUBKEY_LEN);
                vp_inserted = 1;
            }
            memcpy(out[k++], intent->keeper_pks[i], VAULT_XONLY_PUBKEY_LEN);
        }
        if (!vp_inserted) {
            memcpy(out[k++], intent->groups[group_idx].vault_provider_pk, VAULT_XONLY_PUBKEY_LEN);
        }
    }
    return k;
}

/* --------------------------------------------------------------------------
 * vault_build_assert0_payout_leaf
 *
 * Script: <Claimer> OP_CHECKSIGVERIFY
 *         <AppChallengers K-of-K>   (intermediate; K = keeper_count always)
 *         <UC M-of-M>               (intermediate)
 *         <t2> OP_CSV
 *
 * claimer_idx: 0 = VP is claimer; 1..keeper_count = VK_{i-1} is claimer.
 * AppChallengers = {VP, VK_1..VK_N} \ {Claimer}, sorted ascending.
 * ----------------------------------------------------------------------- */

int vault_build_assert0_payout_leaf(const vault_intent_t *intent,
                                    int group_idx,
                                    int claimer_idx,
                                    uint8_t *buf,
                                    int buf_max) {
    if (group_idx < 0 || group_idx >= (int) intent->vault_count) return -1;
    if (claimer_idx < 0 || claimer_idx > (int) intent->keeper_count) return -1;

    /* Stack cost: VAULT_MAX_KEEPERS × VAULT_XONLY_PUBKEY_LEN = 1024 B.
     * Cannot use G_scratch here — buf already points into it. */
    _Static_assert(VAULT_MAX_KEEPERS * VAULT_XONLY_PUBKEY_LEN <= 1024u,
                   "AppChallengers scratch exceeds 1 KB; revisit if target RAM shrinks");
    uint8_t _app_challengers[VAULT_MAX_KEEPERS][VAULT_XONLY_PUBKEY_LEN];
    int k = build_app_challengers(intent, group_idx, claimer_idx, _app_challengers);

    const uint8_t *claimer_pk = (claimer_idx == 0) ? intent->groups[group_idx].vault_provider_pk
                                                   : intent->keeper_pks[claimer_idx - 1];

    int off = 0, r;

    if (off + 34 > buf_max) return -1;
    buf[off++] = OP_PUSHBYTES_32;
    memcpy(buf + off, claimer_pk, VAULT_XONLY_PUBKEY_LEN);
    off += 32;
    buf[off++] = OP_CHECKSIGVERIFY;

    r = encode_multisig_group((const uint8_t (*)[VAULT_XONLY_PUBKEY_LEN]) _app_challengers,
                              k,
                              0,
                              buf + off,
                              buf_max - off);
    if (r < 0) return -1;
    off += r;

    r = encode_multisig_group(intent->challenger_pks,
                              (int) intent->challenger_count,
                              0,
                              buf + off,
                              buf_max - off);
    if (r < 0) return -1;
    off += r;

    if (off + 6 > buf_max) return -1;
    off += _push_number(intent->payout_timelock, buf + off);
    buf[off++] = OP_CSV;

    return off;
}

/* ==========================================================================
 * Derived outputs — merkle root, scriptpubkey builders, pegin txid
 * ========================================================================== */

/* --------------------------------------------------------------------------
 * vault_build_htlc_merkle_root
 *
 * Merkle root of the 2-leaf HTLC taptree:
 *   branch_hash(leaf_hash(Leaf 0), leaf_hash(Leaf 1))
 * ----------------------------------------------------------------------- */

bool vault_build_htlc_merkle_root(const vault_intent_t *intent,
                                  int group_idx,
                                  const uint8_t h[VAULT_HASH256_LEN],
                                  uint8_t out[VAULT_HASH256_LEN]) {
    uint8_t lh0[VAULT_HASH256_LEN], lh1[VAULT_HASH256_LEN];

    int len0 = vault_build_htlc_leaf0(intent,
                                      group_idx,
                                      h,
                                      G_scratch.script_scratch,
                                      VAULT_SCRIPT_MAX_LEN);
    if (len0 < 0) {
        memset(out, 0, VAULT_HASH256_LEN);
        return false;
    }
    vault_taproot_leaf_hash(G_scratch.script_scratch, len0, lh0);

    int len1 = vault_build_htlc_leaf1(intent, G_scratch.script_scratch, VAULT_SCRIPT_MAX_LEN);
    if (len1 < 0) {
        memset(out, 0, VAULT_HASH256_LEN);
        return false;
    }
    vault_taproot_leaf_hash(G_scratch.script_scratch, len1, lh1);

    crypto_tr_combine_taptree_hashes(lh0, lh1, out);
    return true;
}

/* --------------------------------------------------------------------------
 * vault_build_htlc_scriptpubkey
 *
 * P2TR scriptPubKey (34 bytes) for the HTLC output.
 * ----------------------------------------------------------------------- */

bool vault_build_htlc_scriptpubkey(const vault_intent_t *intent,
                                   int group_idx,
                                   const uint8_t h[VAULT_HASH256_LEN],
                                   uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    uint8_t merkle_root[VAULT_HASH256_LEN];
    if (!vault_build_htlc_merkle_root(intent, group_idx, h, merkle_root)) {
        memset(out, 0, VAULT_P2TR_SCRIPTPUBKEY_LEN);
        return false;
    }
    return vault_taproot_tweak_scriptpubkey(merkle_root, NULL, out);
}

/* --------------------------------------------------------------------------
 * vault_build_vault_utxo_scriptpubkey
 *
 * P2TR scriptPubKey (34 bytes) for the Vault UTXO (single-leaf taptree).
 * ----------------------------------------------------------------------- */

bool vault_build_vault_utxo_scriptpubkey(const vault_intent_t *intent,
                                         int group_idx,
                                         uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    uint8_t leaf_hash[VAULT_HASH256_LEN];

    int len = vault_build_vault_utxo_leaf(intent,
                                          group_idx,
                                          G_scratch.script_scratch,
                                          VAULT_SCRIPT_MAX_LEN);
    if (len < 0) {
        memset(out, 0, VAULT_P2TR_SCRIPTPUBKEY_LEN);
        return false;
    }
    vault_taproot_leaf_hash(G_scratch.script_scratch, len, leaf_hash);
    return vault_taproot_tweak_scriptpubkey(leaf_hash, NULL, out);
}

/* --------------------------------------------------------------------------
 * vault_build_depositor_claim_scriptpubkey
 *
 * P2TR scriptPubKey (34 bytes) for the Depositor Claim UTXO.
 * ----------------------------------------------------------------------- */

bool vault_build_depositor_claim_scriptpubkey(const vault_intent_t *intent,
                                              uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    uint8_t script[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    uint8_t leaf_hash[VAULT_HASH256_LEN];

    int len = vault_build_depositor_claim_leaf(intent, script, (int) sizeof(script));
    if (len < 0) {
        memset(out, 0, VAULT_P2TR_SCRIPTPUBKEY_LEN);
        return false;
    }
    vault_taproot_leaf_hash(script, len, leaf_hash);
    return vault_taproot_tweak_scriptpubkey(leaf_hash, NULL, out);
}

/* --------------------------------------------------------------------------
 * vault_build_assert0_payout_scriptpubkey
 *
 * P2TR scriptPubKey (34 bytes) for the Assert:0 Payout output
 * (single-leaf taptree; one variant per claimer_idx).
 * ----------------------------------------------------------------------- */

bool vault_build_assert0_payout_scriptpubkey(const vault_intent_t *intent,
                                             int group_idx,
                                             int claimer_idx,
                                             uint8_t out[VAULT_P2TR_SCRIPTPUBKEY_LEN]) {
    uint8_t leaf_hash[VAULT_HASH256_LEN];

    int len = vault_build_assert0_payout_leaf(intent,
                                              group_idx,
                                              claimer_idx,
                                              G_scratch.script_scratch,
                                              VAULT_SCRIPT_MAX_LEN);
    if (len < 0) {
        memset(out, 0, VAULT_P2TR_SCRIPTPUBKEY_LEN);
        return false;
    }
    vault_taproot_leaf_hash(G_scratch.script_scratch, len, leaf_hash);
    return vault_taproot_tweak_scriptpubkey(leaf_hash, NULL, out);
}

/* --------------------------------------------------------------------------
 * vault_compute_pegin_txid
 *
 * Computes the SegWit txid of the PegIn transaction (double-SHA256 of the
 * non-witness serialization):
 *
 *   version=3  |  1 input: prepegin_txid:htlc_vout seq=0xFFFFFFFE
 *   3 outputs: Vault UTXO (vault_amount) + Depositor Claim (depositor_claim_value)
 *              + P2A anchor (pegin_anchor_value, script 0x51024e73)
 *   locktime=0
 *
 * The first two scriptPubKeys are P2TR (34 bytes) reconstructed from the intent.
 * The serialization is exactly 150 bytes (no segwit marker / witness data).
 * ----------------------------------------------------------------------- */

bool vault_compute_pegin_txid(const vault_intent_t *intent,
                              int group_idx,
                              uint8_t out[VAULT_HASH256_LEN]) {
    uint8_t vault_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN], claim_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    if (!vault_build_vault_utxo_scriptpubkey(intent, group_idx, vault_spk) ||
        !vault_build_depositor_claim_scriptpubkey(intent, claim_spk)) {
        memset(out, 0, VAULT_HASH256_LEN);
        return false;
    }

    uint8_t tx[PEGIN_TX_SIZE];
    int off = 0;

    /* version: 2 (LE) */
    tx[off++] = (uint8_t) (PEGIN_TX_VERSION);
    tx[off++] = (uint8_t) (PEGIN_TX_VERSION >> 8);
    tx[off++] = (uint8_t) (PEGIN_TX_VERSION >> 16);
    tx[off++] = (uint8_t) (PEGIN_TX_VERSION >> 24);

    /* input count: 1 */
    tx[off++] = 1u;
    /* prevout txid (LE as stored) */
    memcpy(tx + off, intent->prepegin_txid, VAULT_HASH256_LEN);
    off += 32;
    /* prevout index (LE) */
    tx[off++] = (uint8_t) (intent->groups[group_idx].htlc_vout);
    tx[off++] = (uint8_t) (intent->groups[group_idx].htlc_vout >> 8);
    tx[off++] = (uint8_t) (intent->groups[group_idx].htlc_vout >> 16);
    tx[off++] = (uint8_t) (intent->groups[group_idx].htlc_vout >> 24);
    /* scriptSig: empty */
    tx[off++] = 0u;
    /* sequence (LE) */
    tx[off++] = (uint8_t) (PEGIN_TX_SEQUENCE);
    tx[off++] = (uint8_t) (PEGIN_TX_SEQUENCE >> 8);
    tx[off++] = (uint8_t) (PEGIN_TX_SEQUENCE >> 16);
    tx[off++] = (uint8_t) (PEGIN_TX_SEQUENCE >> 24);

    /* output count: 3 */
    tx[off++] = 3u;
    /* output 0: Vault UTXO */
    for (int i = 0; i < 8; i++)
        tx[off++] = (uint8_t) (intent->groups[group_idx].vault_amount >> (i * 8));
    tx[off++] = (uint8_t) sizeof(vault_spk);
    memcpy(tx + off, vault_spk, sizeof(vault_spk));
    off += sizeof(vault_spk);
    /* output 1: Depositor Claim */
    for (int i = 0; i < 8; i++)
        tx[off++] = (uint8_t) (intent->groups[group_idx].depositor_claim_value >> (i * 8));
    tx[off++] = (uint8_t) sizeof(claim_spk);
    memcpy(tx + off, claim_spk, sizeof(claim_spk));
    off += sizeof(claim_spk);
    /* output 2: P2A anchor (OP_1 OP_PUSHBYTES_2 0x4e73) */
    for (int i = 0; i < 8; i++)
        tx[off++] = (uint8_t) (intent->groups[group_idx].pegin_anchor_value >> (i * 8));
    tx[off++] = 4u; /* script length */
    tx[off++] = 0x51u;
    tx[off++] = 0x02u;
    tx[off++] = 0x4Eu;
    tx[off++] = 0x73u;

    /* locktime (LE) */
    tx[off++] = (uint8_t) (PEGIN_TX_LOCKTIME);
    tx[off++] = (uint8_t) (PEGIN_TX_LOCKTIME >> 8);
    tx[off++] = (uint8_t) (PEGIN_TX_LOCKTIME >> 16);
    tx[off++] = (uint8_t) (PEGIN_TX_LOCKTIME >> 24);

    /* double-SHA256 */
    cx_sha256_t ctx;
    cx_sha256_init(&ctx);
    _hash_update(&ctx.header, tx, (size_t) off);
    uint8_t mid[VAULT_HASH256_LEN];
    _hash_final(&ctx.header, mid);
    cx_sha256_init(&ctx);
    _hash_update(&ctx.header, mid, VAULT_HASH256_LEN);
    _hash_final(&ctx.header, out);
    return true;
}
