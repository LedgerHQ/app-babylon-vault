#include "vault_script.h"
#include "vault_intent.h"
#include "globals.h"

#include <stdint.h>
#include <string.h>

/*
 * Crypto API — provided by:
 *   Device build : Ledger SDK (cx.h) + btcext bitcoin_app_base (crypto.c)
 *   Unit tests   : unit-tests/mocks/cx.h + unit-tests/mock_cx.c
 */
#include "cx.h"

/* Forward-declare the three btcext taproot functions vault_script.c uses.
 * On device these are implemented in bitcoin_app_base/src/crypto.c and
 * linked via the btcext base; in tests they come from mock_cx.c. */
void crypto_tr_tapleaf_hash_init(cx_sha256_t *ctx);
void crypto_tr_combine_taptree_hashes(const uint8_t left[32],
                                      const uint8_t right[32],
                                      uint8_t out[32]);
int crypto_tr_tweak_pubkey(const uint8_t pubkey[32],
                           const uint8_t *h,
                           size_t h_len,
                           uint8_t *y_parity,
                           uint8_t out[32]);

/* --------------------------------------------------------------------------
 * Local streaming-hash helpers — thin wrappers around cx_hash_no_throw.
 * ----------------------------------------------------------------------- */

static inline void _hash_update(cx_hash_t *ctx, const void *data, size_t n) {
    (void) cx_hash_no_throw(ctx, 0, (const uint8_t *) data, n, NULL, 0);
}

static inline void _hash_update_u8(cx_hash_t *ctx, uint8_t b) {
    (void) cx_hash_no_throw(ctx, 0, &b, 1u, NULL, 0);
}

static inline void _hash_final(cx_hash_t *ctx, uint8_t out[32]) {
    (void) cx_hash_no_throw(ctx, (int) CX_LAST, NULL, 0, out, 32u);
}

/* --------------------------------------------------------------------------
 * Bitcoin compact-size (varint) encoder — used for script-length prefix in
 * the TapLeaf hash construction.
 * Returns the number of bytes written into buf (1, 3, 5, or 9).
 * ----------------------------------------------------------------------- */

static int _varint_write(uint8_t *buf, uint64_t v) {
    if (v < 0xFDu) {
        buf[0] = (uint8_t) v;
        return 1;
    }
    if (v <= 0xFFFFu) {
        buf[0] = 0xFDu;
        buf[1] = (uint8_t) (v);
        buf[2] = (uint8_t) (v >> 8);
        return 3;
    }
    if (v <= 0xFFFFFFFFu) {
        buf[0] = 0xFEu;
        for (int i = 1; i <= 4; i++) buf[i] = (uint8_t) (v >> ((i - 1) * 8));
        return 5;
    }
    buf[0] = 0xFFu;
    for (int i = 1; i <= 8; i++) buf[i] = (uint8_t) (v >> ((i - 1) * 8));
    return 9;
}

/* --------------------------------------------------------------------------
 * NUMS internal key — lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f
 *                            28ec96d547bfee9ace803ac0)
 * All vault P2TR outputs use this x-only key so no key-path spend is possible.
 * ----------------------------------------------------------------------- */

static const uint8_t VAULT_NUMS_XONLY[32] = {
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
        buf[0] = 0x00u;
        return 1;
    }
    if (value <= 16u) {
        buf[0] = (uint8_t) (0x50u + value);
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

void vault_taproot_leaf_hash(const uint8_t *script, int script_len, uint8_t out[32]) {
    if (script_len < 0) {
        memset(out, 0, 32u);
        return;
    }
    cx_sha256_t ctx;
    crypto_tr_tapleaf_hash_init(&ctx);
    _hash_update_u8(&ctx.header, 0xC0u);
    uint8_t vbuf[5];
    int vlen = _varint_write(vbuf, (uint64_t) script_len);
    _hash_update(&ctx.header, vbuf, (size_t) vlen);
    _hash_update(&ctx.header, script, (size_t) script_len);
    _hash_final(&ctx.header, out);
}

/* --------------------------------------------------------------------------
 * vault_taproot_branch_hash  (static — callers use the public scriptpubkey /
 * merkle-root builders)
 *
 * BIP-341: tagged_hash("TapBranch", sort(left, right))
 * Sorting is handled inside crypto_tr_combine_taptree_hashes.
 * ----------------------------------------------------------------------- */

static void vault_taproot_branch_hash(const uint8_t left[32],
                                      const uint8_t right[32],
                                      uint8_t out[32]) {
    crypto_tr_combine_taptree_hashes(left, right, out);
}

/* --------------------------------------------------------------------------
 * vault_taproot_tweak_scriptpubkey  (static)
 *
 * Computes the P2TR scriptPubKey (34 bytes: OP_1 OP_PUSHBYTES_32 <key>)
 * by tweaking the NUMS internal key with the given merkle root.
 * ----------------------------------------------------------------------- */

/* parity_out may be NULL when the caller does not need the parity bit.
 * NAPPS-1377 (signing) will pass a non-NULL pointer for the control block. */
static void vault_taproot_tweak_scriptpubkey(const uint8_t merkle_root[32],
                                             uint8_t *parity_out,
                                             uint8_t out[34]) {
    uint8_t parity;
    uint8_t tweaked[32];
    if (crypto_tr_tweak_pubkey(VAULT_NUMS_XONLY, merkle_root, 32u, &parity, tweaked) != 0) {
        memset(out, 0, 34u);
        return;
    }
    if (parity_out) *parity_out = parity;
    out[0] = 0x51u; /* OP_1  */
    out[1] = 0x20u; /* OP_PUSHBYTES_32 */
    memcpy(out + 2, tweaked, 32u);
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

static int encode_multisig_group(const uint8_t keys[][32],
                                 int key_count,
                                 int is_final,
                                 uint8_t *buf,
                                 int buf_max) {
    /* Upper bound: key_count * (1 + 32 + 1) + 5 (number push) + 1 (opcode) */
    if (key_count <= 0 || (key_count * 34 + 6) > buf_max) return -1;

    int off = 0;

    if (key_count == 1) {
        buf[off++] = 0x20u;
        memcpy(buf + off, keys[0], 32u);
        off += 32;
        buf[off++] = is_final ? 0xACu : 0xADu; /* OP_CHECKSIG / OP_CHECKSIGVERIFY */
    } else {
        buf[off++] = 0x20u;
        memcpy(buf + off, keys[0], 32u);
        off += 32;
        buf[off++] = 0xACu; /* OP_CHECKSIG */

        for (int i = 1; i < key_count; i++) {
            buf[off++] = 0x20u;
            memcpy(buf + off, keys[i], 32u);
            off += 32;
            buf[off++] = 0xBAu; /* OP_CHECKSIGADD */
        }

        int n_len = _push_number((uint32_t) key_count, buf + off);
        off += n_len;
        buf[off++] = is_final ? 0x9Cu : 0x9Du; /* OP_NUMEQUAL / OP_NUMEQUALVERIFY */
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
    buf[0] = 0x20u;
    memcpy(buf + 1, intent->depositor_pk, 32u);
    buf[33] = 0xACu; /* OP_CHECKSIG */
    return 34;
}

/* --------------------------------------------------------------------------
 * vault_build_htlc_leaf1
 *
 * Script: <D> OP_CHECKSIGVERIFY <T_refund> OP_CSV
 * ----------------------------------------------------------------------- */

int vault_build_htlc_leaf1(const vault_intent_t *intent, uint8_t *buf, int buf_max) {
    if (buf_max < 39) return -1; /* conservative upper bound */
    int off = 0;
    buf[off++] = 0x20u;
    memcpy(buf + off, intent->depositor_pk, 32u);
    off += 32;
    buf[off++] = 0xADu; /* OP_CHECKSIGVERIFY */
    off += _push_number(intent->htlc_refund_timelock, buf + off);
    buf[off++] = 0xB2u; /* OP_CSV */
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

int vault_build_vault_utxo_leaf(const vault_intent_t *intent, uint8_t *buf, int buf_max) {
    int off = 0, r;

    if (off + 34 > buf_max) return -1;
    buf[off++] = 0x20u;
    memcpy(buf + off, intent->depositor_pk, 32u);
    off += 32;
    buf[off++] = 0xADu; /* OP_CHECKSIGVERIFY */

    if (off + 34 > buf_max) return -1;
    buf[off++] = 0x20u;
    memcpy(buf + off, intent->vault_provider_pk, 32u);
    off += 32;
    buf[off++] = 0xADu; /* OP_CHECKSIGVERIFY */

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
    buf[off++] = 0xB2u; /* OP_CSV */

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
                           const uint8_t h[32],
                           uint8_t *buf,
                           int buf_max) {
    int off = 0, r;

    /* OP_SIZE <32> OP_EQUALVERIFY */
    if (off + 4 > buf_max) return -1;
    buf[off++] = 0x82u;                  /* OP_SIZE */
    off += _push_number(32u, buf + off); /* 0x01 0x20 */
    buf[off++] = 0x88u;                  /* OP_EQUALVERIFY */

    /* OP_SHA256 <h> OP_EQUALVERIFY */
    if (off + 35 > buf_max) return -1;
    buf[off++] = 0xA8u; /* OP_SHA256 */
    buf[off++] = 0x20u; /* OP_PUSHBYTES_32 */
    memcpy(buf + off, h, 32u);
    off += 32;
    buf[off++] = 0x88u; /* OP_EQUALVERIFY */

    /* <D> OP_CHECKSIGVERIFY */
    if (off + 34 > buf_max) return -1;
    buf[off++] = 0x20u;
    memcpy(buf + off, intent->depositor_pk, 32u);
    off += 32;
    buf[off++] = 0xADu;

    /* <VP> OP_CHECKSIGVERIFY */
    if (off + 34 > buf_max) return -1;
    buf[off++] = 0x20u;
    memcpy(buf + off, intent->vault_provider_pk, 32u);
    off += 32;
    buf[off++] = 0xADu;

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

static int build_app_challengers(const vault_intent_t *intent, int claimer_idx, uint8_t out[][32]) {
    int k = 0;
    if (claimer_idx == 0) {
        for (int i = 0; i < (int) intent->keeper_count; i++) {
            memcpy(out[k++], intent->keeper_pks[i], 32u);
        }
    } else {
        int vp_inserted = 0;
        for (int i = 0; i < (int) intent->keeper_count; i++) {
            if (i == claimer_idx - 1) continue;
            if (!vp_inserted && memcmp(intent->vault_provider_pk, intent->keeper_pks[i], 32u) < 0) {
                memcpy(out[k++], intent->vault_provider_pk, 32u);
                vp_inserted = 1;
            }
            memcpy(out[k++], intent->keeper_pks[i], 32u);
        }
        if (!vp_inserted) {
            memcpy(out[k++], intent->vault_provider_pk, 32u);
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
                                    int claimer_idx,
                                    uint8_t *buf,
                                    int buf_max) {
    if (claimer_idx < 0 || claimer_idx > (int) intent->keeper_count) return -1;

    /* Static avoids a 1 KB stack frame (32 keys × 32 bytes). */
    static uint8_t _app_challengers[VAULT_MAX_KEEPERS][VAULT_XONLY_PUBKEY_LEN];
    int k = build_app_challengers(intent, claimer_idx, _app_challengers);

    const uint8_t *claimer_pk =
        (claimer_idx == 0) ? intent->vault_provider_pk : intent->keeper_pks[claimer_idx - 1];

    int off = 0, r;

    if (off + 34 > buf_max) return -1;
    buf[off++] = 0x20u;
    memcpy(buf + off, claimer_pk, 32u);
    off += 32;
    buf[off++] = 0xADu; /* OP_CHECKSIGVERIFY */

    r = encode_multisig_group((const uint8_t (*)[32]) _app_challengers,
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
    buf[off++] = 0xB2u; /* OP_CSV */

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

void vault_build_htlc_merkle_root(const vault_intent_t *intent,
                                  const uint8_t h[32],
                                  uint8_t out[32]) {
    uint8_t lh0[32], lh1[32];

    int len0 = vault_build_htlc_leaf0(intent, h, G_vault_script_scratch, VAULT_SCRIPT_MAX_LEN);
    if (len0 < 0) {
        memset(out, 0, 32u);
        return;
    }
    vault_taproot_leaf_hash(G_vault_script_scratch, len0, lh0);

    int len1 = vault_build_htlc_leaf1(intent, G_vault_script_scratch, VAULT_SCRIPT_MAX_LEN);
    if (len1 < 0) {
        memset(out, 0, 32u);
        return;
    }
    vault_taproot_leaf_hash(G_vault_script_scratch, len1, lh1);

    vault_taproot_branch_hash(lh0, lh1, out);
}

/* --------------------------------------------------------------------------
 * vault_build_htlc_scriptpubkey
 *
 * P2TR scriptPubKey (34 bytes) for the HTLC output.
 * ----------------------------------------------------------------------- */

void vault_build_htlc_scriptpubkey(const vault_intent_t *intent,
                                   const uint8_t h[32],
                                   uint8_t out[34]) {
    uint8_t merkle_root[32];
    vault_build_htlc_merkle_root(intent, h, merkle_root);
    vault_taproot_tweak_scriptpubkey(merkle_root, NULL, out);
}

/* --------------------------------------------------------------------------
 * vault_build_vault_utxo_scriptpubkey
 *
 * P2TR scriptPubKey (34 bytes) for the Vault UTXO (single-leaf taptree).
 * ----------------------------------------------------------------------- */

void vault_build_vault_utxo_scriptpubkey(const vault_intent_t *intent, uint8_t out[34]) {
    uint8_t leaf_hash[32];

    int len = vault_build_vault_utxo_leaf(intent, G_vault_script_scratch, VAULT_SCRIPT_MAX_LEN);
    if (len < 0) {
        memset(out, 0, 34u);
        return;
    }
    vault_taproot_leaf_hash(G_vault_script_scratch, len, leaf_hash);
    vault_taproot_tweak_scriptpubkey(leaf_hash, NULL, out);
}

/* --------------------------------------------------------------------------
 * vault_build_depositor_claim_scriptpubkey
 *
 * P2TR scriptPubKey (34 bytes) for the Depositor Claim UTXO.
 * ----------------------------------------------------------------------- */

void vault_build_depositor_claim_scriptpubkey(const vault_intent_t *intent, uint8_t out[34]) {
    uint8_t script[34];
    uint8_t leaf_hash[32];

    int len = vault_build_depositor_claim_leaf(intent, script, (int) sizeof(script));
    if (len < 0) {
        memset(out, 0, 34u);
        return;
    }
    vault_taproot_leaf_hash(script, len, leaf_hash);
    vault_taproot_tweak_scriptpubkey(leaf_hash, NULL, out);
}

/* --------------------------------------------------------------------------
 * vault_build_assert0_payout_scriptpubkey
 *
 * P2TR scriptPubKey (34 bytes) for the Assert:0 Payout output
 * (single-leaf taptree; one variant per claimer_idx).
 * ----------------------------------------------------------------------- */

void vault_build_assert0_payout_scriptpubkey(const vault_intent_t *intent,
                                             int claimer_idx,
                                             uint8_t out[34]) {
    uint8_t leaf_hash[32];

    int len = vault_build_assert0_payout_leaf(intent,
                                              claimer_idx,
                                              G_vault_script_scratch,
                                              VAULT_SCRIPT_MAX_LEN);
    if (len < 0) {
        memset(out, 0, 34u);
        return;
    }
    vault_taproot_leaf_hash(G_vault_script_scratch, len, leaf_hash);
    vault_taproot_tweak_scriptpubkey(leaf_hash, NULL, out);
}

/* --------------------------------------------------------------------------
 * vault_compute_pegin_txid
 *
 * Computes the SegWit txid of the PegIn transaction (double-SHA256 of the
 * non-witness serialization):
 *
 *   version=2  |  1 input: prepegin_txid:htlc_vout seq=0xFFFFFFFE
 *   2 outputs: Vault UTXO (vault_amount) + Depositor Claim (depositor_claim_value)
 *   locktime=0
 *
 * Both output scriptPubKeys are P2TR (34 bytes) reconstructed from the intent.
 * The serialization is exactly 137 bytes (no segwit marker / witness data).
 * ----------------------------------------------------------------------- */

void vault_compute_pegin_txid(const vault_intent_t *intent, uint8_t out[32]) {
    uint8_t vault_spk[34], claim_spk[34];
    vault_build_vault_utxo_scriptpubkey(intent, vault_spk);
    vault_build_depositor_claim_scriptpubkey(intent, claim_spk);

    uint8_t tx[137];
    int off = 0;

    /* version: 2 */
    tx[off++] = 0x02u;
    tx[off++] = 0x00u;
    tx[off++] = 0x00u;
    tx[off++] = 0x00u;

    /* input count: 1 */
    tx[off++] = 0x01u;
    /* prevout txid (LE as stored) */
    memcpy(tx + off, intent->prepegin_txid, 32u);
    off += 32;
    /* prevout index */
    tx[off++] = (uint8_t) (intent->htlc_vout);
    tx[off++] = (uint8_t) (intent->htlc_vout >> 8);
    tx[off++] = (uint8_t) (intent->htlc_vout >> 16);
    tx[off++] = (uint8_t) (intent->htlc_vout >> 24);
    /* scriptSig: empty */
    tx[off++] = 0x00u;
    /* sequence: 0xFFFFFFFE */
    tx[off++] = 0xFEu;
    tx[off++] = 0xFFu;
    tx[off++] = 0xFFu;
    tx[off++] = 0xFFu;

    /* output count: 2 */
    tx[off++] = 0x02u;
    /* output 0: Vault UTXO */
    for (int i = 0; i < 8; i++) tx[off++] = (uint8_t) (intent->vault_amount >> (i * 8));
    tx[off++] = 0x22u; /* scriptPubKey length = 34 */
    memcpy(tx + off, vault_spk, 34u);
    off += 34;
    /* output 1: Depositor Claim */
    for (int i = 0; i < 8; i++) tx[off++] = (uint8_t) (intent->depositor_claim_value >> (i * 8));
    tx[off++] = 0x22u;
    memcpy(tx + off, claim_spk, 34u);
    off += 34;

    /* locktime: 0 */
    tx[off++] = 0x00u;
    tx[off++] = 0x00u;
    tx[off++] = 0x00u;
    tx[off++] = 0x00u;

    /* double-SHA256 */
    cx_sha256_t ctx;
    cx_sha256_init(&ctx);
    _hash_update(&ctx.header, tx, (size_t) off);
    uint8_t mid[32];
    _hash_final(&ctx.header, mid);
    cx_sha256_init(&ctx);
    _hash_update(&ctx.header, mid, 32u);
    _hash_final(&ctx.header, out);
}
