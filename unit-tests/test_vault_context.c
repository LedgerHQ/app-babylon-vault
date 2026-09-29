/**
 * Unit tests for vault_context state machine.
 *
 * Covers:
 *   - vault_context_init: zeroes struct, sets IDLE
 *   - vault_context_invalidate: explicit_bzero on root, resets to IDLE, wipes intent + G_scratch
 *   - vault_context_transition: all valid edges in the state diagram
 *   - vault_context_transition: invalid transitions → invalidate + return false
 *   - Idempotent invalidation (IDLE → invalidate → still IDLE)
 *   - GET_VAULT_STATE: response encoding per state, fingerprint vectors, invalidation
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "vault_context.h"
#include "vault_intent_tags.h"
#include "globals.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Fill ctx with a known non-zero pattern, then init and verify zeroed. */
static void _fill(vault_context_t *ctx) {
    memset(ctx, 0xAB, sizeof(*ctx));
}

static bool _secret_is_zero(const vault_context_t *ctx) {
    for (size_t i = 0; i < sizeof(ctx->root); i++) {
        if (ctx->root[i] != 0) return false;
    }
    return true;
}

/** Assert that an illegal transition invalidates the context. */
static void _assert_illegal(vault_state_t current_state,
                             vault_state_t from,
                             vault_state_t to) {
    vault_context_t ctx;
    vault_context_init(&ctx);
    ctx.state = current_state;

    /* Place non-zero root so we can verify it gets wiped */
    memset(ctx.root, 0x42, sizeof(ctx.root));

    bool ok = vault_context_transition(&ctx, from, to);

    assert_false(ok);
    assert_int_equal(ctx.state, VAULT_STATE_IDLE);
    assert_true(_secret_is_zero(&ctx));
}

// ---------------------------------------------------------------------------
// vault_context_init
// ---------------------------------------------------------------------------

static void test_init_zeroes_and_sets_idle(void **state) {
    (void) state;
    vault_context_t ctx;
    _fill(&ctx);
    vault_context_init(&ctx);

    assert_int_equal(ctx.state, VAULT_STATE_IDLE);
    assert_true(_secret_is_zero(&ctx));
    assert_int_equal(ctx.payout_index, 0);
}

// ---------------------------------------------------------------------------
// vault_context_invalidate
// ---------------------------------------------------------------------------

static void test_invalidate_from_idle(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    vault_context_invalidate(&ctx);   // idempotent
    assert_int_equal(ctx.state, VAULT_STATE_IDLE);
    assert_true(_secret_is_zero(&ctx));
}

static void test_invalidate_zeroes_secret_and_intent(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);

    /* Set a fake root + commitments and advance state */
    memset(ctx.root, 0xFF, sizeof(ctx.root));
    memset(ctx.htlc_hashlock, 0xEE, sizeof(ctx.htlc_hashlock));
    memset(ctx.auth_anchor_hash, 0xDD, sizeof(ctx.auth_anchor_hash));
    ctx.state = VAULT_STATE_INTENT_LOADED;

    /* Fill intent with non-zero data */
    memset(&G_vault_intent, 0xCC, sizeof(G_vault_intent));

    vault_context_invalidate(&ctx);

    assert_int_equal(ctx.state, VAULT_STATE_IDLE);
    assert_true(_secret_is_zero(&ctx));

    /* Intent must also be wiped */
    uint8_t *p = (uint8_t *) &G_vault_intent;
    for (size_t i = 0; i < sizeof(G_vault_intent); i++) {
        assert_int_equal(p[i], 0);
    }
}

static void test_invalidate_clears_scratch(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);

    /* Simulate residual script data in the scratch union. */
    memset(&G_scratch, 0xAC, sizeof(G_scratch));

    vault_context_invalidate(&ctx);

    uint8_t *sp = (uint8_t *) &G_scratch;
    for (size_t i = 0; i < sizeof(G_scratch); i++) {
        assert_int_equal(sp[i], 0);
    }
}

// ---------------------------------------------------------------------------
// vault_context_transition — valid edges
// ---------------------------------------------------------------------------

static void test_transition_idle_to_intent_loaded_illegal(void **state) {
    (void) state;
    /* IDLE → INTENT_LOADED is now blocked: DERIVE_CONTEXT_HASH (→ HASH_DERIVED) is
     * mandatory before APPROVE_VAULT_INTENT (HASH_DERIVED → INTENT_LOADED). */
    vault_context_t ctx;
    vault_context_init(&ctx);

    bool ok = vault_context_transition(&ctx, VAULT_STATE_IDLE, VAULT_STATE_INTENT_LOADED);
    assert_false(ok);
    assert_int_equal(ctx.state, VAULT_STATE_IDLE);
}

static void test_transition_idle_to_hash_derived(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);

    bool ok = vault_context_transition(&ctx, VAULT_STATE_IDLE, VAULT_STATE_HASH_DERIVED);
    assert_true(ok);
    assert_int_equal(ctx.state, VAULT_STATE_HASH_DERIVED);
}

static void test_transition_intent_loaded_is_terminal(void **state) {
    (void) state;
    /*
     * INTENT_LOADED has no outgoing legal edges (it is the terminal active state);
     * any attempted forward transition must invalidate the context.
     */
    _assert_illegal(VAULT_STATE_INTENT_LOADED,
                    VAULT_STATE_INTENT_LOADED,
                    VAULT_STATE_INTENT_LOADED);
}

// ---------------------------------------------------------------------------
// vault_context_transition — invalid edges → invalidation
// ---------------------------------------------------------------------------

static void test_transition_wrong_from_state(void **state) {
    (void) state;
    /* Currently IDLE, but `from` claims INTENT_LOADED → mismatch */
    _assert_illegal(VAULT_STATE_IDLE,
                    VAULT_STATE_INTENT_LOADED,
                    VAULT_STATE_HASH_DERIVED);
}

static void test_transition_illegal_to_state(void **state) {
    (void) state;
    /*
     * from matches current state (HASH_DERIVED) but target is IDLE — a backwards
     * step; the only legal from-HASH_DERIVED edge is → INTENT_LOADED.
     * The to-validation must catch this even though from is correct.
     */
    _assert_illegal(VAULT_STATE_HASH_DERIVED,
                    VAULT_STATE_HASH_DERIVED,
                    VAULT_STATE_IDLE);
}

static void test_transition_backwards_without_valid_edge(void **state) {
    (void) state;
    /*
     * from matches current state (INTENT_LOADED) but target is HASH_DERIVED —
     * a backwards step; INTENT_LOADED is terminal (no outgoing edges).
     */
    _assert_illegal(VAULT_STATE_INTENT_LOADED,
                    VAULT_STATE_INTENT_LOADED,
                    VAULT_STATE_HASH_DERIVED);
}

static void test_transition_double_approve(void **state) {
    (void) state;
    /*
     * INTENT_LOADED → INTENT_LOADED: correct from, but self-transitions
     * are not in the legal table (double APPROVE_VAULT_INTENT must invalidate).
     */
    _assert_illegal(VAULT_STATE_INTENT_LOADED,
                    VAULT_STATE_INTENT_LOADED,
                    VAULT_STATE_INTENT_LOADED);
}

static void test_transition_hash_derived_to_intent_loaded(void **state) {
    (void) state;
    /*
     * HASH_DERIVED → INTENT_LOADED is the only legal path to INTENT_LOADED.
     * APPROVE_VAULT_INTENT saves/restores root across vault_context_invalidate,
     * then calls vault_context_transition(HASH_DERIVED, INTENT_LOADED).
     */
    vault_context_t ctx;
    vault_context_init(&ctx);
    ctx.state = VAULT_STATE_HASH_DERIVED;

    bool ok = vault_context_transition(&ctx, VAULT_STATE_HASH_DERIVED, VAULT_STATE_INTENT_LOADED);
    assert_true(ok);
    assert_int_equal(ctx.state, VAULT_STATE_INTENT_LOADED);
}

// ---------------------------------------------------------------------------
// Signature cap counters
// ---------------------------------------------------------------------------

static void test_init_zeroes_cap_counters(void **state) {
    (void) state;
    vault_context_t ctx;
    _fill(&ctx);
    vault_context_init(&ctx);

    assert_int_equal(ctx.pre_pegin_signed, 0);
    assert_int_equal(ctx.pegin_signed,     0);
    assert_int_equal(ctx.payout_signed,    0);
    assert_int_equal(ctx.nopayout_signed,  0);
}

static void test_invalidate_zeroes_cap_counters(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);

    ctx.pre_pegin_signed = 1;
    ctx.pegin_signed     = 5;
    ctx.payout_signed    = 30;
    ctx.nopayout_signed  = 47;
    ctx.state            = VAULT_STATE_INTENT_LOADED;

    vault_context_invalidate(&ctx);

    assert_int_equal(ctx.pre_pegin_signed, 0);
    assert_int_equal(ctx.pegin_signed,     0);
    assert_int_equal(ctx.payout_signed,    0);
    assert_int_equal(ctx.nopayout_signed,  0);
    assert_int_equal(ctx.state,            VAULT_STATE_IDLE);
}

// ---------------------------------------------------------------------------
// GET_VAULT_STATE — reference vectors
//
// Every expected fingerprint is reproducible host-side with hashlib:
//   context: sha256(root).digest()[-4:]
//   intent:  sha256(b"".join(cdata_of_each_apdu)).digest()[-4:]
// ---------------------------------------------------------------------------

/* derive-context-hash §4.2 root (the vector pinned in test_derive_context_hash.c). */
static const uint8_t V42_ROOT[VAULT_HASH256_LEN] = {
    0xf8, 0x2c, 0xed, 0x3b, 0xe0, 0xe2, 0x95, 0x91, 0xa7, 0x86, 0x3e, 0xce, 0x03, 0xd6, 0x5f, 0x79,
    0xfb, 0x49, 0x4f, 0xe0, 0xde, 0x72, 0x03, 0x54, 0x98, 0x55, 0xf4, 0x62, 0x45, 0x5d, 0xf0, 0x08};
static const uint8_t V42_CONTEXT_FP[VAULT_FINGERPRINT_LEN] = {0xd1, 0xf8, 0xec, 0xda};

/* x-only keys of the Ragger suite's 1-keeper / 1-challenger intent (tests/vault_client.py):
 * vault provider = TEST_VP_KEY, keeper = TEST_VALID_KEYS[0], challenger = TEST_VALID_KEYS[1]. */
static const uint8_t VP_KEY[VAULT_XONLY_PUBKEY_LEN] = {
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
static const uint8_t KEEPER_KEY[VAULT_XONLY_PUBKEY_LEN] = {
    0x25, 0xD1, 0xDF, 0xF9, 0x51, 0x05, 0xF5, 0x25, 0x3C, 0x40, 0x22, 0xF6, 0x28, 0xA9, 0x96, 0xAD,
    0x3A, 0x0D, 0x95, 0xFB, 0xF2, 0x1D, 0x46, 0x8A, 0x1B, 0x33, 0xF8, 0xC1, 0x60, 0xD8, 0xF5, 0x17};
static const uint8_t CHALLENGER_KEY[VAULT_XONLY_PUBKEY_LEN] = {
    0x2F, 0x01, 0xE5, 0xE1, 0x5C, 0xCA, 0x35, 0x1D, 0xAF, 0xF3, 0x84, 0x3F, 0xB7, 0x0F, 0x3C, 0x2F,
    0x0A, 0x1B, 0xDD, 0x05, 0xE5, 0xAF, 0x88, 0x8A, 0x67, 0x78, 0x4E, 0xF3, 0xE1, 0x0A, 0x2A, 0x01};

/* Fingerprint of that intent's mainnet APDUs, built below by _build_intent_apdus. */
static const uint8_t INTENT_FP_1K1C_MAINNET[VAULT_FINGERPRINT_LEN] = {0x44, 0xa9, 0x9b, 0x57};

#define APDU_CDATA_MAX 255u

typedef struct {
    uint8_t data[APDU_CDATA_MAX];
    size_t len;
} cdata_t;

/** The CData of each APPROVE_VAULT_INTENT APDU, in the order the host sends them. */
typedef struct {
    cdata_t scalars; /* P1=0x00 */
    cdata_t group;   /* P1=0x01 */
    cdata_t keys;    /* P1=0x02 */
} intent_apdus_t;

static void _put_tlv(cdata_t *c, uint16_t tag, const uint8_t *value, uint8_t value_len) {
    assert_true(c->len + 3u + value_len <= sizeof(c->data));
    c->data[c->len++] = (uint8_t) (tag >> 8);
    c->data[c->len++] = (uint8_t) (tag & 0xFFu);
    c->data[c->len++] = value_len;
    memcpy(c->data + c->len, value, value_len);
    c->len += value_len;
}

/** Big-endian unsigned TLV of @p width bytes. */
static void _put_uint(cdata_t *c, uint16_t tag, uint64_t value, uint8_t width) {
    uint8_t be[8];
    for (uint8_t i = 0; i < width; i++) {
        be[i] = (uint8_t) (value >> (8u * (width - 1u - i)));
    }
    _put_tlv(c, tag, be, width);
}

/** Mirrors test_approve_vault_intent.py _make_scalars("main"), _make_group() and one keeper
 *  + one challenger key batch, tag order included. */
static void _build_intent_apdus(intent_apdus_t *a) {
    memset(a, 0, sizeof(*a));

    const uint32_t coin_type = 0; /* mainnet */
    const uint32_t hardened = 0x80000000u;
    const uint32_t depositor_path[VAULT_DEPOSITOR_PATH_LEN] = {
        hardened | 86u, hardened | coin_type, hardened | 0u, 0u, 0u};
    uint8_t path_be[VAULT_DEPOSITOR_PATH_LEN * 4u];
    for (size_t i = 0; i < VAULT_DEPOSITOR_PATH_LEN; i++) {
        for (size_t b = 0; b < 4u; b++) {
            path_be[i * 4u + b] = (uint8_t) (depositor_path[i] >> (8u * (3u - b)));
        }
    }
    uint8_t prepegin_txid[VAULT_HASH256_LEN];
    for (uint8_t i = 0; i < sizeof(prepegin_txid); i++) {
        prepegin_txid[i] = i;
    }

    cdata_t *s = &a->scalars;
    _put_uint(s, TAG_STRUCTURE_TYPE, VAULT_STRUCTURE_TYPE, 1);
    _put_uint(s, TAG_VERSION, VAULT_PROTOCOL_VERSION, 1);
    _put_uint(s, TAG_COIN_TYPE, coin_type, 4);
    _put_uint(s, TAG_BASE_FEE_RATE, 10u, 8);
    _put_uint(s, TAG_PEGIN_CSV_TIMELOCK, 100u, 4);
    _put_uint(s, TAG_PAYOUT_TIMELOCK, 200u, 4);
    _put_tlv(s, TAG_PREPEGIN_TXID, prepegin_txid, sizeof(prepegin_txid));
    _put_uint(s, TAG_HTLC_REFUND_TIMELOCK, 144u, 4);
    _put_tlv(s, TAG_DEPOSITOR_DERIVATION_PATH, path_be, sizeof(path_be));
    _put_uint(s, TAG_KEEPER_COUNT, 1u, 1);
    _put_uint(s, TAG_CHALLENGER_COUNT, 1u, 1);
    _put_uint(s, TAG_VAULT_COUNT, 1u, 1);
    _put_uint(s, TAG_PREPEGIN_MAX_FEE, 500000u, 8);

    cdata_t *g = &a->group;
    _put_uint(g, TAG_GRP_HTLC_VOUT, 0u, 1);
    _put_tlv(g, TAG_GRP_VAULT_PROVIDER_PK, VP_KEY, sizeof(VP_KEY));
    _put_uint(g, TAG_GRP_VAULT_AMOUNT, 100000u, 8);
    _put_uint(g, TAG_GRP_COMMISSION_FEE, 1000u, 8);
    _put_uint(g, TAG_GRP_DEPOSITOR_CLAIM_VALUE, 10000u, 8);
    _put_uint(g, TAG_GRP_PEGIN_MAX_FEE, 50000u, 8);

    cdata_t *k = &a->keys;
    _put_tlv(k, TAG_KEEPER_PK, KEEPER_KEY, sizeof(KEEPER_KEY));
    _put_tlv(k, TAG_CHALLENGER_PK, CHALLENGER_KEY, sizeof(CHALLENGER_KEY));
}

/** Fingerprint of the APDUs, fed to the streaming API one APDU at a time. */
static void _intent_fp_per_apdu(const intent_apdus_t *a, uint8_t fp[VAULT_FINGERPRINT_LEN]) {
    cx_sha256_t hash;
    vault_fingerprint_init(&hash);
    assert_true(vault_fingerprint_update(&hash, a->scalars.data, a->scalars.len));
    assert_true(vault_fingerprint_update(&hash, a->group.data, a->group.len));
    assert_true(vault_fingerprint_update(&hash, a->keys.data, a->keys.len));
    assert_true(vault_fingerprint_final(&hash, fp));
}

static void _fill_fingerprints(vault_context_t *ctx) {
    static const uint8_t intent_fp[VAULT_FINGERPRINT_LEN] = {0xA1, 0xA2, 0xA3, 0xA4};
    static const uint8_t context_fp[VAULT_FINGERPRINT_LEN] = {0xC1, 0xC2, 0xC3, 0xC4};
    memcpy(ctx->intent_fp, intent_fp, VAULT_FINGERPRINT_LEN);
    memcpy(ctx->context_fp, context_fp, VAULT_FINGERPRINT_LEN);
}

// ---------------------------------------------------------------------------
// GET_VAULT_STATE — response encoding
// ---------------------------------------------------------------------------

static void test_encode_state_idle_reports_nothing(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    /* Stale bytes must not leak into an IDLE answer: the state decides, not the fields. */
    _fill_fingerprints(&ctx);

    uint8_t out[VAULT_STATE_RESPONSE_MAX_LEN];
    size_t len = vault_context_encode_state(&ctx, out);

    const uint8_t expected[] = {0x00, 0x00};
    assert_int_equal(len, sizeof(expected));
    assert_memory_equal(out, expected, sizeof(expected));
}

static void test_encode_state_hash_derived_reports_context_only(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    _fill_fingerprints(&ctx);
    ctx.state = VAULT_STATE_HASH_DERIVED;

    uint8_t out[VAULT_STATE_RESPONSE_MAX_LEN];
    size_t len = vault_context_encode_state(&ctx, out);

    const uint8_t expected[] = {0x00, VAULT_FINGERPRINT_LEN, 0xC1, 0xC2, 0xC3, 0xC4};
    assert_int_equal(len, sizeof(expected));
    assert_memory_equal(out, expected, sizeof(expected));
}

static void test_encode_state_intent_loaded_reports_both(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    _fill_fingerprints(&ctx);
    ctx.state = VAULT_STATE_INTENT_LOADED;

    uint8_t out[VAULT_STATE_RESPONSE_MAX_LEN];
    size_t len = vault_context_encode_state(&ctx, out);

    const uint8_t expected[] = {VAULT_FINGERPRINT_LEN, 0xA1, 0xA2, 0xA3, 0xA4,
                                VAULT_FINGERPRINT_LEN, 0xC1, 0xC2, 0xC3, 0xC4};
    assert_int_equal(len, sizeof(expected));
    assert_int_equal(len, VAULT_STATE_RESPONSE_MAX_LEN);
    assert_memory_equal(out, expected, sizeof(expected));
}

static void test_encode_state_unknown_state_fails(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    _fill_fingerprints(&ctx);
    ctx.state = (vault_state_t) (VAULT_STATE_INTENT_LOADED + 1);

    uint8_t out[VAULT_STATE_RESPONSE_MAX_LEN];
    assert_int_equal(vault_context_encode_state(&ctx, out), 0);
}

static void test_encode_state_is_read_only(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    _fill_fingerprints(&ctx);
    ctx.state = VAULT_STATE_INTENT_LOADED;
    ctx.pre_pegin_signed = 1;
    ctx.payout_signed = 3;

    vault_context_t before;
    memcpy(&before, &ctx, sizeof(ctx));

    uint8_t first[VAULT_STATE_RESPONSE_MAX_LEN];
    uint8_t second[VAULT_STATE_RESPONSE_MAX_LEN];
    size_t first_len = vault_context_encode_state(&ctx, first);
    size_t second_len = vault_context_encode_state(&ctx, second);

    assert_int_equal(first_len, second_len);
    assert_memory_equal(first, second, first_len);
    assert_memory_equal(&ctx, &before, sizeof(ctx));
}

static void test_invalidate_clears_fingerprints(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    _fill_fingerprints(&ctx);
    ctx.state = VAULT_STATE_INTENT_LOADED;

    vault_context_invalidate(&ctx);

    const uint8_t zeros[VAULT_FINGERPRINT_LEN] = {0};
    assert_memory_equal(ctx.intent_fp, zeros, VAULT_FINGERPRINT_LEN);
    assert_memory_equal(ctx.context_fp, zeros, VAULT_FINGERPRINT_LEN);

    uint8_t out[VAULT_STATE_RESPONSE_MAX_LEN];
    const uint8_t expected[] = {0x00, 0x00};
    assert_int_equal(vault_context_encode_state(&ctx, out), sizeof(expected));
    assert_memory_equal(out, expected, sizeof(expected));
}

// ---------------------------------------------------------------------------
// GET_VAULT_STATE — fingerprint vectors
// ---------------------------------------------------------------------------

static void test_context_fp_vector(void **state) {
    (void) state;
    uint8_t fp[VAULT_FINGERPRINT_LEN];
    assert_true(vault_fingerprint(V42_ROOT, sizeof(V42_ROOT), fp));
    assert_memory_equal(fp, V42_CONTEXT_FP, VAULT_FINGERPRINT_LEN);
}

static void test_intent_fp_vector(void **state) {
    (void) state;
    intent_apdus_t apdus;
    _build_intent_apdus(&apdus);

    uint8_t fp[VAULT_FINGERPRINT_LEN];
    _intent_fp_per_apdu(&apdus, fp);
    assert_memory_equal(fp, INTENT_FP_1K1C_MAINNET, VAULT_FINGERPRINT_LEN);
}

static void test_intent_fp_independent_of_batching(void **state) {
    (void) state;
    intent_apdus_t apdus;
    _build_intent_apdus(&apdus);

    uint8_t stream[3u * APDU_CDATA_MAX];
    size_t stream_len = 0;
    memcpy(stream + stream_len, apdus.scalars.data, apdus.scalars.len);
    stream_len += apdus.scalars.len;
    memcpy(stream + stream_len, apdus.group.data, apdus.group.len);
    stream_len += apdus.group.len;
    memcpy(stream + stream_len, apdus.keys.data, apdus.keys.len);
    stream_len += apdus.keys.len;

    /* One-shot over the concatenation. */
    uint8_t fp[VAULT_FINGERPRINT_LEN];
    assert_true(vault_fingerprint(stream, stream_len, fp));
    assert_memory_equal(fp, INTENT_FP_1K1C_MAINNET, VAULT_FINGERPRINT_LEN);

    /* One byte per update, with an empty (NULL-data) APDU between every byte. */
    cx_sha256_t hash;
    vault_fingerprint_init(&hash);
    for (size_t i = 0; i < stream_len; i++) {
        assert_true(vault_fingerprint_update(&hash, stream + i, 1));
        assert_true(vault_fingerprint_update(&hash, NULL, 0));
    }
    memset(fp, 0, sizeof(fp));
    assert_true(vault_fingerprint_final(&hash, fp));
    assert_memory_equal(fp, INTENT_FP_1K1C_MAINNET, VAULT_FINGERPRINT_LEN);
}

static void test_intent_fp_changes_with_one_byte(void **state) {
    (void) state;
    intent_apdus_t apdus;
    _build_intent_apdus(&apdus);
    apdus.keys.data[apdus.keys.len - 1u] ^= 0x01u;

    uint8_t fp[VAULT_FINGERPRINT_LEN];
    _intent_fp_per_apdu(&apdus, fp);
    assert_memory_not_equal(fp, INTENT_FP_1K1C_MAINNET, VAULT_FINGERPRINT_LEN);
}

static void test_fingerprint_final_wipes_hash(void **state) {
    (void) state;
    cx_sha256_t hash;
    vault_fingerprint_init(&hash);
    assert_true(vault_fingerprint_update(&hash, V42_ROOT, sizeof(V42_ROOT)));

    uint8_t fp[VAULT_FINGERPRINT_LEN];
    assert_true(vault_fingerprint_final(&hash, fp));

    const uint8_t *p = (const uint8_t *) &hash;
    for (size_t i = 0; i < sizeof(hash); i++) {
        assert_int_equal(p[i], 0);
    }
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(void) {
    const struct CMUnitTest tests[] = {
        /* init */
        cmocka_unit_test(test_init_zeroes_and_sets_idle),

        /* invalidate */
        cmocka_unit_test(test_invalidate_from_idle),
        cmocka_unit_test(test_invalidate_zeroes_secret_and_intent),
        cmocka_unit_test(test_invalidate_clears_scratch),

        /* valid transitions */
        cmocka_unit_test(test_transition_idle_to_hash_derived),
        cmocka_unit_test(test_transition_hash_derived_to_intent_loaded),

        /* invalid transitions */
        cmocka_unit_test(test_transition_idle_to_intent_loaded_illegal),
        cmocka_unit_test(test_transition_intent_loaded_is_terminal),
        cmocka_unit_test(test_transition_wrong_from_state),
        cmocka_unit_test(test_transition_illegal_to_state),
        cmocka_unit_test(test_transition_backwards_without_valid_edge),
        cmocka_unit_test(test_transition_double_approve),

        /* signature cap counters */
        cmocka_unit_test(test_init_zeroes_cap_counters),
        cmocka_unit_test(test_invalidate_zeroes_cap_counters),

        /* GET_VAULT_STATE response encoding */
        cmocka_unit_test(test_encode_state_idle_reports_nothing),
        cmocka_unit_test(test_encode_state_hash_derived_reports_context_only),
        cmocka_unit_test(test_encode_state_intent_loaded_reports_both),
        cmocka_unit_test(test_encode_state_unknown_state_fails),
        cmocka_unit_test(test_encode_state_is_read_only),
        cmocka_unit_test(test_invalidate_clears_fingerprints),

        /* GET_VAULT_STATE fingerprint vectors */
        cmocka_unit_test(test_context_fp_vector),
        cmocka_unit_test(test_intent_fp_vector),
        cmocka_unit_test(test_intent_fp_independent_of_batching),
        cmocka_unit_test(test_intent_fp_changes_with_one_byte),
        cmocka_unit_test(test_fingerprint_final_wipes_hash),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
