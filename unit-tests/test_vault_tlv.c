/**
 * Unit tests for:
 *   - vault_tlv_parse          (src/vault_tlv.c)
 *   - vault_tlv_parse_group    (src/vault_tlv.c)
 *   - vault_validate_and_store_key   (src/handler/approve_vault_intent_core.h)
 *   - vault_check_depositor_uniqueness (src/handler/approve_vault_intent_core.h)
 *
 * No SDK calls, no mock_cx needed — vault_tlv.c uses only os_utils.h (mocked)
 * and the core functions are pure static inlines.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "vault_tlv.h"
#include "vault_intent_tags.h"
#include "vault_constants.h"
#include "handler/approve_vault_intent_core.h"

/* -------------------------------------------------------------------------
 * Test-fixture constants (BIP44_COIN_TYPE=1 set via CMake compile definition)
 * ---------------------------------------------------------------------- */

#define TEST_VAULT_AMOUNT      100000ULL
#define TEST_COMMISSION_FEE      1000ULL  /* vault_amount > 1000 + 660 = 1660 ✓ */
#define TEST_DEPOSITOR_CLAIM    10000ULL
#define TEST_BASE_FEE_RATE         10ULL
#define TEST_PEGIN_MAX_FEE      50000ULL
#define TEST_PEGIN_CSV            100u    /* [72, 1008] ✓ */
#define TEST_PAYOUT_TIMELOCK      200u    /* (90, 4032) ✓ */
#define TEST_HTLC_REFUND          144u    /* [72, 1008] ✓ */
#define TEST_HTLC_VOUT              0u
#define TEST_PEGIN_ANCHOR_VALUE   240ULL

/* Old v18 per-vault scalar tag byte — rejected in P1=0x00 since v19. */
#define TAG_OLD_VAULT_PROVIDER_PK 0x04u

/* m/86'/1'/0'/0/0 — coin type matches BIP44_COIN_TYPE=1 */
static const uint32_t VALID_PATH[5] = {
    0x80000000u | 86u,
    0x80000000u | 1u,
    0x80000000u | 0u,
    0u,
    0u,
};

static const uint8_t VALID_VP_PK[32] = {
    0x02,0x02,0x02,0x02, 0x02,0x02,0x02,0x02,
    0x02,0x02,0x02,0x02, 0x02,0x02,0x02,0x02,
    0x02,0x02,0x02,0x02, 0x02,0x02,0x02,0x02,
    0x02,0x02,0x02,0x02, 0x02,0x02,0x02,0x02,
};

static const uint8_t VALID_TXID[32] = {
    0x01,0x02,0x03,0x04, 0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C, 0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14, 0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C, 0x1D,0x1E,0x1F,0x20,
};

/* -------------------------------------------------------------------------
 * TLV builder helpers
 * ---------------------------------------------------------------------- */

static uint8_t *tlv_u8(uint8_t *p, uint8_t tag, uint8_t val) {
    *p++ = tag; *p++ = 1; *p++ = val;
    return p;
}

static uint8_t *tlv_u32be(uint8_t *p, uint8_t tag, uint32_t val) {
    *p++ = tag; *p++ = 4;
    *p++ = (val >> 24) & 0xFF;
    *p++ = (val >> 16) & 0xFF;
    *p++ = (val >>  8) & 0xFF;
    *p++ =  val        & 0xFF;
    return p;
}

static uint8_t *tlv_u64be(uint8_t *p, uint8_t tag, uint64_t val) {
    *p++ = tag; *p++ = 8;
    for (int i = 7; i >= 0; i--) *p++ = (val >> (i * 8)) & 0xFF;
    return p;
}

static uint8_t *tlv_bytes(uint8_t *p, uint8_t tag, const uint8_t *val, uint8_t len) {
    *p++ = tag; *p++ = len;
    memcpy(p, val, len); p += len;
    return p;
}

static uint8_t *tlv_path(uint8_t *p, uint8_t tag, const uint32_t *path, int levels) {
    *p++ = tag; *p++ = (uint8_t)(levels * 4);
    for (int i = 0; i < levels; i++) {
        uint32_t v = path[i];
        *p++ = (v >> 24) & 0xFF;
        *p++ = (v >> 16) & 0xFF;
        *p++ = (v >>  8) & 0xFF;
        *p++ =  v        & 0xFF;
    }
    return p;
}

/**
 * Build a complete, valid P1=0x00 TLV payload (13 scalar tags) into @p buf.
 * Returns byte length.
 */
static size_t build_valid_tlv(uint8_t *buf) {
    uint8_t *p = buf;
    p = tlv_u8    (p, TAG_STRUCTURE_TYPE,            VAULT_STRUCTURE_TYPE);
    p = tlv_u8    (p, TAG_VERSION,                   VAULT_PROTOCOL_VERSION);
    p = tlv_u32be (p, TAG_COIN_TYPE,                 BIP44_COIN_TYPE);
    p = tlv_u64be (p, TAG_BASE_FEE_RATE,             TEST_BASE_FEE_RATE);
    p = tlv_u32be (p, TAG_PEGIN_CSV_TIMELOCK,        TEST_PEGIN_CSV);
    p = tlv_u32be (p, TAG_PAYOUT_TIMELOCK,           TEST_PAYOUT_TIMELOCK);
    p = tlv_bytes (p, TAG_PREPEGIN_TXID,             VALID_TXID, 32);
    p = tlv_u32be (p, TAG_HTLC_REFUND_TIMELOCK,      TEST_HTLC_REFUND);
    p = tlv_path  (p, TAG_DEPOSITOR_DERIVATION_PATH, VALID_PATH, 5);
    p = tlv_u8    (p, TAG_KEEPER_COUNT,              1);
    p = tlv_u8    (p, TAG_CHALLENGER_COUNT,          1);
    p = tlv_u64be (p, TAG_PEGIN_ANCHOR_VALUE,        TEST_PEGIN_ANCHOR_VALUE);
    p = tlv_u8    (p, TAG_VAULT_COUNT,               1);
    return (size_t)(p - buf);
}

/** Build a complete, valid P1=0x02 group TLV payload (6 group tags) into @p buf. */
static size_t build_valid_group(uint8_t *buf) {
    uint8_t *p = buf;
    p = tlv_u8    (p, TAG_GRP_HTLC_VOUT,             TEST_HTLC_VOUT);
    p = tlv_bytes (p, TAG_GRP_VAULT_PROVIDER_PK,     VALID_VP_PK, 32);
    p = tlv_u64be (p, TAG_GRP_VAULT_AMOUNT,          TEST_VAULT_AMOUNT);
    p = tlv_u64be (p, TAG_GRP_COMMISSION_FEE,        TEST_COMMISSION_FEE);
    p = tlv_u64be (p, TAG_GRP_DEPOSITOR_CLAIM_VALUE, TEST_DEPOSITOR_CLAIM);
    p = tlv_u64be (p, TAG_GRP_PEGIN_MAX_FEE,         TEST_PEGIN_MAX_FEE);
    return (size_t)(p - buf);
}

/** Replace the value bytes of the first occurrence of @p tag in @p buf. */
static void patch_tlv_u8(uint8_t *buf, size_t len, uint8_t tag, uint8_t val) {
    for (size_t i = 0; i + 2 < len; ) {
        uint8_t t = buf[i];
        uint8_t l = buf[i + 1];
        if (t == tag && l == 1) { buf[i + 2] = val; return; }
        i += 2 + l;
    }
}

static void patch_tlv_u32be(uint8_t *buf, size_t len, uint8_t tag, uint32_t val) {
    for (size_t i = 0; i + 2 < len; ) {
        uint8_t t = buf[i];
        uint8_t l = buf[i + 1];
        if (t == tag && l == 4) {
            buf[i+2] = (val>>24)&0xFF; buf[i+3] = (val>>16)&0xFF;
            buf[i+4] = (val>> 8)&0xFF; buf[i+5] =  val    &0xFF;
            return;
        }
        i += 2 + l;
    }
}

static void patch_tlv_u64be(uint8_t *buf, size_t len, uint8_t tag, uint64_t val) {
    for (size_t i = 0; i + 2 < len; ) {
        uint8_t t = buf[i];
        uint8_t l = buf[i + 1];
        if (t == tag && l == 8) {
            for (int k = 7; k >= 0; k--) buf[i + 2 + (7-k)] = (val >> (k*8)) & 0xFF;
            return;
        }
        i += 2 + l;
    }
}

/* =========================================================================
 * Group 1: vault_tlv_parse
 * ====================================================================== */

static void test_tlv_valid_minimal(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_OK);
    assert_int_equal(out.keeper_count, 1);
    assert_int_equal(out.challenger_count, 1);
    assert_int_equal(out.vault_count, 1);
    assert_int_equal(out.pegin_csv_timelock, TEST_PEGIN_CSV);
    assert_int_equal(out.payout_timelock, TEST_PAYOUT_TIMELOCK);
    assert_int_equal(out.groups[0].pegin_anchor_value, TEST_PEGIN_ANCHOR_VALUE);
}

static void test_tlv_tags_any_order_ok(void **state) {
    (void) state;
    /* Build with TAG_COIN_TYPE after TAG_KEEPER_COUNT — non-canonical order.
     * The cross-field check (depositor_path[1] == coin_type | HARDENED) must
     * still pass even when coin_type tag arrives after the path tag. */
    uint8_t buf[256]; vault_intent_t out;
    uint8_t *p = buf;
    p = tlv_u8    (p, TAG_STRUCTURE_TYPE,            VAULT_STRUCTURE_TYPE);
    p = tlv_u8    (p, TAG_VERSION,                   VAULT_PROTOCOL_VERSION);
    p = tlv_u64be (p, TAG_BASE_FEE_RATE,             TEST_BASE_FEE_RATE);
    p = tlv_u32be (p, TAG_PEGIN_CSV_TIMELOCK,        TEST_PEGIN_CSV);
    p = tlv_u32be (p, TAG_PAYOUT_TIMELOCK,           TEST_PAYOUT_TIMELOCK);
    p = tlv_bytes (p, TAG_PREPEGIN_TXID,             VALID_TXID, 32);
    p = tlv_u32be (p, TAG_HTLC_REFUND_TIMELOCK,      TEST_HTLC_REFUND);
    p = tlv_path  (p, TAG_DEPOSITOR_DERIVATION_PATH, VALID_PATH, 5);
    p = tlv_u8    (p, TAG_KEEPER_COUNT,              1);
    p = tlv_u8    (p, TAG_CHALLENGER_COUNT,          1);
    p = tlv_u64be (p, TAG_PEGIN_ANCHOR_VALUE,        TEST_PEGIN_ANCHOR_VALUE);
    p = tlv_u8    (p, TAG_VAULT_COUNT,               1);
    /* TAG_COIN_TYPE last — intentionally out of spec-table order */
    p = tlv_u32be (p, TAG_COIN_TYPE,                 BIP44_COIN_TYPE);
    assert_int_equal(vault_tlv_parse(buf, (size_t)(p - buf), &out), VAULT_TLV_OK);
    assert_int_equal(out.coin_type, (uint32_t) BIP44_COIN_TYPE);
}

static void test_tlv_wrong_structure_type(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u8(buf, len, TAG_STRUCTURE_TYPE, VAULT_STRUCTURE_TYPE + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_wrong_version(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u8(buf, len, TAG_VERSION, VAULT_PROTOCOL_VERSION + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_wrong_coin_type(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_COIN_TYPE, BIP44_COIN_TYPE + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_pegin_csv_below_min(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_PEGIN_CSV_TIMELOCK, VAULT_TIMELOCK_MIN - 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_pegin_csv_at_min(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_PEGIN_CSV_TIMELOCK, VAULT_TIMELOCK_MIN);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_OK);
}

static void test_tlv_pegin_csv_above_max(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_PEGIN_CSV_TIMELOCK, VAULT_TIMELOCK_MAX + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_pegin_csv_at_max(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_PEGIN_CSV_TIMELOCK, VAULT_TIMELOCK_MAX);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_OK);
}

static void test_tlv_payout_timelock_at_exclusive_min(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_PAYOUT_TIMELOCK, VAULT_PAYOUT_TIMELOCK_MIN); /* = 90, excluded */
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_payout_timelock_just_above_min(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_PAYOUT_TIMELOCK, VAULT_PAYOUT_TIMELOCK_MIN + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_OK);
}

static void test_tlv_payout_timelock_at_exclusive_max(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_PAYOUT_TIMELOCK, VAULT_PAYOUT_TIMELOCK_MAX); /* = 4032, excluded */
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_payout_timelock_just_below_max(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_PAYOUT_TIMELOCK, VAULT_PAYOUT_TIMELOCK_MAX - 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_OK);
}

static void test_tlv_keeper_count_zero(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u8(buf, len, TAG_KEEPER_COUNT, 0);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_keeper_count_too_large(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u8(buf, len, TAG_KEEPER_COUNT, VAULT_MAX_KEEPERS + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_challenger_count_zero(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u8(buf, len, TAG_CHALLENGER_COUNT, 0);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_challenger_count_too_large(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u8(buf, len, TAG_CHALLENGER_COUNT, VAULT_MAX_CHALLENGERS + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_vault_count_zero(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u8(buf, len, TAG_VAULT_COUNT, 0);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_vault_count_too_large(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u8(buf, len, TAG_VAULT_COUNT, VAULT_MAX_VAULTS + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_htlc_refund_below_min(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_HTLC_REFUND_TIMELOCK, VAULT_TIMELOCK_MIN - 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_htlc_refund_at_min(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_HTLC_REFUND_TIMELOCK, VAULT_TIMELOCK_MIN);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_OK);
}

static void test_tlv_htlc_refund_above_max(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_HTLC_REFUND_TIMELOCK, VAULT_TIMELOCK_MAX + 1);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_htlc_refund_at_max(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    patch_tlv_u32be(buf, len, TAG_HTLC_REFUND_TIMELOCK, VAULT_TIMELOCK_MAX);
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_OK);
}

static void test_tlv_empty_payload(void **state) {
    (void) state;
    vault_intent_t out;
    assert_int_equal(vault_tlv_parse(NULL, 0, &out), VAULT_TLV_ERR_MISSING_FIELD);
}

static void test_tlv_depositor_path_wrong_purpose(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    /* Replace path tag value with m/84'/1'/0'/0/0 */
    uint32_t bad_path[5] = { 0x80000000u | 84u, 0x80000000u | 1u, 0x80000000u, 0u, 0u };
    for (size_t i = 0; i + 2 < len; ) {
        if (buf[i] == TAG_DEPOSITOR_DERIVATION_PATH) {
            uint8_t *v = buf + i + 2;
            for (int k = 0; k < 5; k++) {
                v[k*4+0] = (bad_path[k]>>24)&0xFF; v[k*4+1] = (bad_path[k]>>16)&0xFF;
                v[k*4+2] = (bad_path[k]>> 8)&0xFF; v[k*4+3] =  bad_path[k]    &0xFF;
            }
            break;
        }
        i += 2 + buf[i+1];
    }
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_depositor_path_coin_type_mismatch(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    /* path[1] = coin_type 99 ≠ BIP44_COIN_TYPE */
    uint32_t bad_path[5] = { 0x80000000u|86u, 0x80000000u|99u, 0x80000000u, 0u, 0u };
    for (size_t i = 0; i + 2 < len; ) {
        if (buf[i] == TAG_DEPOSITOR_DERIVATION_PATH) {
            uint8_t *v = buf + i + 2;
            for (int k = 0; k < 5; k++) {
                v[k*4+0] = (bad_path[k]>>24)&0xFF; v[k*4+1] = (bad_path[k]>>16)&0xFF;
                v[k*4+2] = (bad_path[k]>> 8)&0xFF; v[k*4+3] =  bad_path[k]    &0xFF;
            }
            break;
        }
        i += 2 + buf[i+1];
    }
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_depositor_path_account_not_hardened(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    /* path[2] = 0 (not hardened) */
    uint32_t bad_path[5] = { 0x80000000u|86u, 0x80000000u|1u, 0u, 0u, 0u };
    for (size_t i = 0; i + 2 < len; ) {
        if (buf[i] == TAG_DEPOSITOR_DERIVATION_PATH) {
            uint8_t *v = buf + i + 2;
            for (int k = 0; k < 5; k++) {
                v[k*4+0] = (bad_path[k]>>24)&0xFF; v[k*4+1] = (bad_path[k]>>16)&0xFF;
                v[k*4+2] = (bad_path[k]>> 8)&0xFF; v[k*4+3] =  bad_path[k]    &0xFF;
            }
            break;
        }
        i += 2 + buf[i+1];
    }
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_duplicate_tag(void **state) {
    (void) state;
    uint8_t buf[300]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    /* Append a duplicate TAG_VERSION */
    buf[len++] = TAG_VERSION; buf[len++] = 1; buf[len++] = VAULT_PROTOCOL_VERSION;
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_DUPLICATE_TAG);
}

static void test_tlv_unknown_tag(void **state) {
    (void) state;
    uint8_t buf[300]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    buf[len++] = 0xFF; buf[len++] = 1; buf[len++] = 0x00;
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_UNKNOWN_TAG);
}

/* Old v18 per-vault scalar tags (0x04–0x07, 0x09, 0x0D) must be rejected in P1=0x00. */
static void test_tlv_rejected_per_vault_tag_in_scalar(void **state) {
    (void) state;
    uint8_t buf[300]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    /* Append old vault_provider_pk tag (0x04) — rejected by whitelist mask */
    buf[len++] = TAG_OLD_VAULT_PROVIDER_PK; buf[len++] = 32;
    memcpy(buf + len, VALID_VP_PK, 32); len += 32;
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_UNKNOWN_TAG);
}

static void test_tlv_missing_field(void **state) {
    (void) state;
    /* Build without TAG_KEEPER_COUNT */
    uint8_t buf[256]; vault_intent_t out;
    uint8_t *p = buf;
    p = tlv_u8    (p, TAG_STRUCTURE_TYPE,            VAULT_STRUCTURE_TYPE);
    p = tlv_u8    (p, TAG_VERSION,                   VAULT_PROTOCOL_VERSION);
    p = tlv_u32be (p, TAG_COIN_TYPE,                 BIP44_COIN_TYPE);
    p = tlv_u64be (p, TAG_BASE_FEE_RATE,             TEST_BASE_FEE_RATE);
    p = tlv_u32be (p, TAG_PEGIN_CSV_TIMELOCK,        TEST_PEGIN_CSV);
    p = tlv_u32be (p, TAG_PAYOUT_TIMELOCK,           TEST_PAYOUT_TIMELOCK);
    p = tlv_bytes (p, TAG_PREPEGIN_TXID,             VALID_TXID, 32);
    p = tlv_u32be (p, TAG_HTLC_REFUND_TIMELOCK,      TEST_HTLC_REFUND);
    p = tlv_path  (p, TAG_DEPOSITOR_DERIVATION_PATH, VALID_PATH, 5);
    /* TAG_KEEPER_COUNT omitted */
    p = tlv_u8    (p, TAG_CHALLENGER_COUNT,          1);
    p = tlv_u64be (p, TAG_PEGIN_ANCHOR_VALUE,        TEST_PEGIN_ANCHOR_VALUE);
    p = tlv_u8    (p, TAG_VAULT_COUNT,               1);
    assert_int_equal(vault_tlv_parse(buf, (size_t)(p - buf), &out), VAULT_TLV_ERR_MISSING_FIELD);
}

static void test_tlv_wrong_field_length(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    /* Corrupt coin_type length from 4 to 3 */
    for (size_t i = 0; i + 1 < len; ) {
        if (buf[i] == TAG_COIN_TYPE) { buf[i + 1] = 3; break; }
        i += 2 + buf[i+1];
    }
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_WRONG_LENGTH);
}

static void test_tlv_overflow(void **state) {
    (void) state;
    uint8_t buf[256]; vault_intent_t out;
    size_t len = build_valid_tlv(buf);
    /* Corrupt prepegin_txid length to extend past buffer end */
    for (size_t i = 0; i + 1 < len; ) {
        if (buf[i] == TAG_PREPEGIN_TXID) { buf[i + 1] = 0xFF; break; }
        i += 2 + buf[i+1];
    }
    assert_int_equal(vault_tlv_parse(buf, len, &out), VAULT_TLV_ERR_OVERFLOW);
}

/* =========================================================================
 * Group 1b: vault_tlv_parse_group
 * ====================================================================== */

static void test_tlv_parse_group_valid(void **state) {
    (void) state;
    uint8_t buf[128]; vault_group_t grp;
    size_t len = build_valid_group(buf);
    assert_int_equal(vault_tlv_parse_group(buf, len, &grp), VAULT_TLV_OK);
    assert_int_equal(grp.htlc_vout, TEST_HTLC_VOUT);
    assert_memory_equal(grp.vault_provider_pk, VALID_VP_PK, 32);
    assert_int_equal(grp.vault_amount, TEST_VAULT_AMOUNT);
    assert_int_equal(grp.commission_fee, TEST_COMMISSION_FEE);
}

static void test_tlv_parse_group_missing_field(void **state) {
    (void) state;
    /* Build without TAG_GRP_VAULT_AMOUNT */
    uint8_t buf[128]; vault_group_t grp;
    uint8_t *p = buf;
    p = tlv_u8    (p, TAG_GRP_HTLC_VOUT,             TEST_HTLC_VOUT);
    p = tlv_bytes (p, TAG_GRP_VAULT_PROVIDER_PK,     VALID_VP_PK, 32);
    /* TAG_GRP_VAULT_AMOUNT omitted */
    p = tlv_u64be (p, TAG_GRP_COMMISSION_FEE,        TEST_COMMISSION_FEE);
    p = tlv_u64be (p, TAG_GRP_DEPOSITOR_CLAIM_VALUE, TEST_DEPOSITOR_CLAIM);
    p = tlv_u64be (p, TAG_GRP_PEGIN_MAX_FEE,         TEST_PEGIN_MAX_FEE);
    assert_int_equal(vault_tlv_parse_group(buf, (size_t)(p - buf), &grp),
                     VAULT_TLV_ERR_MISSING_FIELD);
}

static void test_tlv_parse_group_commission_below_dust(void **state) {
    (void) state;
    uint8_t buf[128]; vault_group_t grp;
    size_t len = build_valid_group(buf);

    /* commission_fee == 0 → the VP commission output would be empty → fail */
    patch_tlv_u64be(buf, len, TAG_GRP_COMMISSION_FEE, 0);
    assert_int_equal(vault_tlv_parse_group(buf, len, &grp), VAULT_TLV_ERR_VALIDATION);

    /* commission_fee just below the relay dust limit → fail */
    patch_tlv_u64be(buf, len, TAG_GRP_COMMISSION_FEE, VAULT_DUST_LIMIT - 1);
    assert_int_equal(vault_tlv_parse_group(buf, len, &grp), VAULT_TLV_ERR_VALIDATION);

    /* commission_fee exactly at the relay dust limit → OK */
    patch_tlv_u64be(buf, len, TAG_GRP_COMMISSION_FEE, VAULT_DUST_LIMIT);
    assert_int_equal(vault_tlv_parse_group(buf, len, &grp), VAULT_TLV_OK);
}

static void test_tlv_parse_group_amount_exactly_at_boundary(void **state) {
    (void) state;
    /* vault_amount == commission_fee + 2*DUST is not strictly greater → fail */
    uint8_t buf[128]; vault_group_t grp;
    size_t len = build_valid_group(buf);
    patch_tlv_u64be(buf, len, TAG_GRP_VAULT_AMOUNT,
                    TEST_COMMISSION_FEE + 2 * VAULT_DUST_LIMIT);
    assert_int_equal(vault_tlv_parse_group(buf, len, &grp), VAULT_TLV_ERR_VALIDATION);
}

static void test_tlv_parse_group_amount_just_above_boundary(void **state) {
    (void) state;
    /* vault_amount == commission_fee + 2*DUST + 1 → OK */
    uint8_t buf[128]; vault_group_t grp;
    size_t len = build_valid_group(buf);
    patch_tlv_u64be(buf, len, TAG_GRP_VAULT_AMOUNT,
                    TEST_COMMISSION_FEE + 2 * VAULT_DUST_LIMIT + 1);
    assert_int_equal(vault_tlv_parse_group(buf, len, &grp), VAULT_TLV_OK);
}

/* =========================================================================
 * Group 2: vault_validate_and_store_key
 * ====================================================================== */

/** Build a minimal vault_intent_t with fields needed for key validation. */
static vault_intent_t make_intent(uint8_t keeper_count, uint8_t challenger_count) {
    vault_intent_t intent;
    memset(&intent, 0, sizeof(intent));
    intent.keeper_count     = keeper_count;
    intent.challenger_count = challenger_count;
    intent.vault_count      = 1;
    memcpy(intent.groups[0].vault_provider_pk, VALID_VP_PK, 32);
    return intent;
}

/* Distinct test keys — lex-sorted ascending */
static const uint8_t KEY_A[32] = {
    0x10,0x00,0x00,0x00, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};
static const uint8_t KEY_B[32] = {
    0x20,0x00,0x00,0x00, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

static void test_key_first_keeper_ok(void **state) {
    (void) state;
    vault_intent_t intent = make_intent(2, 1);
    assert_int_equal(vault_validate_and_store_key(&intent, 0, KEY_A), VAULT_KEY_OK);
    assert_memory_equal(intent.keeper_pks[0], KEY_A, 32);
}

static void test_key_second_keeper_ascending_ok(void **state) {
    (void) state;
    vault_intent_t intent = make_intent(2, 1);
    assert_int_equal(vault_validate_and_store_key(&intent, 0, KEY_A), VAULT_KEY_OK);
    assert_int_equal(vault_validate_and_store_key(&intent, 1, KEY_B), VAULT_KEY_OK);
    assert_memory_equal(intent.keeper_pks[1], KEY_B, 32);
}

static void test_key_second_keeper_equal(void **state) {
    (void) state;
    vault_intent_t intent = make_intent(2, 1);
    vault_validate_and_store_key(&intent, 0, KEY_A);
    assert_int_equal(vault_validate_and_store_key(&intent, 1, KEY_A), VAULT_KEY_ERR_OUT_OF_ORDER);
}

static void test_key_second_keeper_descending(void **state) {
    (void) state;
    vault_intent_t intent = make_intent(2, 1);
    vault_validate_and_store_key(&intent, 0, KEY_B);
    assert_int_equal(vault_validate_and_store_key(&intent, 1, KEY_A), VAULT_KEY_ERR_OUT_OF_ORDER);
}

static void test_key_first_challenger_no_order_check(void **state) {
    (void) state;
    /* First challenger (idx == keeper_count) must not be compared with last keeper */
    vault_intent_t intent = make_intent(1, 2);
    vault_validate_and_store_key(&intent, 0, KEY_B); /* keeper 0 = KEY_B */
    /* KEY_A < KEY_B, but it is the first challenger so lex check is skipped */
    assert_int_equal(vault_validate_and_store_key(&intent, 1, KEY_A), VAULT_KEY_OK);
}

static void test_key_equals_vp(void **state) {
    (void) state;
    vault_intent_t intent = make_intent(1, 1);
    assert_int_equal(vault_validate_and_store_key(&intent, 0, VALID_VP_PK),
                     VAULT_KEY_ERR_ROLE_COLLISION);
}

static void test_key_within_group_repeat_caught_by_order(void **state) {
    (void) state;
    /* KEY_A < KEY_B; re-sending KEY_A at index 2 fails the lex check (KEY_A <= KEY_B)
     * before the duplicate scan.  Within a strictly ascending group a duplicate is
     * always caught by OUT_OF_ORDER first — DUPLICATE fires only for cross-group cases. */
    vault_intent_t intent = make_intent(3, 1);
    vault_validate_and_store_key(&intent, 0, KEY_A);
    vault_validate_and_store_key(&intent, 1, KEY_B);
    assert_int_equal(vault_validate_and_store_key(&intent, 2, KEY_A),
                     VAULT_KEY_ERR_OUT_OF_ORDER);
}

static void test_key_duplicate_across_groups(void **state) {
    (void) state;
    /* Challenger key same as keeper key must be rejected */
    vault_intent_t intent = make_intent(1, 1);
    vault_validate_and_store_key(&intent, 0, KEY_A); /* keeper 0 */
    assert_int_equal(vault_validate_and_store_key(&intent, 1, KEY_A), VAULT_KEY_ERR_DUPLICATE);
}

/* =========================================================================
 * Group 3: vault_check_depositor_uniqueness
 * ====================================================================== */

static const uint8_t DEPOSITOR_KEY[32] = {
    0x05,0x00,0x00,0x00, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

static vault_intent_t make_intent_with_keys(void) {
    vault_intent_t intent = make_intent(1, 1);
    memcpy(intent.keeper_pks[0],     KEY_A, 32);
    memcpy(intent.challenger_pks[0], KEY_B, 32);
    return intent;
}

static void test_depositor_unique(void **state) {
    (void) state;
    vault_intent_t intent = make_intent_with_keys();
    assert_true(vault_check_depositor_uniqueness(&intent, DEPOSITOR_KEY));
}

static void test_depositor_equals_vp(void **state) {
    (void) state;
    vault_intent_t intent = make_intent_with_keys();
    assert_false(vault_check_depositor_uniqueness(&intent, VALID_VP_PK));
}

static void test_depositor_equals_keeper(void **state) {
    (void) state;
    vault_intent_t intent = make_intent_with_keys();
    assert_false(vault_check_depositor_uniqueness(&intent, KEY_A));
}

static void test_depositor_equals_challenger(void **state) {
    (void) state;
    vault_intent_t intent = make_intent_with_keys();
    assert_false(vault_check_depositor_uniqueness(&intent, KEY_B));
}

/* =========================================================================
 * main
 * ====================================================================== */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* vault_tlv_parse — happy paths */
        cmocka_unit_test(test_tlv_valid_minimal),
        cmocka_unit_test(test_tlv_tags_any_order_ok),

        /* vault_tlv_parse — constant validation */
        cmocka_unit_test(test_tlv_wrong_structure_type),
        cmocka_unit_test(test_tlv_wrong_version),
        cmocka_unit_test(test_tlv_wrong_coin_type),

        /* vault_tlv_parse — timelock ranges */
        cmocka_unit_test(test_tlv_pegin_csv_below_min),
        cmocka_unit_test(test_tlv_pegin_csv_at_min),
        cmocka_unit_test(test_tlv_pegin_csv_above_max),
        cmocka_unit_test(test_tlv_pegin_csv_at_max),
        cmocka_unit_test(test_tlv_payout_timelock_at_exclusive_min),
        cmocka_unit_test(test_tlv_payout_timelock_just_above_min),
        cmocka_unit_test(test_tlv_payout_timelock_at_exclusive_max),
        cmocka_unit_test(test_tlv_payout_timelock_just_below_max),
        cmocka_unit_test(test_tlv_htlc_refund_below_min),
        cmocka_unit_test(test_tlv_htlc_refund_at_min),
        cmocka_unit_test(test_tlv_htlc_refund_above_max),
        cmocka_unit_test(test_tlv_htlc_refund_at_max),

        /* vault_tlv_parse — count validation */
        cmocka_unit_test(test_tlv_keeper_count_zero),
        cmocka_unit_test(test_tlv_keeper_count_too_large),
        cmocka_unit_test(test_tlv_challenger_count_zero),
        cmocka_unit_test(test_tlv_challenger_count_too_large),
        cmocka_unit_test(test_tlv_vault_count_zero),
        cmocka_unit_test(test_tlv_vault_count_too_large),

        /* vault_tlv_parse — derivation path validation */
        cmocka_unit_test(test_tlv_depositor_path_wrong_purpose),
        cmocka_unit_test(test_tlv_depositor_path_coin_type_mismatch),
        cmocka_unit_test(test_tlv_depositor_path_account_not_hardened),

        /* vault_tlv_parse — TLV structure errors */
        cmocka_unit_test(test_tlv_empty_payload),
        cmocka_unit_test(test_tlv_duplicate_tag),
        cmocka_unit_test(test_tlv_unknown_tag),
        cmocka_unit_test(test_tlv_rejected_per_vault_tag_in_scalar),
        cmocka_unit_test(test_tlv_missing_field),
        cmocka_unit_test(test_tlv_wrong_field_length),
        cmocka_unit_test(test_tlv_overflow),

        /* vault_tlv_parse_group — happy path */
        cmocka_unit_test(test_tlv_parse_group_valid),

        /* vault_tlv_parse_group — field errors */
        cmocka_unit_test(test_tlv_parse_group_missing_field),

        /* vault_tlv_parse_group — amount / fee validation */
        cmocka_unit_test(test_tlv_parse_group_commission_below_dust),
        cmocka_unit_test(test_tlv_parse_group_amount_exactly_at_boundary),
        cmocka_unit_test(test_tlv_parse_group_amount_just_above_boundary),

        /* vault_validate_and_store_key */
        cmocka_unit_test(test_key_first_keeper_ok),
        cmocka_unit_test(test_key_second_keeper_ascending_ok),
        cmocka_unit_test(test_key_second_keeper_equal),
        cmocka_unit_test(test_key_second_keeper_descending),
        cmocka_unit_test(test_key_first_challenger_no_order_check),
        cmocka_unit_test(test_key_equals_vp),
        cmocka_unit_test(test_key_within_group_repeat_caught_by_order),
        cmocka_unit_test(test_key_duplicate_across_groups),

        /* vault_check_depositor_uniqueness */
        cmocka_unit_test(test_depositor_unique),
        cmocka_unit_test(test_depositor_equals_vp),
        cmocka_unit_test(test_depositor_equals_keeper),
        cmocka_unit_test(test_depositor_equals_challenger),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
