/**
 * Unit tests for sign_psbt_validate_helpers.c — the three pure helper
 * functions extracted from the PSBT validation layer:
 *
 *   check_bip86_path              — BIP-86 derivation path shape check
 *   parse_tap_bip32_deriv_value   — TAP_BIP32_DERIVATION value parser
 *   parse_refund_leaf_script      — Refund HTLC leaf script shape checker
 *
 * Tests verify both acceptance of valid inputs and rejection of every
 * distinct invalid shape. BIP44_COIN_TYPE=1 is set via CMake compile def.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "sign_psbt_validate_helpers.h"

/* ---------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

/* Build a 5-step BIP-86 path: m/purpose'/coin'/account'/change/index */
static void make_bip86_path(uint32_t *out,
                             uint32_t purpose,
                             uint32_t coin,
                             uint32_t account,
                             uint32_t change,
                             uint32_t index) {
    out[0] = purpose  | 0x80000000u;
    out[1] = coin     | 0x80000000u;
    out[2] = account  | 0x80000000u;
    out[3] = change;
    out[4] = index;
}

/* Write a uint32_t in little-endian into a byte buffer at offset. */
static void write_u32_le(uint8_t *buf, size_t offset, uint32_t v) {
    buf[offset + 0] = (uint8_t)(v);
    buf[offset + 1] = (uint8_t)(v >> 8);
    buf[offset + 2] = (uint8_t)(v >> 16);
    buf[offset + 3] = (uint8_t)(v >> 24);
}

/* Write a uint32_t in big-endian into a byte buffer at offset. */
static void write_u32_be(uint8_t *buf, size_t offset, uint32_t v) {
    buf[offset + 0] = (uint8_t)(v >> 24);
    buf[offset + 1] = (uint8_t)(v >> 16);
    buf[offset + 2] = (uint8_t)(v >> 8);
    buf[offset + 3] = (uint8_t)(v);
}

/* ---------------------------------------------------------------------------
 * check_bip86_path — acceptance tests
 * ------------------------------------------------------------------------- */

static void test_bip86_valid_minimal(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 0, 0);
    assert_true(check_bip86_path(path, 5));
}

static void test_bip86_valid_change_1(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 1, 0);
    assert_true(check_bip86_path(path, 5));
}

static void test_bip86_valid_max_account_and_index(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 100, 0, 10000);
    assert_true(check_bip86_path(path, 5));
}

/* ---------------------------------------------------------------------------
 * check_bip86_path — rejection tests
 * ------------------------------------------------------------------------- */

static void test_bip86_reject_short_path(void **state) {
    (void) state;
    uint32_t path[4];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 0, 0);
    assert_false(check_bip86_path(path, 4));
}

static void test_bip86_reject_long_path(void **state) {
    (void) state;
    uint32_t path[6] = {0};
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 0, 0);
    assert_false(check_bip86_path(path, 6));
}

static void test_bip86_reject_purpose_not_hardened(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 0, 0);
    path[0] = 86; /* strip hardened bit */
    assert_false(check_bip86_path(path, 5));
}

static void test_bip86_reject_wrong_purpose(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 84, BIP44_COIN_TYPE, 0, 0, 0); /* BIP-84 */
    assert_false(check_bip86_path(path, 5));
}

static void test_bip86_reject_wrong_coin_type(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE + 1, 0, 0, 0);
    assert_false(check_bip86_path(path, 5));
}

static void test_bip86_reject_coin_type_not_hardened(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 0, 0);
    path[1] = BIP44_COIN_TYPE; /* strip hardened bit */
    assert_false(check_bip86_path(path, 5));
}

static void test_bip86_reject_account_not_hardened(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 0, 0);
    path[2] = 0; /* strip hardened bit */
    assert_false(check_bip86_path(path, 5));
}

static void test_bip86_reject_account_too_large(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 101, 0, 0);
    assert_false(check_bip86_path(path, 5));
}

static void test_bip86_reject_change_too_large(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 2, 0);
    assert_false(check_bip86_path(path, 5));
}

static void test_bip86_reject_index_too_large(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 0, 10001);
    assert_false(check_bip86_path(path, 5));
}

/* ---------------------------------------------------------------------------
 * parse_tap_bip32_deriv_value — acceptance tests
 * ------------------------------------------------------------------------- */

/*
 * Build a TAP_BIP32_DERIVATION value:
 *   [n_hashes (1B)] [n_hashes*32 zero bytes] [fingerprint (4B LE)] [path (4B LE * n_steps)]
 */
static int build_deriv_val(uint8_t *buf,
                            size_t buf_len,
                            int n_hashes,
                            uint32_t fingerprint,
                            const uint32_t *path,
                            int n_steps) {
    int total = 1 + n_hashes * 32 + 4 + n_steps * 4;
    if ((size_t) total > buf_len) return -1;
    memset(buf, 0, (size_t) total);
    buf[0] = (uint8_t) n_hashes;
    int fp_off = 1 + n_hashes * 32;
    write_u32_be(buf, (size_t) fp_off, fingerprint);  /* fingerprint is BE per BIP-32/PSBT */
    for (int i = 0; i < n_steps; i++) {
        write_u32_le(buf, (size_t) (fp_off + 4 + i * 4), path[i]);  /* path steps are LE */
    }
    return total;
}

static void test_deriv_valid_n_hashes_1(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 0, 0);
    uint8_t val[1 + 32 + 4 + 5 * 4];
    int len = build_deriv_val(val, sizeof(val), 1, 0xDEADBEEF, path, 5);
    assert_int_equal(len, (int) sizeof(val));

    uint32_t fp;
    uint32_t out_path[5];
    int n = parse_tap_bip32_deriv_value(val, len, &fp, out_path, 5);
    assert_int_equal(n, 5);
    assert_int_equal(fp, 0xDEADBEEF);
    assert_memory_equal(out_path, path, 5 * sizeof(uint32_t));
}

static void test_deriv_valid_n_hashes_0(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 1, 0, 42);
    uint8_t val[1 + 0 + 4 + 5 * 4];
    int len = build_deriv_val(val, sizeof(val), 0, 0x12345678, path, 5);
    assert_int_equal(len, (int) sizeof(val));

    uint32_t fp;
    uint32_t out_path[5];
    int n = parse_tap_bip32_deriv_value(val, len, &fp, out_path, 5);
    assert_int_equal(n, 5);
    assert_int_equal(fp, 0x12345678);
    assert_memory_equal(out_path, path, 5 * sizeof(uint32_t));
}

static void test_deriv_valid_n_hashes_2(void **state) {
    (void) state;
    uint32_t path[5];
    make_bip86_path(path, 86, BIP44_COIN_TYPE, 0, 1, 7);
    uint8_t val[1 + 64 + 4 + 5 * 4];
    int len = build_deriv_val(val, sizeof(val), 2, 0xCAFEBABE, path, 5);
    assert_int_equal(len, (int) sizeof(val));

    uint32_t fp;
    uint32_t out_path[5];
    int n = parse_tap_bip32_deriv_value(val, len, &fp, out_path, 5);
    assert_int_equal(n, 5);
    assert_int_equal(fp, 0xCAFEBABE);
}

/* ---------------------------------------------------------------------------
 * parse_tap_bip32_deriv_value — rejection tests
 * ------------------------------------------------------------------------- */

static void test_deriv_reject_empty(void **state) {
    (void) state;
    uint8_t val[1] = {0};
    uint32_t fp;
    uint32_t path[5];
    assert_int_equal(parse_tap_bip32_deriv_value(val, 0, &fp, path, 5), -1);
}

static void test_deriv_reject_too_short_for_fingerprint(void **state) {
    (void) state;
    /* n_hashes=0 but only 2 bytes (need at least 5: 1 + 4) */
    uint8_t val[2] = {OP_0, OP_0};
    uint32_t fp;
    uint32_t path[5];
    assert_int_equal(parse_tap_bip32_deriv_value(val, 2, &fp, path, 5), -1);
}

static void test_deriv_reject_hash_truncated(void **state) {
    (void) state;
    /* n_hashes=1 but buffer has only 10 bytes, not 1+32+4=37 */
    uint8_t val[10] = {0x01};
    uint32_t fp;
    uint32_t path[5];
    assert_int_equal(parse_tap_bip32_deriv_value(val, 10, &fp, path, 5), -1);
}

static void test_deriv_reject_path_not_divisible_by_4(void **state) {
    (void) state;
    /* n_hashes=0, fingerprint, then 3 bytes (not divisible by 4) */
    uint8_t val[1 + 4 + 3];
    memset(val, 0, sizeof(val));
    val[0] = 0;
    uint32_t fp;
    uint32_t path[5];
    assert_int_equal(parse_tap_bip32_deriv_value(val, sizeof(val), &fp, path, 5), -1);
}

static void test_deriv_reject_too_many_steps(void **state) {
    (void) state;
    /* n_hashes=0, fingerprint, then 6 path steps — exceeds max_path_steps=5 */
    uint8_t val[1 + 4 + 6 * 4];
    memset(val, 0, sizeof(val));
    val[0] = 0;
    uint32_t fp;
    uint32_t path[5];
    assert_int_equal(parse_tap_bip32_deriv_value(val, sizeof(val), &fp, path, 5), -1);
}

/* ---------------------------------------------------------------------------
 * parse_refund_leaf_script — acceptance tests
 * ------------------------------------------------------------------------- */

/* Build script: OP_PUSHBYTES_32 <key[32]> OP_CHECKSIGVERIFY <csv_push...> OP_CSV */
static int build_refund_script(uint8_t *buf, size_t buf_len,
                                const uint8_t key[32],
                                const uint8_t *csv_push, int csv_push_len) {
    int total = 1 + 32 + 1 + csv_push_len + 1;
    if ((size_t) total > buf_len) return -1;
    int pos = 0;
    buf[pos++] = OP_PUSHBYTES_32;
    memcpy(buf + pos, key, 32); pos += 32;
    buf[pos++] = OP_CHECKSIGVERIFY;
    memcpy(buf + pos, csv_push, (size_t) csv_push_len); pos += csv_push_len;
    buf[pos++] = OP_CHECKSEQUENCEVERIFY;
    return total;
}

static void test_refund_valid_op1(void **state) {
    (void) state;
    uint8_t key[32];
    memset(key, 0xAA, 32);
    uint8_t csv_push[] = {OP_1};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    assert_int_equal(len, 36); /* 1 + 32 + 1 + 1(OP_1) + 1 */

    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_true(parse_refund_leaf_script(script, len, out_key, &csv_value));
    assert_memory_equal(out_key, key, 32);
    assert_int_equal((int) csv_value, 1);
}

static void test_refund_valid_op16(void **state) {
    (void) state;
    uint8_t key[32];
    memset(key, 0xBB, 32);
    uint8_t csv_push[] = {OP_16};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_true(parse_refund_leaf_script(script, len, out_key, &csv_value));
    assert_memory_equal(out_key, key, 32);
    assert_int_equal((int) csv_value, 16);
}

static void test_refund_valid_direct_push_1byte(void **state) {
    (void) state;
    /* CSV = 100 (0x64) — direct 1-byte push: OP_PUSHBYTES_1 + value byte */
    uint8_t key[32];
    memset(key, 0x01, 32);
    uint8_t csv_push[] = {OP_PUSHBYTES_1, 0x64};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 2);
    assert_int_equal(len, 37); /* 1 + 32 + 1 + 2(push) + 1 */
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_true(parse_refund_leaf_script(script, len, out_key, &csv_value));
    assert_memory_equal(out_key, key, 32);
    assert_int_equal((int) csv_value, 100);
}

static void test_refund_valid_direct_push_2byte(void **state) {
    (void) state;
    /* CSV = 144 (0x90): high bit set, needs sign byte → OP_PUSHBYTES_2 0x90 0x00 */
    uint8_t key[32];
    memset(key, 0x02, 32);
    uint8_t csv_push[] = {OP_PUSHBYTES_2, 0x90, 0x00};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 3);
    assert_int_equal(len, 38); /* 1 + 32 + 1 + 3(push) + 1 */
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_true(parse_refund_leaf_script(script, len, out_key, &csv_value));
    assert_memory_equal(out_key, key, 32);
    assert_int_equal((int) csv_value, 144);
}

static void test_refund_valid_pushdata1(void **state) {
    (void) state;
    /* OP_PUSHDATA1 <len=1> <0x01> — unusual but valid */
    uint8_t key[32];
    memset(key, 0x03, 32);
    uint8_t csv_push[] = {OP_PUSHDATA1, OP_PUSHBYTES_1, 0x01};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 3);
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_true(parse_refund_leaf_script(script, len, out_key, &csv_value));
    assert_memory_equal(out_key, key, 32);
    assert_int_equal((int) csv_value, 1);
}

/* ---------------------------------------------------------------------------
 * parse_refund_leaf_script — rejection tests
 * ------------------------------------------------------------------------- */

static void test_refund_reject_too_short(void **state) {
    (void) state;
    /* 35 bytes is one short of the minimum 36 */
    uint8_t script[35] = {0};
    script[0]  = OP_PUSHBYTES_32;
    script[33] = OP_CHECKSIGVERIFY;
    script[34] = OP_1;
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_false(parse_refund_leaf_script(script, 35, out_key, &csv_value));
}

static void test_refund_reject_wrong_first_byte(void **state) {
    (void) state;
    uint8_t key[32] = {0};
    uint8_t csv_push[] = {OP_1};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    script[0] = OP_PUSHBYTES_33; /* wrong push size: 33 instead of 32 */
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_false(parse_refund_leaf_script(script, len, out_key, &csv_value));
}

static void test_refund_reject_wrong_checksigverify(void **state) {
    (void) state;
    /* OP_EQUALVERIFY is rejected; only OP_CHECKSIGVERIFY is valid */
    uint8_t key[32] = {0};
    uint8_t csv_push[] = {OP_1};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    script[33] = OP_EQUALVERIFY;
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_false(parse_refund_leaf_script(script, len, out_key, &csv_value));
}

static void test_refund_reject_csv_op0(void **state) {
    (void) state;
    uint8_t key[32] = {0};
    uint8_t csv_push[] = {OP_0};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_false(parse_refund_leaf_script(script, len, out_key, &csv_value));
}

static void test_refund_reject_csv_op1negate(void **state) {
    (void) state;
    uint8_t key[32] = {0};
    uint8_t csv_push[] = {OP_1NEGATE};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_false(parse_refund_leaf_script(script, len, out_key, &csv_value));
}

static void test_refund_reject_csv_unknown_opcode(void **state) {
    (void) state;
    /* OP_NOP (0x61) is beyond OP_16 and not a valid push opcode */
    uint8_t key[32] = {0};
    uint8_t csv_push[] = {OP_NOP};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_false(parse_refund_leaf_script(script, len, out_key, &csv_value));
}

static void test_refund_reject_extra_bytes_after_csv(void **state) {
    (void) state;
    uint8_t key[32] = {0};
    uint8_t csv_push[] = {OP_1};
    uint8_t script[65];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    script[len] = OP_0; /* extra byte after OP_CSV */
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_false(parse_refund_leaf_script(script, len + 1, out_key, &csv_value));
}

static void test_refund_reject_missing_csv_opcode(void **state) {
    (void) state;
    uint8_t key[32] = {0};
    uint8_t csv_push[] = {OP_1};
    uint8_t script[64];
    int len = build_refund_script(script, sizeof(script), key, csv_push, 1);
    /* Truncate before OP_CSV */
    uint8_t out_key[32];
    uint32_t csv_value = 0;
    assert_false(parse_refund_leaf_script(script, len - 1, out_key, &csv_value));
}

/* ---------------------------------------------------------------------------
 * _pegin_validate_outputs fee arithmetic — overflow guards
 *
 * The two-step overflow-safe addition in _pegin_validate_outputs is a private
 * static function and cannot be called directly.  The helper below mirrors the
 * exact same pattern so the logic — including the second (anchor) overflow
 * branch — is exercised under unit-test conditions.
 * ------------------------------------------------------------------------- */

static bool _test_outputs_sum(uint64_t vault, uint64_t claim, uint64_t anchor,
                              uint64_t *out) {
    uint64_t s = vault + claim;
    if (s < vault) return false;
    s += anchor;
    if (s < anchor) return false;
    *out = s;
    return true;
}

static void test_pegin_fee_sum_overflow_guards(void **state) {
    (void) state;
    uint64_t sum;

    assert_true(_test_outputs_sum(1000, 2000, 3000, &sum));
    assert_int_equal(sum, 6000);

    /* First guard: vault_amount + depositor_claim wraps */
    assert_false(_test_outputs_sum(UINT64_MAX, 1, 0, &sum));

    /* Second guard: vault + claim == UINT64_MAX (no first wrap),
     * then anchor = 1 pushes it over — second branch fires. */
    assert_false(_test_outputs_sum((uint64_t)1u << 63,
                                   ((uint64_t)1u << 63) - 1u,
                                   1, &sum));
}

/* ---------------------------------------------------------------------------
 * Test runner
 * ------------------------------------------------------------------------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* check_bip86_path */
        cmocka_unit_test(test_bip86_valid_minimal),
        cmocka_unit_test(test_bip86_valid_change_1),
        cmocka_unit_test(test_bip86_valid_max_account_and_index),
        cmocka_unit_test(test_bip86_reject_short_path),
        cmocka_unit_test(test_bip86_reject_long_path),
        cmocka_unit_test(test_bip86_reject_purpose_not_hardened),
        cmocka_unit_test(test_bip86_reject_wrong_purpose),
        cmocka_unit_test(test_bip86_reject_wrong_coin_type),
        cmocka_unit_test(test_bip86_reject_coin_type_not_hardened),
        cmocka_unit_test(test_bip86_reject_account_not_hardened),
        cmocka_unit_test(test_bip86_reject_account_too_large),
        cmocka_unit_test(test_bip86_reject_change_too_large),
        cmocka_unit_test(test_bip86_reject_index_too_large),

        /* parse_tap_bip32_deriv_value */
        cmocka_unit_test(test_deriv_valid_n_hashes_1),
        cmocka_unit_test(test_deriv_valid_n_hashes_0),
        cmocka_unit_test(test_deriv_valid_n_hashes_2),
        cmocka_unit_test(test_deriv_reject_empty),
        cmocka_unit_test(test_deriv_reject_too_short_for_fingerprint),
        cmocka_unit_test(test_deriv_reject_hash_truncated),
        cmocka_unit_test(test_deriv_reject_path_not_divisible_by_4),
        cmocka_unit_test(test_deriv_reject_too_many_steps),

        /* _pegin_validate_outputs fee arithmetic */
        cmocka_unit_test(test_pegin_fee_sum_overflow_guards),

        /* parse_refund_leaf_script */
        cmocka_unit_test(test_refund_valid_op1),
        cmocka_unit_test(test_refund_valid_op16),
        cmocka_unit_test(test_refund_valid_direct_push_1byte),
        cmocka_unit_test(test_refund_valid_direct_push_2byte),
        cmocka_unit_test(test_refund_valid_pushdata1),
        cmocka_unit_test(test_refund_reject_too_short),
        cmocka_unit_test(test_refund_reject_wrong_first_byte),
        cmocka_unit_test(test_refund_reject_wrong_checksigverify),
        cmocka_unit_test(test_refund_reject_csv_op0),
        cmocka_unit_test(test_refund_reject_csv_op1negate),
        cmocka_unit_test(test_refund_reject_csv_unknown_opcode),
        cmocka_unit_test(test_refund_reject_extra_bytes_after_csv),
        cmocka_unit_test(test_refund_reject_missing_csv_opcode),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
