/**
 * Unit tests for derive_context_hash_core.h (hkdf_derive_root).
 *
 * Uses the software cx_ mock (mock_cx.c). The BIP-32 IKM is g_mock_bip32_key
 * (default 0x42*32; settable to pin a published vector). Built with
 * BIP44_COIN_TYPE=0 → canonicalNetworkName = "bitcoin-mainnet".
 *
 *   root = HKDF-SHA256(ikm, "derive-context-hash",
 *          SHA256(app_name) || SHA256("bitcoin-mainnet") || connectedPubkey[33] || context, 32)
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "handler/derive_context_hash_core.h"

// Settable BIP-32 mock key (defined in mock_cx.c).
extern uint8_t g_mock_bip32_key[32];
extern bool    g_mock_bip32_key_set;

// ---------------------------------------------------------------------------
// derive-context-hash §4.2 authoritative wallet-integration vector
//   ikm = m/73681862' for the "abandon..." seed; appName="test-app";
//   network="bitcoin-mainnet"; connectedPubkey = m/44'/0'/0'/0/0; context="deadbeef".
// ---------------------------------------------------------------------------
static const uint8_t V42_IKM[32] = {
    0x39, 0x1c, 0xdb, 0x92, 0x20, 0x97, 0xec, 0x9c, 0x96, 0xfc, 0x13, 0xca, 0xdb, 0x01, 0xd5, 0x74,
    0x5c, 0xcf, 0x31, 0xf5, 0xdb, 0xec, 0x3a, 0x38, 0x10, 0x34, 0x40, 0x71, 0x47, 0x79, 0xec, 0x85};
static const uint8_t V42_PUBKEY[33] = {
    0x03, 0xaa, 0xeb, 0x52, 0xdd, 0x74, 0x94, 0xc3, 0x61, 0x04, 0x9d, 0xe6, 0x7c, 0xc6, 0x80, 0xe8,
    0x3e, 0xbc, 0xbb, 0xbd, 0xbe, 0xb1, 0x36, 0x37, 0xd9, 0x2c, 0xd8, 0x45, 0xf7, 0x03, 0x08, 0xaf,
    0x5e};
static const uint8_t V42_ROOT[32] = {
    0xf8, 0x2c, 0xed, 0x3b, 0xe0, 0xe2, 0x95, 0x91, 0xa7, 0x86, 0x3e, 0xce, 0x03, 0xd6, 0x5f, 0x79,
    0xfb, 0x49, 0x4f, 0xe0, 0xde, 0x72, 0x03, 0x54, 0x98, 0x55, 0xf4, 0x62, 0x45, 0x5d, 0xf0, 0x08};

// ---------------------------------------------------------------------------
// Mock-key vectors (ikm=0x42*32, app="TestApp", pubkey=0x02||0x11*32, mainnet).
// ---------------------------------------------------------------------------
static const uint8_t PK_TEST[33] = {
    0x02, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11};
static const uint8_t REF_ROOT_NO_CTX[32] = {
    0x64, 0x4d, 0x5d, 0x2e, 0xf4, 0x57, 0x0a, 0xca, 0xbd, 0x27, 0x45, 0x44, 0xe8, 0x9d, 0xb0, 0x54,
    0xdf, 0xfd, 0xff, 0xc7, 0x69, 0x9b, 0x10, 0x0d, 0x8f, 0x1f, 0x8a, 0xfd, 0x74, 0x65, 0x27, 0x64};
static const uint8_t REF_ROOT_WITH_CTX[32] = {
    0xa3, 0xdf, 0xef, 0x02, 0x68, 0x4f, 0x7b, 0x58, 0xe5, 0xa0, 0xbf, 0xbf, 0x3f, 0xc0, 0x88, 0xbb,
    0x1c, 0xbc, 0xf3, 0xe9, 0xcd, 0x11, 0xfb, 0xa6, 0x97, 0xe7, 0x42, 0x22, 0xf3, 0xa1, 0x55, 0x6d};

static const char CTX[] = "hello_context";  // 13 bytes

// ---------------------------------------------------------------------------
// derive-context-hash §4.1 HKDF function-level vectors
//   IKM is the same as §4.2 (m/73681862' for the "abandon..." seed).
//   Info bytes are opaque — these vectors pin the raw HKDF math independent
//   of the v2 info construction. Verified against Node.js crypto.hkdf('sha256')
//   and a manual HMAC-based implementation (per spec §4.1 note).
// ---------------------------------------------------------------------------

// Raw HKDF: PRK = HMAC-SHA256(salt, ikm); out = HMAC-SHA256(PRK, info || 0x01).
static bool hkdf_raw(const uint8_t *ikm,
                     size_t         ikm_len,
                     const uint8_t *salt,
                     size_t         salt_len,
                     const uint8_t *info,
                     size_t         info_len,
                     uint8_t        out[32]) {
    uint8_t salt_buf[32];  // salt is "derive-context-hash" = 19 B; fits easily
    if (salt_len > sizeof(salt_buf)) return false;
    memcpy(salt_buf, salt, salt_len);

    uint8_t prk[32];
    cx_hkdf_extract(CX_SHA256, ikm, (unsigned int) ikm_len,
                    salt_buf, (unsigned int) salt_len, prk);

    cx_hmac_sha256_t hmac;
    const uint8_t counter = 0x01;
    bool ok = cx_hmac_sha256_init_no_throw(&hmac, prk, 32) == CX_OK &&
              cx_hmac_update((cx_hmac_t *) &hmac, info, info_len) == CX_OK &&
              cx_hmac_update((cx_hmac_t *) &hmac, &counter, 1) == CX_OK;
    size_t out_len = 32;
    if (ok) ok = cx_hmac_final((cx_hmac_t *) &hmac, out, &out_len) == CX_OK;
    return ok;
}

// SHA-256("test-app") — shared info prefix for all three §4.1 vectors.
static const uint8_t V41_INFO_PREFIX[32] = {
    0xb5, 0x8b, 0x0c, 0xb4, 0xec, 0xde, 0xa3, 0xc6, 0x53, 0x11, 0xb4, 0xca, 0x88, 0x33, 0xfe, 0x47,
    0xb6, 0xae, 0x0a, 0x75, 0x00, 0xf8, 0x7a, 0x8e, 0xb3, 0x1e, 0x83, 0x79, 0xd3, 0xfe, 0x48, 0xf1};

static const uint8_t V41_OUT1[32] = {
    0x3b, 0x0e, 0x2d, 0x90, 0xa0, 0x11, 0x22, 0xee, 0xd8, 0xa5, 0x20, 0x64, 0x80, 0x73, 0x89, 0x2f,
    0x6b, 0x2d, 0x8f, 0x44, 0x19, 0x21, 0x60, 0x23, 0xd6, 0x3c, 0xdb, 0xd4, 0x95, 0x00, 0xfc, 0xa3};

static const uint8_t V41_OUT2[32] = {
    0x50, 0x77, 0x51, 0x26, 0x78, 0x2c, 0x1a, 0x5e, 0x4d, 0x60, 0xda, 0xa4, 0x66, 0x6b, 0x2c, 0x75,
    0x90, 0xf0, 0xb5, 0xa4, 0x45, 0xa4, 0x11, 0x5b, 0x0a, 0xbd, 0x41, 0x14, 0x67, 0xc9, 0x25, 0x97};

static const uint8_t V41_OUT3[32] = {
    0xd8, 0x1e, 0x4a, 0x91, 0xf3, 0x2e, 0xab, 0xd3, 0x4d, 0xf0, 0xe5, 0x5c, 0xa3, 0x6f, 0x26, 0xf2,
    0x11, 0xaf, 0x65, 0xdf, 0xe5, 0x75, 0xb7, 0x20, 0x1c, 0x95, 0xba, 0xaa, 0x66, 0x08, 0xcd, 0xd9};

// info = SHA-256("test-app") || 0xdeadbeef
static void test_spec_vector_4_1_v1(void **state) {
    (void) state;
    uint8_t info[36];
    memcpy(info, V41_INFO_PREFIX, 32);
    info[32] = 0xde; info[33] = 0xad; info[34] = 0xbe; info[35] = 0xef;
    uint8_t out[32];
    assert_true(hkdf_raw(V42_IKM, 32,
                         (const uint8_t *) "derive-context-hash", 19,
                         info, 36, out));
    assert_memory_equal(out, V41_OUT1, 32);
}

// info = SHA-256("test-app") || 0x00
static void test_spec_vector_4_1_v2(void **state) {
    (void) state;
    uint8_t info[33];
    memcpy(info, V41_INFO_PREFIX, 32);
    info[32] = 0x00;
    uint8_t out[32];
    assert_true(hkdf_raw(V42_IKM, 32,
                         (const uint8_t *) "derive-context-hash", 19,
                         info, 33, out));
    assert_memory_equal(out, V41_OUT2, 32);
}

// info = SHA-256("test-app") || 64 zero bytes
static void test_spec_vector_4_1_v3(void **state) {
    (void) state;
    uint8_t info[96];
    memcpy(info, V41_INFO_PREFIX, 32);
    memset(info + 32, 0x00, 64);
    uint8_t out[32];
    assert_true(hkdf_raw(V42_IKM, 32,
                         (const uint8_t *) "derive-context-hash", 19,
                         info, 96, out));
    assert_memory_equal(out, V41_OUT3, 32);
}

// ---------------------------------------------------------------------------
// appName charset validation (spec §2.1: [a-z0-9\-] only)
// ---------------------------------------------------------------------------

static void test_charset_valid_lowercase_digits_hyphen(void **state) {
    (void) state;
    const uint8_t name[] = "babylon-btc-vault0";
    assert_true(app_name_charset_valid(name, sizeof(name) - 1));
}

static void test_charset_valid_single_hyphen(void **state) {
    (void) state;
    const uint8_t name[] = "-";
    assert_true(app_name_charset_valid(name, 1));
}

static void test_charset_invalid_uppercase(void **state) {
    (void) state;
    const uint8_t name[] = "TestApp";
    assert_false(app_name_charset_valid(name, sizeof(name) - 1));
}

static void test_charset_invalid_space(void **state) {
    (void) state;
    const uint8_t name[] = "app name";
    assert_false(app_name_charset_valid(name, sizeof(name) - 1));
}

static void test_charset_invalid_underscore(void **state) {
    (void) state;
    const uint8_t name[] = "app_name";
    assert_false(app_name_charset_valid(name, sizeof(name) - 1));
}

// ---------------------------------------------------------------------------

// Authoritative: full v2 info construction matches derive-context-hash §4.2.
static void test_spec_vector_4_2(void **state) {
    (void) state;
    memcpy(g_mock_bip32_key, V42_IKM, 32);
    g_mock_bip32_key_set = true;
    uint8_t root[32];
    bool ok = hkdf_derive_root((const uint8_t *) "test-app", 8, V42_PUBKEY,
                               (const uint8_t *) "\xde\xad\xbe\xef", 4, root);
    g_mock_bip32_key_set = false;  // back to the default 0x42 IKM for other tests
    assert_true(ok);
    assert_memory_equal(root, V42_ROOT, 32);
}

static void test_root_no_ctx(void **state) {
    (void) state;
    uint8_t root[32];
    assert_true(hkdf_derive_root((const uint8_t *) "TestApp", 7, PK_TEST, (const uint8_t *) "", 0,
                                 root));
    assert_memory_equal(root, REF_ROOT_NO_CTX, 32);
}

static void test_root_with_ctx(void **state) {
    (void) state;
    uint8_t root[32];
    assert_true(hkdf_derive_root((const uint8_t *) "TestApp", 7, PK_TEST,
                                 (const uint8_t *) CTX, sizeof(CTX) - 1, root));
    assert_memory_equal(root, REF_ROOT_WITH_CTX, 32);
}

static void test_deterministic(void **state) {
    (void) state;
    uint8_t a[32], b[32];
    hkdf_derive_root((const uint8_t *) "TestApp", 7, PK_TEST, (const uint8_t *) "", 0, a);
    hkdf_derive_root((const uint8_t *) "TestApp", 7, PK_TEST, (const uint8_t *) "", 0, b);
    assert_memory_equal(a, b, 32);
}

static void test_different_app_name_diverges(void **state) {
    (void) state;
    uint8_t a[32];
    hkdf_derive_root((const uint8_t *) "OtherApp", 8, PK_TEST, (const uint8_t *) "", 0, a);
    assert_memory_not_equal(a, REF_ROOT_NO_CTX, 32);
}

static void test_different_context_diverges(void **state) {
    (void) state;
    uint8_t a[32];
    hkdf_derive_root((const uint8_t *) "TestApp", 7, PK_TEST, (const uint8_t *) CTX,
                     sizeof(CTX) - 1, a);
    assert_memory_not_equal(a, REF_ROOT_NO_CTX, 32);
}

// connectedPubkey is part of info (v2): a different pubkey must change the root.
static void test_different_pubkey_diverges(void **state) {
    (void) state;
    uint8_t other_pk[33] = {
        0x03, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22};
    uint8_t a[32];
    hkdf_derive_root((const uint8_t *) "TestApp", 7, other_pk, (const uint8_t *) "", 0, a);
    assert_memory_not_equal(a, REF_ROOT_NO_CTX, 32);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_charset_valid_lowercase_digits_hyphen),
        cmocka_unit_test(test_charset_valid_single_hyphen),
        cmocka_unit_test(test_charset_invalid_uppercase),
        cmocka_unit_test(test_charset_invalid_space),
        cmocka_unit_test(test_charset_invalid_underscore),
        cmocka_unit_test(test_spec_vector_4_1_v1),
        cmocka_unit_test(test_spec_vector_4_1_v2),
        cmocka_unit_test(test_spec_vector_4_1_v3),
        cmocka_unit_test(test_spec_vector_4_2),
        cmocka_unit_test(test_root_no_ctx),
        cmocka_unit_test(test_root_with_ctx),
        cmocka_unit_test(test_deterministic),
        cmocka_unit_test(test_different_app_name_diverges),
        cmocka_unit_test(test_different_context_diverges),
        cmocka_unit_test(test_different_pubkey_diverges),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
