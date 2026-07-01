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
