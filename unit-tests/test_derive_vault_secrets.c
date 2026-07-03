/**
 * Unit tests for derive_vault_secrets_core.h — on-device HKDF-Expand commitments.
 *
 *   commitment = SHA256( HKDF-Expand-SHA256(root, info(label, ctx), 32) )
 *   info(label, ctx) = "babylonbtcvault" || len(label):u8 || label
 *                      || len(ctx):u16-BE || ctx
 *
 * Two roots are used here:
 *
 *   ROOT_SPEC (§4.1 V1) — 3b0e2d90... — the output of derive-context-hash
 *     §4.1 Vector 1, which is pinned by the spec and verified against Node.js
 *     crypto.hkdf. Expansion commitments (SPEC_HASHLOCK_V0, SPEC_HASHLOCK_V1,
 *     SPEC_AUTH_ANCHOR) cross-validated via Python hmac/hashlib:
 *       commitment = SHA256(HMAC-SHA256(root, info || 0x01))
 *     — an independent Expand-only implementation (RFC 5869 §3.3).
 *
 *   ROOT (§4.2) — f82ced... — derive-context-hash §4.2 wallet-integration root.
 *     EXP_HASHLOCK_V0 / EXP_AUTH_ANCHOR cross-validated via Python hmac/hashlib
 *     (same Expand-only implementation). Values confirmed to match the independent
 *     computation; both are authoritative for derive-vault-secrets §4 promotion.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "handler/derive_vault_secrets_core.h"

// derive-context-hash §4.2 root, used here as the expansion PRK.
static const uint8_t ROOT[32] = {
    0xf8, 0x2c, 0xed, 0x3b, 0xe0, 0xe2, 0x95, 0x91, 0xa7, 0x86, 0x3e, 0xce, 0x03, 0xd6, 0x5f, 0x79,
    0xfb, 0x49, 0x4f, 0xe0, 0xde, 0x72, 0x03, 0x54, 0x98, 0x55, 0xf4, 0x62, 0x45, 0x5d, 0xf0, 0x08};

// SHA256(Expand(ROOT, info("hashlock", I2OSP(0,4)), 32)) — cross-validated via Python hmac/hashlib
static const uint8_t EXP_HASHLOCK_V0[32] = {
    0x7b, 0x9d, 0xe6, 0xac, 0x44, 0x5e, 0x10, 0xf1, 0x0f, 0x7e, 0x87, 0x3b, 0x35, 0xe3, 0x5f, 0xb2,
    0xbb, 0xe6, 0x37, 0xe4, 0x4d, 0x75, 0x83, 0x31, 0x6c, 0x65, 0x8d, 0xa8, 0x50, 0xbe, 0xbc, 0xab};

// SHA256(Expand(ROOT, info("auth-anchor", []), 32)) — cross-validated via Python hmac/hashlib
static const uint8_t EXP_AUTH_ANCHOR[32] = {
    0xb9, 0x3c, 0x24, 0x23, 0x40, 0x7b, 0xd0, 0x79, 0x37, 0xdf, 0x76, 0x7c, 0xd8, 0x58, 0xd5, 0x60,
    0xa7, 0x04, 0xbc, 0x28, 0xe1, 0xf5, 0xdf, 0xf9, 0x8d, 0x20, 0x35, 0xd6, 0xda, 0x3e, 0xd1, 0xab};

static void test_hashlock_commitment_vout0(void **state) {
    (void) state;
    uint8_t h[32];
    assert_true(vault_derive_hashlock_commitment(ROOT, 0, h));
    assert_memory_equal(h, EXP_HASHLOCK_V0, 32);
}

static void test_auth_anchor_commitment(void **state) {
    (void) state;
    uint8_t a[32];
    assert_true(vault_derive_auth_anchor_commitment(ROOT, a));
    assert_memory_equal(a, EXP_AUTH_ANCHOR, 32);
}

// htlc_vout is mixed into the hashlock label ctx, so different vouts diverge.
static void test_hashlock_varies_by_vout(void **state) {
    (void) state;
    uint8_t h0[32], h2[32];
    assert_true(vault_derive_hashlock_commitment(ROOT, 0, h0));
    assert_true(vault_derive_hashlock_commitment(ROOT, 2, h2));
    assert_memory_not_equal(h0, h2, 32);
}

// Distinct labels must be domain-separated.
static void test_hashlock_differs_from_auth_anchor(void **state) {
    (void) state;
    uint8_t h[32], a[32];
    assert_true(vault_derive_hashlock_commitment(ROOT, 0, h));
    assert_true(vault_derive_auth_anchor_commitment(ROOT, a));
    assert_memory_not_equal(h, a, 32);
}

// ---------------------------------------------------------------------------
// Spec-anchored pinned tests using derive-context-hash §4.1 Vector 1 root.
//   ROOT_SPEC = 3b0e2d90... is pinned by the spec (verified against Node.js
//   crypto.hkdf). SPEC_HASHLOCK_V0 / SPEC_HASHLOCK_V1 / SPEC_AUTH_ANCHOR
//   cross-validated via independent Python hmac/hashlib Expand-only computation:
//     commitment = SHA256(HMAC-SHA256(root, info || 0x01))
// ---------------------------------------------------------------------------
static const uint8_t ROOT_SPEC[32] = {
    0x3b, 0x0e, 0x2d, 0x90, 0xa0, 0x11, 0x22, 0xee, 0xd8, 0xa5, 0x20, 0x64, 0x80, 0x73, 0x89, 0x2f,
    0x6b, 0x2d, 0x8f, 0x44, 0x19, 0x21, 0x60, 0x23, 0xd6, 0x3c, 0xdb, 0xd4, 0x95, 0x00, 0xfc, 0xa3};

// SHA256(Expand(ROOT_SPEC, info("hashlock", I2OSP(0,4)), 32))
static const uint8_t SPEC_HASHLOCK_V0[32] = {
    0xf9, 0x09, 0x62, 0x71, 0xcd, 0xa2, 0x58, 0x94, 0x22, 0xe3, 0xaf, 0x42, 0x02, 0x49, 0x19, 0x93,
    0x8e, 0xdf, 0x59, 0xca, 0xd5, 0xda, 0xf8, 0xe1, 0x6c, 0x43, 0x5c, 0xbb, 0x9e, 0xaf, 0x74, 0x6b};

// SHA256(Expand(ROOT_SPEC, info("hashlock", I2OSP(1,4)), 32))
static const uint8_t SPEC_HASHLOCK_V1[32] = {
    0xd9, 0x8c, 0x5d, 0xa8, 0xb5, 0x1a, 0xa5, 0xef, 0xd3, 0x92, 0x64, 0x66, 0x5e, 0xa9, 0x6b, 0xd0,
    0x1c, 0xee, 0xe9, 0x9e, 0xd4, 0x5c, 0x62, 0x75, 0xea, 0x4a, 0x40, 0x76, 0x3d, 0x7b, 0x07, 0x02};

// SHA256(Expand(ROOT_SPEC, info("auth-anchor", []), 32))
static const uint8_t SPEC_AUTH_ANCHOR[32] = {
    0x4f, 0xa4, 0xb5, 0x62, 0xa5, 0x13, 0x3e, 0xcf, 0x29, 0x9e, 0xb2, 0x12, 0x7e, 0xed, 0xd8, 0xcd,
    0x71, 0x30, 0x82, 0x2c, 0xa0, 0xe7, 0xa4, 0x8d, 0x36, 0xfc, 0x9e, 0x64, 0x87, 0x1b, 0x9b, 0x62};

// Pinned: hashlock[0] on ROOT_SPEC matches independently-computed value.
static void test_spec_root_hashlock_v0_pinned(void **state) {
    (void) state;
    uint8_t h[32];
    assert_true(vault_derive_hashlock_commitment(ROOT_SPEC, 0, h));
    assert_memory_equal(h, SPEC_HASHLOCK_V0, 32);
}

// Pinned: hashlock[1] on ROOT_SPEC — verifies vout sensitivity and correct encoding.
static void test_spec_root_hashlock_v1_pinned(void **state) {
    (void) state;
    uint8_t h[32];
    assert_true(vault_derive_hashlock_commitment(ROOT_SPEC, 1, h));
    assert_memory_equal(h, SPEC_HASHLOCK_V1, 32);
}

// Pinned: auth-anchor on ROOT_SPEC matches independently-computed value.
static void test_spec_root_auth_anchor_pinned(void **state) {
    (void) state;
    uint8_t a[32];
    assert_true(vault_derive_auth_anchor_commitment(ROOT_SPEC, a));
    assert_memory_equal(a, SPEC_AUTH_ANCHOR, 32);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_hashlock_commitment_vout0),
        cmocka_unit_test(test_auth_anchor_commitment),
        cmocka_unit_test(test_hashlock_varies_by_vout),
        cmocka_unit_test(test_hashlock_differs_from_auth_anchor),
        cmocka_unit_test(test_spec_root_hashlock_v0_pinned),
        cmocka_unit_test(test_spec_root_hashlock_v1_pinned),
        cmocka_unit_test(test_spec_root_auth_anchor_pinned),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
