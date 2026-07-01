/**
 * Unit tests for derive_vault_secrets_core.h — on-device HKDF-Expand commitments.
 *
 *   commitment = SHA256( HKDF-Expand-SHA256(root, info(label, ctx), 32) )
 *   info(label, ctx) = "babylonbtcvault" || len(label):u8 || label
 *                      || len(ctx):u16-BE || ctx
 *
 * References were computed with a standalone Expand-only HKDF over the
 * derive-context-hash §4.2 root (f82ced...). NOTE: derive-vault-secrets rev 0.1
 * does not pin concrete outputs yet — these MUST be cross-checked against the
 * host SDK (@noble/hashes expand) before they are considered authoritative.
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

// SHA256(Expand(ROOT, info("hashlock", I2OSP(0,4)), 32))
static const uint8_t EXP_HASHLOCK_V0[32] = {
    0x7b, 0x9d, 0xe6, 0xac, 0x44, 0x5e, 0x10, 0xf1, 0x0f, 0x7e, 0x87, 0x3b, 0x35, 0xe3, 0x5f, 0xb2,
    0xbb, 0xe6, 0x37, 0xe4, 0x4d, 0x75, 0x83, 0x31, 0x6c, 0x65, 0x8d, 0xa8, 0x50, 0xbe, 0xbc, 0xab};

// SHA256(Expand(ROOT, info("auth-anchor", []), 32))
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

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_hashlock_commitment_vout0),
        cmocka_unit_test(test_auth_anchor_commitment),
        cmocka_unit_test(test_hashlock_varies_by_vout),
        cmocka_unit_test(test_hashlock_differs_from_auth_anchor),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
