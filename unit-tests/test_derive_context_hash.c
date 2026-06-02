/**
 * Unit tests for derive_context_hash_core.h
 *
 * All tests use the software cx_ mock (mock_cx.c) which fixes the BIP-32
 * private key to 0x42*32 for reproducible vectors.
 *
 * Reference values computed with Python:
 *   IKM  = bytes([0x42] * 32)
 *   SALT = b"derive-context-hash"
 *   PRK  = HMAC-SHA256(SALT, IKM)
 *   htlc_preimage = HMAC-SHA256(PRK, SHA256(app_name) || context || 0x01)
 *   htlc_hashlock = SHA256(htlc_preimage)
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "handler/derive_context_hash_core.h"
#include "globals.h"

// ---------------------------------------------------------------------------
// Reference vectors (Python-computed, fixed BIP-32 mock key 0x42*32)
// ---------------------------------------------------------------------------

// app_name="TestApp", context empty
static const uint8_t REF_PREIMAGE_NO_CTX[32] = {
    0x5c, 0x19, 0xfb, 0x51, 0x05, 0x1b, 0x50, 0xf0,
    0x83, 0x65, 0x25, 0xe0, 0x7c, 0xbf, 0x6a, 0x39,
    0xab, 0xab, 0xb0, 0x09, 0x85, 0xa3, 0xf4, 0x5c,
    0xe6, 0x53, 0x05, 0xb5, 0x12, 0xa6, 0xe4, 0xd0
};
static const uint8_t REF_HASHLOCK_NO_CTX[32] = {
    0x85, 0x2a, 0xec, 0xf8, 0x58, 0x3d, 0x5a, 0x93,
    0xe6, 0x18, 0x67, 0x66, 0xe0, 0x5e, 0xad, 0xe6,
    0x96, 0x83, 0x84, 0x7e, 0x63, 0x4b, 0xd0, 0x08,
    0x23, 0xbd, 0x56, 0x1c, 0xef, 0x9d, 0x5b, 0xc1
};

// app_name="TestApp", context="hello_context" (13 bytes)
static const uint8_t REF_PREIMAGE_WITH_CTX[32] = {
    0xb9, 0xd5, 0x02, 0xee, 0xaf, 0x94, 0xd8, 0x55,
    0xf7, 0x44, 0x33, 0xb1, 0xb7, 0x3b, 0x4b, 0x98,
    0xfa, 0xbe, 0xc5, 0x57, 0x32, 0xd3, 0xef, 0x1d,
    0xaa, 0xdf, 0xde, 0xf2, 0xe7, 0x1f, 0x21, 0x27
};
static const uint8_t REF_HASHLOCK_WITH_CTX[32] = {
    0x04, 0xc8, 0xb8, 0xb7, 0x4b, 0x22, 0xe7, 0xee,
    0xf2, 0x3e, 0xa7, 0x66, 0xce, 0xeb, 0x78, 0xc4,
    0xd0, 0x12, 0x96, 0xf5, 0xc6, 0xac, 0xba, 0x8f,
    0x3b, 0xe7, 0x90, 0x4d, 0x0a, 0x3c, 0xc1, 0xcf
};

// app_name="OtherApp" (different app_name, same context=""), for divergence test
static const uint8_t REF_PREIMAGE_OTHER_APP[32] = {
    0x3a, 0x75, 0x90, 0xd1, 0x22, 0xb4, 0x95, 0xe6,
    0x5a, 0xea, 0xd1, 0x63, 0x87, 0x6a, 0xc5, 0x32,
    0xca, 0xcb, 0xff, 0x2e, 0x6d, 0x9f, 0xb6, 0xce,
    0x83, 0xe2, 0xff, 0xfe, 0x60, 0xcd, 0xaf, 0xab
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void reset_stream(void) {
    explicit_bzero(&G_hkdf_stream, sizeof(G_hkdf_stream));
}

static bool all_zero(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// hkdf_stream_begin + hkdf_stream_finalize — zero context
// ---------------------------------------------------------------------------

static void test_zero_context_matches_reference(void **state) {
    (void) state;
    reset_stream();
    uint8_t preimage[32] = {0};
    uint8_t hashlock[32] = {0};

    bool ok = hkdf_stream_begin(&G_hkdf_stream,
                                (const uint8_t *)"TestApp", 7, 0);
    assert_true(ok);

    ok = hkdf_stream_finalize(&G_hkdf_stream, preimage, hashlock);
    assert_true(ok);

    assert_memory_equal(preimage, REF_PREIMAGE_NO_CTX, 32);
    assert_memory_equal(hashlock, REF_HASHLOCK_NO_CTX, 32);
}

// ---------------------------------------------------------------------------
// hkdf_stream_begin + hkdf_stream_feed + hkdf_stream_finalize — single feed
// ---------------------------------------------------------------------------

static void test_single_feed_matches_reference(void **state) {
    (void) state;
    reset_stream();
    uint8_t preimage[32] = {0};
    uint8_t hashlock[32] = {0};
    const uint8_t ctx_data[] = "hello_context";

    bool ok = hkdf_stream_begin(&G_hkdf_stream,
                                (const uint8_t *)"TestApp", 7, sizeof(ctx_data) - 1);
    assert_true(ok);

    ok = hkdf_stream_feed(&G_hkdf_stream, ctx_data, sizeof(ctx_data) - 1);
    assert_true(ok);

    G_hkdf_stream.context_received_len = (uint16_t)(sizeof(ctx_data) - 1);

    ok = hkdf_stream_finalize(&G_hkdf_stream, preimage, hashlock);
    assert_true(ok);

    assert_memory_equal(preimage, REF_PREIMAGE_WITH_CTX, 32);
    assert_memory_equal(hashlock, REF_HASHLOCK_WITH_CTX, 32);
}

// ---------------------------------------------------------------------------
// Multi-chunk streaming produces the same result as single-chunk
// ---------------------------------------------------------------------------

static void test_multi_chunk_equals_single_chunk(void **state) {
    (void) state;

    // Single chunk: "hello_context" in one feed
    reset_stream();
    uint8_t preimage_single[32] = {0};
    uint8_t hashlock_single[32] = {0};
    const uint8_t full[]  = "hello_context";
    const uint16_t ctx_len = sizeof(full) - 1;

    hkdf_stream_begin(&G_hkdf_stream, (const uint8_t *)"TestApp", 7, ctx_len);
    hkdf_stream_feed(&G_hkdf_stream, full, ctx_len);
    hkdf_stream_finalize(&G_hkdf_stream, preimage_single, hashlock_single);

    // Two chunks: "hello_" then "context"
    reset_stream();
    uint8_t preimage_multi[32] = {0};
    uint8_t hashlock_multi[32] = {0};
    const uint8_t part1[] = "hello_";
    const uint8_t part2[] = "context";

    hkdf_stream_begin(&G_hkdf_stream, (const uint8_t *)"TestApp", 7, ctx_len);
    hkdf_stream_feed(&G_hkdf_stream, part1, sizeof(part1) - 1);
    hkdf_stream_feed(&G_hkdf_stream, part2, sizeof(part2) - 1);
    hkdf_stream_finalize(&G_hkdf_stream, preimage_multi, hashlock_multi);

    assert_memory_equal(preimage_single, preimage_multi, 32);
    assert_memory_equal(hashlock_single, hashlock_multi, 32);
}

// ---------------------------------------------------------------------------
// Determinism: same inputs → same output across two runs
// ---------------------------------------------------------------------------

static void test_deterministic(void **state) {
    (void) state;
    uint8_t preimage_a[32], hashlock_a[32];
    uint8_t preimage_b[32], hashlock_b[32];

    reset_stream();
    hkdf_stream_begin(&G_hkdf_stream, (const uint8_t *)"TestApp", 7, 0);
    hkdf_stream_finalize(&G_hkdf_stream, preimage_a, hashlock_a);

    reset_stream();
    hkdf_stream_begin(&G_hkdf_stream, (const uint8_t *)"TestApp", 7, 0);
    hkdf_stream_finalize(&G_hkdf_stream, preimage_b, hashlock_b);

    assert_memory_equal(preimage_a, preimage_b, 32);
    assert_memory_equal(hashlock_a, hashlock_b, 32);
}

// ---------------------------------------------------------------------------
// Different app_name → different preimage
// ---------------------------------------------------------------------------

static void test_different_app_name_produces_different_output(void **state) {
    (void) state;
    uint8_t preimage_a[32], hashlock_a[32];

    reset_stream();
    hkdf_stream_begin(&G_hkdf_stream, (const uint8_t *)"OtherApp", 8, 0);
    hkdf_stream_finalize(&G_hkdf_stream, preimage_a, hashlock_a);

    assert_memory_equal(preimage_a, REF_PREIMAGE_OTHER_APP, 32);
    // Must differ from "TestApp" output
    assert_memory_not_equal(preimage_a, REF_PREIMAGE_NO_CTX, 32);
}

// ---------------------------------------------------------------------------
// Different context → different preimage
// ---------------------------------------------------------------------------

static void test_different_context_produces_different_output(void **state) {
    (void) state;
    uint8_t preimage_a[32], hashlock_a[32];
    const uint8_t ctx[] = "different_context";

    reset_stream();
    hkdf_stream_begin(&G_hkdf_stream, (const uint8_t *)"TestApp", 7, sizeof(ctx) - 1);
    hkdf_stream_feed(&G_hkdf_stream, ctx, sizeof(ctx) - 1);
    hkdf_stream_finalize(&G_hkdf_stream, preimage_a, hashlock_a);

    assert_memory_not_equal(preimage_a, REF_PREIMAGE_WITH_CTX, 32);
    assert_memory_not_equal(preimage_a, REF_PREIMAGE_NO_CTX, 32);
}

// ---------------------------------------------------------------------------
// hashlock == SHA256(preimage) invariant
// ---------------------------------------------------------------------------

static void test_hashlock_is_sha256_of_preimage(void **state) {
    (void) state;
    uint8_t preimage[32], hashlock[32], expected_hashlock[32];

    reset_stream();
    hkdf_stream_begin(&G_hkdf_stream, (const uint8_t *)"TestApp", 7, 0);
    hkdf_stream_finalize(&G_hkdf_stream, preimage, hashlock);

    cx_hash_sha256(preimage, 32, expected_hashlock, 32);
    assert_memory_equal(hashlock, expected_hashlock, 32);
}

// ---------------------------------------------------------------------------
// preimage and hashlock are non-zero after a successful derivation
// ---------------------------------------------------------------------------

static void test_outputs_are_nonzero(void **state) {
    (void) state;
    uint8_t preimage[32] = {0};
    uint8_t hashlock[32] = {0};

    reset_stream();
    hkdf_stream_begin(&G_hkdf_stream, (const uint8_t *)"TestApp", 7, 0);
    hkdf_stream_finalize(&G_hkdf_stream, preimage, hashlock);

    assert_false(all_zero(preimage, 32));
    assert_false(all_zero(hashlock, 32));
}

// ---------------------------------------------------------------------------
// Empty app_name (len=0) is accepted; output differs from non-empty name
// ---------------------------------------------------------------------------

static void test_empty_app_name_accepted(void **state) {
    (void) state;
    uint8_t preimage[32] = {0};
    uint8_t hashlock[32] = {0};

    reset_stream();
    bool ok = hkdf_stream_begin(&G_hkdf_stream, NULL, 0, 0);
    assert_true(ok);
    ok = hkdf_stream_finalize(&G_hkdf_stream, preimage, hashlock);
    assert_true(ok);

    assert_false(all_zero(preimage, 32));
    assert_memory_not_equal(preimage, REF_PREIMAGE_NO_CTX, 32);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_zero_context_matches_reference),
        cmocka_unit_test(test_single_feed_matches_reference),
        cmocka_unit_test(test_multi_chunk_equals_single_chunk),
        cmocka_unit_test(test_deterministic),
        cmocka_unit_test(test_different_app_name_produces_different_output),
        cmocka_unit_test(test_different_context_produces_different_output),
        cmocka_unit_test(test_hashlock_is_sha256_of_preimage),
        cmocka_unit_test(test_outputs_are_nonzero),
        cmocka_unit_test(test_empty_app_name_accepted),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
