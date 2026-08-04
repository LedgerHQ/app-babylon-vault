/**
 * Unit tests for vault_context state machine.
 *
 * Covers:
 *   - vault_context_init: zeroes struct, sets IDLE
 *   - vault_context_invalidate: explicit_bzero on root, resets to IDLE, wipes intent + G_scratch
 *   - vault_context_transition: all valid edges in the state diagram
 *   - vault_context_transition: invalid transitions → invalidate + return false
 *   - Idempotent invalidation (IDLE → invalidate → still IDLE)
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "vault_context.h"
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

static void test_transition_intent_loaded_to_session1(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    ctx.state = VAULT_STATE_INTENT_LOADED;

    bool ok = vault_context_transition(&ctx,
                                       VAULT_STATE_INTENT_LOADED,
                                       VAULT_STATE_SESSION1_PREPEGIN_EXPECTED);
    assert_true(ok);
    assert_int_equal(ctx.state, VAULT_STATE_SESSION1_PREPEGIN_EXPECTED);
}

static void test_transition_session1_back_to_intent_loaded(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    ctx.state = VAULT_STATE_SESSION1_PREPEGIN_EXPECTED;

    /* SESSION1_PREPEGIN_EXPECTED is terminal — no forward transition is defined;
     * vault_context_transition must reject this edge and invalidate the context. */
    bool ok = vault_context_transition(&ctx,
                                       VAULT_STATE_SESSION1_PREPEGIN_EXPECTED,
                                       VAULT_STATE_INTENT_LOADED);
    assert_false(ok);
    assert_int_equal(ctx.state, VAULT_STATE_IDLE);
}

static void test_transition_intent_loaded_to_session2_pegin(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    ctx.state = VAULT_STATE_INTENT_LOADED;

    bool ok = vault_context_transition(&ctx,
                                       VAULT_STATE_INTENT_LOADED,
                                       VAULT_STATE_SESSION2_PEGIN_EXPECTED);
    assert_true(ok);
    assert_int_equal(ctx.state, VAULT_STATE_SESSION2_PEGIN_EXPECTED);
}

static void test_transition_session2_pegin_to_payout(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    ctx.state = VAULT_STATE_SESSION2_PEGIN_EXPECTED;

    bool ok = vault_context_transition(&ctx,
                                       VAULT_STATE_SESSION2_PEGIN_EXPECTED,
                                       VAULT_STATE_SESSION2_PAYOUT_EXPECTED);
    assert_true(ok);
    assert_int_equal(ctx.state, VAULT_STATE_SESSION2_PAYOUT_EXPECTED);
}

static void test_transition_session2_payout_to_complete(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    ctx.state = VAULT_STATE_SESSION2_PAYOUT_EXPECTED;

    bool ok = vault_context_transition(&ctx,
                                       VAULT_STATE_SESSION2_PAYOUT_EXPECTED,
                                       VAULT_STATE_SESSION2_COMPLETE);
    assert_true(ok);
    assert_int_equal(ctx.state, VAULT_STATE_SESSION2_COMPLETE);
}

static void test_transition_session2_complete_to_idle(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);
    ctx.state = VAULT_STATE_SESSION2_COMPLETE;

    /* SESSION2_COMPLETE is terminal — no forward transition is defined;
     * vault_context_transition must reject this edge and invalidate the context. */
    bool ok = vault_context_transition(&ctx,
                                       VAULT_STATE_SESSION2_COMPLETE,
                                       VAULT_STATE_IDLE);
    assert_false(ok);
    assert_int_equal(ctx.state, VAULT_STATE_IDLE);
}

// ---------------------------------------------------------------------------
// vault_context_transition — invalid edges → invalidation
// ---------------------------------------------------------------------------

/** Helper: assert that an illegal transition invalidates the context. */
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

static void test_transition_wrong_from_state(void **state) {
    (void) state;
    /* Currently IDLE, but `from` claims INTENT_LOADED → mismatch */
    _assert_illegal(VAULT_STATE_IDLE,
                    VAULT_STATE_INTENT_LOADED,
                    VAULT_STATE_SESSION1_PREPEGIN_EXPECTED);
}

static void test_transition_illegal_to_state(void **state) {
    (void) state;
    /*
     * from matches current state (IDLE) but target is illegal:
     * IDLE → SESSION2_PEGIN_EXPECTED skips INTENT_LOADED.
     * The to-validation must catch this even though from is correct.
     */
    _assert_illegal(VAULT_STATE_IDLE,
                    VAULT_STATE_IDLE,
                    VAULT_STATE_SESSION2_PEGIN_EXPECTED);
}

static void test_transition_backwards_without_valid_edge(void **state) {
    (void) state;
    /*
     * from matches current state (SESSION2_COMPLETE) but target is an
     * illegal backwards edge — SESSION2_COMPLETE can only go to IDLE.
     */
    _assert_illegal(VAULT_STATE_SESSION2_COMPLETE,
                    VAULT_STATE_SESSION2_COMPLETE,
                    VAULT_STATE_SESSION2_PAYOUT_EXPECTED);
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
        cmocka_unit_test(test_transition_intent_loaded_to_session1),
        cmocka_unit_test(test_transition_session1_back_to_intent_loaded),
        cmocka_unit_test(test_transition_intent_loaded_to_session2_pegin),
        cmocka_unit_test(test_transition_session2_pegin_to_payout),
        cmocka_unit_test(test_transition_session2_payout_to_complete),
        cmocka_unit_test(test_transition_session2_complete_to_idle),

        /* invalid transitions */
        cmocka_unit_test(test_transition_idle_to_intent_loaded_illegal),
        cmocka_unit_test(test_transition_wrong_from_state),
        cmocka_unit_test(test_transition_illegal_to_state),
        cmocka_unit_test(test_transition_backwards_without_valid_edge),
        cmocka_unit_test(test_transition_double_approve),

        /* signature cap counters */
        cmocka_unit_test(test_init_zeroes_cap_counters),
        cmocka_unit_test(test_invalidate_zeroes_cap_counters),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
