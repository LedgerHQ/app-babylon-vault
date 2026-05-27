/**
 * Unit tests for vault_context state machine.
 *
 * Covers:
 *   - vault_context_init: zeroes struct, sets IDLE
 *   - vault_context_invalidate: explicit_bzero on s, resets to IDLE, wipes intent
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
    for (size_t i = 0; i < sizeof(ctx->s); i++) {
        if (ctx->s[i] != 0) return false;
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

    /* Set a fake secret and advance state */
    memset(ctx.s, 0xFF, sizeof(ctx.s));
    memset(ctx.h, 0xEE, sizeof(ctx.h));
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

// ---------------------------------------------------------------------------
// vault_context_transition — valid edges
// ---------------------------------------------------------------------------

static void test_transition_idle_to_intent_loaded(void **state) {
    (void) state;
    vault_context_t ctx;
    vault_context_init(&ctx);

    bool ok = vault_context_transition(&ctx, VAULT_STATE_IDLE, VAULT_STATE_INTENT_LOADED);
    assert_true(ok);
    assert_int_equal(ctx.state, VAULT_STATE_INTENT_LOADED);
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

    bool ok = vault_context_transition(&ctx,
                                       VAULT_STATE_SESSION1_PREPEGIN_EXPECTED,
                                       VAULT_STATE_INTENT_LOADED);
    assert_true(ok);
    assert_int_equal(ctx.state, VAULT_STATE_INTENT_LOADED);
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

    bool ok = vault_context_transition(&ctx,
                                       VAULT_STATE_SESSION2_COMPLETE,
                                       VAULT_STATE_IDLE);
    assert_true(ok);
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

    /* Place non-zero secret so we can verify it gets wiped */
    memset(ctx.s, 0x42, sizeof(ctx.s));

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

        /* valid transitions */
        cmocka_unit_test(test_transition_idle_to_intent_loaded),
        cmocka_unit_test(test_transition_intent_loaded_to_session1),
        cmocka_unit_test(test_transition_session1_back_to_intent_loaded),
        cmocka_unit_test(test_transition_intent_loaded_to_session2_pegin),
        cmocka_unit_test(test_transition_session2_pegin_to_payout),
        cmocka_unit_test(test_transition_session2_payout_to_complete),
        cmocka_unit_test(test_transition_session2_complete_to_idle),

        /* invalid transitions */
        cmocka_unit_test(test_transition_wrong_from_state),
        cmocka_unit_test(test_transition_illegal_to_state),
        cmocka_unit_test(test_transition_backwards_without_valid_edge),
        cmocka_unit_test(test_transition_double_approve),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
