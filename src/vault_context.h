#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "vault_intent.h"

/**
 * @brief Session state machine states.
 *
 * Transition table:
 *
 *   IDLE
 *     └─(APPROVE_VAULT_INTENT accepted)──► INTENT_LOADED
 *           │
 *           ├─(Session 1: Pre-PegIn signed)──► SESSION1_PREPEGIN_EXPECTED
 *           │                                        │
 *           │                                        └─(Pre-PegIn SIGN_PSBT)──► INTENT_LOADED
 *           │
 *           └─(Session 2: DERIVE_CONTEXT_HASH + APPROVE_VAULT_INTENT)
 *                 │
 *                 └─► SESSION2_PEGIN_EXPECTED
 *                           │
 *                           └─(PegIn SIGN_PSBT)──► SESSION2_PAYOUT_EXPECTED
 *                                                         │  (payout_index 0..N)
 *                                                         └─(last Payout signed)──►
 * SESSION2_COMPLETE │ └─(RELEASE_CONTEXT_SECRET)──► IDLE
 *
 * Invalidation triggers (any of these → explicit_bzero(htlc_preimage) + IDLE):
 *   - Signing error in any hook
 *   - APPROVE_VAULT_INTENT while intent already loaded
 *   - DERIVE_CONTEXT_HASH while intent is loaded
 */
typedef enum {
    VAULT_STATE_IDLE = 0,
    VAULT_STATE_INTENT_LOADED,
    VAULT_STATE_SESSION1_PREPEGIN_EXPECTED,
    VAULT_STATE_SESSION2_PEGIN_EXPECTED,
    VAULT_STATE_SESSION2_PAYOUT_EXPECTED,  // payout_index tracks which claimer (0=VP, 1..N=VK)
    VAULT_STATE_SESSION2_COMPLETE,
} vault_state_t;

/**
 * @brief Session context — secret, hash, and state machine.
 *
 * The htlc_preimage field MUST be zeroed via explicit_bzero() on every invalidation.
 * The state MUST be reset to VAULT_STATE_IDLE after zeroing.
 */
typedef struct {
    /** HTLC preimage (secret s). Zeroed on any invalidation. */
    uint8_t htlc_preimage[VAULT_HASH256_LEN];

    /** HTLC hashlock h = SHA256(htlc_preimage), returned by DERIVE_CONTEXT_HASH. */
    uint8_t htlc_hashlock[VAULT_HASH256_LEN];

    /** Current session state. */
    vault_state_t state;

    /**
     * Payout iteration index.
     * 0 = VP claimer, 1..keeper_count = VK claimers in ascending key order.
     * Only meaningful in VAULT_STATE_SESSION2_PAYOUT_EXPECTED.
     */
    uint8_t payout_index;
} vault_context_t;

// ---------------------------------------------------------------------------
// State machine API (defined in vault_context.c)
// ---------------------------------------------------------------------------

/**
 * @brief Zero-initialise the context and set state to VAULT_STATE_IDLE.
 *
 * Must be called once at application start-up.
 */
void vault_context_init(vault_context_t *ctx);

/**
 * @brief Unconditionally invalidate the session.
 *
 * Uses explicit_bzero on the secret field s, then zeroes the remainder of the
 * struct and resets state to VAULT_STATE_IDLE.  Safe to call from any state,
 * including IDLE (idempotent).
 */
void vault_context_invalidate(vault_context_t *ctx);

/**
 * @brief Attempt a validated state transition.
 *
 * @param ctx         Session context to update.
 * @param from        State that must be current for the transition to succeed.
 * @param to          Target state.
 * @return true       Transition accepted; ctx->state == to on return.
 * @return false      Transition rejected (state mismatch); ctx is invalidated
 *                    and ctx->state == VAULT_STATE_IDLE on return.
 *
 * Callers must treat a false return as a fatal session error and propagate
 * SW_BAD_STATE to the host.
 */
bool vault_context_transition(vault_context_t *ctx, vault_state_t from, vault_state_t to);
