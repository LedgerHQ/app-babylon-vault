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
 *     └─(DERIVE_CONTEXT_HASH complete)──► HASH_DERIVED   [root held, no intent yet]
 *           │
 *           └─(APPROVE_VAULT_INTENT accepted)──► INTENT_LOADED   [root preserved;
 *                 │                                htlc_hashlock + auth_anchor_hash computed]
 *                 ├─(Session 1: prepegin_txid == 0)─► INTENT_LOADED
 *                 │         └─(Pre-PegIn SIGN_PSBT)──► SESSION1_PREPEGIN_EXPECTED ──► INTENT_LOADED
 *                 │
 *                 └─(Session 2: prepegin_txid != 0)─► SESSION2_PEGIN_EXPECTED
 *                           │
 *                           └─(PegIn SIGN_PSBT)──► SESSION2_PAYOUT_EXPECTED
 *                                                    │  (payout_index 0..N)
 *                                                    └─(last Payout signed)──► SESSION2_COMPLETE
 *
 * The host receives the root from DERIVE_CONTEXT_HASH and expands the per-vault
 * secrets itself; there is no on-device secret-release step.
 *
 * Invalidation triggers (any of these → explicit_bzero(root) + IDLE):
 *   - Signing error in any hook
 *   - APPROVE_VAULT_INTENT while intent already loaded (state != IDLE and state != HASH_DERIVED)
 *   - DERIVE_CONTEXT_HASH while intent is loaded
 */
typedef enum {
    VAULT_STATE_IDLE = 0,
    VAULT_STATE_HASH_DERIVED,  // DERIVE_CONTEXT_HASH complete; root held, no intent yet
    VAULT_STATE_INTENT_LOADED,
    VAULT_STATE_SESSION1_PREPEGIN_EXPECTED,
    VAULT_STATE_SESSION2_PEGIN_EXPECTED,
    VAULT_STATE_SESSION2_PAYOUT_EXPECTED,  // payout_index tracks which claimer (0=VP, 1..N=VK)
    VAULT_STATE_SESSION2_COMPLETE,
} vault_state_t;

/**
 * @brief Session context — derived root, on-chain commitments, and state machine.
 *
 * The root field MUST be zeroed via explicit_bzero() on every invalidation.
 * The state MUST be reset to VAULT_STATE_IDLE after zeroing.
 */
typedef struct {
    /**
     * DERIVE_CONTEXT_HASH root (the 32-byte HKDF output returned to the host).
     * Set by DERIVE_CONTEXT_HASH, preserved across the APPROVE_VAULT_INTENT reset.
     * Zeroed on any invalidation. The host expands it into the per-vault secrets;
     * the device retains it only to recompute on-chain commitments at approve-time.
     */
    uint8_t root[VAULT_HASH256_LEN];

    /**
     * HTLC hashlock h = SHA256(Expand(root, "hashlock" || I2OSP(htlc_vout, 4))).
     * Computed at APPROVE_VAULT_INTENT once htlc_vout is known; bound into the
     * Pre-PegIn HTLC scriptPubKey and the PegIn Leaf 0 during validation.
     */
    uint8_t htlc_hashlock[VAULT_HASH256_LEN];

    /**
     * Auth-anchor commitment SHA256(Expand(root, "auth-anchor")). Computed at
     * APPROVE_VAULT_INTENT; bound into the Pre-PegIn OP_RETURN output.
     */
    uint8_t auth_anchor_hash[VAULT_HASH256_LEN];

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
