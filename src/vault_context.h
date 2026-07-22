#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "vault_intent.h"

/**
 * @brief Session state machine states.
 *
 * Transition table (DERIVE_CONTEXT_HASH is mandatory before APPROVE_VAULT_INTENT):
 *
 *   IDLE
 *     └─(DERIVE_CONTEXT_HASH complete)──► HASH_DERIVED   [root held, no intent yet]
 *           │
 *           └─(APPROVE_VAULT_INTENT accepted)──► INTENT_LOADED   [root zeroed after
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
    VAULT_STATE_SESSION2_PAYOUT_EXPECTED,  // payout_index tracks claimer (0=VP, 1..N=VK, N+1=Depositor)
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
     * Zeroed immediately after APPROVE_VAULT_INTENT derives both on-chain commitments
     * (htlc_hashlock, auth_anchor_hash) from it — the raw root is not needed after that.
     * Also zeroed on any invalidation.
     */
    uint8_t root[VAULT_HASH256_LEN];

    /**
     * Per-vault HTLC hashlocks h_i = SHA256(Expand(root, "hashlock" || I2OSP(htlc_vout_i, 4))).
     * Computed at APPROVE_VAULT_INTENT for each vault group once the group's htlc_vout is known.
     * htlc_hashlock[i] is bound into vault group i's Pre-PegIn HTLC scriptPubKey and PegIn Leaf 0.
     */
    uint8_t htlc_hashlock[VAULT_MAX_VAULTS][VAULT_HASH256_LEN];

    /**
     * Auth-anchor commitment SHA256(Expand(root, "auth-anchor")). Computed at
     * APPROVE_VAULT_INTENT; bound into the Pre-PegIn OP_RETURN output (global, not per-vault).
     */
    uint8_t auth_anchor_hash[VAULT_HASH256_LEN];

    /** Current session state. */
    vault_state_t state;

    /**
     * Payout iteration index within the active vault group.
     * 0 = VP claimer, 1..keeper_count = VK claimers, keeper_count+1 = Depositor.
     * Only meaningful in VAULT_STATE_SESSION2_PAYOUT_EXPECTED.
     */
    uint8_t payout_index;

    /**
     * Number of NoPayout PSBTs signed so far in the current Session 2.
     * Each vault contributes (keeper_count + challenger_count) NoPayout leaves.
     * Capped at vault_count × (keeper_count + challenger_count) ≤ 10×64 = 640.
     */
    uint16_t nopayout_index;

    /**
     * Index of the vault group currently being processed in Session 2.
     * Advances after the last payout of each group (0..vault_count-1).
     * Only meaningful when state >= VAULT_STATE_SESSION2_PEGIN_EXPECTED.
     */
    uint8_t vault_group_index;

    /**
     * BIP-32 derivation path stored from DERIVE_CONTEXT_HASH.
     * Compared against depositor_derivation_path from the intent at
     * APPROVE_VAULT_INTENT time to enforce path alignment.
     */
    uint32_t derivation_path[VAULT_MAX_PATH_DEPTH];

    /** Number of levels in derivation_path. */
    uint8_t derivation_path_len;

    /**
     * True when the root was derived with user approval (P2=0x00 on
     * DERIVE_CONTEXT_HASH).  False for silent re-derivation (P2=0x01).
     * APPROVE_VAULT_INTENT requires this to be true; a silently-derived root
     * cannot be used to sign vault transactions without a prior user confirmation.
     */
    bool root_user_approved;
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
