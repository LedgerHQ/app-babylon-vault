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
 *                                                 htlc_hashlock + auth_anchor_hash computed]
 *
 * INTENT_LOADED is the terminal active state.  All signing flows (Pre-PegIn, PegIn,
 * Payout, NoPayout, Refund, Claim, Assert, WC) are dispatched by PSBT structure alone;
 * there is no inter-transaction ordering requirement (v22).
 *
 * Invalidation triggers (any of these → explicit_bzero(root) + IDLE):
 *   - Signing error in any hook
 *   - APPROVE_VAULT_INTENT while intent already loaded (state != IDLE and state != HASH_DERIVED)
 *   - DERIVE_CONTEXT_HASH while intent is loaded
 */
typedef enum {
    VAULT_STATE_IDLE = 0,
    VAULT_STATE_HASH_DERIVED,   // DERIVE_CONTEXT_HASH complete; root held, no intent yet
    VAULT_STATE_INTENT_LOADED,  // intent loaded; all signing flows accepted
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
     * Claimer index for the payout currently being validated/signed.
     * 0 = VP claimer, 1..keeper_count = VK claimers, keeper_count+1 = Depositor.
     * Set by _validate_payout from PSBT structure; read by sign_custom_inputs.
     */
    uint8_t payout_index;

    /**
     * Per-type signature counters (sampling countermeasure, v22).
     *
     * Each counter is incremented once a signature is produced and capped at the
     * expected count for the approved intent.  Exceeding any cap nullifies the intent
     * and returns SW_CAP_EXCEEDED; all counters reset to zero on each intent approval.
     *
     * Caps (vault_count=V, keeper_count=N, challenger_count=M):
     *   pre_pegin_signed : 1
     *   pegin_signed     : V
     *   payout_signed    : V × (N+2)
     *   nopayout_signed  : V × (N+M)
     *   pop_signed       : VAULT_POP_CAP (state-independent; caps key-correlation exposure)
     */
    uint16_t pre_pegin_signed;
    uint16_t pegin_signed;
    uint16_t payout_signed;
    uint16_t nopayout_signed;
    uint16_t pop_signed;

    /**
     * Dual-use field:
     *   - During APPROVE_VAULT_INTENT P1=0x01: counts groups received (0..vault_count).
     *   - During Payout signing: group index currently being validated/signed (set by
     *     _validate_payout from PSBT structure, read by sign_custom_inputs).
     */
    uint8_t vault_group_index;

    /**
     * Set to true by _validate_payout, false by _validate_display_payout_finalize.
     * Allows sign_custom_inputs to distinguish a VK/Depositor Payout (2 inputs, 2 outputs,
     * Input 0 signed) from a PayoutFinalize (same shape, Input 1 signed).
     */
    bool is_payout_signing;

    /**
     * BIP-32 derivation path stored from DERIVE_CONTEXT_HASH.
     * Compared against depositor_derivation_path from the intent at
     * APPROVE_VAULT_INTENT time to enforce path alignment.
     */
    uint32_t derivation_path[VAULT_MAX_PATH_DEPTH];

    /** Number of levels in derivation_path. */
    uint8_t derivation_path_len;

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
