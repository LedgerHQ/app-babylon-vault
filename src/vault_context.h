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
     */
    uint16_t pre_pegin_signed;
    uint16_t pegin_signed;
    uint16_t payout_signed;
    uint16_t nopayout_signed;

    /**
     * Per-slot payout deduplication bitmask.
     *
     * Bit (gi*(keeper_count+2)+claimer_idx) is set once the corresponding Payout
     * PSBT is signed, preventing a malicious host from exhausting the flat
     * payout_signed cap by replaying the same PSBT.  Cleared by vault_context_invalidate.
     */
    uint8_t payout_claimer_mask[(VAULT_MAX_VAULTS * (VAULT_MAX_KEEPERS + 2u) + 7u) / 8u];

    /**
     * Per-group PegIn deduplication bitmask.
     *
     * Bit gi is set once the PegIn PSBT for vault group gi is signed, preventing
     * a malicious host from replaying the same PegIn PSBT to exhaust the flat
     * pegin_signed cap.  Cleared by vault_context_invalidate.
     */
    uint8_t pegin_group_mask[(VAULT_MAX_VAULTS + 7u) / 8u];

    /**
     * Per-(vault_group, challenger) NoPayout deduplication bitmask.
     *
     * Bit (gi*(keeper_count+challenger_count)+challenger_idx) is set once the NoPayout
     * PSBT for that (vault group, challenger) pair is signed, preventing replay of the
     * same NoPayout PSBT to exhaust the cap.  The vault group index gi is inferred from
     * the Assert:0 WITNESS_UTXO tweaked output key fingerprint (nopayout_group_spk_fp).
     * Cleared by vault_context_invalidate.
     */
    uint8_t nopayout_claimer_mask[(VAULT_MAX_VAULTS * (VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS) +
                                   7u) /
                                  8u];

    /**
     * Challenger index for the NoPayout currently being validated/signed.
     * Ranges 0..keeper_count+challenger_count-1.
     * Set by _validate_nopayout; read by sign_custom_inputs to set the dedup bit.
     */
    uint8_t nopayout_challenger_index;

    /**
     * Group index for the NoPayout currently being validated/signed.
     * Ranges 0..vault_count-1; assigned by _validate_nopayout on first encounter of each
     * vault group's Assert:0 WITNESS_UTXO tweaked key fingerprint (nopayout_group_spk_fp).
     * Set by _validate_nopayout; read by sign_custom_inputs to set the dedup bit.
     */
    uint8_t nopayout_group_index;

    /**
     * Number of distinct vault groups encountered in NoPayout signing this session.
     * Incremented (up to vault_count) the first time each group's Assert:0 UTXO is seen.
     */
    uint8_t nopayout_group_count;

    /**
     * First 4 bytes of the Assert:0 WITNESS_UTXO tweaked output key (SPK bytes [2..5])
     * for each encountered NoPayout vault group.  Used to assign a stable gi when the
     * same vault group's Assert:0 UTXO appears for additional challengers.
     */
    uint8_t nopayout_group_spk_fp[VAULT_MAX_VAULTS][4];

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

    /**
     * HKDF appName bytes stored from DERIVE_CONTEXT_HASH.
     *
     * Binding the app_name across the full session (from DERIVE_CONTEXT_HASH to
     * APPROVE_VAULT_INTENT) ensures the user can confirm which application key
     * domain was used — even when P2=0x01 (silent) was used and no Screen 1
     * was shown.  display_vault_intent() MUST render this field so the user
     * sees the appName before approving the intent.
     */
    uint8_t app_name[VAULT_APP_NAME_MAX_LEN];

    /** Number of bytes in app_name (0 if DERIVE_CONTEXT_HASH not yet called). */
    uint8_t app_name_len;

} vault_context_t;

// ---------------------------------------------------------------------------
// State machine API (defined in vault_context.c)
// ---------------------------------------------------------------------------

/**
 * @brief Zero-initialise the context and set state to VAULT_STATE_IDLE.
 *
 * In production the global G_vault_context is BSS-zero-initialized at device
 * boot (VAULT_STATE_IDLE == 0), so this function has no production caller.
 * Call it from unit tests to reset context to a known state between cases.
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
