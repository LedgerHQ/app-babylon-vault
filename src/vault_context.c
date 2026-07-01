#include <string.h>

#include "vault_context.h"
#include "globals.h"

// ---------------------------------------------------------------------------
// State machine implementation
// ---------------------------------------------------------------------------

void vault_context_init(vault_context_t *ctx) {
    explicit_bzero(ctx, sizeof(*ctx));
    ctx->state = VAULT_STATE_IDLE;
}

void vault_context_invalidate(vault_context_t *ctx) {
    // Zero the root first to guarantee it is wiped even if we fault later.
    explicit_bzero(ctx->root, sizeof(ctx->root));

    // Zero the rest and return to IDLE.
    explicit_bzero(ctx, sizeof(*ctx));
    ctx->state = VAULT_STATE_IDLE;

    // Wipe all globals whose validity depends on state != IDLE.
    explicit_bzero(&G_vault_intent, sizeof(G_vault_intent));
    explicit_bzero(&G_approve_intent_state, sizeof(G_approve_intent_state));
    explicit_bzero(&G_scratch, sizeof(G_scratch));
}

/**
 * @brief Return true iff (from → to) is a legal edge in the state diagram.
 *
 * No default case — combined with -Wall/-Wswitch/-Werror this becomes a
 * compile error whenever a new vault_state_t value is added without being
 * handled here, enforcing exhaustiveness at build time.
 */
static inline bool vault_transition_allowed(vault_state_t from, vault_state_t to) {
    switch (from) {
        case VAULT_STATE_IDLE:
            return (to == VAULT_STATE_INTENT_LOADED || to == VAULT_STATE_HASH_DERIVED);
        case VAULT_STATE_HASH_DERIVED:
            return false;  // APPROVE saves/restores around invalidate; no direct transition needed
        case VAULT_STATE_INTENT_LOADED:
            return (to == VAULT_STATE_SESSION1_PREPEGIN_EXPECTED ||
                    to == VAULT_STATE_SESSION2_PEGIN_EXPECTED);
        case VAULT_STATE_SESSION1_PREPEGIN_EXPECTED:
            return (to == VAULT_STATE_INTENT_LOADED);
        case VAULT_STATE_SESSION2_PEGIN_EXPECTED:
            return (to == VAULT_STATE_SESSION2_PAYOUT_EXPECTED);
        case VAULT_STATE_SESSION2_PAYOUT_EXPECTED:
            return (to == VAULT_STATE_SESSION2_COMPLETE);
        case VAULT_STATE_SESSION2_COMPLETE:
            return (to == VAULT_STATE_IDLE);
            /* no default */
    }
    return false; /* unreachable; satisfies -Wreturn-type */
}

bool vault_context_transition(vault_context_t *ctx, vault_state_t from, vault_state_t to) {
    if (ctx->state != from || !vault_transition_allowed(from, to)) {
        vault_context_invalidate(ctx);
        return false;
    }
    ctx->state = to;
    return true;
}
