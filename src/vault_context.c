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
    // Zero the secret first to guarantee it is wiped even if we fault later.
    explicit_bzero(ctx->s, sizeof(ctx->s));

    // Zero the rest and return to IDLE.
    explicit_bzero(ctx, sizeof(*ctx));
    ctx->state = VAULT_STATE_IDLE;

    // Mirror: wipe the intent as well — it is only valid when state != IDLE.
    explicit_bzero(&G_vault_intent, sizeof(G_vault_intent));
}

bool vault_context_transition(vault_context_t *ctx,
                              vault_state_t    from,
                              vault_state_t    to) {
    if (ctx->state != from) {
        vault_context_invalidate(ctx);
        return false;
    }
    ctx->state = to;
    return true;
}
