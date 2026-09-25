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
            return (to == VAULT_STATE_HASH_DERIVED);
        case VAULT_STATE_HASH_DERIVED:
            /* APPROVE_VAULT_INTENT saves/restores root across invalidate and re-sets
             * state to HASH_DERIVED before transitioning here. */
            return (to == VAULT_STATE_INTENT_LOADED);
        case VAULT_STATE_INTENT_LOADED:
            /* Terminal active state: all signing flows accepted without ordering.
             * The only exit is vault_context_invalidate (full reset to IDLE). */
            return false;
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

// ---------------------------------------------------------------------------
// GET_VAULT_STATE
// ---------------------------------------------------------------------------

/**
 * @brief Which fingerprints @p state holds.
 *
 * No default case, for the same exhaustiveness guarantee as vault_transition_allowed.
 * An out-of-range state reports false rather than an empty answer.
 */
static bool vault_state_fingerprints(vault_state_t state, bool *has_intent, bool *has_context) {
    switch (state) {
        case VAULT_STATE_IDLE:
            *has_intent = false;
            *has_context = false;
            return true;
        case VAULT_STATE_HASH_DERIVED:
            *has_intent = false;
            *has_context = true;
            return true;
        case VAULT_STATE_INTENT_LOADED:
            *has_intent = true;
            *has_context = true;
            return true;
            /* no default */
    }
    return false;
}

static size_t _encode_fingerprint(uint8_t *out, bool present, const uint8_t *fp) {
    if (!present) {
        out[0] = 0u;
        return 1u;
    }
    out[0] = VAULT_FINGERPRINT_LEN;
    memcpy(out + 1, fp, VAULT_FINGERPRINT_LEN);
    return 1u + VAULT_FINGERPRINT_LEN;
}

size_t vault_context_encode_state(const vault_context_t *ctx,
                                  uint8_t out[VAULT_STATE_RESPONSE_MAX_LEN]) {
    bool has_intent;
    bool has_context;
    if (!vault_state_fingerprints(ctx->state, &has_intent, &has_context)) {
        return 0u;
    }
    size_t len = _encode_fingerprint(out, has_intent, ctx->intent_fp);
    len += _encode_fingerprint(out + len, has_context, ctx->context_fp);
    return len;
}

// ---------------------------------------------------------------------------
// Fingerprints
// ---------------------------------------------------------------------------

static void _truncate_digest(const uint8_t digest[VAULT_HASH256_LEN],
                             uint8_t fp_out[VAULT_FINGERPRINT_LEN]) {
    memcpy(fp_out, digest + VAULT_HASH256_LEN - VAULT_FINGERPRINT_LEN, VAULT_FINGERPRINT_LEN);
}

bool vault_fingerprint(const uint8_t *data, size_t len, uint8_t fp_out[VAULT_FINGERPRINT_LEN]) {
    uint8_t digest[VAULT_HASH256_LEN];
    bool ok = cx_hash_sha256(data, len, digest, sizeof(digest)) == VAULT_HASH256_LEN;
    if (ok) {
        _truncate_digest(digest, fp_out);
    }
    explicit_bzero(digest, sizeof(digest));
    return ok;
}

void vault_fingerprint_init(cx_sha256_t *hash) {
    cx_sha256_init_no_throw(hash);
}

bool vault_fingerprint_update(cx_sha256_t *hash, const uint8_t *data, size_t len) {
    if (len == 0u) {
        return true; /* an empty CData may come with a NULL data pointer */
    }
    return cx_hash_no_throw(&hash->header, 0, data, len, NULL, 0) == CX_OK;
}

bool vault_fingerprint_final(cx_sha256_t *hash, uint8_t fp_out[VAULT_FINGERPRINT_LEN]) {
    uint8_t digest[VAULT_HASH256_LEN];
    bool ok = cx_hash_no_throw(&hash->header, CX_LAST, NULL, 0, digest, sizeof(digest)) == CX_OK;
    if (ok) {
        _truncate_digest(digest, fp_out);
    }
    explicit_bzero(digest, sizeof(digest));
    explicit_bzero(hash, sizeof(*hash));
    return ok;
}
