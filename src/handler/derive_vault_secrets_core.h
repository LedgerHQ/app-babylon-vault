#pragma once

/**
 * @file derive_vault_secrets_core.h
 * @brief On-device subset of the babylon-toolkit `derive-vault-secrets` expansion.
 *
 * The host SDK expands the DERIVE_CONTEXT_HASH root into three secrets
 * (hashlock / auth-anchor / WOTS seed) via HKDF-Expand-only with prefix-free
 * `info` labels under the "babylonbtcvault" domain tag (derive-vault-secrets §2.2,
 * Appendix A). The device never needs the secrets themselves — only the on-chain
 * SHA-256 commitments — so it recomputes:
 *
 *   commitment(label, ctx) = SHA-256( HKDF-Expand-SHA256(root, info(label, ctx), 32) )
 *   info(label, ctx)       = "babylonbtcvault" || len(label):u8 || label
 *                            || len(ctx):u16-BE || ctx
 *
 * to bind the PegIn HTLC hashlock and the Pre-PegIn OP_RETURN auth-anchor to the
 * depositor's wallet-derived root. Expand-only: PRK = root, single 32-byte block
 * (HMAC-SHA256(root, info || 0x01)) — NOT the full Extract+Expand HKDF.
 *
 * static inline, no APDU-layer references — unit-testable with mock cx_.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cx.h"

#include "../vault_intent.h"

// Fixed domain tag for the TBV expansion (derive-vault-secrets Appendix A.1).
static const uint8_t VS_DOMAIN_TAG[] = "babylonbtcvault";
#define VS_DOMAIN_TAG_LEN ((uint8_t) (sizeof(VS_DOMAIN_TAG) - 1u))  // 15

/**
 * @brief commitment = SHA-256(HKDF-Expand-SHA256(root, info(label, ctx), 32)).
 *
 * @param root           32-byte DERIVE_CONTEXT_HASH root (the HKDF PRK).
 * @param label          ASCII label bytes (e.g. "hashlock").
 * @param label_len      Label length in [1, 255].
 * @param ctx            Per-label context bytes (may be NULL when ctx_len == 0).
 * @param ctx_len        Context length in [0, 65535].
 * @param commitment_out 32-byte output: SHA-256 of the expanded secret.
 * @return true on success; false on any crypto error.
 */
static inline bool vault_expand_commitment(const uint8_t root[VAULT_HASH256_LEN],
                                           const uint8_t *label,
                                           uint8_t label_len,
                                           const uint8_t *ctx,
                                           uint16_t ctx_len,
                                           uint8_t commitment_out[VAULT_HASH256_LEN]) {
    cx_hmac_sha256_t hmac;
    uint8_t secret[VAULT_HASH256_LEN];
    const uint8_t label_len_b = label_len;
    const uint8_t ctx_len_be[2] = {(uint8_t) (ctx_len >> 8), (uint8_t) (ctx_len & 0xFFu)};
    const uint8_t counter = 0x01;

    bool ok =
        cx_hmac_sha256_init_no_throw(&hmac, root, VAULT_HASH256_LEN) == CX_OK &&
        // info = "babylonbtcvault" || len(label) || label || len(ctx):u16-BE || ctx
        cx_hmac_update((cx_hmac_t *) &hmac, VS_DOMAIN_TAG, VS_DOMAIN_TAG_LEN) == CX_OK &&
        cx_hmac_update((cx_hmac_t *) &hmac, &label_len_b, 1) == CX_OK &&
        cx_hmac_update((cx_hmac_t *) &hmac, label, label_len) == CX_OK &&
        cx_hmac_update((cx_hmac_t *) &hmac, ctx_len_be, 2) == CX_OK &&
        (ctx_len == 0u || cx_hmac_update((cx_hmac_t *) &hmac, ctx, ctx_len) == CX_OK) &&
        // HKDF-Expand single-block counter
        cx_hmac_update((cx_hmac_t *) &hmac, &counter, 1) == CX_OK;

    if (ok) {
        size_t out_len = VAULT_HASH256_LEN;
        ok = cx_hmac_final((cx_hmac_t *) &hmac, secret, &out_len) == CX_OK;
    }
    if (ok) {
        ok = cx_hash_sha256(secret, VAULT_HASH256_LEN, commitment_out, VAULT_HASH256_LEN) ==
             VAULT_HASH256_LEN;
    }

    explicit_bzero(secret, sizeof(secret));
    explicit_bzero(&hmac, sizeof(hmac));
    return ok;
}

/**
 * @brief HTLC hashlock h = SHA256(hashlockSecret[htlc_vout]).
 * ctx = I2OSP(htlc_vout, 4); htlc_vout is a protocol u8 so the high 3 bytes are 0.
 */
static inline bool vault_derive_hashlock_commitment(const uint8_t root[VAULT_HASH256_LEN],
                                                    uint8_t htlc_vout,
                                                    uint8_t commitment_out[VAULT_HASH256_LEN]) {
    static const uint8_t LABEL_HASHLOCK[] = "hashlock";  // 8 bytes
    const uint8_t ctx[4] = {0u, 0u, 0u, htlc_vout};      // I2OSP(htlc_vout, 4)
    return vault_expand_commitment(root,
                                   LABEL_HASHLOCK,
                                   (uint8_t) (sizeof(LABEL_HASHLOCK) - 1u),
                                   ctx,
                                   sizeof(ctx),
                                   commitment_out);
}

/**
 * @brief Pre-PegIn auth-anchor commitment = SHA256(authAnchor). ctx is empty (shared
 * across the Pre-PegIn).
 */
static inline bool vault_derive_auth_anchor_commitment(const uint8_t root[VAULT_HASH256_LEN],
                                                       uint8_t commitment_out[VAULT_HASH256_LEN]) {
    static const uint8_t LABEL_AUTH_ANCHOR[] = "auth-anchor";  // 11 bytes
    return vault_expand_commitment(root,
                                   LABEL_AUTH_ANCHOR,
                                   (uint8_t) (sizeof(LABEL_AUTH_ANCHOR) - 1u),
                                   NULL,
                                   0u,
                                   commitment_out);
}
