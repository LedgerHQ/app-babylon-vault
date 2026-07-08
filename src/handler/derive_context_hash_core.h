#pragma once

/**
 * @file derive_context_hash_core.h
 * @brief Core HKDF logic for DERIVE_CONTEXT_HASH (INS 0x81).
 *
 * All functions are static inline — zero call overhead when used from the handler.
 * No APDU layer references (no dispatcher_context_t, no SEND_SW).
 * Unit tests include this header directly and substitute mock cx_ implementations.
 *
 * The Babylon vaultContext is a fixed ~72 bytes, so it always fits one APDU and the
 * whole root is computed in a single call — hkdf_derive_root() — with no streaming.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cx.h"
#include "crypto_helpers.h"

#include "../globals.h"
#include "../vault_intent.h"
#include "../vault_constants.h"

// BIP-32 path: m/73681862'  (0x80000000 | 73681862 = 0x84644BC6)
#define VAULT_HKDF_PATH_INDEX (0x80000000u | 73681862u)

// HKDF salt per spec (no null terminator counted)
static const uint8_t HKDF_SALT[] = "derive-context-hash";
#define HKDF_SALT_LEN ((uint32_t) (sizeof(HKDF_SALT) - 1u))

// Canonical network name bytes + length (string literal, NUL excluded).
static const uint8_t HKDF_NETWORK_NAME[] = VAULT_CANONICAL_NETWORK_NAME;
#define HKDF_NETWORK_NAME_LEN ((uint32_t) (sizeof(HKDF_NETWORK_NAME) - 1u))

// ---------------------------------------------------------------------------
// appName charset validation — spec §2.1: [a-z0-9\-] only
// ---------------------------------------------------------------------------

/**
 * @brief Return true iff every byte of @p name is in [a-z0-9\-].
 *
 * Extracted here so it can be included directly by unit tests without
 * bringing in the full handler (which requires dispatcher_context_t).
 */
static inline bool app_name_charset_valid(const uint8_t *name, uint8_t len) {
    for (uint8_t i = 0; i < len; i++) {
        uint8_t c = name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Phase 1 — BIP-32 key derivation
// ---------------------------------------------------------------------------

/**
 * @brief Derive the BIP-32 private key at m/73681862' (hardened) into @p privkey.
 * @return true on success; false if the SDK returns an error (reject — do not substitute).
 */
static inline bool derive_vault_privkey(cx_ecfp_256_private_key_t *privkey) {
    static const uint32_t path[1] = {VAULT_HKDF_PATH_INDEX};
    return bip32_derive_init_privkey_256(CX_CURVE_SECP256K1, path, 1, privkey, NULL) == CX_OK;
}

// ---------------------------------------------------------------------------
// Phase 1 — HKDF-Extract
// ---------------------------------------------------------------------------

/**
 * @brief Compute PRK = HMAC-SHA256(salt="derive-context-hash", ikm).
 *
 * Uses a stack-local mutable copy of the salt because cx_hkdf_extract
 * takes a non-const salt pointer.
 *
 * @param ikm      32-byte IKM (BIP-32 private key bytes).
 * @param prk_out  32-byte output buffer for the PRK.
 */
static inline void extract_prk(const uint8_t *ikm, uint8_t *prk_out) {
    uint8_t salt_buf[HKDF_SALT_LEN];
    memcpy(salt_buf, HKDF_SALT, HKDF_SALT_LEN);
    cx_hkdf_extract(CX_SHA256, ikm, VAULT_HASH256_LEN, salt_buf, HKDF_SALT_LEN, prk_out);
    explicit_bzero(salt_buf, sizeof(salt_buf));
}

// ---------------------------------------------------------------------------
// Single-shot root derivation
// ---------------------------------------------------------------------------

/**
 * @brief Compute the 32-byte DERIVE_CONTEXT_HASH root in one call.
 *
 *   ikm  = privkey @ m/73681862'
 *   salt = "derive-context-hash"
 *   info = SHA-256(app_name) || SHA-256(canonicalNetworkName)
 *          || connectedPubkey[33] || context
 *   root = HKDF-SHA-256(ikm, salt, info, 32)
 *
 * HKDF-Expand is a single HMAC block for L=32: HMAC-SHA256(PRK, info || 0x01).
 * app_name is host-supplied over the APDU (per the deriveContextHash API; the host
 * sends the fixed "babylon-btc-vault"). The whole vaultContext fits one APDU, so
 * context is passed in full — no streaming.
 *
 * Sensitive intermediates (privkey, PRK, hashes, HMAC ctx) are zeroed before return.
 *
 * @param app_name          UTF-8 app-name bytes (host-supplied, ≤64 B).
 * @param app_name_len      Length of @p app_name.
 * @param connected_pubkey  33-byte compressed SEC1 connected public key.
 * @param context           Context bytes (vaultContext); must be non-empty.
 * @param context_len       Length of @p context.
 * @param root_out          32-byte output buffer for the HKDF root.
 * @return true on success; false on any crypto error.
 */
// hkdf_derive_root places cx_ecfp_256_private_key_t (~80 B) and cx_hmac_sha256_t (~112 B)
// on the caller's stack frame.  This is safe because it is called after io_ui_process()
// returns, at which point the NBGL call stack is fully unwound and stack headroom is
// at its maximum for the APDU handler.
static inline bool hkdf_derive_root(const uint8_t *app_name,
                                    uint8_t app_name_len,
                                    const uint8_t connected_pubkey[VAULT_COMPRESSED_PUBKEY_LEN],
                                    const uint8_t *context,
                                    size_t context_len,
                                    uint8_t root_out[VAULT_HASH256_LEN]) {
    cx_ecfp_256_private_key_t privkey;
    if (!derive_vault_privkey(&privkey)) {
        explicit_bzero(&privkey, sizeof(privkey));
        return false;
    }

    uint8_t prk[VAULT_HASH256_LEN];
    extract_prk(privkey.d, prk);
    explicit_bzero(&privkey, sizeof(privkey));

    cx_hmac_sha256_t hmac;
    uint8_t name_hash[VAULT_HASH256_LEN];  // reused for app-name then network-name hash
    const uint8_t counter = 0x01;

    bool ok =
        cx_hmac_sha256_init_no_throw(&hmac, prk, VAULT_HASH256_LEN) == CX_OK &&
        // info[0..31]: SHA-256(app_name)
        cx_hash_sha256(app_name, app_name_len, name_hash, VAULT_HASH256_LEN) == VAULT_HASH256_LEN &&
        cx_hmac_update((cx_hmac_t *) &hmac, name_hash, VAULT_HASH256_LEN) == CX_OK &&
        // info[32..63]: SHA-256(canonicalNetworkName)
        cx_hash_sha256(HKDF_NETWORK_NAME, HKDF_NETWORK_NAME_LEN, name_hash, VAULT_HASH256_LEN) ==
            VAULT_HASH256_LEN &&
        cx_hmac_update((cx_hmac_t *) &hmac, name_hash, VAULT_HASH256_LEN) == CX_OK &&
        // info[64..96]: connectedPubkey (33-byte compressed)
        cx_hmac_update((cx_hmac_t *) &hmac, connected_pubkey, VAULT_COMPRESSED_PUBKEY_LEN) ==
            CX_OK &&
        // info[97..]: context (vaultContext)
        cx_hmac_update((cx_hmac_t *) &hmac, context, context_len) == CX_OK &&
        // HKDF-Expand single-block counter
        cx_hmac_update((cx_hmac_t *) &hmac, &counter, 1) == CX_OK;

    if (ok) {
        size_t out_len = VAULT_HASH256_LEN;
        ok = cx_hmac_final((cx_hmac_t *) &hmac, root_out, &out_len) == CX_OK;
    }

    explicit_bzero(prk, sizeof(prk));
    explicit_bzero(name_hash, sizeof(name_hash));
    explicit_bzero(&hmac, sizeof(hmac));
    return ok;
}
