#pragma once

/**
 * @file derive_context_hash_core.h
 * @brief Core HKDF streaming logic for DERIVE_CONTEXT_HASH (INS 0x81).
 *
 * All functions are static inline — zero call overhead when used from the handler.
 * No APDU layer references (no dispatcher_context_t, no SEND_SW).
 * Unit tests include this header directly and substitute mock cx_ implementations.
 *
 * Three-phase protocol matching the chunked APDU wire format:
 *   1. hkdf_stream_begin()  — BIP-32 derive → HKDF-Extract → HMAC init with SHA256(app_name)
 *   2. hkdf_stream_feed()   — feed context chunks into the running HMAC (zero or more times)
 *   3. hkdf_stream_finalize() — append 0x01 counter, finalise HMAC → htlc_preimage, compute
 * htlc_hashlock
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "cx.h"
#include "crypto_helpers.h"

#include "../globals.h"
#include "../vault_intent.h"

// BIP-32 path: m/73681862'  (0x80000000 | 73681862 = 0x84644BC6)
#define VAULT_HKDF_PATH_INDEX (0x80000000u | 73681862u)

// HKDF salt per spec (no null terminator counted)
static const uint8_t HKDF_SALT[] = "derive-context-hash";
#define HKDF_SALT_LEN ((uint32_t) (sizeof(HKDF_SALT) - 1u))

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
    cx_hkdf_extract(CX_SHA256, ikm, 32u, salt_buf, HKDF_SALT_LEN, prk_out);
    explicit_bzero(salt_buf, sizeof(salt_buf));
}

// ---------------------------------------------------------------------------
// Phase 1 — Full stream begin: derive + extract + HMAC init
// ---------------------------------------------------------------------------

/** Zero sensitive intermediates on both success and error paths of hkdf_stream_begin(). */
static inline void wipe_hkdf_intermediates(uint8_t *prk, uint8_t *app_name_hash) {
    explicit_bzero(prk, VAULT_HASH256_LEN);
    explicit_bzero(app_name_hash, VAULT_HASH256_LEN);
}

/**
 * @brief Begin a streaming HKDF derivation.
 *
 * Derives the BIP-32 private key, runs HKDF-Extract, initialises the running
 * HMAC-SHA256 for HKDF-Expand, and feeds SHA256(app_name) as the first
 * part of the info string.  Sets context_total_len and resets context_received_len.
 *
 * Sensitive intermediates (privkey, PRK, app_name_hash) are zeroed before return.
 *
 * @param stream            Streaming state to initialise (must be zeroed by caller).
 * @param app_name          UTF-8 app name bytes (max 64 B).
 * @param app_name_len      Length of app_name in bytes.
 * @param context_total_len Total context byte count that will follow in feed() calls.
 * @return true on success; false on any crypto error.
 */
static inline bool hkdf_stream_begin(hkdf_stream_t *stream,
                                     const uint8_t *app_name,
                                     uint8_t app_name_len,
                                     uint16_t context_total_len) {
    cx_ecfp_256_private_key_t privkey;
    if (!derive_vault_privkey(&privkey)) {
        explicit_bzero(&privkey, sizeof(privkey));
        return false;
    }

    uint8_t prk[VAULT_HASH256_LEN];
    extract_prk(privkey.d, prk);
    explicit_bzero(&privkey, sizeof(privkey));

    uint8_t app_name_hash[VAULT_HASH256_LEN];

    if (cx_hash_sha256(app_name, app_name_len, app_name_hash, VAULT_HASH256_LEN) !=
        VAULT_HASH256_LEN) {
        wipe_hkdf_intermediates(prk, app_name_hash);
        return false;
    }
    if (cx_hmac_sha256_init_no_throw(&stream->hmac, prk, VAULT_HASH256_LEN) != CX_OK) {
        wipe_hkdf_intermediates(prk, app_name_hash);
        return false;
    }
    if (cx_hmac_update((cx_hmac_t *) &stream->hmac, app_name_hash, VAULT_HASH256_LEN) != CX_OK) {
        wipe_hkdf_intermediates(prk, app_name_hash);
        return false;
    }

    wipe_hkdf_intermediates(prk, app_name_hash);
    stream->context_total_len = context_total_len;
    stream->context_received_len = 0;
    return true;
}

// ---------------------------------------------------------------------------
// Phase 2 — Feed one context chunk
// ---------------------------------------------------------------------------

/**
 * @brief Feed @p len bytes of context data into the running HKDF-Expand HMAC.
 * @return true on success; false on HMAC update error.
 */
static inline bool hkdf_stream_feed(hkdf_stream_t *stream, const uint8_t *data, uint8_t len) {
    return cx_hmac_update((cx_hmac_t *) &stream->hmac, data, len) == CX_OK;
}

// ---------------------------------------------------------------------------
// Phase 3 — Finalise: append HKDF counter byte, close HMAC, compute hashlock
// ---------------------------------------------------------------------------

/**
 * @brief Finalise the HKDF-Expand computation and derive htlc_preimage + htlc_hashlock.
 *
 * Appends the single-block HKDF counter byte (0x01), finalises the HMAC to
 * obtain htlc_preimage = OKM, then computes htlc_hashlock = SHA256(htlc_preimage).
 *
 * @param stream           Streaming state (HMAC context with all info already fed).
 * @param htlc_preimage_out  32-byte output buffer for the HTLC preimage.
 * @param htlc_hashlock_out  32-byte output buffer for the HTLC hashlock.
 * @return true on success; false on any crypto error.
 */
static inline bool hkdf_stream_finalize(hkdf_stream_t *stream,
                                        uint8_t *htlc_preimage_out,
                                        uint8_t *htlc_hashlock_out) {
    const uint8_t counter = 0x01;
    if (cx_hmac_update((cx_hmac_t *) &stream->hmac, &counter, 1) != CX_OK) {
        return false;
    }

    size_t out_len = VAULT_HASH256_LEN;
    if (cx_hmac_final((cx_hmac_t *) &stream->hmac, htlc_preimage_out, &out_len) != CX_OK) {
        return false;
    }

    return cx_hash_sha256(htlc_preimage_out,
                          VAULT_HASH256_LEN,
                          htlc_hashlock_out,
                          VAULT_HASH256_LEN) == VAULT_HASH256_LEN;
}
