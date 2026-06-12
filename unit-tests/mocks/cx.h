#pragma once

/**
 * Mock SDK crypto types for unit tests.
 * Replaces the Ledger SDK's cx.h — included first via the CMake mock include path.
 * Implementations live in unit-tests/mock_cx.c.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// GCC attribute used in real SDK headers — no-op in tests
#define WARN_UNUSED_RESULT __attribute__((warn_unused_result))

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------
typedef int cx_err_t;
#define CX_OK    0
#define CX_ERROR (-1)

// ---------------------------------------------------------------------------
// Hash algorithm identifier
// ---------------------------------------------------------------------------
typedef unsigned int cx_md_t;
#define CX_SHA256 4u

// ---------------------------------------------------------------------------
// Curve identifier
// ---------------------------------------------------------------------------
typedef unsigned int cx_curve_t;
#define CX_CURVE_SECP256K1 0x21u

// ---------------------------------------------------------------------------
// Hash flags (subset of SDK constants used by cx_hash_no_throw)
// ---------------------------------------------------------------------------
#define CX_LAST       0x80u
#define CX_SHA256_SIZE 32u

// ---------------------------------------------------------------------------
// Software SHA-256 context (used inside cx_sha256_t and cx_hmac_sha256_t)
// ---------------------------------------------------------------------------
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buf_len;
} sha256_sw_t;

// ---------------------------------------------------------------------------
// Generic hash context — used as cx_hash_t throughout the vault app.
// In the mock it is the same as sha256_sw_t.
// ---------------------------------------------------------------------------
typedef sha256_sw_t cx_hash_t;

// ---------------------------------------------------------------------------
// SHA-256 context with the .header field expected by crypto_hash_* helpers.
// ---------------------------------------------------------------------------
typedef struct {
    cx_hash_t header;
} cx_sha256_t;

// ---------------------------------------------------------------------------
// Mock HMAC-SHA256 context
// ---------------------------------------------------------------------------
typedef struct {
    sha256_sw_t inner;       // running inner SHA-256 (key⊕ipad || message)
    uint8_t     opad[64];    // key⊕opad — saved for the outer hash
} cx_hmac_sha256_t;

// In the real SDK cx_hmac_t is the base struct; for the mock it's the same type.
typedef cx_hmac_sha256_t cx_hmac_t;

// ---------------------------------------------------------------------------
// EC private key
// ---------------------------------------------------------------------------
typedef struct {
    cx_curve_t curve;
    size_t     d_len;
    uint8_t    d[32];
} cx_ecfp_256_private_key_t;

// ---------------------------------------------------------------------------
// Function declarations (implemented in mock_cx.c)
// ---------------------------------------------------------------------------

// --- Streaming SHA-256 (cx_hash_no_throw / cx_sha256_init) ------------------

// Single-step digest update and finalise.
// mode=0: update; mode=CX_LAST: finalise into out[out_len].
cx_err_t cx_hash_no_throw(cx_hash_t     *hash,
                           int            mode,
                           const uint8_t *in,
                           size_t         in_len,
                           uint8_t       *out,
                           size_t         out_len);

void cx_sha256_init(cx_sha256_t *ctx);

// --- HMAC-SHA256 ------------------------------------------------------------

WARN_UNUSED_RESULT cx_err_t cx_hmac_sha256_init_no_throw(cx_hmac_sha256_t *hmac,
                                                          const uint8_t    *key,
                                                          size_t            key_len);

WARN_UNUSED_RESULT cx_err_t cx_hmac_update(cx_hmac_t     *hmac,
                                            const uint8_t *in,
                                            size_t         in_len);

WARN_UNUSED_RESULT cx_err_t cx_hmac_final(cx_hmac_t *hmac,
                                           uint8_t   *out,
                                           size_t    *out_len);

void cx_hkdf_extract(cx_md_t        hash_id,
                     const uint8_t *ikm,
                     unsigned int   ikm_len,
                     uint8_t       *salt,
                     unsigned int   salt_len,
                     uint8_t       *prk);

// --- Oneshot SHA-256 --------------------------------------------------------

size_t cx_hash_sha256(const uint8_t *in,
                      size_t         len,
                      uint8_t       *out,
                      size_t         out_len);

// --- Taproot BIP-340/341 crypto (vault_script.c uses these) ----------------

// Tagged-hash init: SHA256(SHA256(tag)||SHA256(tag)||...) streaming start.
void crypto_tr_tagged_hash_init(cx_sha256_t    *ctx,
                                 const uint8_t  *tag,
                                 uint16_t        tag_len);

// TapLeaf tagged hash init (tag = "TapLeaf").
void crypto_tr_tapleaf_hash_init(cx_sha256_t *ctx);

// TapBranch: tagged_hash("TapBranch", sort(left, right)).
void crypto_tr_combine_taptree_hashes(const uint8_t left[32],
                                       const uint8_t right[32],
                                       uint8_t       out[32]);

// Taproot key tweak: Q = lift_x(pubkey) + t*G where t = tagged_hash("TapTweak", pubkey||h).
// Writes x-coordinate of Q to out[32]; sets *y_parity to 0 or 1.
// Returns 0 on success, -1 on error.
int crypto_tr_tweak_pubkey(const uint8_t  pubkey[32],
                            const uint8_t *h,
                            size_t         h_len,
                            uint8_t       *y_parity,
                            uint8_t        out[32]);
