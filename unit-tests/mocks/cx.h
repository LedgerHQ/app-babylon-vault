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
// Software SHA-256 context (used inside cx_hmac_sha256_t)
// ---------------------------------------------------------------------------
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t  buf[64];
    uint32_t buf_len;
} sha256_sw_t;

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

size_t cx_hash_sha256(const uint8_t *in,
                      size_t         len,
                      uint8_t       *out,
                      size_t         out_len);
