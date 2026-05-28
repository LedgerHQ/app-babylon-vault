/**
 * Software implementations of Ledger SDK cx_ functions used by derive_context_hash_core.h.
 *
 * SHA-256 implementation: public domain, FIPS 180-4 (Brad Conte / multiple contributors).
 * HMAC-SHA256: standard RFC 2104 construction on top of the software SHA-256.
 * BIP-32 mock: returns a fixed 0x42-filled private key for reproducible test vectors.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "mocks/cx.h"
#include "mocks/crypto_helpers.h"

// ---------------------------------------------------------------------------
// Software SHA-256 (FIPS 180-4)
// ---------------------------------------------------------------------------

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32u - (n))))

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

static void sha256_sw_init(sha256_sw_t *ctx) {
    ctx->state[0] = 0x6a09e667u;
    ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u;
    ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu;
    ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu;
    ctx->state[7] = 0x5be0cd19u;
    ctx->count    = 0;
    ctx->buf_len  = 0;
}

static void sha256_sw_transform(sha256_sw_t *ctx, const uint8_t block[64]) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;

    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4  ] << 24) | ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] <<  8) |  (uint32_t)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = ROR32(w[i-15], 7) ^ ROR32(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROR32(w[i-2], 17) ^ ROR32(w[i-2],  19) ^ (w[i-2]  >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + (ROR32(e,6) ^ ROR32(e,11) ^ ROR32(e,25))
               + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i];
        t2 = (ROR32(a,2) ^ ROR32(a,13) ^ ROR32(a,22))
           + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_sw_update(sha256_sw_t *ctx, const uint8_t *data, size_t len) {
    while (len > 0) {
        uint32_t space = 64u - ctx->buf_len;
        uint32_t take  = (len < space) ? (uint32_t)len : space;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        ctx->count   += take;
        data         += take;
        len          -= take;
        if (ctx->buf_len == 64u) {
            sha256_sw_transform(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }
}

static void sha256_sw_final(sha256_sw_t *ctx, uint8_t out[32]) {
    uint64_t bit_count = ctx->count * 8u;
    uint8_t  pad       = 0x80u;
    sha256_sw_update(ctx, &pad, 1);
    while (ctx->buf_len != 56u) {
        uint8_t z = 0;
        sha256_sw_update(ctx, &z, 1);
    }
    for (int i = 7; i >= 0; i--) {
        uint8_t b = (uint8_t)(bit_count >> (i * 8));
        sha256_sw_update(ctx, &b, 1);
    }
    for (int i = 0; i < 8; i++) {
        out[i*4  ] = (uint8_t)(ctx->state[i] >> 24);
        out[i*4+1] = (uint8_t)(ctx->state[i] >> 16);
        out[i*4+2] = (uint8_t)(ctx->state[i] >>  8);
        out[i*4+3] = (uint8_t)(ctx->state[i]);
    }
}

static void sha256_sw_oneshot(const uint8_t *in, size_t len, uint8_t out[32]) {
    sha256_sw_t ctx;
    sha256_sw_init(&ctx);
    sha256_sw_update(&ctx, in, len);
    sha256_sw_final(&ctx, out);
}

// ---------------------------------------------------------------------------
// cx_hash_sha256
// ---------------------------------------------------------------------------

size_t cx_hash_sha256(const uint8_t *in, size_t len, uint8_t *out, size_t out_len) {
    if (out_len < 32u) return 0;
    sha256_sw_oneshot(in, len, out);
    return 32u;
}

// ---------------------------------------------------------------------------
// HMAC-SHA256 (RFC 2104)
// ---------------------------------------------------------------------------

cx_err_t cx_hmac_sha256_init_no_throw(cx_hmac_sha256_t *hmac,
                                       const uint8_t    *key,
                                       size_t            key_len) {
    uint8_t k[64];
    memset(k, 0, sizeof(k));

    if (key_len > 64u) {
        sha256_sw_oneshot(key, key_len, k);
    } else {
        memcpy(k, key, key_len);
    }

    uint8_t ipad[64];
    for (int i = 0; i < 64; i++) {
        ipad[i]       = k[i] ^ 0x36u;
        hmac->opad[i] = k[i] ^ 0x5cu;
    }

    sha256_sw_init(&hmac->inner);
    sha256_sw_update(&hmac->inner, ipad, 64u);
    return CX_OK;
}

cx_err_t cx_hmac_update(cx_hmac_t *hmac, const uint8_t *in, size_t in_len) {
    sha256_sw_update(&hmac->inner, in, in_len);
    return CX_OK;
}

cx_err_t cx_hmac_final(cx_hmac_t *hmac, uint8_t *out, size_t *out_len) {
    if (*out_len < 32u) return CX_ERROR;

    uint8_t inner_hash[32];
    sha256_sw_final(&hmac->inner, inner_hash);

    sha256_sw_t outer;
    sha256_sw_init(&outer);
    sha256_sw_update(&outer, hmac->opad, 64u);
    sha256_sw_update(&outer, inner_hash, 32u);
    sha256_sw_final(&outer, out);

    *out_len = 32u;
    return CX_OK;
}

// ---------------------------------------------------------------------------
// cx_hkdf_extract: PRK = HMAC-SHA256(salt, ikm)
// ---------------------------------------------------------------------------

void cx_hkdf_extract(cx_md_t        hash_id,
                     const uint8_t *ikm,
                     unsigned int   ikm_len,
                     uint8_t       *salt,
                     unsigned int   salt_len,
                     uint8_t       *prk) {
    (void)hash_id;
    cx_hmac_sha256_t hmac;
    (void)cx_hmac_sha256_init_no_throw(&hmac, salt, salt_len);
    (void)cx_hmac_update(&hmac, ikm, ikm_len);
    size_t len = 32u;
    (void)cx_hmac_final(&hmac, prk, &len);
}

// ---------------------------------------------------------------------------
// BIP-32 mock: always returns 0x42-filled key regardless of path
// ---------------------------------------------------------------------------

cx_err_t bip32_derive_init_privkey_256(cx_curve_t                 curve,
                                        const uint32_t            *path,
                                        size_t                     path_len,
                                        cx_ecfp_256_private_key_t *privkey,
                                        uint8_t                   *chain_code) {
    (void)curve; (void)path; (void)path_len; (void)chain_code;
    privkey->curve = curve;
    privkey->d_len = 32u;
    memset(privkey->d, 0x42, 32u);
    return CX_OK;
}
