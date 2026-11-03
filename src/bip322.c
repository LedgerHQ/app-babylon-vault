#include "bip322.h"

#include <string.h>

#include "cx.h"
#include "ledger_assert.h"

static const char BIP322_TAG[] = "BIP0322-signed-message";

const uint8_t BIP322_PSBT_PROP_POP_MSG_KEY[BIP322_PSBT_PROP_KEY_LEN] =
    {0xFC, 0x06, 'b', 'v', 'a', 'u', 'l', 't', 0x00};

/* -------------------------------------------------------------------------
 * PoP message grammar validation
 * ---------------------------------------------------------------------- */

static bool _is_lowercase_hex(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
}

/* Validate "0x" + 40 lowercase hex chars — writes 42 chars + NUL into out. */
static bool _parse_eth_address(const uint8_t *field,
                               int field_len,
                               char out[BIP322_ETH_ADDR_STR_LEN]) {
    if (field_len != 42) return false;
    if (field[0] != '0' || field[1] != 'x') return false;
    for (int i = 2; i < 42; i++) {
        if (!_is_lowercase_hex(field[i])) return false;
    }
    memcpy(out, field, 42);
    out[42] = '\0';
    return true;
}

bool bip322_parse_pop_message(const uint8_t *msg,
                              int msg_len,
                              char eth_addr[BIP322_ETH_ADDR_STR_LEN],
                              char chain_id[BIP322_CHAIN_ID_STR_LEN],
                              char registry[BIP322_ETH_ADDR_STR_LEN]) {
    /* Scan for the first 3 colons; any extra colons fall into field 3 and are
     * implicitly rejected by _parse_eth_address's strict field_len == 42 check. */
    int colon[3];
    int nc = 0;
    for (int i = 0; i < msg_len && nc < 3; i++) {
        if (msg[i] == ':') colon[nc++] = i;
    }
    if (nc != 3) return false;

    /* Field 0: eth_address [0 .. colon[0]-1] */
    if (!_parse_eth_address(msg, colon[0], eth_addr)) return false;

    /* Field 1: chain_id [colon[0]+1 .. colon[1]-1] */
    int f1_start = colon[0] + 1;
    int f1_len = colon[1] - f1_start;
    if (f1_len <= 0 || f1_len > BIP322_CHAIN_ID_STR_LEN - 1) return false;
    /* No leading zeros unless the field is the single character "0". */
    if (f1_len > 1 && msg[f1_start] == '0') return false;
    for (int i = 0; i < f1_len; i++) {
        if (msg[f1_start + i] < '0' || msg[f1_start + i] > '9') return false;
    }
    memcpy(chain_id, msg + f1_start, f1_len);
    chain_id[f1_len] = '\0';

    /* Field 2: literal "pegin" */
    int f2_start = colon[1] + 1;
    int f2_len = colon[2] - f2_start;
    if (f2_len != 5 || memcmp(msg + f2_start, "pegin", 5) != 0) return false;

    /* Field 3: registry_address [colon[2]+1 .. end] */
    int f3_start = colon[2] + 1;
    int f3_len = msg_len - f3_start;
    if (!_parse_eth_address(msg + f3_start, f3_len, registry)) return false;

    return true;
}

/* -------------------------------------------------------------------------
 * BIP-322 to_spend txid computation
 * ---------------------------------------------------------------------- */

/*
 * Build and hash the BIP-322 "to_spend" virtual transaction.
 *
 * to_spend (128 bytes, legacy serialization):
 *   version  (4B LE) = 0x00000000
 *   vin_count (1B)   = 0x01
 *   input 0:
 *     prevout txid   (32B) = 0x00 * 32
 *     prevout vout   (4B LE) = 0xFFFFFFFF
 *     scriptSig_len  (1B) = 0x22 (34 bytes)
 *     scriptSig      (34B): OP_0(0x00) PUSHBYTES_32(0x20) tagged_hash(32B)
 *     sequence       (4B LE) = 0x00000000
 *   vout_count (1B)  = 0x01
 *   output 0:
 *     value          (8B LE) = 0x00 * 8
 *     scriptPubKey_len (1B) = 0x22 (34 bytes)
 *     scriptPubKey   (34B): OP_1(0x51) PUSHBYTES_32(0x20) tweaked_key(32B)
 *   locktime (4B LE) = 0x00000000
 *
 * tagged_hash("BIP0322-signed-message", message) = SHA256(tag||tag||message)
 * where tag = SHA256("BIP0322-signed-message").
 *
 * txid = SHA256(SHA256(to_spend_bytes)) — PSBT/wire byte order (SHA256d output, not reversed).
 */
bool bip322_compute_to_spend_txid(const uint8_t *message,
                                  int msg_len,
                                  const uint8_t tweaked_key[32],
                                  uint8_t txid_out[32]) {
    cx_sha256_t sha;
    uint8_t tag_hash[32];
    uint8_t tagged_hash[32];

    /* tag_hash = SHA256("BIP0322-signed-message") */
    cx_sha256_init_no_throw(&sha);
    if (cx_hash_no_throw(&sha.header,
                         CX_LAST,
                         (const uint8_t *) BIP322_TAG,
                         sizeof(BIP322_TAG) - 1,
                         tag_hash,
                         sizeof(tag_hash)) != CX_OK) {
        return false;
    }

    /* tagged_hash = SHA256(tag_hash || tag_hash || message) */
    cx_sha256_init_no_throw(&sha);
    if (cx_hash_no_throw(&sha.header, 0, tag_hash, sizeof(tag_hash), NULL, 0) != CX_OK) {
        return false;
    }
    if (cx_hash_no_throw(&sha.header, 0, tag_hash, sizeof(tag_hash), NULL, 0) != CX_OK) {
        return false;
    }
    if (cx_hash_no_throw(&sha.header,
                         CX_LAST,
                         message,
                         (size_t) msg_len,
                         tagged_hash,
                         sizeof(tagged_hash)) != CX_OK) {
        return false;
    }

    /* Build to_spend (128 bytes). */
    uint8_t to_spend[128];
    int pos = 0;

    /* version = 0 */
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;

    /* vin_count = 1 */
    to_spend[pos++] = 0x01;

    /* input 0: txid = 00..00 */
    memset(to_spend + pos, 0x00, 32);
    pos += 32;

    /* input 0: vout = 0xFFFFFFFF */
    to_spend[pos++] = 0xFF;
    to_spend[pos++] = 0xFF;
    to_spend[pos++] = 0xFF;
    to_spend[pos++] = 0xFF;

    /* input 0: scriptSig length = 34 (0x22) */
    to_spend[pos++] = BIP322_SCRIPT_LEN_34;

    /* input 0: scriptSig = OP_0 PUSHBYTES_32 tagged_hash */
    to_spend[pos++] = BIP322_OP_0;
    to_spend[pos++] = BIP322_PUSHBYTES_32;
    memcpy(to_spend + pos, tagged_hash, 32);
    pos += 32;

    /* input 0: sequence = 0 */
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;

    /* vout_count = 1 */
    to_spend[pos++] = 0x01;

    /* output 0: value = 0 */
    memset(to_spend + pos, 0x00, 8);
    pos += 8;

    /* output 0: scriptPubKey length = 34 (0x22) */
    to_spend[pos++] = BIP322_SCRIPT_LEN_34;

    /* output 0: scriptPubKey = OP_1 PUSHBYTES_32 tweaked_key */
    to_spend[pos++] = BIP322_OP_1;
    to_spend[pos++] = BIP322_PUSHBYTES_32;
    memcpy(to_spend + pos, tweaked_key, 32);
    pos += 32;

    /* locktime = 0 */
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;
    to_spend[pos++] = 0x00;

    LEDGER_ASSERT(pos == 128, "to_spend size mismatch");

    /* SHA256d(to_spend) */
    uint8_t hash1[32];
    cx_sha256_init_no_throw(&sha);
    if (cx_hash_no_throw(&sha.header, CX_LAST, to_spend, (size_t) pos, hash1, sizeof(hash1)) !=
        CX_OK) {
        return false;
    }

    cx_sha256_init_no_throw(&sha);
    if (cx_hash_no_throw(&sha.header, CX_LAST, hash1, sizeof(hash1), txid_out, 32) != CX_OK) {
        return false;
    }

    return true;
}
