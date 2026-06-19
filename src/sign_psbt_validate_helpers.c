#include "sign_psbt_validate_helpers.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/* read_u32_le comes from ledger-secure-sdk/lib_standard_app/read.h (device build)
 * or unit-tests/mocks/read.h (test build). */
#include "read.h"

/* BIP44_COIN_TYPE is provided as a compile-time -D flag in both builds. */

#ifndef BIP32_FIRST_HARDENED_CHILD
#define BIP32_FIRST_HARDENED_CHILD 0x80000000u
#endif

/* BIP-86 path shape */
#define BIP86_PATH_LEN            5
#define BIP86_PURPOSE             86u
#define BIP86_MAX_ACCOUNT         100u
#define BIP86_MAX_ADDRESS_INDEX   10000u

/* BIP-32 derivation record layout */
#define BIP32_PATH_STEP_SIZE      4   /* bytes per path component (uint32_t LE) */
#define BIP32_FINGERPRINT_SIZE    4   /* bytes for the key fingerprint (uint32_t BE) */

/* CScriptNum encoding */
#define SCRIPT_NUM_MAX_LEN        4   /* max bytes in a minimal-push CScriptNum */
#define SCRIPT_NUM_SIGN_BIT       0x80u

/* Refund leaf script minimum length:
 * OP_PUSHBYTES_32 (1) + xonly key (32) + OP_CHECKSIGVERIFY (1) + push (1) + OP_CSV (1) */
#define REFUND_SCRIPT_MIN_LEN (1 + VAULT_XONLY_PUBKEY_LEN + 1 + 1 + 1)

bool check_bip86_path(const uint32_t *path, int path_len) {
    /* Exactly 5 levels: m/86'/coin_type'/account'/change/index */
    if (path_len != BIP86_PATH_LEN) return false;
    /* m/86' */
    if (path[0] != (BIP86_PURPOSE | BIP32_FIRST_HARDENED_CHILD)) return false;
    /* coin_type' */
    if (path[1] != ((uint32_t) BIP44_COIN_TYPE | BIP32_FIRST_HARDENED_CHILD)) return false;
    /* account' (hardened, <= 100) */
    if ((path[2] & BIP32_FIRST_HARDENED_CHILD) == 0) return false;
    if ((path[2] & ~BIP32_FIRST_HARDENED_CHILD) > BIP86_MAX_ACCOUNT) return false;
    /* change: 0 or 1 */
    if (path[3] > 1u) return false;
    /* address_index <= 10000 */
    if (path[4] > BIP86_MAX_ADDRESS_INDEX) return false;
    return true;
}

int parse_tap_bip32_deriv_value(const uint8_t *val,
                                int val_len,
                                uint32_t *fingerprint_out,
                                uint32_t *path_out,
                                int max_path_steps) {
    if (val_len < 1) return -1;
    int n_hashes = (int) val[0];
    int offset = 1 + n_hashes * VAULT_HASH256_LEN;
    if (offset + BIP32_FINGERPRINT_SIZE > val_len) return -1;

    *fingerprint_out = read_u32_be(val, offset);
    offset += BIP32_FINGERPRINT_SIZE;

    int remaining = val_len - offset;
    if (remaining % BIP32_PATH_STEP_SIZE != 0) return -1;
    int n_steps = remaining / BIP32_PATH_STEP_SIZE;
    if (n_steps > max_path_steps) return -1;

    for (int i = 0; i < n_steps; i++) {
        path_out[i] = read_u32_le(val, offset + i * BIP32_PATH_STEP_SIZE);
    }
    return n_steps;
}

bool parse_refund_leaf_script(const uint8_t *script,
                              int script_len,
                              uint8_t leaf_key_out[VAULT_XONLY_PUBKEY_LEN],
                              uint32_t *csv_value_out) {
    /* Minimum: OP_PUSHBYTES_32 (1) + key (32) + OP_CHECKSIGVERIFY (1)
     *        + push opcode for CSV (1) + OP_CSV (1) = 36 bytes.
     * OP_1..OP_16 encodes the value in the opcode itself with no extra data
     * bytes, so REFUND_SCRIPT_MIN_LEN is the true minimum. */
    if (script_len < REFUND_SCRIPT_MIN_LEN) return false;

    int pos = 0;

    /* OP_PUSHBYTES_32 */
    if (script[pos++] != OP_PUSHBYTES_32) return false;

    /* 32-byte x-only key */
    memcpy(leaf_key_out, script + pos, VAULT_XONLY_PUBKEY_LEN);
    pos += VAULT_XONLY_PUBKEY_LEN;

    /* OP_CHECKSIGVERIFY */
    if (script[pos++] != OP_CHECKSIGVERIFY) return false;

    /* Minimal push of the CSV value — any positive minimal-push encoding is OK */
    if (pos >= script_len) return false;
    uint8_t push_op = script[pos++];

    uint32_t csv = 0;

    if (push_op == OP_0) {
        return false; /* OP_0 not valid for a positive CSV */
    } else if (push_op >= OP_PUSHBYTES_1 && push_op <= OP_PUSHBYTES_75) {
        /* OP_PUSHBYTES_1..OP_PUSHBYTES_75: next push_op bytes are CScriptNum LE */
        int data_len = (int) push_op;
        if (data_len > SCRIPT_NUM_MAX_LEN || pos + data_len > script_len) return false;
        /* Decode CScriptNum: LE bytes, sign bit in MSB of last byte */
        if (script[pos + data_len - 1] & SCRIPT_NUM_SIGN_BIT) return false; /* negative → invalid */
        for (int i = 0; i < data_len; i++) {
            csv |= (uint32_t) script[pos + i] << (8 * i);
        }
        pos += data_len;
    } else if (push_op == OP_PUSHDATA1) {
        /* OP_PUSHDATA1: next byte is length, then CScriptNum LE data */
        if (pos >= script_len) return false;
        int data_len = (int) script[pos++];
        if (data_len > SCRIPT_NUM_MAX_LEN || pos + data_len > script_len) return false;
        if (script[pos + data_len - 1] & SCRIPT_NUM_SIGN_BIT) return false; /* negative */
        for (int i = 0; i < data_len; i++) {
            csv |= (uint32_t) script[pos + i] << (8 * i);
        }
        pos += data_len;
    } else if (push_op >= OP_1 && push_op <= OP_16) {
        /* OP_1..OP_16: value encoded in the opcode, no extra bytes */
        csv = (uint32_t) (push_op - OP_RESERVED);
    } else if (push_op == OP_1NEGATE) {
        return false; /* OP_1NEGATE — not valid for a positive timelock */
    } else {
        return false;
    }

    if (csv == 0) return false; /* zero timelock makes no sense */

    /* OP_CHECKSEQUENCEVERIFY (0xB2) */
    if (pos >= script_len) return false;
    if (script[pos++] != OP_CHECKSEQUENCEVERIFY) return false;

    /* Must have consumed exactly the script */
    if (pos != script_len) return false;

    *csv_value_out = csv;
    return true;
}
