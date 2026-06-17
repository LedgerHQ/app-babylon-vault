#include "sign_psbt_validate_helpers.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * Opcodes come from bitcoin_app_base/src/common/script.h (device build)
 * or unit-tests/mocks/common/script.h (test build), both resolved as
 * "common/script.h" via the include-path ordering in each environment.
 */
#include "common/script.h"

/*
 * read_u32_le comes from ledger-secure-sdk/lib_standard_app/read.h (device build)
 * or unit-tests/mocks/read.h (test build).
 */
#include "read.h"

/* BIP44_COIN_TYPE is provided as a compile-time -D flag in both builds. */

#ifndef OP_PUSHBYTES_32
#define OP_PUSHBYTES_32 0x20u
#endif

bool check_bip86_path(const uint32_t *path, int path_len) {
    /* Exactly 5 levels: m/86'/coin_type'/account'/change/index */
    if (path_len != 5) return false;
    /* m/86' */
    if (path[0] != (86u | 0x80000000u)) return false;
    /* coin_type' */
    if (path[1] != ((uint32_t) BIP44_COIN_TYPE | 0x80000000u)) return false;
    /* account' (hardened, <= 100) */
    if ((path[2] & 0x80000000u) == 0) return false;
    if ((path[2] & ~0x80000000u) > 100u) return false;
    /* change: 0 or 1 */
    if (path[3] > 1u) return false;
    /* address_index <= 10000 */
    if (path[4] > 10000u) return false;
    return true;
}

int parse_tap_bip32_deriv_value(const uint8_t *val,
                                int val_len,
                                uint32_t *fingerprint_out,
                                uint32_t *path_out,
                                int max_path_steps) {
    if (val_len < 1) return -1;
    int n_hashes = (int) val[0];
    int offset = 1 + n_hashes * 32;
    if (offset + 4 > val_len) return -1;

    *fingerprint_out = read_u32_be(val, offset);
    offset += 4;

    int remaining = val_len - offset;
    if (remaining % 4 != 0) return -1;
    int n_steps = remaining / 4;
    if (n_steps > max_path_steps) return -1;

    for (int i = 0; i < n_steps; i++) {
        path_out[i] = read_u32_le(val, offset + i * 4);
    }
    return n_steps;
}

bool parse_refund_leaf_script(const uint8_t *script,
                              int script_len,
                              uint8_t leaf_key_out[VAULT_XONLY_PUBKEY_LEN]) {
    /* Minimum: 1 (OP_PUSHBYTES_32) + 32 (key) + 1 (OP_CHECKSIGVERIFY)
     *        + 1 (push opcode for CSV) + 1 (OP_CSV)
     * = 36 bytes. OP_1..OP_16 encodes the value in the opcode itself with no
     * extra data bytes, so 36 is the true minimum. */
    if (script_len < 36) return false;

    int pos = 0;

    /* OP_PUSHBYTES_32 */
    if (script[pos++] != OP_PUSHBYTES_32) return false;

    /* 32-byte x-only key */
    memcpy(leaf_key_out, script + pos, VAULT_XONLY_PUBKEY_LEN);
    pos += VAULT_XONLY_PUBKEY_LEN;

    /* OP_CHECKSIGVERIFY (0xAD) */
    if (script[pos++] != OP_CHECKSIGVERIFY) return false;

    /* Minimal push of the CSV value — any positive minimal-push encoding is OK */
    if (pos >= script_len) return false;
    uint8_t push_op = script[pos++];
    if (push_op == 0x00) return false; /* OP_0 not valid for a positive CSV */
    if (push_op >= 0x01 && push_op <= 0x4b) {
        /* OP_PUSHBYTES_1..OP_PUSHBYTES_75: next push_op bytes are the data */
        pos += push_op;
    } else if (push_op == 0x4c) {
        /* OP_PUSHDATA1: next byte is length, then data */
        if (pos >= script_len) return false;
        pos += (int) script[pos] + 1;
    } else if (push_op >= 0x51 && push_op <= 0x60) {
        /* OP_1..OP_16: value encoded in the opcode, no extra bytes */
    } else if (push_op == 0x4f) {
        /* OP_1NEGATE — not valid for a positive timelock */
        return false;
    } else {
        return false;
    }

    /* OP_CHECKSEQUENCEVERIFY (0xB2) */
    if (pos >= script_len) return false;
    if (script[pos++] != OP_CHECKSEQUENCEVERIFY) return false;

    /* Must have consumed exactly the script */
    return pos == script_len;
}
