#pragma once

/* Minimal mock of bitcoin_app_base/src/common/script.h for unit tests.
 * Contains only the opcode enum — no Ledger SDK dependencies. */

enum opcodetype {
    OP_0 = 0x00,
    OP_FALSE = OP_0,
    OP_1 = 0x51,
    OP_TRUE = OP_1,
    OP_2 = 0x52,
    OP_SIZE = 0x82,
    OP_EQUAL = 0x87,
    OP_EQUALVERIFY = 0x88,
    OP_NUMEQUAL = 0x9c,
    OP_NUMEQUALVERIFY = 0x9d,
    OP_SHA256 = 0xa8,
    OP_CHECKSIG = 0xac,
    OP_CHECKSIGVERIFY = 0xad,
    OP_CHECKSEQUENCEVERIFY = 0xb2,
    OP_CSV = OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIGADD = 0xba,
};
