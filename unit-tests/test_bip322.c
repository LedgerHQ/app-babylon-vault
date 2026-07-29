/**
 * Unit tests for src/bip322.c:
 *   - bip322_parse_pop_message
 *   - bip322_compute_to_spend_txid
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <cmocka.h>

#include "bip322.h"

/* -------------------------------------------------------------------------
 * bip322_parse_pop_message
 * ---------------------------------------------------------------------- */

static void test_parse_happy_path(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:1:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_true(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
    assert_string_equal(eth_addr, "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    assert_string_equal(chain_id, "1");
    assert_string_equal(registry, "0xcafecafecafecafecafecafecafecafecafecafe");
}

static void test_parse_chain_id_zero(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:0:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_true(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
    assert_string_equal(chain_id, "0");
}

static void test_parse_chain_id_max_length(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    /* 20-digit chain_id fills BIP322_CHAIN_ID_STR_LEN - 1 exactly */
    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:12345678901234567890:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_true(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
    assert_string_equal(chain_id, "12345678901234567890");
}

static void test_parse_too_few_colons(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:1:pegin";

    assert_false(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
}

static void test_parse_eth_addr_wrong_length(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    /* ETH address is 41 chars instead of 42 */
    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbee:1:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_false(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
}

static void test_parse_eth_addr_uppercase(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    static const uint8_t msg[] =
        "0xDEADBEEFDEADBEEFDEADBEEFDEADBEEFDEADBEEF:1:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_false(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
}

static void test_parse_chain_id_leading_zero(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:01:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_false(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
}

static void test_parse_chain_id_non_decimal(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:1a:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_false(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
}

static void test_parse_chain_id_too_long(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    /* 21-digit chain_id exceeds BIP322_CHAIN_ID_STR_LEN - 1 */
    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:123456789012345678901:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_false(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
}

static void test_parse_wrong_literal(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:1:pegout:"
        "0xcafecafecafecafecafecafecafecafecafecafe";

    assert_false(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
}

static void test_parse_registry_wrong_length(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    /* registry is 43 chars instead of 42 */
    static const uint8_t msg[] =
        "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:1:pegin:"
        "0xcafecafecafecafecafecafecafecafecafecafef";

    assert_false(bip322_parse_pop_message(msg, sizeof(msg) - 1, eth_addr, chain_id, registry));
}

/* -------------------------------------------------------------------------
 * bip322_compute_to_spend_txid — known reference vector
 *
 * Computed with Python (hashlib) from the BIP-322 spec:
 *   message     = "0xdeadbeef...beef:1:pegin:0xcafecafe...cafe"  (93 bytes)
 *   tweaked_key = 0x01 0x02 ... 0x20
 *   txid        = 6f156a5a d5782f6b 34c0ea44 c897fe84
 *                 a2dbad26 ce7a063c 2d336c4b 9ee86ddc
 * ---------------------------------------------------------------------- */

static const uint8_t VECTOR_MSG[] =
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:1:pegin:"
    "0xcafecafecafecafecafecafecafecafecafecafe";

static const uint8_t VECTOR_TWEAKED_KEY[32] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
};

static const uint8_t VECTOR_TXID[32] = {
    0x6f, 0x15, 0x6a, 0x5a, 0xd5, 0x78, 0x2f, 0x6b,
    0x34, 0xc0, 0xea, 0x44, 0xc8, 0x97, 0xfe, 0x84,
    0xa2, 0xdb, 0xad, 0x26, 0xce, 0x7a, 0x06, 0x3c,
    0x2d, 0x33, 0x6c, 0x4b, 0x9e, 0xe8, 0x6d, 0xdc,
};

static void test_compute_txid_known_vector(void **state) {
    (void) state;
    uint8_t txid[32];
    assert_true(bip322_compute_to_spend_txid(VECTOR_MSG,
                                              sizeof(VECTOR_MSG) - 1,
                                              VECTOR_TWEAKED_KEY,
                                              txid));
    assert_memory_equal(txid, VECTOR_TXID, 32);
}

/* -------------------------------------------------------------------------
 * bip322_compute_to_spend_txid — Babylon canonical vector
 *
 * Provided by the Babylon team; sourced from vault
 * d93596e78999e88e93a328ab44f176834e1e2ff797cffd176ecca37e024b322d on signet.
 *   message     = "0xcabdce2a2010a9a88c75506a86dba669716d47fa:11155111:pegin:
 *                  0xb331467c4db13dccc77fa66c2d185b74ed57ab80"  (100 bytes)
 *   tweaked_key = 3ba1d14c 8716be79 30aebf51 cd0866ac
 *                 56af9b85 078df5fc 31756a09 4ba55c6f
 *   txid        = 9c12fc24 51c22053 afab00c6 b2e56c62
 *                 495c9fda 61942eca 124ee79b fe4f4ce5
 * ---------------------------------------------------------------------- */

static const uint8_t BABYLON_MSG[] =
    "0xcabdce2a2010a9a88c75506a86dba669716d47fa:11155111:pegin:"
    "0xb331467c4db13dccc77fa66c2d185b74ed57ab80";

static const uint8_t BABYLON_TWEAKED_KEY[32] = {
    0x3b, 0xa1, 0xd1, 0x4c, 0x87, 0x16, 0xbe, 0x79,
    0x30, 0xae, 0xbf, 0x51, 0xcd, 0x08, 0x66, 0xac,
    0x56, 0xaf, 0x9b, 0x85, 0x07, 0x8d, 0xf5, 0xfc,
    0x31, 0x75, 0x6a, 0x09, 0x4b, 0xa5, 0x5c, 0x6f,
};

static const uint8_t BABYLON_TXID[32] = {
    0x9c, 0x12, 0xfc, 0x24, 0x51, 0xc2, 0x20, 0x53,
    0xaf, 0xab, 0x00, 0xc6, 0xb2, 0xe5, 0x6c, 0x62,
    0x49, 0x5c, 0x9f, 0xda, 0x61, 0x94, 0x2e, 0xca,
    0x12, 0x4e, 0xe7, 0x9b, 0xfe, 0x4f, 0x4c, 0xe5,
};

static void test_parse_babylon_canonical_message(void **state) {
    (void) state;
    char eth_addr[BIP322_ETH_ADDR_STR_LEN];
    char chain_id[BIP322_CHAIN_ID_STR_LEN];
    char registry[BIP322_ETH_ADDR_STR_LEN];

    assert_true(bip322_parse_pop_message(BABYLON_MSG, sizeof(BABYLON_MSG) - 1,
                                         eth_addr, chain_id, registry));
    assert_string_equal(eth_addr, "0xcabdce2a2010a9a88c75506a86dba669716d47fa");
    assert_string_equal(chain_id, "11155111");
    assert_string_equal(registry, "0xb331467c4db13dccc77fa66c2d185b74ed57ab80");
}

static void test_compute_txid_babylon_canonical(void **state) {
    (void) state;
    uint8_t txid[32];
    assert_true(bip322_compute_to_spend_txid(BABYLON_MSG,
                                              sizeof(BABYLON_MSG) - 1,
                                              BABYLON_TWEAKED_KEY,
                                              txid));
    assert_memory_equal(txid, BABYLON_TXID, 32);
}

/* -------------------------------------------------------------------------
 * main
 * ---------------------------------------------------------------------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_parse_happy_path),
        cmocka_unit_test(test_parse_chain_id_zero),
        cmocka_unit_test(test_parse_chain_id_max_length),
        cmocka_unit_test(test_parse_too_few_colons),
        cmocka_unit_test(test_parse_eth_addr_wrong_length),
        cmocka_unit_test(test_parse_eth_addr_uppercase),
        cmocka_unit_test(test_parse_chain_id_leading_zero),
        cmocka_unit_test(test_parse_chain_id_non_decimal),
        cmocka_unit_test(test_parse_chain_id_too_long),
        cmocka_unit_test(test_parse_wrong_literal),
        cmocka_unit_test(test_parse_registry_wrong_length),
        cmocka_unit_test(test_compute_txid_known_vector),
        cmocka_unit_test(test_parse_babylon_canonical_message),
        cmocka_unit_test(test_compute_txid_babylon_canonical),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
