/**
 * Unit tests for vault_script.c — leaf script builders, taproot primitives,
 * scriptpubkey derivation, and PegIn txid computation.
 *
 * Tests verify byte-level structure of generated scripts against independently
 * computed expected values. See docs/babylon-vault/jira-issues.md NAPPS-1374
 * for script layout specifications.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include <cmocka.h>

#include "../../bitcoin_app_base/src/common/script.h"
#include "vault_script.h"
#include "vault_intent.h"
#include "cx.h"  /* mock SHA-256 / tagged-hash helpers for cross-validation tests */

/* ---------------------------------------------------------------------------
 * Test fixtures
 * ------------------------------------------------------------------------- */

/** 1-of-1 keeper / 1-of-1 challenger intent for structural tests. */
static vault_intent_t make_n1m1(void) {
    vault_intent_t intent;
    memset(&intent, 0, sizeof(intent));
    memset(intent.depositor_pk,      0x01, 32);
    memset(intent.vault_provider_pk, 0x02, 32);
    memset(intent.keeper_pks[0],     0x03, 32);
    memset(intent.challenger_pks[0], 0x04, 32);
    intent.keeper_count          = 1;
    intent.challenger_count      = 1;
    /* 144 = 0x90: high bit set → requires sign byte in Script push */
    intent.htlc_refund_timelock  = 144;
    intent.pegin_csv_timelock    = 144;
    /* 200 = 0xC8: high bit set → requires sign byte */
    intent.payout_timelock       = 200;
    intent.vault_amount          = 100000;
    intent.depositor_claim_value = 1000;
    return intent;
}

/** 2-of-2 keeper intent — exercises CHECKSIGADD path and VP-merge insertion. */
static vault_intent_t make_n2m1(void) {
    vault_intent_t intent = make_n1m1();
    /* VP = 0x04, VK0 = 0x03, VK1 = 0x05 — VP sorts between VK0 and VK1 */
    memset(intent.vault_provider_pk, 0x04, 32);
    memset(intent.keeper_pks[0],     0x03, 32);
    memset(intent.keeper_pks[1],     0x05, 32);
    intent.keeper_count = 2;
    return intent;
}

/* ---------------------------------------------------------------------------
 * vault_build_depositor_claim_leaf
 *
 * Expected: OP_PUSHBYTES_32 | depositor_pk[32] | OP_CHECKSIG = 34 bytes
 * ------------------------------------------------------------------------- */

static void test_depositor_claim_leaf_length(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[64];
    int len = vault_build_depositor_claim_leaf(&intent, buf, sizeof(buf));
    assert_int_equal(len, 34);
}

static void test_depositor_claim_leaf_bytes(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[64];
    vault_build_depositor_claim_leaf(&intent, buf, sizeof(buf));
    assert_int_equal(buf[0],  OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[1 + i], 0x01);
    assert_int_equal(buf[33], OP_CHECKSIG);
}

/* ---------------------------------------------------------------------------
 * vault_build_htlc_leaf1
 *
 * Expected: <D> OP_CHECKSIGVERIFY | <T_refund> OP_CSV
 * With T_refund=144 (0x90, high-bit set) → push = OP_PUSHBYTES_2 0x90 0x00
 * = 34 + 3 + 1 = 38 bytes
 * ------------------------------------------------------------------------- */

static void test_htlc_leaf1_length(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[64];
    int len = vault_build_htlc_leaf1(&intent, buf, sizeof(buf));
    assert_int_equal(len, 38);
}

static void test_htlc_leaf1_bytes(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[64];
    vault_build_htlc_leaf1(&intent, buf, sizeof(buf));
    assert_int_equal(buf[0],  OP_PUSHBYTES_32);  /* D */
    assert_int_equal(buf[33], OP_CHECKSIGVERIFY);
    assert_int_equal(buf[34], OP_PUSHBYTES_2);   /* sign-byte encoding of 144 */
    assert_int_equal(buf[35], 0x90);             /* 144 lo */
    assert_int_equal(buf[36], 0x00);             /* sign byte */
    assert_int_equal(buf[37], OP_CSV);
}

/* ---------------------------------------------------------------------------
 * vault_build_vault_utxo_leaf  (N=1, M=1)
 *
 * Expected: D(34) + VP(34) + VK1-of-1-interm(34) + UC1-of-1-interm(34)
 *           + push(144)(3) + OP_CSV(1) = 140 bytes
 * ------------------------------------------------------------------------- */

static void test_vault_utxo_leaf_n1m1_length(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    int len = vault_build_vault_utxo_leaf(&intent, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 140);
}

static void test_vault_utxo_leaf_n1m1_opcodes(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    vault_build_vault_utxo_leaf(&intent, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(buf[0],   OP_PUSHBYTES_32);   /* D push */
    assert_int_equal(buf[33],  OP_CHECKSIGVERIFY);
    assert_int_equal(buf[34],  OP_PUSHBYTES_32);   /* VP push */
    assert_int_equal(buf[67],  OP_CHECKSIGVERIFY);
    assert_int_equal(buf[68],  OP_PUSHBYTES_32);   /* VK push */
    assert_int_equal(buf[101], OP_CHECKSIGVERIFY); /* N=1 intermediate */
    assert_int_equal(buf[102], OP_PUSHBYTES_32);   /* UC push */
    assert_int_equal(buf[135], OP_CHECKSIGVERIFY); /* M=1 intermediate */
    assert_int_equal(buf[139], OP_CSV);
}

/* ---------------------------------------------------------------------------
 * vault_build_vault_utxo_leaf  (N=2 — exercises CHECKSIGADD path)
 *
 * VK group (2-of-2 intermediate):
 *   OP_PUSHBYTES_32 VK0 OP_CHECKSIG | OP_PUSHBYTES_32 VK1 OP_CHECKSIGADD
 *   | OP_2 | OP_NUMEQUALVERIFY = 34 + 34 + 1 + 1 = 70 bytes
 * UC group (1-of-1 intermediate): 34 bytes
 *
 * Total: D(34) + VP(34) + VK2-of-2(70) + UC1-of-1(34) + push+CSV(4) = 176
 * ------------------------------------------------------------------------- */

static void test_vault_utxo_leaf_n2_checksigadd(void **state) {
    (void)state;
    vault_intent_t intent = make_n2m1();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    int len = vault_build_vault_utxo_leaf(&intent, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 176);
    /* VK group starts at offset 68 */
    assert_int_equal(buf[68],  OP_PUSHBYTES_32);    /* VK0 push */
    assert_int_equal(buf[101], OP_CHECKSIG);        /* first of group */
    assert_int_equal(buf[102], OP_PUSHBYTES_32);    /* VK1 push */
    assert_int_equal(buf[135], OP_CHECKSIGADD);
    assert_int_equal(buf[136], OP_2);               /* N=2 threshold */
    assert_int_equal(buf[137], OP_NUMEQUALVERIFY);  /* intermediate */
}

/* ---------------------------------------------------------------------------
 * vault_build_htlc_leaf0  (N=1, M=1)
 *
 * Expected:
 *   OP_SIZE(1) + OP_PUSHBYTES_1 <32>(2) + OP_EQUALVERIFY(1) = 4 bytes @ off 0
 *   OP_SHA256(1) + OP_PUSHBYTES_32(1) + h(32) + OP_EQUALVERIFY(1) = 35 bytes @ off 4
 *   <D>(34)                             @ off 39
 *   <VP>(34)                            @ off 73
 *   VK 1-of-1 intermediate(34)          @ off 107
 *   UC 1-of-1 final(34)                 @ off 141
 *   Total = 175 bytes
 * ------------------------------------------------------------------------- */

static void test_htlc_leaf0_length(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t h[32];
    memset(h, 0xAA, 32);
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    int len = vault_build_htlc_leaf0(&intent, h, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 175);
}

static void test_htlc_leaf0_hashlock_bytes(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t h[32];
    memset(h, 0xAA, 32);
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    vault_build_htlc_leaf0(&intent, h, buf, VAULT_SCRIPT_MAX_LEN);
    /* hashlock preamble */
    assert_int_equal(buf[0],  OP_SIZE);
    assert_int_equal(buf[1],  OP_PUSHBYTES_1);
    assert_int_equal(buf[2],  32);               /* expected preimage length */
    assert_int_equal(buf[3],  OP_EQUALVERIFY);
    assert_int_equal(buf[4],  OP_SHA256);
    assert_int_equal(buf[5],  OP_PUSHBYTES_32);  /* push h[32] */
    for (int i = 0; i < 32; i++) assert_int_equal(buf[6 + i], 0xAA);
    assert_int_equal(buf[38], OP_EQUALVERIFY);
}

static void test_htlc_leaf0_party_opcodes(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t h[32];
    memset(h, 0xAA, 32);
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    vault_build_htlc_leaf0(&intent, h, buf, VAULT_SCRIPT_MAX_LEN);
    /* D at 39..72 */
    assert_int_equal(buf[39],  OP_PUSHBYTES_32);
    assert_int_equal(buf[72],  OP_CHECKSIGVERIFY);
    /* VP at 73..106 */
    assert_int_equal(buf[73],  OP_PUSHBYTES_32);
    assert_int_equal(buf[106], OP_CHECKSIGVERIFY);
    /* VK 1-of-1 intermediate at 107..140 */
    assert_int_equal(buf[107], OP_PUSHBYTES_32);
    assert_int_equal(buf[140], OP_CHECKSIGVERIFY);
    /* UC 1-of-1 final at 141..174 */
    assert_int_equal(buf[141], OP_PUSHBYTES_32);
    assert_int_equal(buf[174], OP_CHECKSIG);  /* final */
}

/* ---------------------------------------------------------------------------
 * vault_build_assert0_payout_leaf
 *
 * N=1 VP claimer (claimer_idx=0):
 *   AppChallengers = [VK0=0x03]
 *   <VP(34)> + <VK0 1-of-1 interm(34)> + <UC 1-of-1 interm(34)> + push(3)+CSV(1)
 *   = 106 bytes
 *
 * N=1 VK claimer (claimer_idx=1):
 *   AppChallengers = [VP=0x02]
 *   <VK0(34)> + <VP 1-of-1 interm(34)> + <UC 1-of-1 interm(34)> + push(3)+CSV(1)
 *   = 106 bytes
 * ------------------------------------------------------------------------- */

static void test_assert0_vp_claimer_bytes(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    int len = vault_build_assert0_payout_leaf(&intent, 0, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 106);
    assert_int_equal(buf[0],  OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[1 + i], 0x02); /* VP as claimer */
    assert_int_equal(buf[33], OP_CHECKSIGVERIFY);
    /* AppChallengers[0] = VK0 = 0x03 */
    assert_int_equal(buf[34], OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[35 + i], 0x03);
    assert_int_equal(buf[67], OP_CHECKSIGVERIFY);
}

static void test_assert0_vk_claimer_vp_inserted(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    int len = vault_build_assert0_payout_leaf(&intent, 1, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 106);
    /* Claimer is VK0 = 0x03 */
    assert_int_equal(buf[0], OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[1 + i], 0x03);
    assert_int_equal(buf[33], OP_CHECKSIGVERIFY);
    /* AppChallengers[0] = VP = 0x02 (only challenger with keeper_count=1) */
    assert_int_equal(buf[34], OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[35 + i], 0x02);
    assert_int_equal(buf[67], OP_CHECKSIGVERIFY);
}

/**
 * N=2 intent (VP=0x04, VK0=0x03, VK1=0x05):
 * claimer_idx=1 (VK0=0x03 is claimer) → AppChallengers = sorted[VP=0x04, VK1=0x05]
 * Verify VP is inserted at the correct sorted position (after VK1 would be wrong).
 */
static void test_assert0_vp_sorted_into_challengers(void **state) {
    (void)state;
    vault_intent_t intent = make_n2m1();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    vault_build_assert0_payout_leaf(&intent, 1, buf, VAULT_SCRIPT_MAX_LEN);
    /* Claimer = VK0 = 0x03 */
    for (int i = 0; i < 32; i++) assert_int_equal(buf[1 + i], 0x03);
    /* AppChallengers must be sorted: VP=0x04 before VK1=0x05 */
    assert_int_equal(buf[34], OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[35 + i], 0x04); /* VP first */
    assert_int_equal(buf[67], OP_CHECKSIG);  /* first key of 2-of-2 group */
    assert_int_equal(buf[68], OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[69 + i], 0x05); /* VK1 second */
    assert_int_equal(buf[101], OP_CHECKSIGADD);
}

/* ---------------------------------------------------------------------------
 * scriptpubkey builders — P2TR format: OP_1 OP_PUSHBYTES_32 <key>
 * ------------------------------------------------------------------------- */

static void test_all_scriptpubkeys_are_p2tr(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t h[32];
    memset(h, 0xBB, 32);
    uint8_t spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];

    assert_true(vault_build_htlc_scriptpubkey(&intent, h, spk));
    assert_int_equal(spk[0], OP_1);
    assert_int_equal(spk[1], OP_PUSHBYTES_32);

    assert_true(vault_build_vault_utxo_scriptpubkey(&intent, spk));
    assert_int_equal(spk[0], OP_1);
    assert_int_equal(spk[1], OP_PUSHBYTES_32);

    assert_true(vault_build_depositor_claim_scriptpubkey(&intent, spk));
    assert_int_equal(spk[0], OP_1);
    assert_int_equal(spk[1], OP_PUSHBYTES_32);

    assert_true(vault_build_assert0_payout_scriptpubkey(&intent, 0, spk));
    assert_int_equal(spk[0], OP_1);
    assert_int_equal(spk[1], OP_PUSHBYTES_32);
}

/** Different intents must produce different scriptpubkeys. */
static void test_scriptpubkeys_differ_across_intents(void **state) {
    (void)state;
    vault_intent_t i1 = make_n1m1();
    vault_intent_t i2 = make_n1m1();
    memset(i2.keeper_pks[0], 0xEE, 32); /* different keeper key */
    uint8_t spk1[VAULT_P2TR_SCRIPTPUBKEY_LEN], spk2[VAULT_P2TR_SCRIPTPUBKEY_LEN];

    assert_true(vault_build_vault_utxo_scriptpubkey(&i1, spk1));
    assert_true(vault_build_vault_utxo_scriptpubkey(&i2, spk2));
    assert_memory_not_equal(spk1, spk2, VAULT_P2TR_SCRIPTPUBKEY_LEN);
}

/** Same h → same HTLC scriptpubkey (deterministic). */
static void test_htlc_scriptpubkey_deterministic(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t h[32];
    memset(h, 0xCC, 32);
    uint8_t spk1[VAULT_P2TR_SCRIPTPUBKEY_LEN], spk2[VAULT_P2TR_SCRIPTPUBKEY_LEN];

    assert_true(vault_build_htlc_scriptpubkey(&intent, h, spk1));
    assert_true(vault_build_htlc_scriptpubkey(&intent, h, spk2));
    assert_memory_equal(spk1, spk2, VAULT_P2TR_SCRIPTPUBKEY_LEN);
}

/* ---------------------------------------------------------------------------
 * vault_compute_pegin_txid
 * ------------------------------------------------------------------------- */

static void test_pegin_txid_deterministic(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    memset(intent.prepegin_txid, 0xCC, 32);
    intent.htlc_vout = 2;

    uint8_t txid1[32], txid2[32];
    assert_true(vault_compute_pegin_txid(&intent, txid1));
    assert_true(vault_compute_pegin_txid(&intent, txid2));
    assert_memory_equal(txid1, txid2, 32);
}

static void test_pegin_txid_not_zero(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    memset(intent.prepegin_txid, 0xDD, 32);
    intent.htlc_vout = 0;

    uint8_t txid[32];
    assert_true(vault_compute_pegin_txid(&intent, txid));
    bool all_zero = true;
    for (int i = 0; i < 32; i++) if (txid[i]) { all_zero = false; break; }
    assert_false(all_zero);
}

/** Different pre-peg-in txid → different pegin txid. */
static void test_pegin_txid_varies_with_input(void **state) {
    (void)state;
    vault_intent_t i1 = make_n1m1();
    vault_intent_t i2 = make_n1m1();
    memset(i1.prepegin_txid, 0x11, 32);
    memset(i2.prepegin_txid, 0x22, 32);

    uint8_t txid1[32], txid2[32];
    assert_true(vault_compute_pegin_txid(&i1, txid1));
    assert_true(vault_compute_pegin_txid(&i2, txid2));
    assert_memory_not_equal(txid1, txid2, 32);
}

/* ---------------------------------------------------------------------------
 * vault_taproot_leaf_hash — smoke test: deterministic, non-zero, changes with script
 * ------------------------------------------------------------------------- */

static void test_leaf_hash_deterministic(void **state) {
    (void)state;
    uint8_t script[1] = {OP_CHECKSIG};
    uint8_t h1[32], h2[32];
    vault_taproot_leaf_hash(script, 1, h1);
    vault_taproot_leaf_hash(script, 1, h2);
    assert_memory_equal(h1, h2, 32);
}

static void test_leaf_hash_varies_with_script(void **state) {
    (void)state;
    uint8_t s1[1] = {OP_CHECKSIG};
    uint8_t s2[1] = {OP_CHECKSIGVERIFY};
    uint8_t h1[32], h2[32];
    vault_taproot_leaf_hash(s1, 1, h1);
    vault_taproot_leaf_hash(s2, 1, h2);
    assert_memory_not_equal(h1, h2, 32);
}

/* ---------------------------------------------------------------------------
 * Error-path tests — buffer too small / invalid arguments return -1
 * ------------------------------------------------------------------------- */

static void test_depositor_claim_leaf_buf_too_small(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[64];
    assert_int_equal(vault_build_depositor_claim_leaf(&intent, buf, 33), -1);
    assert_int_equal(vault_build_depositor_claim_leaf(&intent, buf, 34), 34); /* boundary: ok */
}

static void test_htlc_leaf1_buf_too_small(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[64];
    assert_int_equal(vault_build_htlc_leaf1(&intent, buf, 37), -1); /* too small */
    assert_int_equal(vault_build_htlc_leaf1(&intent, buf, 38), 38); /* exact fit */
}

static void test_vault_utxo_leaf_buf_too_small(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    assert_int_equal(vault_build_vault_utxo_leaf(&intent, buf, 33), -1);
}

static void test_htlc_leaf0_buf_too_small(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t h[32];
    memset(h, 0xAA, 32);
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    assert_int_equal(vault_build_htlc_leaf0(&intent, h, buf, 3), -1);
}

static void test_assert0_payout_leaf_claimer_out_of_range(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1(); /* keeper_count=1 */
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    assert_int_equal(vault_build_assert0_payout_leaf(&intent, -1, buf, VAULT_SCRIPT_MAX_LEN), -1);
    assert_int_equal(vault_build_assert0_payout_leaf(&intent,  2, buf, VAULT_SCRIPT_MAX_LEN), -1);
}

/* ---------------------------------------------------------------------------
 * vault_build_htlc_leaf0  N=2 keepers (CHECKSIGADD path)
 *
 * With make_n2m1(): D=0x01, VP=0x04, VK0=0x03, VK1=0x05, UC=0x04, h=0xAA*32
 *
 *   hashlock preamble:  4 bytes   (off   0)
 *   OP_SHA256 + h:     35 bytes   (off   4)
 *   D push+CSGV:       34 bytes   (off  39)
 *   VP push+CSGV:      34 bytes   (off  73)
 *   VK 2-of-2 interm:  70 bytes   (off 107)
 *     VK0 push+CHECKSIG(34) + VK1 push+CHECKSIGADD(34) + OP_2(1) + OP_NUMEQUALVERIFY(1)
 *   UC 1-of-1 final:   34 bytes   (off 177)
 *   Total: 211 bytes
 * ------------------------------------------------------------------------- */

static void test_htlc_leaf0_n2_length(void **state) {
    (void)state;
    vault_intent_t intent = make_n2m1();
    uint8_t h[32];
    memset(h, 0xAA, 32);
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    int len = vault_build_htlc_leaf0(&intent, h, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 211);
}

static void test_htlc_leaf0_n2_vk_group_opcodes(void **state) {
    (void)state;
    vault_intent_t intent = make_n2m1();
    uint8_t h[32];
    memset(h, 0xAA, 32);
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    vault_build_htlc_leaf0(&intent, h, buf, VAULT_SCRIPT_MAX_LEN);

    /* VK group starts at offset 107 */
    assert_int_equal(buf[107], OP_PUSHBYTES_32);   /* VK0 push */
    for (int i = 0; i < 32; i++) assert_int_equal(buf[108 + i], 0x03); /* VK0=0x03 */
    assert_int_equal(buf[140], OP_CHECKSIG);        /* first of CHECKSIGADD group */
    assert_int_equal(buf[141], OP_PUSHBYTES_32);   /* VK1 push */
    for (int i = 0; i < 32; i++) assert_int_equal(buf[142 + i], 0x05); /* VK1=0x05 */
    assert_int_equal(buf[174], OP_CHECKSIGADD);
    assert_int_equal(buf[175], OP_2);               /* N=2 threshold */
    assert_int_equal(buf[176], OP_NUMEQUALVERIFY);  /* intermediate */

    /* UC 1-of-1 final at offset 177 */
    assert_int_equal(buf[177], OP_PUSHBYTES_32);
    assert_int_equal(buf[210], OP_CHECKSIG);        /* final */
}

/* ---------------------------------------------------------------------------
 * vault_build_assert0_payout_leaf — claimer_idx = keeper_count (last VK)
 *
 * make_n2m1(): VP=0x04, VK0=0x03, VK1=0x05, UC=0x04, keeper_count=2
 * claimer_idx=2 → Claimer=VK1=0x05
 * AppChallengers = {VP=0x04, VK0=0x03} sorted = [VK0=0x03, VP=0x04]
 *   (VP=0x04 > VK0=0x03, so VP is appended after VK0)
 *
 * Script:
 *   Claimer(VK1=0x05) push+CSGV:          34 bytes
 *   AppChallengers 2-of-2 interm (sorted): 70 bytes
 *   UC 1-of-1 interm:                      34 bytes
 *   push(200)+CSV:                          4 bytes
 *   Total: 142 bytes
 * ------------------------------------------------------------------------- */

static void test_assert0_last_vk_claimer(void **state) {
    (void)state;
    vault_intent_t intent = make_n2m1();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    /* claimer_idx = keeper_count = 2 → VK1 (0x05) is the claimer */
    int len = vault_build_assert0_payout_leaf(&intent, 2, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 142);

    /* Claimer = VK1 = 0x05 */
    assert_int_equal(buf[0],  OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[1 + i], 0x05);
    assert_int_equal(buf[33], OP_CHECKSIGVERIFY);

    /* AppChallengers sorted: VK0=0x03 first (smaller), VP=0x04 second (larger) */
    assert_int_equal(buf[34], OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[35 + i], 0x03); /* VK0 first */
    assert_int_equal(buf[67], OP_CHECKSIG);    /* first of 2-of-2 group */
    assert_int_equal(buf[68], OP_PUSHBYTES_32);
    for (int i = 0; i < 32; i++) assert_int_equal(buf[69 + i], 0x04); /* VP second */
    assert_int_equal(buf[101], OP_CHECKSIGADD);
    assert_int_equal(buf[102], OP_2);
    assert_int_equal(buf[103], OP_NUMEQUALVERIFY);
}

/* ---------------------------------------------------------------------------
 * Cross-validation: vault_taproot_leaf_hash matches BIP-341 formula
 *
 * Independently computes tagged_hash("TapLeaf", 0xC0 || compact_size(len) || script)
 * using crypto_tr_tapleaf_hash_init + cx_hash_no_throw, then compares against
 * vault_taproot_leaf_hash.  Catches bugs in the version byte, varint encoding,
 * or argument order inside vault_taproot_leaf_hash.
 * ------------------------------------------------------------------------- */

static void test_leaf_hash_matches_bip341_formula(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    uint8_t script[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    int len = vault_build_depositor_claim_leaf(&intent, script, sizeof(script));
    assert_int_equal(len, 34);

    /* Reference: manually feed BIP-341 TapLeaf formula */
    cx_sha256_t ref_ctx;
    crypto_tr_tapleaf_hash_init(&ref_ctx);
    uint8_t ver = TAPSCRIPT_LEAF_VERSION;
    cx_hash_no_throw(&ref_ctx.header, 0, &ver, 1u, NULL, 0u);
    uint8_t vl  = (uint8_t) len;  /* compact_size(34) fits in one byte since 34 < 0xFD */
    cx_hash_no_throw(&ref_ctx.header, 0, &vl, 1u, NULL, 0u);
    cx_hash_no_throw(&ref_ctx.header, 0, script, (size_t) len, NULL, 0u);
    uint8_t expected[32];
    cx_hash_no_throw(&ref_ctx.header, (int) CX_LAST, NULL, 0u, expected, 32u);

    uint8_t actual[32];
    vault_taproot_leaf_hash(script, len, actual);
    assert_memory_equal(expected, actual, 32);
}

/* ---------------------------------------------------------------------------
 * Cross-validation: vault_compute_pegin_txid matches manual dSHA256
 *
 * Independently serializes the non-witness transaction and double-SHA256s it,
 * then compares against vault_compute_pegin_txid.  Verifies both the
 * serialization layout (version, input/output encoding, locktime) and the
 * hash computation.
 * ------------------------------------------------------------------------- */

static void test_pegin_txid_matches_manual_serialization(void **state) {
    (void)state;
    vault_intent_t intent = make_n1m1();
    memset(intent.prepegin_txid, 0xDD, 32);
    intent.htlc_vout = 1;

    /* Build both output scriptPubKeys the same way vault_compute_pegin_txid does */
    uint8_t vault_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN], claim_spk[VAULT_P2TR_SCRIPTPUBKEY_LEN];
    assert_true(vault_build_vault_utxo_scriptpubkey(&intent, vault_spk));
    assert_true(vault_build_depositor_claim_scriptpubkey(&intent, claim_spk));

    /* Manually assemble the 137-byte non-witness transaction */
    uint8_t tx[137];
    int off = 0;

    /* version: 2 LE */
    tx[off++] = 0x02u; tx[off++] = 0x00u; tx[off++] = 0x00u; tx[off++] = 0x00u;
    /* input count: 1 */
    tx[off++] = 0x01u;
    /* prevout txid (as stored in intent — LE) */
    memcpy(tx + off, intent.prepegin_txid, 32u); off += 32;
    /* prevout index (htlc_vout=1 LE) */
    for (int i = 0; i < 4; i++) tx[off++] = (uint8_t)(intent.htlc_vout >> (i * 8));
    /* scriptSig: empty */
    tx[off++] = 0x00u;
    /* sequence: 0xFFFFFFFE LE */
    tx[off++] = 0xFEu; tx[off++] = 0xFFu; tx[off++] = 0xFFu; tx[off++] = 0xFFu;
    /* output count: 2 */
    tx[off++] = 0x02u;
    /* output 0: Vault UTXO */
    for (int i = 0; i < 8; i++) tx[off++] = (uint8_t)(intent.vault_amount >> (i * 8));
    tx[off++] = (uint8_t) VAULT_P2TR_SCRIPTPUBKEY_LEN;
    memcpy(tx + off, vault_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN); off += VAULT_P2TR_SCRIPTPUBKEY_LEN;
    /* output 1: Depositor Claim */
    for (int i = 0; i < 8; i++) tx[off++] = (uint8_t)(intent.depositor_claim_value >> (i * 8));
    tx[off++] = (uint8_t) VAULT_P2TR_SCRIPTPUBKEY_LEN;
    memcpy(tx + off, claim_spk, VAULT_P2TR_SCRIPTPUBKEY_LEN); off += VAULT_P2TR_SCRIPTPUBKEY_LEN;
    /* locktime: 0 */
    tx[off++] = 0x00u; tx[off++] = 0x00u; tx[off++] = 0x00u; tx[off++] = 0x00u;

    assert_int_equal(off, 137);

    /* double-SHA256 */
    cx_sha256_t ctx;
    uint8_t mid[32], expected[32];
    cx_sha256_init(&ctx);
    cx_hash_no_throw(&ctx.header, 0, tx, 137u, NULL, 0u);
    cx_hash_no_throw(&ctx.header, (int) CX_LAST, NULL, 0u, mid, 32u);
    cx_sha256_init(&ctx);
    cx_hash_no_throw(&ctx.header, 0, mid, 32u, NULL, 0u);
    cx_hash_no_throw(&ctx.header, (int) CX_LAST, NULL, 0u, expected, 32u);

    uint8_t actual[32];
    assert_true(vault_compute_pegin_txid(&intent, actual));
    assert_memory_equal(expected, actual, 32);
}

/* ===========================================================================
 * Real-world cross-validation: Vault A on Bitcoin signet
 *
 * Golden values sourced from on-chain transactions:
 *   Pre-PegIn: 553ecee5883d5fb619c61525762937ac94c5f7a31ff66738a70dbdef29c16aa6
 *   PegIn:     41bd883be7f787bbbfc24ebd4c33a3e73b7d050f6cc887f66ef64e7024a9e7f7
 *
 * htlc_refund_timelock and pegin_csv_timelock (both 432 blocks) were recovered
 * by computing BIP-341 leaf hashes for candidate values until they matched the
 * sibling hash in the PegIn control block and the Vault UTXO output key.
 * =========================================================================== */

/* Keys and parameters extracted from the PegIn witness (HTLC Leaf 0 script). */
static const uint8_t s_depositor_pk[32] = {
    0x16,0x5b,0x9e,0x30,0x78,0x6a,0x84,0x7a,0xe5,0xa5,0x1c,0xb8,0xee,0x0b,0x01,0x0a,
    0xe3,0x7e,0x76,0x69,0xfb,0xfe,0x87,0x63,0x86,0x6d,0x28,0xda,0x25,0xf2,0xe2,0x03,
};
static const uint8_t s_vault_provider_pk[32] = {
    0xcf,0xcc,0xb2,0xf0,0x55,0x81,0x75,0x06,0xfd,0x17,0xd6,0x04,0x1b,0x10,0x13,0x48,
    0x36,0x4c,0xe2,0xa4,0xd1,0x06,0xf8,0xc6,0x24,0x56,0xec,0x0a,0x56,0x5e,0x49,0x5d,
};
static const uint8_t s_keeper_pk0[32] = {
    0x9b,0x03,0xef,0xc0,0xa4,0x94,0xb2,0x9e,0x2a,0xd5,0x63,0x1a,0xc1,0x5e,0xc3,0x2c,
    0x84,0xc3,0xa5,0x29,0x5a,0x64,0x76,0x0c,0x3b,0x2e,0xc9,0xc0,0x14,0x1c,0x77,0xc7,
};
static const uint8_t s_keeper_pk1[32] = {
    0xcf,0x68,0x28,0xd0,0x99,0x11,0x2c,0x3f,0xf8,0x7d,0x43,0x93,0xe5,0xc2,0x22,0x54,
    0x0f,0x6f,0x5c,0xec,0x30,0xbe,0x8e,0xa0,0x73,0xfc,0x78,0x29,0xdd,0x16,0x1e,0xd8,
};
static const uint8_t s_keeper_pk2[32] = {
    0xda,0xae,0x4c,0x44,0x65,0xea,0x84,0x92,0x1a,0x41,0x0c,0x3a,0x18,0x5b,0xd0,0x03,
    0xcd,0xef,0x91,0x02,0xc7,0xf4,0x76,0x07,0x46,0x41,0x39,0x22,0xcb,0x47,0x82,0x41,
};
static const uint8_t s_challenger_pk0[32] = {
    0x1d,0x40,0x36,0x7b,0xb1,0xa1,0xf6,0x4e,0x0c,0x7b,0x3a,0xbb,0x3a,0x3b,0x8a,0x88,
    0xfa,0x8f,0x34,0xc2,0x4f,0xe2,0x55,0xd0,0x43,0xb3,0xab,0xae,0xd0,0x4a,0xda,0xca,
};
static const uint8_t s_challenger_pk1[32] = {
    0xed,0x94,0xe1,0x1d,0x6a,0x9f,0x04,0x48,0x20,0x09,0xe1,0x6e,0x30,0xd1,0xb9,0x32,
    0x6f,0x05,0x22,0x12,0xf5,0xf0,0xda,0xe6,0xb2,0xc1,0x91,0xe1,0x5b,0xe6,0xe5,0xc4,
};
static const uint8_t s_challenger_pk2[32] = {
    0xf4,0xb5,0x42,0xac,0x5a,0xac,0x10,0xb6,0xea,0xd6,0xbc,0x00,0xa5,0xff,0xa0,0xd1,
    0x62,0xab,0xbe,0xda,0x4c,0x48,0x5e,0xe5,0x0d,0x6a,0x77,0xd7,0xe8,0x3c,0x93,0x00,
};
static const uint8_t s_hashlock[32] = {
    0xfb,0xf0,0xba,0xcf,0x7b,0x72,0x36,0xeb,0xfd,0x83,0x94,0x56,0x26,0x72,0x29,0x83,
    0xd9,0x3a,0x51,0xed,0x77,0x26,0x0f,0xbc,0x97,0xcc,0x44,0x68,0x44,0x93,0xf7,0x80,
};
/* prepegin_txid in raw LE byte order (byte-reversed from display TXID) */
static const uint8_t s_prepegin_txid_raw[32] = {
    0xa6,0x6a,0xc1,0x29,0xef,0xbd,0x0d,0xa7,0x38,0x67,0xf6,0x1f,0xa3,0xf7,0xc5,0x94,
    0xac,0x37,0x29,0x76,0x25,0x15,0xc6,0x19,0xb6,0x5f,0x3d,0x88,0xe5,0xce,0x3e,0x55,
};

/* Golden outputs verified against on-chain data.
 * NOTE: scriptpubkey and pegin_txid golden vectors require real secp256k1 EC
 * math which the unit-test mock replaces with SHA-256(pubkey || h).  Those
 * checks are covered structurally by test_all_scriptpubkeys_are_p2tr /
 * test_scriptpubkeys_differ_across_intents, and end-to-end by Ragger tests. */
static const uint8_t s_expected_htlc_leaf0[315] = {
    0x82,0x01,0x20,0x88,0xa8,0x20,0xfb,0xf0,0xba,0xcf,0x7b,0x72,0x36,0xeb,0xfd,0x83,
    0x94,0x56,0x26,0x72,0x29,0x83,0xd9,0x3a,0x51,0xed,0x77,0x26,0x0f,0xbc,0x97,0xcc,
    0x44,0x68,0x44,0x93,0xf7,0x80,0x88,0x20,0x16,0x5b,0x9e,0x30,0x78,0x6a,0x84,0x7a,
    0xe5,0xa5,0x1c,0xb8,0xee,0x0b,0x01,0x0a,0xe3,0x7e,0x76,0x69,0xfb,0xfe,0x87,0x63,
    0x86,0x6d,0x28,0xda,0x25,0xf2,0xe2,0x03,0xad,0x20,0xcf,0xcc,0xb2,0xf0,0x55,0x81,
    0x75,0x06,0xfd,0x17,0xd6,0x04,0x1b,0x10,0x13,0x48,0x36,0x4c,0xe2,0xa4,0xd1,0x06,
    0xf8,0xc6,0x24,0x56,0xec,0x0a,0x56,0x5e,0x49,0x5d,0xad,0x20,0x9b,0x03,0xef,0xc0,
    0xa4,0x94,0xb2,0x9e,0x2a,0xd5,0x63,0x1a,0xc1,0x5e,0xc3,0x2c,0x84,0xc3,0xa5,0x29,
    0x5a,0x64,0x76,0x0c,0x3b,0x2e,0xc9,0xc0,0x14,0x1c,0x77,0xc7,0xac,0x20,0xcf,0x68,
    0x28,0xd0,0x99,0x11,0x2c,0x3f,0xf8,0x7d,0x43,0x93,0xe5,0xc2,0x22,0x54,0x0f,0x6f,
    0x5c,0xec,0x30,0xbe,0x8e,0xa0,0x73,0xfc,0x78,0x29,0xdd,0x16,0x1e,0xd8,0xba,0x20,
    0xda,0xae,0x4c,0x44,0x65,0xea,0x84,0x92,0x1a,0x41,0x0c,0x3a,0x18,0x5b,0xd0,0x03,
    0xcd,0xef,0x91,0x02,0xc7,0xf4,0x76,0x07,0x46,0x41,0x39,0x22,0xcb,0x47,0x82,0x41,
    0xba,0x53,0x9d,0x20,0x1d,0x40,0x36,0x7b,0xb1,0xa1,0xf6,0x4e,0x0c,0x7b,0x3a,0xbb,
    0x3a,0x3b,0x8a,0x88,0xfa,0x8f,0x34,0xc2,0x4f,0xe2,0x55,0xd0,0x43,0xb3,0xab,0xae,
    0xd0,0x4a,0xda,0xca,0xac,0x20,0xed,0x94,0xe1,0x1d,0x6a,0x9f,0x04,0x48,0x20,0x09,
    0xe1,0x6e,0x30,0xd1,0xb9,0x32,0x6f,0x05,0x22,0x12,0xf5,0xf0,0xda,0xe6,0xb2,0xc1,
    0x91,0xe1,0x5b,0xe6,0xe5,0xc4,0xba,0x20,0xf4,0xb5,0x42,0xac,0x5a,0xac,0x10,0xb6,
    0xea,0xd6,0xbc,0x00,0xa5,0xff,0xa0,0xd1,0x62,0xab,0xbe,0xda,0x4c,0x48,0x5e,0xe5,
    0x0d,0x6a,0x77,0xd7,0xe8,0x3c,0x93,0x00,0xba,0x53,0x9c,
};
/* HTLC Leaf 1 (38B): <D> OP_CHECKSIGVERIFY 432 OP_CSV
 * depositor_pk + htlc_refund_timelock=432 (0x01b0, 2-byte sign-extended push) */
static const uint8_t s_expected_htlc_leaf1[38] = {
    0x20,0x16,0x5b,0x9e,0x30,0x78,0x6a,0x84,0x7a,0xe5,0xa5,0x1c,0xb8,0xee,0x0b,0x01,
    0x0a,0xe3,0x7e,0x76,0x69,0xfb,0xfe,0x87,0x63,0x86,0x6d,0x28,0xda,0x25,0xf2,0xe2,
    0x03,0xad,0x02,0xb0,0x01,0xb2,
};
/* BIP-341 TapLeaf hash of Leaf 0 (315B) — verified by Python reference impl. */
static const uint8_t s_expected_leaf0_hash[32] = {
    0x96,0x74,0x04,0xff,0xb8,0x03,0x35,0xe2,0x5a,0xd4,0x44,0x5c,0x3a,0x52,0xc5,0x05,
    0x52,0xd0,0x26,0x4a,0xf8,0x05,0x06,0x3a,0xff,0x10,0xac,0x83,0xa1,0x23,0xed,0xab,
};
/* BIP-341 TapLeaf hash of Leaf 1 (38B) — equals the sibling hash in the PegIn
 * control block (0cef2a5b…), confirming both the leaf script and hash formula. */
static const uint8_t s_expected_leaf1_hash[32] = {
    0x0c,0xef,0x2a,0x5b,0x6f,0x5d,0xed,0xc2,0x60,0xc2,0xd9,0x47,0x60,0xf1,0xa0,0x9c,
    0xdf,0xd8,0xd2,0x6c,0x0d,0x03,0xeb,0x41,0x62,0x1f,0x48,0x9a,0xe9,0xd8,0x21,0x70,
};

static vault_intent_t make_vault_a(void) {
    vault_intent_t intent;
    memset(&intent, 0, sizeof(intent));
    memcpy(intent.depositor_pk,      s_depositor_pk,      32);
    memcpy(intent.vault_provider_pk, s_vault_provider_pk, 32);
    memcpy(intent.keeper_pks[0],     s_keeper_pk0,        32);
    memcpy(intent.keeper_pks[1],     s_keeper_pk1,        32);
    memcpy(intent.keeper_pks[2],     s_keeper_pk2,        32);
    memcpy(intent.challenger_pks[0], s_challenger_pk0,    32);
    memcpy(intent.challenger_pks[1], s_challenger_pk1,    32);
    memcpy(intent.challenger_pks[2], s_challenger_pk2,    32);
    intent.keeper_count          = 3;
    intent.challenger_count      = 3;
    intent.htlc_refund_timelock  = 432;
    intent.pegin_csv_timelock    = 432;
    intent.vault_amount          = 1000000u;
    intent.depositor_claim_value = 26228u;
    memcpy(intent.prepegin_txid, s_prepegin_txid_raw, 32);
    intent.htlc_vout = 0;
    return intent;
}

/* ---------------------------------------------------------------------------
 * vault_build_htlc_leaf0 — real-world golden vector
 *
 * vault_build_htlc_leaf0 with Vault A parameters must reproduce the exact
 * 315-byte HTLC Leaf 0 script observed in the PegIn transaction witness.
 * ------------------------------------------------------------------------- */

static void test_htlc_leaf0_real_world_vault_a(void **state) {
    (void)state;
    vault_intent_t intent = make_vault_a();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    int len = vault_build_htlc_leaf0(&intent, s_hashlock, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 315);
    assert_memory_equal(buf, s_expected_htlc_leaf0, 315);
}

/* ---------------------------------------------------------------------------
 * vault_build_htlc_leaf1 — real-world golden vector
 *
 * vault_build_htlc_leaf1 with depositor_pk and htlc_refund_timelock=432 must
 * produce the exact 38-byte refund leaf.  432 (0x01b0) requires a 2-byte
 * sign-extended Script push.  The timelock was recovered by searching for the
 * value whose BIP-341 TapLeaf hash matches the sibling hash in the PegIn
 * control block.
 * ------------------------------------------------------------------------- */

static void test_htlc_leaf1_real_world_vault_a(void **state) {
    (void)state;
    vault_intent_t intent = make_vault_a();
    uint8_t buf[64];
    int len = vault_build_htlc_leaf1(&intent, buf, sizeof(buf));
    assert_int_equal(len, 38);
    assert_memory_equal(buf, s_expected_htlc_leaf1, 38);
}

/* ---------------------------------------------------------------------------
 * vault_taproot_leaf_hash — real-world golden vectors for Leaf 0 and Leaf 1
 *
 * Leaf 0 hash must match the value computed independently by the Python
 * reference implementation.  Leaf 1 hash must equal the sibling hash seen in
 * the PegIn control block (0cef2a5b…), confirming both the leaf script bytes
 * and the BIP-341 TapLeaf hash formula.
 * ------------------------------------------------------------------------- */

static void test_htlc_leaf0_hash_real_world_vault_a(void **state) {
    (void)state;
    vault_intent_t intent = make_vault_a();
    uint8_t buf[VAULT_SCRIPT_MAX_LEN];
    int len = vault_build_htlc_leaf0(&intent, s_hashlock, buf, VAULT_SCRIPT_MAX_LEN);
    assert_int_equal(len, 315);
    uint8_t hash[VAULT_HASH256_LEN];
    vault_taproot_leaf_hash(buf, len, hash);
    assert_memory_equal(hash, s_expected_leaf0_hash, VAULT_HASH256_LEN);
}

static void test_htlc_leaf1_hash_real_world_vault_a(void **state) {
    (void)state;
    vault_intent_t intent = make_vault_a();
    uint8_t buf[64];
    int len = vault_build_htlc_leaf1(&intent, buf, sizeof(buf));
    assert_int_equal(len, 38);
    uint8_t hash[VAULT_HASH256_LEN];
    vault_taproot_leaf_hash(buf, len, hash);
    /* Must equal the sibling hash extracted from the on-chain PegIn control block. */
    assert_memory_equal(hash, s_expected_leaf1_hash, VAULT_HASH256_LEN);
}

/* ---------------------------------------------------------------------------
 * Test registration
 * ------------------------------------------------------------------------- */

int main(void) {
    const struct CMUnitTest tests[] = {
        /* depositor_claim_leaf */
        cmocka_unit_test(test_depositor_claim_leaf_length),
        cmocka_unit_test(test_depositor_claim_leaf_bytes),
        /* htlc_leaf1 */
        cmocka_unit_test(test_htlc_leaf1_length),
        cmocka_unit_test(test_htlc_leaf1_bytes),
        /* vault_utxo_leaf */
        cmocka_unit_test(test_vault_utxo_leaf_n1m1_length),
        cmocka_unit_test(test_vault_utxo_leaf_n1m1_opcodes),
        cmocka_unit_test(test_vault_utxo_leaf_n2_checksigadd),
        /* htlc_leaf0 */
        cmocka_unit_test(test_htlc_leaf0_length),
        cmocka_unit_test(test_htlc_leaf0_hashlock_bytes),
        cmocka_unit_test(test_htlc_leaf0_party_opcodes),
        /* assert0_payout_leaf */
        cmocka_unit_test(test_assert0_vp_claimer_bytes),
        cmocka_unit_test(test_assert0_vk_claimer_vp_inserted),
        cmocka_unit_test(test_assert0_vp_sorted_into_challengers),
        /* scriptpubkeys */
        cmocka_unit_test(test_all_scriptpubkeys_are_p2tr),
        cmocka_unit_test(test_scriptpubkeys_differ_across_intents),
        cmocka_unit_test(test_htlc_scriptpubkey_deterministic),
        /* pegin txid */
        cmocka_unit_test(test_pegin_txid_deterministic),
        cmocka_unit_test(test_pegin_txid_not_zero),
        cmocka_unit_test(test_pegin_txid_varies_with_input),
        /* taproot leaf hash */
        cmocka_unit_test(test_leaf_hash_deterministic),
        cmocka_unit_test(test_leaf_hash_varies_with_script),
        /* error paths */
        cmocka_unit_test(test_depositor_claim_leaf_buf_too_small),
        cmocka_unit_test(test_htlc_leaf1_buf_too_small),
        cmocka_unit_test(test_vault_utxo_leaf_buf_too_small),
        cmocka_unit_test(test_htlc_leaf0_buf_too_small),
        cmocka_unit_test(test_assert0_payout_leaf_claimer_out_of_range),
        /* htlc_leaf0 N=2 */
        cmocka_unit_test(test_htlc_leaf0_n2_length),
        cmocka_unit_test(test_htlc_leaf0_n2_vk_group_opcodes),
        /* assert0_payout_leaf claimer_idx = keeper_count */
        cmocka_unit_test(test_assert0_last_vk_claimer),
        /* cross-validation: golden-vector checks */
        cmocka_unit_test(test_leaf_hash_matches_bip341_formula),
        cmocka_unit_test(test_pegin_txid_matches_manual_serialization),
        /* real-world: Vault A on Bitcoin signet */
        cmocka_unit_test(test_htlc_leaf0_real_world_vault_a),
        cmocka_unit_test(test_htlc_leaf1_real_world_vault_a),
        cmocka_unit_test(test_htlc_leaf0_hash_real_world_vault_a),
        cmocka_unit_test(test_htlc_leaf1_hash_real_world_vault_a),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
