#include "display.h"

#include <stdio.h>
#include <string.h>

#include "../bitcoin_app_base/src/ui/display.h"
#include "../bitcoin_app_base/src/ui/menu.h"
#include "bip322.h"
#include "globals.h"
#include "io_ext.h"
#include "ledger_assert.h"
#include "nbgl_use_case.h"

static void review_choice(bool approved) {
    set_ux_flow_response(approved);
    nbgl_useCaseReviewStatus(
        approved ? STATUS_TYPE_TRANSACTION_SIGNED : STATUS_TYPE_TRANSACTION_REJECTED,
        ui_menu_main);
}

#define MAX_N_PAIRS 6

_Static_assert(MAX_N_PAIRS == TX_DISPLAY_MAX_PAIRS,
               "TX_DISPLAY_MAX_PAIRS out of sync with MAX_N_PAIRS");
_Static_assert(TX_DISPLAY_AMOUNT_STR_SIZE >= MAX_AMOUNT_LENGTH + 1,
               "TX_DISPLAY_AMOUNT_STR_SIZE too small; update globals.h");
_Static_assert(TX_DISPLAY_ADDR_STR_SIZE >= MAX_ADDRESS_LENGTH_STR + 1,
               "TX_DISPLAY_ADDR_STR_SIZE too small; update globals.h");
_Static_assert(TX_DISPLAY_TXID_STR_SIZE >= 2 * 32 + 1,
               "TX_DISPLAY_TXID_STR_SIZE too small for 32-byte hex txid; update globals.h");
_Static_assert(TX_DISPLAY_ADDR_STR_SIZE >= 2 * VAULT_HASH256_LEN + 1,
               "TX_DISPLAY_ADDR_STR_SIZE too small for hex txid reuse in Claim/Assert display");
/* NBGL stores all pair pointers before rendering; VAULT_KEY_PAIR_SLOTS must cover the
 * maximum pairs laid out per page on any supported device (currently 4 on Flex/Stax/Apex).
 * Verify this assumption against the SDK when updating to a new device target. */
_Static_assert(VAULT_KEY_PAIR_SLOTS >= 4,
               "VAULT_KEY_PAIR_SLOTS too small; verify NBGL per-page pair limit before reducing");
_Static_assert(TX_DISPLAY_ADDR_STR_SIZE >= BIP322_ETH_ADDR_STR_LEN,
               "TX_DISPLAY_ADDR_STR_SIZE too small for Ethereum address");
_Static_assert(TX_DISPLAY_AMOUNT_STR_SIZE >= BIP322_CHAIN_ID_STR_LEN,
               "TX_DISPLAY_AMOUNT_STR_SIZE too small for chain ID");
_Static_assert(TX_DISPLAY_TXID_STR_SIZE >= BIP322_ETH_ADDR_STR_LEN,
               "TX_DISPLAY_TXID_STR_SIZE too small for registry address");

// ---------------------------------------------------------------------------
// Screen 1 — DERIVE_CONTEXT_HASH approval
// ---------------------------------------------------------------------------

// Separate rejection callback so TYPE_OPERATION reviews show STATUS_TYPE_OPERATION_REJECTED
// rather than STATUS_TYPE_TRANSACTION_REJECTED (which review_choice emits).
static void derive_context_hash_choice(bool approved) {
    set_ux_flow_response(approved);
    nbgl_useCaseReviewStatus(
        approved ? STATUS_TYPE_OPERATION_SIGNED : STATUS_TYPE_OPERATION_REJECTED,
        ui_menu_main);
}

bool display_derive_context_hash(dispatcher_context_t *dc,
                                 const uint8_t *app_name,
                                 uint8_t app_name_len) {
    // app_name_len <= 64, addr_str is 80 bytes — safe.
    char *const name_str = G_scratch.display_tx.addr_str;
    memcpy(name_str, app_name, app_name_len);
    name_str[app_name_len] = '\0';

    // Screen 1 shows app_name only (spec §2.1: wallet MUST display appName).
    nbgl_layoutTagValue_t *const pairs = (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    pairs[0] = (nbgl_layoutTagValue_t) {.item = "App name", .value = name_str};

    nbgl_layoutTagValueList_t pair_list = {
        .nbMaxLinesForValue = 0,
        .nbPairs = 1,
        .pairs = pairs,
    };

    nbgl_useCaseReview(TYPE_OPERATION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Derive context hash",
                       NULL,
                       "Allow derivation?",
                       derive_context_hash_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Screen 3 — Refund transaction
// ---------------------------------------------------------------------------

bool display_refund_transaction(dispatcher_context_t *dc,
                                uint64_t amount_reclaimed,
                                uint64_t fee,
                                uint32_t timelock_blocks,
                                const uint8_t *prepegin_txid,
                                const char *refund_address) {
    nbgl_layoutTagValue_t *const tx_pairs =
        (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list = {0};

    format_hex(prepegin_txid, 32, G_scratch.display_tx.txid_str, TX_DISPLAY_TXID_STR_SIZE);
    format_sats_amount(COIN_COINID_SHORT, amount_reclaimed, G_scratch.display_tx.amount_str);
    snprintf(G_scratch.display_tx.extra_str,
             TX_DISPLAY_AMOUNT_STR_SIZE,
             "%lu blocks",
             (unsigned long) timelock_blocks);
    format_sats_amount(COIN_COINID_SHORT, fee, G_scratch.display_tx.fee_str);

    int n = 0;
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Pre-PegIn txid", .value = G_scratch.display_tx.txid_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Reclaimed amount",
                                             .value = G_scratch.display_tx.amount_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Refund timelock",
                                             .value = G_scratch.display_tx.extra_str};
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Transaction fee", .value = G_scratch.display_tx.fee_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Reclaim address", .value = refund_address};

    LEDGER_ASSERT(n <= MAX_N_PAIRS, "Too many pairs");

    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = n;
    pair_list.pairs = tx_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Review refund\ntransaction",
                       NULL,
                       "Sign refund\ntransaction?",
                       review_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Screen 4 — Claim transaction
// ---------------------------------------------------------------------------

bool display_claim_transaction(dispatcher_context_t *dc,
                               uint64_t amount_spent,
                               uint64_t connector_amount,
                               uint64_t fee,
                               const uint8_t *pegin_txid,
                               const char *out0_address) {
    nbgl_layoutTagValue_t *const tx_pairs =
        (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list = {0};

    format_sats_amount(COIN_COINID_SHORT, amount_spent, G_scratch.display_tx.amount_str);
    format_sats_amount(COIN_COINID_SHORT, connector_amount, G_scratch.display_tx.extra_str);
    format_sats_amount(COIN_COINID_SHORT, fee, G_scratch.display_tx.fee_str);
    /* txid_str (65 B): 32-byte txid as 64 hex chars + NUL; addr_str is free for out0_address. */
    format_hex(pegin_txid, 32, G_scratch.display_tx.txid_str, TX_DISPLAY_TXID_STR_SIZE);

    int n = 0;
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Amount spent", .value = G_scratch.display_tx.amount_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Connector amount",
                                             .value = G_scratch.display_tx.extra_str};
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Transaction fee", .value = G_scratch.display_tx.fee_str};
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "PegIn txid", .value = G_scratch.display_tx.txid_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Output 0 address", .value = out0_address};

    LEDGER_ASSERT(n <= MAX_N_PAIRS, "Too many pairs");

    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = n;
    pair_list.pairs = tx_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Review Claim\ntransaction",
                       NULL,
                       "Sign Claim\ntransaction?",
                       review_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Screen 5 — Assert transaction
// ---------------------------------------------------------------------------

bool display_assert_transaction(dispatcher_context_t *dc,
                                const uint8_t *claim_txid,
                                uint64_t amount_carried,
                                uint64_t fee) {
    nbgl_layoutTagValue_t *const tx_pairs =
        (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list = {0};

    /* addr_str (80 B) holds 64-char hex txid + NUL. */
    format_hex(claim_txid, 32, G_scratch.display_tx.addr_str, TX_DISPLAY_ADDR_STR_SIZE);
    format_sats_amount(COIN_COINID_SHORT, amount_carried, G_scratch.display_tx.amount_str);
    format_sats_amount(COIN_COINID_SHORT, fee, G_scratch.display_tx.fee_str);

    int n = 0;
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Claim txid", .value = G_scratch.display_tx.addr_str};
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Amount", .value = G_scratch.display_tx.amount_str};
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Transaction fee", .value = G_scratch.display_tx.fee_str};

    LEDGER_ASSERT(n <= MAX_N_PAIRS, "Too many pairs");

    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = n;
    pair_list.pairs = tx_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Review Assert\ntransaction",
                       NULL,
                       "Sign Assert\ntransaction?",
                       review_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Screen 6 — Wrongly Challenged (WC) transaction
// ---------------------------------------------------------------------------

bool display_wc_transaction(dispatcher_context_t *dc,
                            uint64_t amount_reclaimed,
                            uint64_t wallet_inputs_amount,
                            uint64_t fee,
                            const char *wc_address) {
    nbgl_layoutTagValue_t *const tx_pairs =
        (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list = {0};

    format_sats_amount(COIN_COINID_SHORT, amount_reclaimed, G_scratch.display_tx.amount_str);
    format_sats_amount(COIN_COINID_SHORT, fee, G_scratch.display_tx.fee_str);

    int n = 0;
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Reclaimed amount",
                                             .value = G_scratch.display_tx.amount_str};
    if (wallet_inputs_amount > 0) {
        format_sats_amount(COIN_COINID_SHORT, wallet_inputs_amount, G_scratch.display_tx.extra_str);
        tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Wallet inputs",
                                                 .value = G_scratch.display_tx.extra_str};
    }
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Transaction fee", .value = G_scratch.display_tx.fee_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Reclaim address", .value = wc_address};

    LEDGER_ASSERT(n <= MAX_N_PAIRS, "Too many pairs");

    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = n;
    pair_list.pairs = tx_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Review wrongly\nchallenged tx",
                       NULL,
                       "Sign wrongly\nchallenged tx?",
                       review_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Screen 7 — PoP (Register ETH address)
// ---------------------------------------------------------------------------

bool display_pop_transaction(dispatcher_context_t *dc,
                             const char *eth_addr,
                             const char *chain_id,
                             const char *registry,
                             const char *btc_address) {
    nbgl_layoutTagValue_t *const tx_pairs =
        (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list = {0};

    // addr_str (80 B): ETH address (42 chars + NUL fits within 80 B)
    strlcpy(G_scratch.display_tx.addr_str, eth_addr, TX_DISPLAY_ADDR_STR_SIZE);
    // extra_str (TX_DISPLAY_AMOUNT_STR_SIZE B): chain ID (≤20 decimal digits + NUL)
    strlcpy(G_scratch.display_tx.extra_str, chain_id, TX_DISPLAY_AMOUNT_STR_SIZE);
    // txid_str (65 B): registry address (42 chars + NUL fits within 65 B)
    strlcpy(G_scratch.display_tx.txid_str, registry, TX_DISPLAY_TXID_STR_SIZE);
    /* btc_addr_buf lives on this function's stack frame, which remains active while
     * io_ui_process blocks below — NBGL pointer stays valid throughout rendering. */
    char btc_addr_buf[TX_DISPLAY_ADDR_STR_SIZE];
    strlcpy(btc_addr_buf, btc_address, sizeof(btc_addr_buf));

    int n = 0;
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Ethereum address",
                                             .value = G_scratch.display_tx.addr_str};
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Chain id", .value = G_scratch.display_tx.extra_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Registry address",
                                             .value = G_scratch.display_tx.txid_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Bitcoin address", .value = btc_addr_buf};

    LEDGER_ASSERT(n <= MAX_N_PAIRS, "Too many pairs");

    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = n;
    pair_list.pairs = tx_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Register ETH\naddress",
                       NULL,
                       "Register ETH\naddress?",
                       review_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Screen 8 — Payout finalize
// ---------------------------------------------------------------------------

bool display_payout_finalize(dispatcher_context_t *dc,
                             uint64_t amount_received,
                             const char *address,
                             const char *cpfp_address,
                             uint64_t fee,
                             const char *vault_prevout_txid) {
    nbgl_layoutTagValue_t *const tx_pairs =
        (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list = {0};

    format_sats_amount(COIN_COINID_SHORT, amount_received, G_scratch.display_tx.amount_str);
    format_sats_amount(COIN_COINID_SHORT, fee, G_scratch.display_tx.fee_str);

    // The fee pair is unconditional: a suppressed row is indistinguishable from a
    // zero fee, and the user must never approve a payout with no fee shown.
    int n = 0;
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Vault UTXO txid", .value = vault_prevout_txid};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Amount received",
                                             .value = G_scratch.display_tx.amount_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Destination", .value = address};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "CPFP address", .value = cpfp_address};
    tx_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Transaction fee", .value = G_scratch.display_tx.fee_str};

    LEDGER_ASSERT(n <= MAX_N_PAIRS, "Too many pairs");

    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = n;
    pair_list.pairs = tx_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Review payout\nfinalization",
                       NULL,
                       "Sign payout\nfinalization?",
                       review_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Vault intent approval screen
// ---------------------------------------------------------------------------

#define VAULT_INTENT_MAX_PAIRS VAULT_SCALAR_PAIRS_MAX

_Static_assert(sizeof(nbgl_layoutTagValue_t) == VAULT_DISPLAY_PAIR_SIZE,
               "nbgl_layoutTagValue_t size changed; update VAULT_DISPLAY_PAIR_SIZE in globals.h");

// "4294967295 sat/vB\0" — TLV parser rejects base_fee_rate > UINT32_MAX, so cast is safe
#define VAULT_FEE_RATE_STR_SIZE 20
// "1008 blocks (~7 days)\0" + headroom
#define VAULT_TIMELOCK_STR_SIZE 32

// 1 block ≈ 10 minutes. Examples: "100 blocks (~17 h)", "1008 blocks (~7 days)"
static void format_timelock_blocks(uint16_t blocks, char *buf, size_t len) {
    uint32_t minutes = (uint32_t) blocks * 10u;
    if (minutes < 60u) {
        snprintf(buf, len, "%u blocks (~%u min)", blocks, (unsigned) minutes);
    } else if (minutes < 1440u) {
        snprintf(buf, len, "%u blocks (~%u h)", blocks, (unsigned) (minutes / 60u));
    } else {
        snprintf(buf, len, "%u blocks (~%u days)", blocks, (unsigned) (minutes / 1440u));
    }
}

#ifdef SCREEN_SIZE_WALLET
#define VAULT_INTENT_REVIEW_TITLE "Review vault intent\nto approve vault\nparameters"
#define VAULT_INTENT_FINISH_TITLE "Approve vault\nintent?"
#define VAULT_VP_KEY_LABEL        "Vault provider key"
#else
#define VAULT_INTENT_REVIEW_TITLE "Review vault intent"
#define VAULT_INTENT_FINISH_TITLE "Approve intent?"
#define VAULT_VP_KEY_LABEL        "Provider key"
#endif

// ---- Streaming review state machine ----
//
// The vault intent is reviewed in two streaming phases:
//
//   Phase 1: intro → [params segment] → confirm
//   Phase 2: intro → [vault groups] → [keys segment] → approve/reject
//
// Neither phase is skippable.  Every field shown here is a displayed-and-approved
// field in the HLD's intent TLV table, and this approval is the only anchor for the
// silent signing that follows it (Pre-PegIn signs with no further screen), so no part
// of it may be bypassed.  The two-phase split remains because the NBGL SDK's
// SKIPPABLE_OPERATION flag applies to every segment of a streaming review equally:
// keeping the phases separate means a future decision to make one of them skippable
// does not silently make the other skippable too.  On nano there is no skip affordance
// in any case (a non-NULL skipCallback would interleave a skip page after every screen).
//
// All intent data is already in G_vault_intent, so the whole chain is driven from
// the choice/skip callbacks within a single io_ui_process() pump in
// display_vault_intent; only the final approve/reject sets the UX flow response.
//
// Single-flow invariant: display_vault_intent blocks on io_ui_process for the whole
// review, so these file-scope lists are safe (no re-entrancy).
static nbgl_layoutTagValueList_t g_vault_params_list;
static nbgl_layoutTagValueList_t g_vault_keys_list;
// Per-vault group streaming state for multi-vault (vault_count > 1).
// File-scope so these buffers survive across NBGL callback frames inside io_ui_process.
// Safe to reuse per segment: streaming review never navigates back to a confirmed segment.
static uint8_t g_stream_vault_idx;
static nbgl_layoutTagValueList_t g_vault_grp_list;
static nbgl_layoutTagValue_t g_vault_grp_pairs[6];
static char g_grp_vault_label[16]; /* "10 of 10\0" */
static char g_grp_vp_str[VAULT_HEX_KEY_STR_SIZE];
static char g_grp_amt_str[TX_DISPLAY_AMOUNT_STR_SIZE];
static char g_grp_comm_str[TX_DISPLAY_AMOUNT_STR_SIZE];
static char g_grp_claim_str[TX_DISPLAY_AMOUNT_STR_SIZE];
static char g_grp_fee_str[TX_DISPLAY_AMOUNT_STR_SIZE];

static void vault_stream_keys(void);
static void vault_stream_finish(void);
static void vault_stream_group(void);

static void vault_stream_reject(void) {
    set_ux_flow_response(false);
    nbgl_useCaseReviewStatus(STATUS_TYPE_OPERATION_REJECTED, ui_menu_main);
}

static void vault_stream_final_choice(bool approved) {
    set_ux_flow_response(approved);
    nbgl_useCaseReviewStatus(
        approved ? STATUS_TYPE_OPERATION_SIGNED : STATUS_TYPE_OPERATION_REJECTED,
        ui_menu_main);
}

// After the keys segment has been paged through: go to the approval page.
static void vault_stream_finish(void) {
    nbgl_useCaseReviewStreamingFinish(VAULT_INTENT_FINISH_TITLE, vault_stream_final_choice);
}

static void vault_after_keys(bool confirm) {
    if (!confirm) {
        vault_stream_reject();
        return;
    }
    vault_stream_finish();
}

// After all vault groups are confirmed: show the keys segment.
static void vault_stream_keys(void) {
    /* No skip callback: the keeper/challenger key list is the participant set the whole
     * intent rests on, and must be reviewed in full. */
    nbgl_useCaseReviewStreamingContinueExt(&g_vault_keys_list, vault_after_keys, NULL);
}

static void vault_after_group(bool confirm) {
    if (!confirm) {
        vault_stream_reject();
        return;
    }
    vault_stream_group();
}

// Streams vault groups one segment at a time, reusing static string buffers.
// Calls vault_stream_keys() once all vault_count groups have been confirmed.
static void vault_stream_group(void) {
    if (g_stream_vault_idx >= G_vault_intent.vault_count) {
        vault_stream_keys();
        return;
    }
    uint8_t i = g_stream_vault_idx++;
    const vault_group_t *grp = &G_vault_intent.groups[i];

    snprintf(g_grp_vault_label,
             sizeof(g_grp_vault_label),
             "%u of %u",
             (unsigned) (i + 1u),
             (unsigned) G_vault_intent.vault_count);
    format_hex(grp->vault_provider_pk, VAULT_XONLY_PUBKEY_LEN, g_grp_vp_str, sizeof(g_grp_vp_str));
    format_sats_amount(COIN_COINID_SHORT, grp->vault_amount, g_grp_amt_str);
    format_sats_amount(COIN_COINID_SHORT, grp->commission_fee, g_grp_comm_str);
    format_sats_amount(COIN_COINID_SHORT, grp->depositor_claim_value, g_grp_claim_str);
    format_sats_amount(COIN_COINID_SHORT, grp->pegin_max_fee, g_grp_fee_str);

    g_vault_grp_pairs[0] = (nbgl_layoutTagValue_t) {.item = "Vault", .value = g_grp_vault_label};
    g_vault_grp_pairs[1] =
        (nbgl_layoutTagValue_t) {.item = VAULT_VP_KEY_LABEL, .value = g_grp_vp_str};
    g_vault_grp_pairs[2] = (nbgl_layoutTagValue_t) {.item = "Vault amount", .value = g_grp_amt_str};
    g_vault_grp_pairs[3] =
        (nbgl_layoutTagValue_t) {.item = "Max commission fee", .value = g_grp_comm_str};
    g_vault_grp_pairs[4] =
        (nbgl_layoutTagValue_t) {.item = "Depositor claim", .value = g_grp_claim_str};
    g_vault_grp_pairs[5] =
        (nbgl_layoutTagValue_t) {.item = "Max PegIn fee", .value = g_grp_fee_str};

    g_vault_grp_list.pairs = g_vault_grp_pairs;
    g_vault_grp_list.nbPairs = 6;
    g_vault_grp_list.nbMaxLinesForValue = 0;

    /* No skip callback: each group's vault amount, commission fee, depositor claim and
     * PegIn fee are all displayed-and-approved fields (S-01 / Govard #5 / D7). */
    nbgl_useCaseReviewStreamingContinueExt(&g_vault_grp_list, vault_after_group, NULL);
}

#ifdef SCREEN_SIZE_WALLET
// Entry point for phase 2 (touch only): the skippable streaming review for vault
// groups and keys.  Called when the phase 2 intro "Continue" is pressed.
static void vault_stream_vaults_start(bool confirm) {
    if (!confirm) {
        vault_stream_reject();
        return;
    }
    vault_stream_group();
}
#endif

// After the params segment is confirmed: on touch, start a new skippable streaming
// review for vault groups and keys (phase 2).  On nano, continue the existing
// streaming review directly.
static void vault_after_params(bool confirm) {
    if (!confirm) {
        vault_stream_reject();
        return;
    }
    g_stream_vault_idx = 0;
#ifdef SCREEN_SIZE_WALLET
    /* Deliberately NOT SKIPPABLE_OPERATION.  Every field in this review is marked as
     * displayed-and-approved by the HLD's intent TLV table, and this approval is the sole
     * anchor for subsequent *silent* signing (Pre-PegIn signs with no further screen), so
     * nothing here may be bypassed.  NBGL arms Skip for a whole streaming review and
     * excludes per-page narrowing for STREAMING_NAV, so the flag cannot be limited to the
     * vault-group segments while keeping the keeper/challenger key list mandatory. */
    nbgl_useCaseReviewStreamingStart(TYPE_OPERATION,
                                     &ICON_APP_ACTION,
                                     VAULT_INTENT_REVIEW_TITLE,
                                     NULL,
                                     vault_stream_vaults_start);
#else
    vault_stream_group();
#endif
}

// After the phase 1 intro: start the params segment.  No skip callback — params
// are always reviewed in full before vault group details are shown.
static void vault_stream_intro_choice(bool confirm) {
    if (!confirm) {
        vault_stream_reject();
        return;
    }
    nbgl_useCaseReviewStreamingContinueExt(&g_vault_params_list, vault_after_params, NULL);
}

// Called by NBGL lazily for each key pair it needs to render.
// NBGL stores pair->item and pair->value as raw pointers across all pairs on a page
// before rendering any of them, so each pairIndex must write into a distinct buffer
// slot.  The slot is pairIndex % VAULT_KEY_PAIR_SLOTS; 4 slots covers the maximum
// number of pairs NBGL lays out per page on any supported device.
// G_vault_intent is immutable while io_ui_process blocks, so pk indexing is safe.
static nbgl_contentTagValue_t *_vault_key_pair_callback(uint8_t pairIndex) {
    const vault_intent_t *intent = &G_vault_intent;
    LEDGER_ASSERT(pairIndex < (uint8_t) (intent->keeper_count + intent->challenger_count),
                  "pairIndex out of range");
    const uint8_t *pk;
    uint8_t slot = pairIndex % VAULT_KEY_PAIR_SLOTS;
    if (pairIndex < intent->keeper_count) {
        pk = intent->keeper_pks[pairIndex];
        snprintf(G_scratch.display.key_label[slot],
                 sizeof(G_scratch.display.key_label[slot]),
                 "Keeper %u",
                 (unsigned) (pairIndex + 1u));
    } else {
        uint8_t ci = pairIndex - intent->keeper_count;
        pk = intent->challenger_pks[ci];
        snprintf(G_scratch.display.key_label[slot],
                 sizeof(G_scratch.display.key_label[slot]),
                 "Challenger %u",
                 (unsigned) (ci + 1u));
    }
    format_hex(pk,
               VAULT_XONLY_PUBKEY_LEN,
               G_scratch.display.key_str[slot],
               sizeof(G_scratch.display.key_str[slot]));
    nbgl_contentTagValue_t *pair = (nbgl_contentTagValue_t *) G_scratch.display.key_pair_raw[slot];
    memset(pair, 0, sizeof(*pair));
    pair->item = G_scratch.display.key_label[slot];
    pair->value = G_scratch.display.key_str[slot];
    return pair;
}

bool display_vault_intent(dispatcher_context_t *dc) {
    // vault_pairs lives in G_scratch.display (scalar segment only).
    // Scalar string buffers stay on the stack — small, and the frame must remain
    // alive through the blocking io_ui_process() call so NBGL pointers stay valid.
    // Key pairs are formatted on demand by _vault_key_pair_callback().
    // G_scratch.display is safe here: display_vault_intent blocks on io_ui_process
    // and cannot overlap with the hkdf or script_scratch union members.
    nbgl_layoutTagValue_t *const vault_pairs =
        (nbgl_layoutTagValue_t *) G_scratch.display.vault_pairs_raw;
    char vault_app_name_str[VAULT_APP_NAME_MAX_LEN + 1u]; /* +1 for NUL */
    char vault_fee_rate_str[VAULT_FEE_RATE_STR_SIZE];
    char vault_pegin_csv_str[VAULT_TIMELOCK_STR_SIZE];
    char vault_payout_tl_str[VAULT_TIMELOCK_STR_SIZE];
    char vault_refund_tl_str[VAULT_TIMELOCK_STR_SIZE];
    char vault_prepegin_fee_str[TX_DISPLAY_AMOUNT_STR_SIZE];

    int n = 0;

    // ---- Scalar fields (global params only) ----
    //
    // Per-vault group fields are streamed one segment at a time by vault_stream_group(),
    // for all vault counts including 1.  This keeps the display path uniform and ensures
    // every vault review shows a "Vault N of M" header regardless of vault_count.

    // App name is shown first so the user can confirm the HKDF domain even when
    // DERIVE_CONTEXT_HASH was called with P2=0x01 (silent, no Screen 1 shown).
    memcpy(vault_app_name_str, G_vault_context.app_name, G_vault_context.app_name_len);
    vault_app_name_str[G_vault_context.app_name_len] = '\0';
    vault_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "App name", .value = vault_app_name_str};

    snprintf(vault_fee_rate_str,
             sizeof(vault_fee_rate_str),
             "%u sat/vB",
             (unsigned) G_vault_intent.base_fee_rate);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Base fee rate", .value = vault_fee_rate_str};

    format_timelock_blocks(G_vault_intent.pegin_csv_timelock,
                           vault_pegin_csv_str,
                           sizeof(vault_pegin_csv_str));
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "PegIn timelock", .value = vault_pegin_csv_str};

    format_timelock_blocks(G_vault_intent.payout_timelock,
                           vault_payout_tl_str,
                           sizeof(vault_payout_tl_str));
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Payout timelock", .value = vault_payout_tl_str};

    format_timelock_blocks(G_vault_intent.htlc_refund_timelock,
                           vault_refund_tl_str,
                           sizeof(vault_refund_tl_str));
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Refund timelock", .value = vault_refund_tl_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.prepegin_max_fee, vault_prepegin_fee_str);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Max Pre-PegIn fee", .value = vault_prepegin_fee_str};

    LEDGER_ASSERT(n <= VAULT_INTENT_MAX_PAIRS, "Too many pairs");

    // Scalar params segment: pairs live in vault_pairs_raw; value strings live on
    // this stack frame and stay valid because io_ui_process blocks here for the
    // whole flow.
    g_vault_params_list.pairs = vault_pairs;
    g_vault_params_list.nbPairs = (uint8_t) n;
    g_vault_params_list.nbMaxLinesForValue = 0;

    // Keys segment: formatted on demand by _vault_key_pair_callback().  No pair
    // array is pre-allocated; NBGL calls the callback with the absolute pair index.
    g_vault_keys_list.pairs = NULL;
    g_vault_keys_list.callback = _vault_key_pair_callback;
    g_vault_keys_list.nbPairs =
        (uint8_t) (G_vault_intent.keeper_count + G_vault_intent.challenger_count);
    g_vault_keys_list.nbMaxLinesForValue = 0;

    // Phase 1: review for global parameters.  SKIPPABLE_OPERATION is intentionally
    // absent here and in phase 2 — see the file-header note.
    nbgl_useCaseReviewStreamingStart(TYPE_OPERATION,
                                     &ICON_APP_ACTION,
                                     VAULT_INTENT_REVIEW_TITLE,
                                     NULL,
                                     vault_stream_intro_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}
