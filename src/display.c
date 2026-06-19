#include "display.h"

#include <stdio.h>

#include "../bitcoin_app_base/src/ui/display.h"
#include "../bitcoin_app_base/src/ui/menu.h"
#include "globals.h"
#include "io_ext.h"
#include "nbgl_use_case.h"

static void review_choice(bool approved) {
    set_ux_flow_response(approved);  // sets the return value of io_ui_process
    if (!approved) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

static void vault_review_choice(bool approved) {
    set_ux_flow_response(approved);
    nbgl_useCaseReviewStatus(
        approved ? STATUS_TYPE_OPERATION_SIGNED : STATUS_TYPE_OPERATION_REJECTED,
        ui_menu_main);
}

#define MAX_N_PAIRS 4

_Static_assert(MAX_N_PAIRS == TX_DISPLAY_MAX_PAIRS, "TX_DISPLAY_MAX_PAIRS out of sync with MAX_N_PAIRS");
_Static_assert(TX_DISPLAY_AMOUNT_STR_SIZE >= MAX_AMOUNT_LENGTH + 1,
               "TX_DISPLAY_AMOUNT_STR_SIZE too small; update globals.h");
_Static_assert(TX_DISPLAY_ADDR_STR_SIZE >= MAX_ADDRESS_LENGTH_STR + 1,
               "TX_DISPLAY_ADDR_STR_SIZE too small; update globals.h");

bool display_transaction(dispatcher_context_t *dc,
                         int64_t value_spent,
                         uint64_t magic_input_value,
                         uint64_t fee) {
    nbgl_layoutTagValue_t *const tx_pairs = (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list;

    uint64_t value_spent_abs = value_spent < 0 ? -value_spent : value_spent;
    format_sats_amount(COIN_COINID_SHORT, value_spent_abs, G_scratch.display_tx.amount_str);
    format_sats_amount(COIN_COINID_SHORT, magic_input_value, G_scratch.display_tx.extra_str);
    format_sats_amount(COIN_COINID_SHORT, fee, G_scratch.display_tx.fee_str);

    int n_pairs = 0;
    tx_pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
        .item = "Transaction type",
        .value = "FOO",
    };

    if (value_spent >= 0) {
        tx_pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
            .item = "Value spent",
            .value = G_scratch.display_tx.amount_str,
        };
    } else {
        tx_pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
            .item = "Value received",
            .value = G_scratch.display_tx.amount_str,
        };
    }

    tx_pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
        .item = "Magic value",
        .value = G_scratch.display_tx.extra_str,
    };

    tx_pairs[n_pairs++] = (nbgl_layoutTagValue_t) {
        .item = "Fee",
        .value = G_scratch.display_tx.fee_str,
    };

    assert(n_pairs <= MAX_N_PAIRS);

    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = n_pairs;
    pair_list.pairs = tx_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Review transaction\nto a FOO output",
                       NULL,
                       "Sign transaction\nto create a FOO output?",
                       review_choice);

    bool result = io_ui_process(dc);
    if (!result) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Screen 2 — Pre-PegIn transaction
// ---------------------------------------------------------------------------

bool display_prepegin_transaction(dispatcher_context_t *dc,
                                  uint64_t vault_amount,
                                  uint64_t fee,
                                  const char *htlc_address) {
    nbgl_layoutTagValue_t *const tx_pairs = (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list;

    format_sats_amount(COIN_COINID_SHORT, vault_amount, G_scratch.display_tx.amount_str);
    format_sats_amount(COIN_COINID_SHORT, fee, G_scratch.display_tx.fee_str);

    int n = 0;
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Vault amount", .value = G_scratch.display_tx.amount_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Transaction fee", .value = G_scratch.display_tx.fee_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "HTLC address", .value = htlc_address};

    assert(n <= MAX_N_PAIRS);

    pair_list.nbMaxLinesForValue = 0;
    pair_list.nbPairs = n;
    pair_list.pairs = tx_pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pair_list,
                       &ICON_APP_ACTION,
                       "Review Pre-PegIn\ntransaction",
                       NULL,
                       "Sign Pre-PegIn\ntransaction?",
                       review_choice);

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
                                const char *refund_address) {
    nbgl_layoutTagValue_t *const tx_pairs = (nbgl_layoutTagValue_t *) G_scratch.display_tx.pairs_raw;
    nbgl_layoutTagValueList_t pair_list;

    format_sats_amount(COIN_COINID_SHORT, amount_reclaimed, G_scratch.display_tx.amount_str);
    format_sats_amount(COIN_COINID_SHORT, fee, G_scratch.display_tx.fee_str);

    int n = 0;
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Reclaimed amount", .value = G_scratch.display_tx.amount_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Transaction fee", .value = G_scratch.display_tx.fee_str};
    tx_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Reclaim address", .value = refund_address};

    assert(n <= MAX_N_PAIRS);

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
// Vault intent approval screen
// ---------------------------------------------------------------------------

#define VAULT_INTENT_MAX_PAIRS VAULT_DISPLAY_PAIRS_COUNT

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

bool display_vault_intent(dispatcher_context_t *dc) {
    // vault_pairs and key string/label arrays all live in G_scratch.display.
    // Scalar string buffers stay on the stack (small, and the frame must stay
    // alive through the blocking io_ui_process() call so NBGL pointer remain valid).
    // G_scratch.display is safe here: display_vault_intent blocks on io_ui_process
    // and cannot overlap with the hkdf or script_scratch union members.
    nbgl_layoutTagValue_t *const vault_pairs =
        (nbgl_layoutTagValue_t *) G_scratch.display.vault_pairs_raw;
    nbgl_layoutTagValueList_t vault_pair_list;
    char vault_vp_key_str[VAULT_HEX_KEY_STR_SIZE];
    char vault_amount_str[MAX_AMOUNT_LENGTH + 1];
    char vault_commission_str[MAX_AMOUNT_LENGTH + 1];
    char vault_claim_str[MAX_AMOUNT_LENGTH + 1];
    char vault_fee_rate_str[VAULT_FEE_RATE_STR_SIZE];
    char vault_pegin_fee_str[MAX_AMOUNT_LENGTH + 1];
    char vault_pegin_csv_str[VAULT_TIMELOCK_STR_SIZE];
    char vault_payout_tl_str[VAULT_TIMELOCK_STR_SIZE];
    char vault_refund_tl_str[VAULT_TIMELOCK_STR_SIZE];

    int n = 0;

    // ---- Scalar fields ----

    format_hex(G_vault_intent.vault_provider_pk,
               VAULT_XONLY_PUBKEY_LEN,
               vault_vp_key_str,
               sizeof(vault_vp_key_str));
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = VAULT_VP_KEY_LABEL, .value = vault_vp_key_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.vault_amount, vault_amount_str);
    vault_pairs[n++] = (nbgl_layoutTagValue_t) {.item = "Vault amount", .value = vault_amount_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.commission_fee, vault_commission_str);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Commission fee", .value = vault_commission_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.depositor_claim_value, vault_claim_str);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Depositor claim", .value = vault_claim_str};

    snprintf(vault_fee_rate_str,
             sizeof(vault_fee_rate_str),
             "%u sat/vB",
             (unsigned) G_vault_intent.base_fee_rate);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Base fee rate", .value = vault_fee_rate_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.pegin_max_fee, vault_pegin_fee_str);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t) {.item = "Max PegIn fee", .value = vault_pegin_fee_str};

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

    // ---- Keeper public keys ----

    for (uint8_t i = 0; i < G_vault_intent.keeper_count; i++) {
        format_hex(G_vault_intent.keeper_pks[i],
                   VAULT_XONLY_PUBKEY_LEN,
                   G_scratch.display.key_strs[i],
                   sizeof(G_scratch.display.key_strs[i]));
        snprintf(G_scratch.display.key_labels[i],
                 sizeof(G_scratch.display.key_labels[i]),
                 "Keeper %u",
                 i + 1u);
        vault_pairs[n++] = (nbgl_layoutTagValue_t) {.item = G_scratch.display.key_labels[i],
                                                    .value = G_scratch.display.key_strs[i]};
    }

    // ---- Challenger public keys ----

    for (uint8_t i = 0; i < G_vault_intent.challenger_count; i++) {
        uint8_t slot = G_vault_intent.keeper_count + i;
        format_hex(G_vault_intent.challenger_pks[i],
                   VAULT_XONLY_PUBKEY_LEN,
                   G_scratch.display.key_strs[slot],
                   sizeof(G_scratch.display.key_strs[slot]));
        snprintf(G_scratch.display.key_labels[slot],
                 sizeof(G_scratch.display.key_labels[slot]),
                 "Challenger %u",
                 i + 1u);
        vault_pairs[n++] = (nbgl_layoutTagValue_t) {.item = G_scratch.display.key_labels[slot],
                                                    .value = G_scratch.display.key_strs[slot]};
    }

    assert(n <= VAULT_INTENT_MAX_PAIRS);

    vault_pair_list.pairs = vault_pairs;
    vault_pair_list.nbPairs = n;
    vault_pair_list.nbMaxLinesForValue = 0;

    nbgl_useCaseReview(TYPE_OPERATION,
                       &vault_pair_list,
                       &ICON_APP_ACTION,
                       VAULT_INTENT_REVIEW_TITLE,
                       NULL,
                       VAULT_INTENT_FINISH_TITLE,
                       vault_review_choice);

    bool approved = io_ui_process(dc);
    if (!approved) {
        SEND_SW(dc, SW_DENY);
        return false;
    }
    return true;
}
