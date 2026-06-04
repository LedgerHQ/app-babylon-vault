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

// These are kept static rather than on the stack because the NBGL library
// stores pointers to them that must remain valid long term.
static nbgl_layoutTagValue_t pairs[MAX_N_PAIRS];
static nbgl_layoutTagValueList_t pairList;
static char value_str[32], magic_value_str[32], fee_str[32];

bool display_transaction(dispatcher_context_t *dc,
                         int64_t value_spent,
                         uint64_t magic_input_value,
                         uint64_t fee) {
    uint64_t value_spent_abs = value_spent < 0 ? -value_spent : value_spent;
    format_sats_amount(COIN_COINID_SHORT, value_spent_abs, value_str);
    format_sats_amount(COIN_COINID_SHORT, magic_input_value, magic_value_str);
    format_sats_amount(COIN_COINID_SHORT, fee, fee_str);

    int n_pairs = 0;
    pairs[n_pairs++] = (nbgl_layoutTagValue_t){
        .item = "Transaction type",
        .value = "FOO",
    };

    if (value_spent >= 0) {
        pairs[n_pairs++] = (nbgl_layoutTagValue_t){
            .item = "Value spent",
            .value = value_str,
        };
    } else {
        pairs[n_pairs++] = (nbgl_layoutTagValue_t){
            .item = "Value received",
            .value = value_str,
        };
    }

    pairs[n_pairs++] = (nbgl_layoutTagValue_t){
        .item = "Magic value",
        .value = magic_value_str,
    };

    pairs[n_pairs++] = (nbgl_layoutTagValue_t){
        .item = "Fee",
        .value = fee_str,
    };

    assert(n_pairs <= MAX_N_PAIRS);

    // Setup list
    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = n_pairs;
    pairList.pairs = pairs;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &ICON_APP_ACTION,
                       "Review transaction\nto a FOO output",
                       NULL,
                       "Sign transaction\nto create a FOO output?",
                       review_choice);

    // blocking call until the user approves or rejects the transaction
    bool result = io_ui_process(dc);
    if (!result) {
        SEND_SW(dc, SW_DENY);
        return false;
    }

    return true;
}

// ---------------------------------------------------------------------------
// Vault intent approval screen
// ---------------------------------------------------------------------------

#define VAULT_INTENT_MAX_PAIRS (9 + VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS)

static nbgl_layoutTagValue_t vault_pairs[VAULT_INTENT_MAX_PAIRS];
static nbgl_layoutTagValueList_t vault_pair_list;

// Scalar value string buffers
static char vault_vp_key_str[65];  // 32-byte hex
static char vault_amount_str[MAX_AMOUNT_LENGTH + 1];
static char vault_commission_str[MAX_AMOUNT_LENGTH + 1];
static char vault_claim_str[MAX_AMOUNT_LENGTH + 1];
static char vault_fee_rate_str[20];  // "9999 sat/vB\0"
static char vault_pegin_fee_str[MAX_AMOUNT_LENGTH + 1];
static char vault_pegin_csv_str[32];
static char vault_payout_tl_str[32];
static char vault_refund_tl_str[32];

// Key value and label string buffers (one entry per key slot)
static char vault_key_strs[VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS][65];
static char vault_key_labels[VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS][14];

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
#else
#define VAULT_INTENT_REVIEW_TITLE "Review vault intent"
#define VAULT_INTENT_FINISH_TITLE "Approve intent?"
#endif

bool display_vault_intent(dispatcher_context_t *dc) {
    int n = 0;

    // ---- Scalar fields ----

    format_hex(G_vault_intent.vault_provider_pk,
               VAULT_XONLY_PUBKEY_LEN,
               vault_vp_key_str,
               sizeof(vault_vp_key_str));
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t){.item = "Vault provider key", .value = vault_vp_key_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.vault_amount, vault_amount_str);
    vault_pairs[n++] = (nbgl_layoutTagValue_t){.item = "Vault amount", .value = vault_amount_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.commission_fee, vault_commission_str);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t){.item = "Commission fee", .value = vault_commission_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.depositor_claim_value, vault_claim_str);
    vault_pairs[n++] = (nbgl_layoutTagValue_t){.item = "Depositor claim", .value = vault_claim_str};

    snprintf(vault_fee_rate_str,
             sizeof(vault_fee_rate_str),
             "%u sat/vB",
             (unsigned) G_vault_intent.base_fee_rate);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t){.item = "Base fee rate", .value = vault_fee_rate_str};

    format_sats_amount(COIN_COINID_SHORT, G_vault_intent.pegin_max_fee, vault_pegin_fee_str);
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t){.item = "Max PegIn fee", .value = vault_pegin_fee_str};

    format_timelock_blocks(G_vault_intent.pegin_csv_timelock,
                           vault_pegin_csv_str,
                           sizeof(vault_pegin_csv_str));
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t){.item = "PegIn timelock", .value = vault_pegin_csv_str};

    format_timelock_blocks(G_vault_intent.payout_timelock,
                           vault_payout_tl_str,
                           sizeof(vault_payout_tl_str));
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t){.item = "Payout timelock", .value = vault_payout_tl_str};

    format_timelock_blocks(G_vault_intent.htlc_refund_timelock,
                           vault_refund_tl_str,
                           sizeof(vault_refund_tl_str));
    vault_pairs[n++] =
        (nbgl_layoutTagValue_t){.item = "Refund timelock", .value = vault_refund_tl_str};

    // ---- Keeper public keys ----

    for (uint8_t i = 0; i < G_vault_intent.keeper_count; i++) {
        format_hex(G_vault_intent.keeper_pks[i],
                   VAULT_XONLY_PUBKEY_LEN,
                   vault_key_strs[i],
                   sizeof(vault_key_strs[i]));
        snprintf(vault_key_labels[i], sizeof(vault_key_labels[i]), "Keeper %u", i + 1u);
        vault_pairs[n++] =
            (nbgl_layoutTagValue_t){.item = vault_key_labels[i], .value = vault_key_strs[i]};
    }

    // ---- Challenger public keys ----

    for (uint8_t i = 0; i < G_vault_intent.challenger_count; i++) {
        uint8_t slot = G_vault_intent.keeper_count + i;
        format_hex(G_vault_intent.challenger_pks[i],
                   VAULT_XONLY_PUBKEY_LEN,
                   vault_key_strs[slot],
                   sizeof(vault_key_strs[slot]));
        snprintf(vault_key_labels[slot], sizeof(vault_key_labels[slot]), "Challenger %u", i + 1u);
        vault_pairs[n++] =
            (nbgl_layoutTagValue_t){.item = vault_key_labels[slot], .value = vault_key_strs[slot]};
    }

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
