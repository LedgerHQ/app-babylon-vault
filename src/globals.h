#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "vault_intent.h"
#include "vault_context.h"
#include "vault_script.h"

#include "cx.h"

/** Loaded vault intent. Valid only when G_vault_context.state != VAULT_STATE_IDLE. */
extern vault_intent_t G_vault_intent;

/** Active session context. Always valid; state == VAULT_STATE_IDLE when no session is running. */
extern vault_context_t G_vault_context;

/**
 * @brief In-flight state for a two-phase APPROVE_VAULT_INTENT exchange.
 *
 * Lives from the first P1=0x00 call until all keys are accepted or any
 * error/invalidation occurs.  Zeroed at the start of every P1=0x00 call and
 * inside vault_context_invalidate.
 */
typedef struct {
    /** True after a valid P1=0x00; gates acceptance of P1=0x01 batches. */
    bool scalars_loaded;
    /** Total number of x-only keys stored so far (keepers then challengers). */
    uint8_t keys_received;
} approve_intent_state_t;

/* sizeof(nbgl_layoutTagValue_t) — verified at compile time in display.c */
#define VAULT_DISPLAY_PAIR_SIZE 16

/* Pair count for vault intent display: 9 scalar fields + one entry per key */
#define VAULT_DISPLAY_PAIRS_COUNT (9 + VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS)

/* Scratch layout for display_transaction / display_prepegin_transaction /
 * display_refund_transaction.  String sizes verified by static asserts in display.c. */
#define TX_DISPLAY_MAX_PAIRS       4
#define TX_DISPLAY_AMOUNT_STR_SIZE 28 /* MAX_AMOUNT_LENGTH + 1 */
#define TX_DISPLAY_ADDR_STR_SIZE   80 /* MAX_ADDRESS_LENGTH_STR + 1 */

/**
 * Scratch buffers for display_vault_intent.  Lives in G_scratch.display for the
 * duration of the blocking io_ui_process() call.
 *
 * vault_pairs_raw holds the nbgl_layoutTagValue_t array as raw bytes to avoid
 * pulling NBGL headers into globals.h.  display.c asserts sizeof(nbgl_layoutTagValue_t)
 * == VAULT_DISPLAY_PAIR_SIZE and casts the pointer before use.
 */
typedef struct {
    uint8_t vault_pairs_raw[VAULT_DISPLAY_PAIRS_COUNT * VAULT_DISPLAY_PAIR_SIZE];
    char key_strs[VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS][VAULT_HEX_KEY_STR_SIZE];
    char key_labels[VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS][VAULT_KEY_LABEL_SIZE];
} display_vault_intent_scratch_t;

/**
 * Scratch buffers for display_transaction / display_prepegin_transaction /
 * display_refund_transaction.  All three functions are mutually exclusive and
 * block on io_ui_process(), so they share one union member.
 *
 * pairs_raw holds the nbgl_layoutTagValue_t array as raw bytes (same pattern as
 * display_vault_intent_scratch_t).  addr_str is written by the caller before
 * invoking the display function; NBGL holds a pointer to it across io_ui_process.
 */
typedef struct {
    uint8_t pairs_raw[TX_DISPLAY_MAX_PAIRS * VAULT_DISPLAY_PAIR_SIZE];
    char amount_str[TX_DISPLAY_AMOUNT_STR_SIZE];
    char fee_str[TX_DISPLAY_AMOUNT_STR_SIZE];
    char extra_str[TX_DISPLAY_AMOUNT_STR_SIZE];
    char addr_str[TX_DISPLAY_ADDR_STR_SIZE];
} display_tx_scratch_t;

/**
 * Scratch buffer pair for _validate_display_refund leaf-script verification.
 *
 * expected_script aliases script_scratch (offset 0) — vault_build_htlc_leaf0 writes
 * there as usual.  actual_buf reuses the tail bytes of display_vault_intent_scratch_t
 * that are idle during validation (display_vault_intent blocks on io_ui_process and
 * therefore cannot overlap with any validation call).
 *
 * sizeof(refund_leaf_check_t) < sizeof(display_vault_intent_scratch_t), so adding it to
 * the union does not increase the union size.
 */
typedef struct {
    uint8_t expected_script[VAULT_SCRIPT_MAX_LEN];
    uint8_t actual_buf[sizeof(display_vault_intent_scratch_t) - VAULT_SCRIPT_MAX_LEN];
} refund_leaf_check_t;

/**
 * State for the _tap_leaf_script_callback scan over a PSBT input map.
 *
 * Lives in G_scratch.tls — 2636 B saved from BSS versus a static local.
 * The struct is zeroed by _validate_display_refund before each scan.
 */
typedef struct {
    bool found;
    bool ambiguous;
    uint8_t control_block[1 + VAULT_XONLY_PUBKEY_LEN + VAULT_HASH256_LEN];
    uint8_t control_block_len;
    uint8_t leaf_script[VAULT_SCRIPT_MAX_LEN];
    int leaf_script_len;
    uint8_t leaf_version;
} tap_leaf_script_state_t;

/**
 * Mutually-exclusive scratch union.
 *
 * Each member is live in exactly one handler and is zeroed before use:
 *   - script_scratch  vault_build_* signing hooks
 *   - display         display_vault_intent only (blocks on io_ui_process)
 *   - display_tx      display_transaction / display_prepegin / display_refund
 *   - leaf_check      _validate_display_refund leaf-script comparison
 *   - tls             _tap_leaf_script_callback state during refund validation
 *
 * Timing is non-overlapping: tls is populated by the callback inside
 * call_get_merkleized_map_with_callback (step 5), then consumed through
 * step 10; leaf_check.actual_buf is first written at step 11 — safe.
 * display_tx is written (addr_str) and then read (io_ui_process) only after
 * tls and leaf_check are fully consumed.
 *
 * approve_intent_state_t is intentionally NOT in this union.  Its boolean guard
 * at the first byte (scalars_loaded) would, if it were a union member, be aliased
 * by stale non-zero bytes left by script_scratch or display (e.g. an opcode or
 * ASCII hex char at offset 0) and cause handle_key_batch() to treat spurious data
 * as an in-progress exchange.
 */
typedef union {
    uint8_t script_scratch[VAULT_SCRIPT_MAX_LEN];
    display_vault_intent_scratch_t display;
    display_tx_scratch_t display_tx;
    refund_leaf_check_t leaf_check;
    tap_leaf_script_state_t tls;
} vault_scratch_t;

extern vault_scratch_t G_scratch;

/** In-flight state for APPROVE_VAULT_INTENT multi-step exchange. */
extern approve_intent_state_t G_approve_intent_state;
