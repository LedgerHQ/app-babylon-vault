#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "vault_constants.h"
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

/* Scratch layout shared by Screen 2–8 transaction display functions.
 * String sizes verified by static asserts in display.c. */
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
 * Scratch buffers shared by Screen 2–8 transaction display functions.
 * All are mutually exclusive and block on io_ui_process(), so they share
 * one union member.
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
 * Scratch for handler_derive_context_hash.
 *
 * display_tx must be first: display_derive_context_hash writes to display_tx.addr_str
 * for the app-name string while the blocking display call is in progress.
 * All other fields sit above the display_tx footprint and are never clobbered
 * during the call.  After display returns, hkdf_derive_root reads context_buf.
 *
 * Multi-chunk streaming state (NAPPS-1441):
 *   streaming_in_progress — set on P1=0x00 when context spans multiple APDUs.
 *   context_total_len     — declared length from the P1=0x00 header (2-byte BE).
 *   context_received_len  — bytes accumulated so far.
 *   p2_mode               — 0x00 = show screen + return root; 0x01 = silent.
 *
 * Max context size is VAULT_CONTEXT_MAX_LEN (1024 bytes), delivered across one or
 * more APDUs.  context_buf is placed last so the struct layout keeps the
 * smaller scalar fields at low offsets.
 */
typedef struct {
    display_tx_scratch_t display_tx;
    uint8_t app_name_buf[VAULT_APP_NAME_MAX_LEN];
    uint8_t app_name_len;
    uint8_t p2_mode;
    bool streaming_in_progress;
    uint8_t path_len;
    // path[] and connected_pubkey live here (not on the handler stack) so that the
    // combined stack depth during the blocking display call stays within budget.
    uint32_t path[VAULT_MAX_PATH_DEPTH];
    uint8_t connected_pubkey[VAULT_COMPRESSED_PUBKEY_LEN];
    uint16_t context_total_len;
    uint16_t context_received_len;
    uint8_t context_buf[VAULT_CONTEXT_MAX_LEN];
} derive_context_hash_scratch_t;

/**
 * Mutually-exclusive scratch union.
 *
 * Each member is live in exactly one handler and is zeroed before use:
 *   - script_scratch  vault_build_* signing hooks
 *   - display         display_vault_intent only (blocks on io_ui_process)
 *   - display_tx      Screen 2–8 transaction display functions
 *   - derive_ctx      handler_derive_context_hash
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
    derive_context_hash_scratch_t derive_ctx;
    refund_leaf_check_t leaf_check;
    tap_leaf_script_state_t tls;
} vault_scratch_t;

extern vault_scratch_t G_scratch;

/** In-flight state for APPROVE_VAULT_INTENT multi-step exchange. */
extern approve_intent_state_t G_approve_intent_state;
