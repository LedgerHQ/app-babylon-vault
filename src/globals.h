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
 * @brief In-flight state for a streaming HKDF-SHA-256 derivation (DERIVE_CONTEXT_HASH).
 *
 * Lives for the duration of one chunked APDU exchange (P1=0x00 through the
 * final P1=0x01).  Zeroed at the start of every P1=0x00 call.
 * Never written to NVM — s is re-derivable on demand.
 */
typedef struct {
    /** True after a valid P1=0x00 chunk; gates acceptance of P1=0x01 chunks. */
    bool active;
    /** Total context byte count declared in P1=0x00. */
    uint16_t context_total_len;
    /** Context bytes fed so far via P1=0x01 chunks. */
    uint16_t context_received_len;
    /**
     * Running HMAC-SHA256 context for HKDF-Expand.
     * Keyed with PRK; fed SHA256(app_name) then context chunks then 0x01.
     */
    cx_hmac_sha256_t hmac;
} hkdf_stream_t;

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

/**
 * Scratch buffers for display_vault_intent: the two key string/label arrays
 * sized for the maximum keeper+challenger count.  Lives in G_scratch.display
 * for the duration of the blocking io_ui_process() call.
 */
typedef struct {
    char key_strs[VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS][VAULT_HEX_KEY_STR_SIZE];
    char key_labels[VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS][VAULT_KEY_LABEL_SIZE];
} display_vault_intent_scratch_t;

/**
 * Mutually-exclusive scratch union.
 *
 * Each member is live in exactly one handler and is zeroed before use:
 *   - hkdf            DERIVE_CONTEXT_HASH only
 *   - script_scratch  vault_build_* signing hooks (never live during DERIVE_CONTEXT_HASH)
 *   - display         display_vault_intent only (blocks on io_ui_process)
 *
 * approve_intent_state_t is intentionally NOT in this union: its first field
 * (scalars_loaded) aliases hkdf.active at offset 0, causing false-positive
 * active checks after APPROVE_VAULT_INTENT sets scalars_loaded=true.
 */
typedef union {
    hkdf_stream_t hkdf;
    uint8_t script_scratch[VAULT_SCRIPT_MAX_LEN];
    display_vault_intent_scratch_t display;
} vault_scratch_t;

extern vault_scratch_t G_scratch;

/** In-flight state for APPROVE_VAULT_INTENT multi-step exchange. */
extern approve_intent_state_t G_approve_intent_state;
