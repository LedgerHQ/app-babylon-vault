#pragma once

/**
 * @file approve_vault_intent_core.h
 * @brief Pure key-batch validation logic for APPROVE_VAULT_INTENT (INS 0x80).
 *
 * All functions are static inline — no APDU layer, no globals, no SDK calls.
 * Unit tests include this header directly with no mocking required.
 *
 * Covers two operations:
 *   1. vault_validate_and_store_key() — per-key lex order, uniqueness, VP check
 *   2. vault_check_depositor_uniqueness() — final cross-role check after all keys loaded
 *
 * The handler (approve_vault_intent.c) owns:
 *   - G_approve_intent_state management
 *   - crypto_get_compressed_pubkey_at_path() call (SDK)
 *   - vault_context_invalidate / vault_context_transition
 *   - SEND_SW
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../vault_intent.h"

/**
 * Return codes for vault_validate_and_store_key.
 * The handler maps these to SW_INCORRECT_DATA; separate values aid unit-test diagnostics.
 */
typedef enum {
    VAULT_KEY_OK = 0,
    VAULT_KEY_ERR_OUT_OF_ORDER,   /**< key ≤ previous key in the same group (lex order) */
    VAULT_KEY_ERR_DUPLICATE,      /**< identical to an already-stored key               */
    VAULT_KEY_ERR_ROLE_COLLISION, /**< equals vault_provider_pk                         */
} vault_key_err_t;

/**
 * @brief Validate one x-only key at position @p idx and store it in @p intent.
 *
 * Keys are partitioned into two groups by position:
 *   [0, keeper_count)                    → keeper group
 *   [keeper_count, keeper_count + challenger_count) → challenger group
 *
 * Enforces within each group:
 *   - Strictly ascending lexicographic order (key > previous key in the same group)
 *   - Global uniqueness across all previously stored keys
 *   - Not equal to vault_provider_pk
 *
 * On VAULT_KEY_OK the key is stored in the appropriate array slot.
 * On any error @p intent is left unchanged; the caller must invalidate the session.
 *
 * @param intent  Partially-populated intent (all scalar fields already loaded).
 * @param idx     Global key index (0-based, equals keys_received before this call).
 * @param key     Pointer to VAULT_XONLY_PUBKEY_LEN (32) bytes.
 */
static inline vault_key_err_t vault_validate_and_store_key(vault_intent_t *intent,
                                                           uint8_t idx,
                                                           const uint8_t *key) {
    bool in_keepers = (idx < intent->keeper_count);
    bool first_in_group = (idx == 0) || (idx == intent->keeper_count);

    /* Lex order — only checked for the second and later key in each group. */
    if (!first_in_group) {
        const uint8_t *prev = in_keepers ? intent->keeper_pks[idx - 1]
                                         : intent->challenger_pks[idx - intent->keeper_count - 1];
        if (memcmp(key, prev, VAULT_XONLY_PUBKEY_LEN) <= 0) {
            return VAULT_KEY_ERR_OUT_OF_ORDER;
        }
    }

    /* Must not collide with any group's vault_provider_pk. */
    for (uint8_t g = 0; g < intent->vault_count; g++) {
        if (memcmp(key, intent->groups[g].vault_provider_pk, VAULT_XONLY_PUBKEY_LEN) == 0) {
            return VAULT_KEY_ERR_ROLE_COLLISION;
        }
    }

    /* Must be unique across every key stored so far (O(n²), max n = 64). */
    for (uint8_t j = 0; j < idx; j++) {
        const uint8_t *seen = (j < intent->keeper_count)
                                  ? intent->keeper_pks[j]
                                  : intent->challenger_pks[j - intent->keeper_count];
        if (memcmp(key, seen, VAULT_XONLY_PUBKEY_LEN) == 0) {
            return VAULT_KEY_ERR_DUPLICATE;
        }
    }

    /* Store into the correct slot. */
    if (in_keepers) {
        memcpy(intent->keeper_pks[idx], key, VAULT_XONLY_PUBKEY_LEN);
    } else {
        memcpy(intent->challenger_pks[idx - intent->keeper_count], key, VAULT_XONLY_PUBKEY_LEN);
    }
    return VAULT_KEY_OK;
}

/**
 * @brief Verify that @p depositor_xonly does not appear in any key role of @p intent.
 *
 * Checks against vault_provider_pk, all keeper_pks[0..keeper_count-1], and
 * all challenger_pks[0..challenger_count-1].  Call this after all keys have
 * been stored (keys_received == keeper_count + challenger_count).
 *
 * @param intent          Intent with all keys fully loaded.
 * @param depositor_xonly 32-byte x-only depositor public key.
 * @return true if no collision (depositor key is unique across all roles).
 */
static inline bool vault_check_depositor_uniqueness(const vault_intent_t *intent,
                                                    const uint8_t *depositor_xonly) {
    for (uint8_t g = 0; g < intent->vault_count; g++) {
        if (memcmp(depositor_xonly, intent->groups[g].vault_provider_pk, VAULT_XONLY_PUBKEY_LEN) ==
            0) {
            return false;
        }
    }
    for (uint8_t j = 0; j < intent->keeper_count; j++) {
        if (memcmp(depositor_xonly, intent->keeper_pks[j], VAULT_XONLY_PUBKEY_LEN) == 0) {
            return false;
        }
    }
    for (uint8_t j = 0; j < intent->challenger_count; j++) {
        if (memcmp(depositor_xonly, intent->challenger_pks[j], VAULT_XONLY_PUBKEY_LEN) == 0) {
            return false;
        }
    }
    return true;
}
