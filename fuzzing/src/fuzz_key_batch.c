/*
 * libFuzzer harness for vault_validate_and_store_key() and
 * vault_check_depositor_uniqueness().
 *
 * Input layout:
 *   [0]     keeper_count    — clamped to [1, VAULT_MAX_KEEPERS]
 *   [1]     challenger_count — clamped to [1, VAULT_MAX_CHALLENGERS]
 *   [2..]   raw key bytes — each 32-byte window is one x-only key candidate
 *
 * Both functions are static inline in approve_vault_intent_core.h — no
 * extra .c compilation needed, no globals, no SDK calls.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "handler/approve_vault_intent_core.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    uint8_t keeper_count     = (data[0] % VAULT_MAX_KEEPERS)     + 1;
    uint8_t challenger_count = (data[1] % VAULT_MAX_CHALLENGERS) + 1;

    vault_intent_t intent;
    memset(&intent, 0, sizeof(intent));
    intent.keeper_count     = keeper_count;
    intent.challenger_count = challenger_count;
    /* vault_provider_pk stays zero — intentionally not a valid EC point; used as
     * a deterministic collision target so the fuzzer can reach VAULT_KEY_ERR_ROLE_COLLISION. */

    const uint8_t *ptr  = data + 2;
    size_t remaining    = size - 2;
    uint8_t total       = keeper_count + challenger_count;

    for (uint8_t idx = 0; idx < total; idx++) {
        if (remaining < VAULT_XONLY_PUBKEY_LEN) break;
        (void) vault_validate_and_store_key(&intent, idx, ptr);
        ptr       += VAULT_XONLY_PUBKEY_LEN;
        remaining -= VAULT_XONLY_PUBKEY_LEN;
    }

    /* Exercise the depositor uniqueness check with any remaining bytes. */
    if (remaining >= VAULT_XONLY_PUBKEY_LEN) {
        (void) vault_check_depositor_uniqueness(&intent, ptr);
    }

    return 0;
}
