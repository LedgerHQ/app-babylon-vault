/*
 * libFuzzer harness for vault_validate_and_store_key() and
 * vault_check_depositor_uniqueness().
 *
 * Input layout:
 *   [0]     keeper_count    — clamped to [1, VAULT_MAX_KEEPERS]
 *   [1]     challenger_count — clamped to [1, VAULT_MAX_CHALLENGERS]
 *   [2]     control byte — selects which key is replayed as a collision candidate
 *   [3..34] groups[0].vault_provider_pk
 *   [35..]  raw key bytes — each 32-byte window is one x-only key candidate
 *
 * Both functions are static inline in approve_vault_intent_core.h; secp256k1.c supplies
 * the field prime that vault_xonly_key_is_canonical compares against. No globals, no SDK
 * calls.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* The base app's secp256k1 constant table is pulled into this translation unit rather
 * than linked as its own object, which is unusual and deliberate.
 *
 * secp256k1.c defines only const arrays — no functions — so it compiles to zero coverage
 * guards and zero UBSan handlers. Linked separately it made half of this target's objects
 * carry no instrumentation, and oss-fuzz's bad_build_check then rejected the binary under
 * SANITIZER=undefined ("only partial coverage instrumentation", "does not seem to be
 * compiled with UBSan"). AddressSanitizer passes the same binary because it instruments
 * globals, which is why only the UBSan matrix entry failed.
 *
 * Including it here keeps the field prime single-sourced from the base app — the
 * alternative, a local copy of p, is what vault_xonly_key_is_canonical exists to avoid —
 * while leaving this target as one fully instrumented object. The unit tests still link
 * secp256k1.c normally and assert the constant matches (test_xonly_matches_base_app_prime). */
#include "../../bitcoin_app_base/src/secp256k1.c"

#include "handler/approve_vault_intent_core.h"

#define FUZZ_HEADER_LEN (3u + VAULT_XONLY_PUBKEY_LEN)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < FUZZ_HEADER_LEN) return 0;

    uint8_t keeper_count = (data[0] % VAULT_MAX_KEEPERS) + 1;
    uint8_t challenger_count = (data[1] % VAULT_MAX_CHALLENGERS) + 1;
    uint8_t control = data[2];

    vault_intent_t intent;
    memset(&intent, 0, sizeof(intent));
    intent.keeper_count = keeper_count;
    intent.challenger_count = challenger_count;

    /* vault_count MUST be non-zero.  It was left at 0, which made both provider-key loops
     * in approve_vault_intent_core.h dead: `for (g = 0; g < intent->vault_count; g++)`
     * cannot execute, so VAULT_KEY_ERR_ROLE_COLLISION and the depositor-versus-provider
     * collision path were unreachable in this target despite the old comment claiming the
     * zero provider key exercised them.  One active group is enough to reach both. */
    intent.vault_count = 1;
    memcpy(intent.groups[0].vault_provider_pk, data + 3, VAULT_XONLY_PUBKEY_LEN);

    const uint8_t *ptr = data + FUZZ_HEADER_LEN;
    size_t remaining = size - FUZZ_HEADER_LEN;
    uint8_t total = keeper_count + challenger_count;

    for (uint8_t idx = 0; idx < total; idx++) {
        if (remaining < VAULT_XONLY_PUBKEY_LEN) break;
        /* Reaching the collision branches must not depend on the fuzzer guessing a
         * 32-byte equality.  The control byte deterministically replays the provider key
         * as a candidate, so ROLE_COLLISION is reachable in a single input. */
        const uint8_t *candidate = ((control & 1u) && idx == (control >> 1u) % total)
                                       ? intent.groups[0].vault_provider_pk
                                       : ptr;
        (void) vault_xonly_key_is_canonical(candidate);
        (void) vault_validate_and_store_key(&intent, idx, candidate);
        ptr += VAULT_XONLY_PUBKEY_LEN;
        remaining -= VAULT_XONLY_PUBKEY_LEN;
    }

    /* Exercise the depositor uniqueness check: against remaining bytes when present, and
     * otherwise against the provider key, so the provider-collision arm is also reached. */
    if (remaining >= VAULT_XONLY_PUBKEY_LEN) {
        (void) vault_check_depositor_uniqueness(&intent, ptr);
    } else {
        (void) vault_check_depositor_uniqueness(&intent, intent.groups[0].vault_provider_pk);
    }

    return 0;
}
