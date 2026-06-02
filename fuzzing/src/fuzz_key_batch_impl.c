/*
 * Separate compilation unit for fuzz_key_batch.
 *
 * vault_validate_and_store_key() and vault_check_depositor_uniqueness() are
 * static inline in approve_vault_intent_core.h.  When the single-TU fuzzer
 * harness (fuzz_key_batch.c) calls them, the compiler tracks the call-site
 * ranges (keeper/challenger counts clamped to [1,32]) and proves every array
 * index and arithmetic operation is safe at -O1, eliding every UBSan check.
 * The resulting binary then fails ClusterFuzzLite's bad_build_check because it
 * has no __ubsan_handle_* symbols and minimal coverage instrumentation.
 *
 * By instantiating the same functions in this separate TU, the compiler cannot
 * see the call-site ranges and must emit UBSan checks (array-bounds,
 * unsigned-integer-overflow, …) and coverage counters for each basic block.
 */

#include "handler/approve_vault_intent_core.h"

__attribute__((noinline, used))
vault_key_err_t vault_key_validate(vault_intent_t *intent,
                                    uint8_t idx,
                                    const uint8_t *key) {
    return vault_validate_and_store_key(intent, idx, key);
}

__attribute__((noinline, used))
bool vault_key_check_depositor(const vault_intent_t *intent,
                                const uint8_t *depositor_xonly) {
    return vault_check_depositor_uniqueness(intent, depositor_xonly);
}
