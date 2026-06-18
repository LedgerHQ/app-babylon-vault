#include "globals.h"

// ---------------------------------------------------------------------------
// Compile-time RAM budget assertions (Nano S+ target)
//
// vault_intent_t layout:
//   scalar fields        ~56 B
//   keeper_pks           1024 B  (32 × 32)
//   challenger_pks       1024 B  (32 × 32)
//   total               ~2104 B
//
// vault_context_t layout:
//   s + h                 64 B  (2 × VAULT_HASH256_LEN)
//   state                  4 B  (enum = int)
//   payout_index           1 B  + 3 B padding
//   total                 72 B
//
// Combined globals budget (Nano S+ 40 KB SRAM; Flex/Stax 36 KB SRAM; base app BSS ~8.2 KB):
//   vault_intent_t              ≤ 3072 B
//   vault_context_t             ≤  128 B
//   G_scratch (union)             6224 B  (largest member: display_vault_intent_scratch_t:
//                                          1168 B vault_pairs_raw + 4160 B key_strs + 896 B key_labels)
//                                         tap_leaf_script_state_t tls: 2636 B — in union, no growth
//   G_hkdf_stream               ≤  512 B  (outside union — see globals.h for why)
//   G_approve_intent_state      ≤    8 B  (outside union — same reason)
//                                        ≤ 9944 B  (well within remaining SRAM after min stack)
// ---------------------------------------------------------------------------

_Static_assert(sizeof(vault_intent_t) <= 3072,
               "vault_intent_t exceeds 3 KB — review key array sizes or scalar layout");
_Static_assert(sizeof(vault_context_t) <= 128, "vault_context_t exceeds expected size");
_Static_assert(sizeof(hkdf_stream_t) <= 512, "hkdf_stream_t exceeds expected size");
_Static_assert(sizeof(approve_intent_state_t) <= 8, "approve_intent_state_t unexpectedly large");
_Static_assert(sizeof(vault_scratch_t) == sizeof(display_vault_intent_scratch_t),
               "vault_scratch_t size != display_vault_intent_scratch_t; check union definition");

/* refund_leaf_check.actual_buf must hold the largest possible leaf0 script + 1 version byte.
 * encode_multisig_group upper bound: key_count * 34 + 6 bytes per group.
 * Max = 107 (fixed header) + (32K * 34 + 6) + (32C * 34 + 6) + 1 (leaf version) = 2296 B. */
#define _VAULT_MAX_LEAF0_WITH_VERSION \
    (107 + (VAULT_MAX_KEEPERS * 34 + 6) + (VAULT_MAX_CHALLENGERS * 34 + 6) + 1)
_Static_assert(sizeof(refund_leaf_check_t) - VAULT_SCRIPT_MAX_LEN >= _VAULT_MAX_LEAF0_WITH_VERSION,
               "refund_leaf_check.actual_buf too small for max leaf0 script + version byte");

vault_intent_t G_vault_intent;
vault_context_t G_vault_context;
vault_scratch_t G_scratch;
hkdf_stream_t G_hkdf_stream;
approve_intent_state_t G_approve_intent_state;
