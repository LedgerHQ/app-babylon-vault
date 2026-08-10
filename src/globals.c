#include "globals.h"

// ---------------------------------------------------------------------------
// Compile-time RAM budget assertions (Nano S+ target)
//
// vault_intent_t layout:
//   scalar fields        ~120 B
//   groups[10]            720 B  (10 × 72)
//   keeper_pks           1024 B  (32 × 32)
//   challenger_pks       1024 B  (32 × 32)
//   total               ~2888 B
//
// vault_context_t layout:
//   root                  32 B
//   htlc_hashlock        320 B  (VAULT_MAX_VAULTS=10 × VAULT_HASH256_LEN=32)
//   auth_anchor_hash      32 B
//   state                  4 B  (enum = int)
//   payout_index           1 B
//   sig cap counters       8 B  (pre_pegin/pegin/payout/nopayout _signed, 2 B each)
//   payout_claimer_mask   43 B  (VAULT_MAX_VAULTS × (VAULT_MAX_KEEPERS+2) bits, per-slot dedup)
//   pegin_group_mask       2 B  (VAULT_MAX_VAULTS=10 bits, per-group dedup)
//   vault_group_index      1 B  + padding
//   is_payout_signing      1 B  + padding
//   derivation_path       40 B  (VAULT_MAX_PATH_DEPTH=10 × uint32_t)
//   derivation_path_len    1 B  + padding
//   app_name              64 B  (VAULT_APP_NAME_MAX_LEN)
//   app_name_len           1 B  + padding
//   total               ~552 B  (sizeof verified at compile time)
//
// Combined globals budget (Nano S+ 40 KB SRAM; Flex/Stax 36 KB SRAM; base app BSS ~8.2 KB):
//   vault_intent_t              ≤ 3072 B
//   vault_context_t             ≤  576 B
//   G_scratch (union)             5120 B  (largest member: refund_leaf_check_t =
//                                          2 × VAULT_SCRIPT_MAX_LEN; was 6224 B when
//                                          display_vault_intent_scratch_t dominated)
//                                         tap_leaf_script_state_t tls: ~2830 B — in union, grows
//                                         with VAULT_MAX_TAPTREE_DEPTH display: ~524 B — keys via
//                                         4-slot callback ring buffer
//   G_approve_intent_state      ≤    8 B  (outside union — see globals.h for why)
//                                       ≤ 9128 B  (well within remaining SRAM after min stack)
// display.c per-vault group streaming static buffers (NAPPS-1442): ~270 B outside this union
// ---------------------------------------------------------------------------

_Static_assert(sizeof(vault_intent_t) <= 3072,
               "vault_intent_t exceeds 3 KB — review key array sizes or scalar layout");
_Static_assert(sizeof(vault_context_t) <= 576, "vault_context_t exceeds expected size");
_Static_assert(sizeof(approve_intent_state_t) <= 8, "approve_intent_state_t unexpectedly large");
_Static_assert(sizeof(vault_scratch_t) == sizeof(refund_leaf_check_t),
               "vault_scratch_t size != refund_leaf_check_t; check union definition");

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
approve_intent_state_t G_approve_intent_state;
