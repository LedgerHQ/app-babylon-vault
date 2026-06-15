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
// Combined globals budget (Nano S+ has 40 KB SRAM; base app BSS ~8.2 KB):
//   vault_intent_t        ≤ 3072 B
//   vault_context_t       ≤  128 B
//   G_scratch (union)       2560 B  (max of hkdf 512 B / approve 8 B / script_scratch 2560 B)
//   combined              ≤ 5760 B  (well within remaining ~31.8 KB)
// ---------------------------------------------------------------------------

_Static_assert(sizeof(vault_intent_t) <= 3072,
               "vault_intent_t exceeds 3 KB — review key array sizes or scalar layout");
_Static_assert(sizeof(vault_context_t) <= 128, "vault_context_t exceeds expected size");
_Static_assert(sizeof(hkdf_stream_t) <= 512, "hkdf_stream_t exceeds expected size");
_Static_assert(sizeof(approve_intent_state_t) <= 8, "approve_intent_state_t unexpectedly large");
_Static_assert(sizeof(vault_scratch_t) == VAULT_SCRIPT_MAX_LEN,
               "vault_scratch_t size changed; update budget comment");

vault_intent_t G_vault_intent;
vault_context_t G_vault_context;
vault_scratch_t G_scratch;
