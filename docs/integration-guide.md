# Babylon Vault Ledger App — Integration Guide

This guide describes how to integrate with the Babylon Vault Ledger app from the host side.
It covers the full APDU command sequence for each flow, the PSBT shape required by each
signing step, and the device session state at every point.

**CLA:** `0xE1` for all commands.  
**Full wire formats:** see [`apdu.md`](apdu.md).

---

## Session state machine

The device tracks a single global session through these states (from `vault_context.h`):

```
IDLE
 ├─ 0x81 DERIVE_CONTEXT_HASH ──────────────► HASH_DERIVED
 │          └─ 0x80 APPROVE_VAULT_INTENT ──► INTENT_LOADED
 │                       └─────────────────► SESSION2_PEGIN_EXPECTED  (if preimage present)
 └─ 0x80 APPROVE_VAULT_INTENT ─────────────► INTENT_LOADED

INTENT_LOADED
  └─ 0x04 SIGN_PSBT (Pre-PegIn) ──────────► SESSION1_PREPEGIN_EXPECTED

SESSION2_PEGIN_EXPECTED
  └─ 0x04 SIGN_PSBT (PegIn) ─────────────► SESSION2_PAYOUT_EXPECTED

SESSION2_PAYOUT_EXPECTED
  └─ 0x04 SIGN_PSBT (Payout ×N) ─────────► SESSION2_COMPLETE  (after last)

SESSION2_COMPLETE
  └─ 0x82 RELEASE_CONTEXT_SECRET ────────► IDLE
```

**Refund** (`0x04 SIGN_PSBT` with a 1-in/1-out PSBT and no wallet policy) is accepted
in `IDLE`, `HASH_DERIVED`, `INTENT_LOADED`, and `SESSION1_PREPEGIN_EXPECTED`. It does not
change state.

**Invalidation** — a **Payout signing** failure wipes `htlc_preimage` via `explicit_bzero`
and resets to `IDLE`; the host must then restart the full sequence from `DERIVE_CONTEXT_HASH`.
PSBT **validation** failures (and PegIn/Pre-PegIn/Refund signing failures) do **not**
invalidate — the session state is left unchanged so the host can fix the PSBT and retry.
See [Error recovery](#error-recovery) for the per-flow retry rules.

---

## Flow A — Full deposit (Session 1 + Session 2)

### Step 1 — Derive the HTLC secret: `0x81 DERIVE_CONTEXT_HASH`

Required state: `IDLE`.

The device derives a deterministic HTLC preimage `s` using HKDF-SHA-256:

```
PRK         = HMAC-SHA256(salt="derive-context-hash", IKM=privkey(m/73681862'))
htlc_preimage = HMAC-SHA256(PRK, SHA256(app_name) || context || 0x01)
htlc_hashlock = SHA256(htlc_preimage)
```

The device returns only `htlc_hashlock` (32 bytes). `htlc_preimage` stays in device RAM
until `RELEASE_CONTEXT_SECRET` is called.

**State after:** `IDLE → HASH_DERIVED`

---

### Step 2 — Load the vault intent: `0x80 APPROVE_VAULT_INTENT`

Required state: `HASH_DERIVED` (for Session 2) or `IDLE` (Session 1 standalone).

Send all 17 scalar TLV fields (P1=`0x00`), then stream all keeper + challenger x-only
public keys (P1=`0x01`). The device displays the vault parameters for user approval.

**If called from `HASH_DERIVED`:** the device saves `htlc_preimage` and `htlc_hashlock`
across the internal session reset, then restores them. After the user approves, if
`prepegin_txid` (tag `0x0C`) is non-zero, the device immediately transitions:

```
HASH_DERIVED → INTENT_LOADED → SESSION2_PEGIN_EXPECTED
```

**If called from `IDLE`:** transitions `IDLE → INTENT_LOADED` only. Session 2 path
requires calling `DERIVE_CONTEXT_HASH` first.

**State after (Session 2):** `SESSION2_PEGIN_EXPECTED`  
**State after (Session 1):** `INTENT_LOADED`

---

### Step 3a (Session 1) — Sign Pre-PegIn: `0x04 SIGN_PSBT`

Required state: `INTENT_LOADED`.  
Required wallet policy: **BIP-86 wallet policy provided** (host passes the policy;
`has_no_wallet_policy == false`).

#### PSBT requirements

| Field | Requirement |
|-------|-------------|
| `nVersion` | ≥ 2 |
| Inputs | All inputs must be wallet-policy (BIP-86) owned — device rejects any non-internal input |
| Sighash | `SIGHASH_DEFAULT` (absent) or `SIGHASH_ALL` (1) per input |
| Output at `htlc_vout` | P2TR scriptPubKey matching `vault_build_htlc_scriptpubkey(intent, htlc_hashlock)` |
| Output at `htlc_vout` value | Must be in `[vault_amount + depositor_claim_value, vault_amount + depositor_claim_value + pegin_max_fee]` |
| All other outputs | Must be BIP-86 internal change |

The device displays: vault amount, depositor claim value, fee, HTLC address. User must approve.

**The device signs all BIP-86 inputs via the standard wallet-policy path.** No custom signing.

**State after:** `INTENT_LOADED → SESSION1_PREPEGIN_EXPECTED`

Broadcast the Pre-PegIn transaction. Record the resulting `prepegin_txid`. The device remains
in `SESSION1_PREPEGIN_EXPECTED` until Session 2 begins (next `APPROVE_VAULT_INTENT` with the
TXID embedded in the TLV).

---

### Step 3b (Session 2) — Sign PegIn: `0x04 SIGN_PSBT`

Required state: `SESSION2_PEGIN_EXPECTED`.  
Required wallet policy: **none** (host must not provide a wallet policy).

#### PSBT requirements

| Field | Requirement |
|-------|-------------|
| `nVersion` | ≥ 2 |
| `nLockTime` | 0 |
| Input count | Exactly 1 |
| Output count | Exactly 2 |
| Input 0 `PSBT_IN_PREVIOUS_TXID` | Must equal `intent.prepegin_txid` (little-endian) |
| Input 0 `PSBT_IN_OUTPUT_INDEX` | Must equal `intent.htlc_vout` |
| Input 0 `PSBT_IN_SEQUENCE` | Must be `0xFFFFFFFE` (RBF, no relative lock) |
| Input 0 `PSBT_IN_SIGHASH_TYPE` | `SIGHASH_DEFAULT` (absent or 0) or `SIGHASH_ALL` (1) |
| Input 0 `PSBT_IN_TAP_INTERNAL_KEY` | Must be `VAULT_NUMS_XONLY` (no key-path spend) |
| Input 0 `PSBT_IN_TAP_MERKLE_ROOT` | Must equal `vault_build_htlc_merkle_root(intent, htlc_hashlock)` |
| Input 0 `PSBT_IN_TAP_LEAF_SCRIPT` | Must include HTLC Leaf 0 (hashlock script) |
| Output 0 scriptPubKey | Must match `vault_build_vault_utxo_scriptpubkey(intent)` |
| Output 0 value | Must equal `intent.vault_amount` |
| Output 1 scriptPubKey | Must match `vault_build_depositor_claim_scriptpubkey(intent)` |
| Output 1 value | Must equal `intent.depositor_claim_value` |
| Fee (`htlc_value - vault_amount - depositor_claim_value`) | Must be ≤ `intent.pegin_max_fee` |

PegIn validation is **silent** — no display shown to the user. The device signs HTLC Leaf 0
(hashlock tapscript) with the depositor key at `intent.depositor_path`.

State advances only after signing succeeds, so the host can retry on communication failure
without losing session state.

**State after signing:** `SESSION2_PEGIN_EXPECTED → SESSION2_PAYOUT_EXPECTED`, `payout_index = 0`

---

### Step 4 — Sign Payout transactions: `0x04 SIGN_PSBT` × (1 + `keeper_count`)

Required state: `SESSION2_PAYOUT_EXPECTED`.  
Required wallet policy: **none**.

Must be sent in claimer order: index 0 = Vault Provider (VP), indices 1..`keeper_count` = Vault
Keepers (VK) in the same order keys were loaded in `APPROVE_VAULT_INTENT`. The device tracks
position in `payout_index` — sending them out of order returns `SW_BAD_STATE`.

#### PSBT requirements (apply to every payout)

| Field | Requirement |
|-------|-------------|
| `nVersion` | ≥ 2 |
| `nLockTime` | 0 |
| Input count | Exactly 2 |
| Output count | 3 (VP, `payout_index == 0`) or 2 (VK, `payout_index > 0`) |

**Input 0 (Vault UTXO — spent from PegIn output 0):**

| PSBT field | Requirement |
|------------|-------------|
| `PSBT_IN_PREVIOUS_TXID` | Must equal `vault_compute_pegin_txid(intent)` (device recomputes) |
| `PSBT_IN_OUTPUT_INDEX` | Must be 0 |
| `PSBT_IN_SEQUENCE` | Must equal `intent.pegin_csv_timelock` |
| `PSBT_IN_SIGHASH_TYPE` | `SIGHASH_DEFAULT` only (absent or 0); explicit `SIGHASH_ALL` (1) is rejected |
| `PSBT_IN_WITNESS_UTXO` value | Must equal `intent.vault_amount` |
| `PSBT_IN_WITNESS_UTXO` scriptPubKey | Must match `vault_build_vault_utxo_scriptpubkey(intent)` |
| `PSBT_IN_TAP_LEAF_SCRIPT` | Must contain the Vault UTXO leaf script |

**Input 1 (Assert:0 Payout UTXO for current `claimer_idx`):**

| PSBT field | Requirement |
|------------|-------------|
| `PSBT_IN_SEQUENCE` | Must equal `intent.payout_timelock` |
| `PSBT_IN_WITNESS_UTXO` value | Must equal `VAULT_DUST_LIMIT` (546 sat) |
| `PSBT_IN_WITNESS_UTXO` scriptPubKey | Must match Assert:0 Payout spk for `claimer_idx` |
| `PSBT_IN_TAP_LEAF_SCRIPT` | Must contain the Assert:0 Payout leaf for `claimer_idx` |

**Outputs (VP payout, `claimer_idx == 0`):**

| Index | scriptPubKey | Value |
|-------|-------------|-------|
| 0 | BIP-86 P2TR of depositor (`depositor_pk` tweaked) | `intent.vault_amount - intent.commission_fee - fee` |
| 1 | BIP-86 P2TR of VP (`vault_provider_pk` tweaked) | `intent.commission_fee` |
| 2 | BIP-86 P2TR of VP (`vault_provider_pk` tweaked, CPFP anchor) | `VAULT_DUST_LIMIT` |

**Outputs (VK payout, `claimer_idx > 0`):**

| Index | scriptPubKey | Value |
|-------|-------------|-------|
| 0 | BIP-86 P2TR of `keeper_pks[claimer_idx - 1]` | `intent.vault_amount - fee` |
| 1 | BIP-86 P2TR of `keeper_pks[claimer_idx - 1]` (CPFP anchor) | `VAULT_DUST_LIMIT` |

**Fee bound:** `fee ≤ intent.base_fee_rate × (500 + 55 × (keeper_count + challenger_count))` vbytes.

Payout validation is **silent** — no display. The device signs Input 0 (Vault UTXO) with the
depositor key. If signing fails at any point during payout the session is **invalidated**
(`SW_INCORRECT_DATA` or `SW_BAD_STATE` returned, session reset to `IDLE`).

**State after last payout's validation:** `SESSION2_PAYOUT_EXPECTED → SESSION2_COMPLETE`  
The final payout's signing runs in state `SESSION2_COMPLETE` — this is expected.

---

### Step 5 — Release the HTLC secret: `0x82 RELEASE_CONTEXT_SECRET`

Required state: `SESSION2_COMPLETE`.  
No payload (P1=0, P2=0, Lc=0).

Returns the 32-byte `htlc_preimage`. The device zeroes it in RAM before sending the
response, then resets to `IDLE`.

**State after:** `SESSION2_COMPLETE → IDLE`

Use the returned preimage to claim the Depositor Claim UTXO on-chain.

---

## Flow B — Refund

Refund is independent of the Session 1/2 lifecycle. It signs a tapscript path on the
HTLC output to recover funds back to the depositor after the CSV timelock expires.

Accepted in states: `IDLE`, `HASH_DERIVED`, `INTENT_LOADED`, `SESSION1_PREPEGIN_EXPECTED`.  
Blocked in: `SESSION2_PAYOUT_EXPECTED`, `SESSION2_COMPLETE` (PegIn already on-chain).  
Required wallet policy: **none** (`has_no_wallet_policy == true`).

#### PSBT requirements

| Field | Requirement |
|-------|-------------|
| `nVersion` | ≥ 2 |
| `nLockTime` | 0 |
| Input count | Exactly 1 |
| Output count | Exactly 1 |
| Input 0 sighash | `SIGHASH_DEFAULT` or `SIGHASH_ALL` |
| Input 0 `PSBT_IN_WITNESS_UTXO` | P2TR HTLC scriptPubKey (34 bytes, `OP_1 OP_PUSHBYTES_32 ...`) |
| Input 0 `PSBT_IN_TAP_LEAF_SCRIPT` | Exactly one entry; leaf version must be `0xC0` |
| Leaf script shape | Standard refund script: `<leaf_key> OP_CHECKSIGVERIFY <csv_value> OP_CHECKSEQUENCEVERIFY` |
| CSV value in leaf | When intent is loaded: must equal `intent.htlc_refund_timelock` |
| Input 0 `PSBT_IN_SEQUENCE` | Must satisfy BIP-68: `sequence ≥ csv_value`, bits 31 and 22 clear (block-based) |
| Input 0 `PSBT_IN_TAP_BIP32_DERIVATION` for `leaf_key` | Must be present; fingerprint must match this device's master key; path must be BIP-86 |
| Taproot commitment | Control block internal key must be `VAULT_NUMS_XONLY`; Merkle root must verify against HTLC spk |
| Output 0 | P2TR BIP-86 change output; must include valid `PSBT_OUT_TAP_BIP32_DERIVATION` pointing to this device |

The device derives the signing key from the BIP-86 path in `PSBT_IN_TAP_BIP32_DERIVATION`,
verifies the derived x-only key matches `leaf_key`, then signs.

The device **displays** amount reclaimed, fee, and destination address. User must approve.

**State after:** unchanged.

---

## Error recovery

| SW | Meaning | Recovery action |
|----|---------|-----------------|
| `0x9000` | Success | Continue to next step |
| `0x6985` | User rejected on device | Offer retry — device state is unchanged on rejection (no invalidation) |
| `0x6A80` | PSBT validation failure | Fix the PSBT; resend. State unchanged if before signing; **invalidated** if during Payout signing |
| `0xB007` | Wrong session state, or BIP-32 derivation failure during `DERIVE_CONTEXT_HASH` (session invalidated) | Check current state; restart from `DERIVE_CONTEXT_HASH` if invalidated |

**Retry rules:**
- **Pre-PegIn, PegIn, Refund:** PSBT can be resent after any non-signing failure; state is unchanged.
- **PegIn:** if signing fails after validation, state remains `SESSION2_PEGIN_EXPECTED` — host can resend the same PSBT.
- **Payout:** any failure after entering the payout handler invalidates the session. The host must restart from `DERIVE_CONTEXT_HASH`.
- **User rejection (`0x6985`):** never invalidates. The same APDU can be resent to re-prompt the user.

---

## Key ordering requirement for `APPROVE_VAULT_INTENT`

Keeper and challenger public keys must arrive in **strictly ascending lexicographic order**
within each group, packed as raw 32-byte x-only keys with no gaps between groups:

```
[ keeper_pks[0] (32B) ] ... [ keeper_pks[keeper_count-1] (32B) ]
[ challenger_pks[0] (32B) ] ... [ challenger_pks[challenger_count-1] (32B) ]
```

This order must be **consistent throughout the protocol** — Payout transactions reference
`keeper_pks[claimer_idx - 1]` in the same order, and Assert:0 Payout leaf scripts embed
keeper keys by index.

---

## Payout PSBT count and claimer index

`APPROVE_VAULT_INTENT` declares `keeper_count` keepers. The total number of Payout PSBTs
to sign is `1 + keeper_count`:

| Sequence | `payout_index` | Claimer | Outputs |
|----------|---------------|---------|---------|
| 1st | 0 | Vault Provider | 3 (depositor claim, VP commission, VP dust) |
| 2nd | 1 | Keeper 0 | 2 (VK claim, VK dust) |
| 3rd | 2 | Keeper 1 | 2 (VK claim, VK dust) |
| … | … | … | … |
| Last | `keeper_count` | Keeper N-1 | 2 (VK claim, VK dust) |

After the last payout is **validated** the device transitions to `SESSION2_COMPLETE`.
The final signing runs in that state — this is expected and handled correctly.
