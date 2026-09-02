# Babylon Vault Ledger App — Integration Guide

This guide describes how to integrate with the Babylon Vault Ledger app from the host side.
It covers the full APDU command sequence for each flow, the PSBT shape required by each
signing step, and the device session state at every point.

**CLA:** `0xE1` for all commands.  
**Full wire formats:** see [`apdu.md`](apdu.md).  
**Upstream derivation specs:** [`specs/derive-context-hash.md`](specs/derive-context-hash.md) (rev 2.1)
and [`specs/derive-vault-secrets.md`](specs/derive-vault-secrets.md) (rev 0.1).

---

## Derivation model (read first)

`DERIVE_CONTEXT_HASH` returns a **32-byte root**, not a hashlock. The device does **not**
retain any secret and has **no secret-release step**. The host is responsible for expanding
the root into the per-vault secrets it needs — the device only recomputes the on-chain
*commitments* (hashlock, auth-anchor) so it can bind them during signing.

```
root          = HKDF-SHA256(ikm = privkey(m/73681862'),
                            salt = "derive-context-hash",
                            info = SHA256(app_name) || SHA256(canonicalNetworkName)
                                   || connectedPubkey[33] || context,
                            L = 32)                              # returned to the host
```

The host then expands the root locally (HKDF-**Expand-only**, `PRK = root`, domain tag
`"babylonbtcvault"`, per `derive-vault-secrets`):

```
hashlockSecret[vout] = Expand(root, info("hashlock", I2OSP(vout, 4)), 32)   # per HTLC output
authAnchor           = Expand(root, info("auth-anchor", []),        32)     # shared per Pre-PegIn
wotsSeed[vout]       = Expand(root, info("wots-seed",  I2OSP(vout, 4)), 64) # host-only
```

The on-chain commitments (what the device recomputes and enforces):

```
htlc_hashlock   = SHA256(hashlockSecret[htlc_vout])   # embedded in the HTLC taproot leaf
auth_anchor_cmt = SHA256(authAnchor)                  # committed in the Pre-PegIn OP_RETURN
```

> **Note:** the hashlock is `SHA256(Expand(root, "hashlock" ‖ vout))`, **not** `SHA256(root)`.
> Because the secret is keyed per output index, one root can serve several HTLC outputs — but
> **this app supports a single HTLC output per Pre-PegIn (one `htlc_vout`)**; batched deposits
> are defined by the protocol but not implemented on-device in this version.

To **claim** the Depositor Claim UTXO later, the host uses `hashlockSecret[htlc_vout]` (which it
derived itself from the root) as the HTLC preimage — there is no device round-trip.

---

## Session state machine

The device tracks a single global session through three states (from `vault_context.h`):

```
IDLE
 └─ 0x81 DERIVE_CONTEXT_HASH ──────────────► HASH_DERIVED   (P2=0x00: Screen 1, returns root;
                                                             P2=0x01: silent, SW_OK only)
        └─ 0x80 APPROVE_VAULT_INTENT ──────► INTENT_LOADED  (root preserved; commitments
                                                             recomputed from it)

INTENT_LOADED
  ├─ 0x04 SIGN_PSBT (Pre-PegIn) ──────────────────────────► INTENT_LOADED  (silent, cap 1)
  ├─ 0x04 SIGN_PSBT (PegIn ×vault_count) ─────────────────► INTENT_LOADED  (silent)
  ├─ 0x04 SIGN_PSBT (Payout ×vault_count×(N+2)) ──────────► INTENT_LOADED  (silent)
  ├─ 0x04 SIGN_PSBT (NoPayout ×vault_count×(N+M)) ────────► INTENT_LOADED  (silent)
  └─ 0x04 SIGN_PSBT (Assert) ─────────────────────────────► INTENT_LOADED  (user review, uncapped)

IDLE / HASH_DERIVED / INTENT_LOADED
  └─ 0x04 SIGN_PSBT (Refund / Claim / WronglyChallenged / PoP) → (state unchanged)
```

`DERIVE_CONTEXT_HASH` is accepted from any state and resets the session before deriving. There
is no `RELEASE_CONTEXT_SECRET`: the host receives the 32-byte root (P2=`0x00`) and expands
the per-vault secrets itself.

`APPROVE_VAULT_INTENT` requires `HASH_DERIVED` for P1=`0x00` (scalars). The three-phase
command (P1=`0x00` scalars → P1=`0x01` per-vault groups → P1=`0x02` public keys) transitions
to `INTENT_LOADED` on user approval. There is no session-1/session-2 distinction: all
intent-bound signing flows are accepted from `INTENT_LOADED` in any order.

**Standalone flows** (Refund, Claim, WronglyChallenged, PoP) are accepted from any
state. They do not change state.

**Assert is the exception.** It is dispatched like a standalone flow — by leaf shape, with no
wallet policy — but it requires `INTENT_LOADED`, because the device verifies the leaf's signer
prefix against the approved keeper and challenger keys and those exist nowhere else. Since
`APPROVE_VAULT_INTENT` itself requires `HASH_DERIVED`, a host signing an Assert in a fresh session
must replay `DERIVE_CONTEXT_HASH` → `APPROVE_VAULT_INTENT` first. Note this resets all per-type
signature counters. See [APP_SPECIFICATION.md](../APP_SPECIFICATION.md) §7.

**Invalidation** — any signing failure after a signature is produced wipes the `root` via
`explicit_bzero` and resets to `IDLE`. PSBT **validation** failures (before signing) leave
state unchanged so the host can fix and retry. See [Error recovery](#error-recovery).

---

## Flow A — Full deposit

### Step 1 — Derive the root: `0x81 DERIVE_CONTEXT_HASH`

Required state: any (calling from any state resets the session first).

Multi-chunk streaming command. **P2 selector controls user visibility:**

| P2 | Behaviour |
|----|-----------|
| `0x00` | Show Screen 1 (user approval of `app_name`); return 32-byte root on final chunk |
| `0x01` | Silent re-derivation (no display); return `SW_OK` only on final chunk |

Use P2=`0x00` on the first connection (host needs the root to build the Pre-PegIn). Use
P2=`0x01` on subsequent connections (root is re-derived silently; `APPROVE_VAULT_INTENT` then
loads the intent again for user approval).

**P1=`0x00` — initial chunk payload:**

```
[ app_name_len: 1B ][ app_name: L B ][ path_len: 1B ][ path: path_len×4B BE ]
[ context_total_len: 2B BE ][ first context chunk: remaining bytes ]
```

- `app_name` — host sends `"babylon-btc-vault"`. Validated for length and character set
  (`[a-z0-9\-]`) only: it is **not** an authentication signal, and any caller can claim this
  string. Screen 1 shows it and nothing else, so the user cannot distinguish two callers
  using the same name, and approving releases a deterministic secret root. See
  "DERIVE_CONTEXT_HASH — caller identity is not authenticated" in `APP_SPECIFICATION.md`
  for the accepted deviation from the protocol spec's requirement to display a requesting
  origin.
- `path` — BIP-32 path of the **connectedPubkey**; the device derives the 33-byte compressed
  key and mixes it into `info`.
- `context_total_len` — total `vaultContext` byte count (1–1024), **2 bytes big-endian**.
- first context chunk — initial bytes of `vaultContext` (may be empty if `context_total_len`
  exceeds the remaining APDU space).

If all context bytes fit in the initial APDU, the stream finalizes immediately and returns the
response. Otherwise the device returns `SW_OK` and expects P1=`0x01` continuation chunks.

**P1=`0x01` — continuation chunk payload:** raw context bytes. Repeat until
`context_total_len` bytes are delivered.

**Response (final chunk only):** P2=`0x00` → 32-byte root; P2=`0x01` → `SW_OK`, no data.

The device retains the root in the session context to recompute on-chain commitments at
approve-time; no preimage is stored, and nothing is released separately later.

**State after:** `→ HASH_DERIVED`

---

### Step 2 — Load the vault intent: `0x80 APPROVE_VAULT_INTENT`

Required state: `HASH_DERIVED` (P1=`0x00` is rejected from any other state).

Three-phase streaming command — all three phases must complete before the approval screen is
shown:

| Phase | P1 | Payload | Repeats |
|-------|----|---------|---------|
| Scalars | `0x00` | 13 scalar TLV fields (≈ 128 B total) | Once |
| Per-vault groups | `0x01` | One or more complete group records per APDU | Until `vault_count` groups received |
| Public key batch | `0x02` | TLV-encoded 32-byte x-only keys | Until `keeper_count + challenger_count` keys received |

The device displays the vault parameters for user approval only after all groups and keys are
delivered. On approval the device saves the `root` across the internal session reset, then
recomputes and stores the per-vault on-chain commitments:

```
htlc_hashlock[i] = SHA256(Expand(root, "hashlock" || I2OSP(htlc_vout_i, 4)))
auth_anchor_hash = SHA256(Expand(root, "auth-anchor"))
```

The root is then zeroed immediately — commitments are held for subsequent signing validation.

`prepegin_txid` (tag `0x0027`) is always set in the intent (the host computes the Pre-PegIn
txid before calling `APPROVE_VAULT_INTENT`). All intent-bound signing flows are available from
`INTENT_LOADED`; there is no session-1/session-2 branching.

**State after:** `HASH_DERIVED → INTENT_LOADED`

---

### Step 3 — Sign Pre-PegIn: `0x04 SIGN_PSBT`

Required state: `INTENT_LOADED`.  
Required wallet policy: **a native SegWit wallet policy provided** (host passes the policy;
`has_no_wallet_policy == false`). Accepted templates: `wpkh(@0/**)` / `wsh(...)` (SegWit v0)
and `tr(...)` (SegWit v1). `sh(wpkh(@0/**))` (BIP-49) and `pkh(@0/**)` (BIP-44) are rejected
with `SW_INCORRECT_DATA`: their inputs spend through a scriptSig the device never sees, so
the reconstructed Pre-PegIn txid could not match the broadcast one.

#### PSBT requirements

| Field | Requirement |
|-------|-------------|
| `nVersion` | ≥ 2 |
| Inputs | All inputs must be wallet-policy owned — device rejects any non-internal input, and any policy that is not native SegWit |
| Sighash | `SIGHASH_DEFAULT` (absent) or `SIGHASH_ALL` (1) per input |
| Output at `htlc_vout` | P2TR scriptPubKey matching `vault_build_htlc_scriptpubkey(intent, htlc_hashlock)` |
| Output at `htlc_vout` value | Must be in `[vault_amount + depositor_claim_value, vault_amount + depositor_claim_value + pegin_max_fee]` |
| **Auth-anchor output** | Optional `OP_RETURN` output with scriptPubKey `6A 20 ‖ auth_anchor_hash` (34 bytes) and **value 0**; at most one permitted |
| **CPFP anchor output** | Optional P2TR(depositor_pk) BIP-86 key-path output at exactly **546 sat** (`VAULT_DUST_LIMIT`); at most one permitted |
| All other outputs | Must be BIP-86 internal change |

The auth-anchor `OP_RETURN` payload is bound to `SHA256(authAnchor)` recomputed on-device from the root — the host cannot substitute it. Its value must be **0** (it is provably unspendable; a non-zero value would silently burn change).

The CPFP anchor at `VAULT_DUST_LIMIT` is appended by the protocol to every Pre-PegIn transaction so the depositor can fee-bump via CPFP if needed.

Pre-PegIn signing is **silent** — no per-signing screen is shown. The fee bound is enforced by `prepegin_max_fee` displayed during intent approval (Screen 2). The device verifies the PSBT and signs all BIP-86 inputs via the standard wallet-policy path. No custom signing.

**State after:** `INTENT_LOADED` (unchanged). Per-type cap: at most 1 Pre-PegIn signature
per approved intent.

---

### Step 4 — Sign PegIn: `0x04 SIGN_PSBT` × `vault_count`

Required state: `INTENT_LOADED`.  
Required wallet policy: **none** (host must not provide a wallet policy).

One PegIn PSBT per vault group (one per `htlc_vout`). They may be sent in any order.

#### PSBT requirements

| Field | Requirement |
|-------|-------------|
| `nVersion` | Must be **3** (TRUC) |
| `nLockTime` | 0 |
| Input count | Exactly 1 |
| Output count | Exactly 3 |
| Input 0 `PSBT_IN_PREVIOUS_TXID` | Must equal `intent.prepegin_txid` (little-endian) |
| Input 0 `PSBT_IN_OUTPUT_INDEX` | Must equal `intent.htlc_vout` for this vault group |
| Input 0 `PSBT_IN_SEQUENCE` | Must be `0xFFFFFFFE` (RBF, no relative lock) |
| Input 0 `PSBT_IN_SIGHASH_TYPE` | `SIGHASH_DEFAULT` (absent or 0) only |
| Input 0 `PSBT_IN_TAP_INTERNAL_KEY` | Must be `VAULT_NUMS_XONLY` (no key-path spend) |
| Input 0 `PSBT_IN_TAP_MERKLE_ROOT` | Must equal `vault_build_htlc_merkle_root(intent, htlc_hashlock)` |
| Input 0 `PSBT_IN_TAP_LEAF_SCRIPT` | Must include HTLC Leaf 0 (hashlock script bound to `htlc_hashlock`) |
| Output 0 scriptPubKey | Must match `vault_build_vault_utxo_scriptpubkey(intent)` |
| Output 0 value | Must equal `intent.vault_amount` |
| Output 1 scriptPubKey | Must match `vault_build_depositor_claim_scriptpubkey(intent)` |
| Output 1 value | Must equal `intent.depositor_claim_value` |
| Output 2 scriptPubKey | `0x51 0x02 0x4e 0x73` (P2A anchor — `OP_1 PUSHBYTES_2 4e73`) |
| Output 2 value | Must equal `P2A_ANCHOR_VALUE` (240 sat) |
| Fee (`htlc_value − vault_amount − depositor_claim_value − P2A_ANCHOR_VALUE`) | Must be ≤ `intent.pegin_max_fee` |

Here `htlc_hashlock` is the value the device recomputed from the root at approve-time
(`SHA256(Expand(root, "hashlock" ‖ I2OSP(htlc_vout, 4)))`), so the host must build the HTLC
leaf with the matching `hashlockSecret[htlc_vout]`.

PegIn validation is **silent** — no display shown to the user. The device signs HTLC Leaf 0
(hashlock tapscript) with the depositor key at `intent.depositor_path` (SIGHASH_DEFAULT).
Per-type cap: at most `vault_count` PegIn signatures per approved intent.

**State after:** `INTENT_LOADED` (unchanged)

---

### Step 5 — Sign Payout transactions: `0x04 SIGN_PSBT` × `vault_count × (keeper_count + 2)`

Required state: `INTENT_LOADED`.  
Required wallet policy: **none**.

One Payout PSBT per claimer per vault group. There are `keeper_count + 2` claimers per vault
(VP, VK_1…VK_N, Depositor), giving `vault_count × (keeper_count + 2)` total Payout PSBTs.
They may be sent in any order across vault groups; the device tracks which per-slot signatures
have been issued via `payout_claimer_mask`.

#### PSBT requirements (apply to every payout)

| Field | Requirement |
|-------|-------------|
| `nVersion` | ≥ 2 |
| `nLockTime` | 0 |
| Input count | Exactly 2 |
| Output count | 3 (VP claimer) or 2 (VK or Depositor claimer) |

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
| `PSBT_IN_WITNESS_UTXO` value | In `[VAULT_DUST_LIMIT, VAULT_DUST_LIMIT + base_fee_rate × MAX_COUNCIL_NOPAYOUT_VSIZE]` — Assert:0 is funded to cover the CouncilNoPayout that may spend it instead, so its value scales with the fee rate rather than being fixed at dust |
| `PSBT_IN_WITNESS_UTXO` scriptPubKey | Must match Assert:0 Payout spk for `claimer_idx` |
| `PSBT_IN_TAP_LEAF_SCRIPT` | Must contain the Assert:0 Payout leaf for `claimer_idx` |

**Outputs (VP claimer — 3 outputs):**

| Index | scriptPubKey | Value |
|-------|-------------|-------|
| 0 | BIP-86 P2TR of depositor (device-verified) | `intent.vault_amount - intent.commission_fee - fee` |
| 1 | Any standard address (VP's registered address) | ≤ `intent.commission_fee` |
| 2 | CPFP anchor (host-provided) | `VAULT_DUST_LIMIT` |

**Outputs (VK or Depositor claimer — 2 outputs):**

| Index | scriptPubKey | Value |
|-------|-------------|-------|
| 0 | Any standard address (VK's) or BIP-86 P2TR of depositor (device-verified when Depositor is claimer) | `intent.vault_amount - fee` |
| 1 | CPFP anchor (host-provided, or BIP-86 P2TR of depositor when Depositor is claimer) | `VAULT_DUST_LIMIT` |

Claimer identity (VP, VK_i, or Depositor) is established from the Input 1 Assert:0 leaf
script read from the PSBT, not from output scripts.

**Fee bound:** `fee ≤ intent.base_fee_rate × (500 + 55 × (keeper_count + challenger_count))` vbytes.

Payout signing is **silent** — no per-signing screen is shown. The payout parameters were already approved during intent review. See APP_SPECIFICATION.md §3.

The device displays the Payout Finalize screen (Screen 8) showing: Vault UTXO txid, amount
received, destination address, CPFP anchor address, and transaction fee. User must approve.
The device signs Input 0 (Vault UTXO) with the depositor key. Per-type cap: at most
`vault_count × (keeper_count + 2)` Payout signatures per approved intent.

**State after:** `INTENT_LOADED` (unchanged)

---

### Step 6 — Sign NoPayout transactions: `0x04 SIGN_PSBT` × `vault_count × (keeper_count + challenger_count)`

Required state: `INTENT_LOADED`.  
Required wallet policy: **none**.

One NoPayout PSBT per depositor-graph challenger per vault group. The depositor-graph challenger
set is all VaultKeepers plus all UniversalChallengers (the VaultProvider is excluded). Total:
`vault_count × (keeper_count + challenger_count)` NoPayout PSBTs. They may be sent in any order.

#### PSBT requirements

| Field | Requirement |
|-------|-------------|
| `nVersion` | ≥ 2 |
| `nLockTime` | 0 |
| Input count | Exactly 3 |
| Output count | Exactly 1 |
| Input 0 (signed) | P2TR script-path spend of Assert:0 (depositor graph); leaf: `<Depositor> OP_CHECKSIGVERIFY <Challenger_j> OP_CHECKSIG`; `SIGHASH_DEFAULT`. `PSBT_IN_OUTPUT_INDEX` must be 0; value in `[VAULT_DUST_LIMIT, VAULT_DUST_LIMIT + base_fee_rate × MAX_COUNCIL_NOPAYOUT_VSIZE]` |
| Input 1, 2 (not signed) | ChallengeAssertX_j:0 / ChallengeAssertY_j:0; committed via Input 0 `SIGHASH_DEFAULT`. Values are **not** constrained individually — they are read untrusted and used only to compute the fee, so fund them as the protocol requires (they exceed `VAULT_DUST_LIMIT` above 1 sat/vB) |
| Output 0 | BIP-86 P2TR of `Challenger_j` (key-path tweak, no script tree) — reconstructed and compared byte-for-byte by the device, **not** an arbitrary registered address; value must be ≥ `VAULT_DUST_LIMIT` |
| Fee | `Σ inputs − Σ outputs` must be non-negative and `≤ base_fee_rate × MAX_NOPAYOUT_VSIZE` (450) |

The device reconstructs the 2-key NoPayout leaf from `Depositor` and `Challenger_j` (keepers
first, then challengers, by index). Per-type cap: at most
`vault_count × (keeper_count + challenger_count)` NoPayout signatures per approved intent.

**State after:** `INTENT_LOADED` (unchanged)

---

### Step 7 — Proof of Possession: `0x04 SIGN_PSBT` (BIP-322)

Required state: any.  
Required wallet policy: **none**.

Standalone BIP-322 `bip322-simple` signing of the PoP message
`<eth_address>:<chain_id>:pegin:<registry_address>` using the depositor's BIP-86 key.

The device validates the message grammar, reconstructs the `to_spend` virtual transaction,
and signs the `to_sign` PSBT bound to it. Screen 7 displays the parsed message fields
(Ethereum address, chain ID, registry address, Bitcoin address) for user approval.

| Field | Requirement |
|-------|-------------|
| Input count | Exactly 1 |
| Input 0 | Spends the BIP-322 `to_spend` virtual txid; key-path BIP-86 spend |
| Sighash | `SIGHASH_DEFAULT` |

**State after:** unchanged.

---

### Claiming the Depositor Claim UTXO (host-side, no device call)

To spend the Depositor Claim UTXO on-chain, the host reveals the HTLC preimage. That preimage
is `hashlockSecret[htlc_vout] = Expand(root, "hashlock" ‖ I2OSP(htlc_vout, 4))`, which the host
already derived from the root returned by `DERIVE_CONTEXT_HASH` (Step 1). No further APDU is
needed — the device never returns the secret.

---

## Flow B — Refund

Refund is a standalone flow that signs a tapscript path on the HTLC output to recover funds
back to the depositor after the CSV timelock expires.

Accepted in states: `IDLE`, `HASH_DERIVED`, `INTENT_LOADED`.  
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
| CSV value in leaf | At most `0xFFFF` — the BIP-68 block-count field is all `OP_CHECKSEQUENCEVERIFY` acts on, so a larger operand would claim a delay the transaction does not enforce. When intent is loaded: must equal `intent.htlc_refund_timelock`; otherwise must be `≥ 72` (protocol minimum) |
| Input 0 `PSBT_IN_SEQUENCE` | Must equal `csv_value` **exactly** (compared unmasked), with bits 31 (disable) and 22 (time-based) clear. Note this is stricter than BIP-68 itself, which would allow any `sequence ≥ csv_value`: the device signs only the timelock it displayed, so bits consensus ignores are rejected rather than masked away |
| Input 0 `PSBT_IN_TAP_BIP32_DERIVATION` for `leaf_key` | Must be present; fingerprint must match this device's master key; path must be BIP-86 |
| Taproot commitment | Control block internal key must be `VAULT_NUMS_XONLY`; Merkle root must verify against HTLC spk |
| Output 0 | P2TR BIP-86 change output; must include valid `PSBT_OUT_TAP_BIP32_DERIVATION` pointing to this device |

The device derives the signing key from the BIP-86 path in `PSBT_IN_TAP_BIP32_DERIVATION`,
verifies the derived x-only key matches `leaf_key`, then signs.

The device **displays** the Pre-PegIn txid, amount reclaimed, refund timelock (blocks), fee, and
reclaim address. User must approve.

**State after:** unchanged.

---

## Error recovery

| SW | Meaning | Recovery action |
|----|---------|-----------------|
| `0x9000` | Success | Continue to next step |
| `0x6985` | User rejected on device | Offer retry — device state is unchanged on rejection (no invalidation) |
| `0x6A80` | PSBT/TLV validation failure (bad field, wrong output policy, missing auth-anchor, …) | Fix the PSBT; resend. State unchanged if before signing; **invalidated** if during Payout signing |
| `0x6F00` | BIP-32 derivation failure (connected-pubkey in `DERIVE_CONTEXT_HASH`, or depositor key) | Check the derivation path; session is reset |
| `0xB007` | Wrong session state (`SW_BAD_STATE`), or HMAC/HKDF failure during `DERIVE_CONTEXT_HASH` | Check current state; run `DERIVE_CONTEXT_HASH` first if a signing step was rejected for a missing root |
| `0xB00A` | Per-type signature cap exceeded (`SW_CAP_EXCEEDED`) — more signatures were requested than the approved intent allows (Pre-PegIn: 1, PegIn: `vault_count`, Payout: `vault_count×(N+2)`, NoPayout: `vault_count×(N+M)`). Intent is nullified. | Re-run `DERIVE_CONTEXT_HASH` + `APPROVE_VAULT_INTENT` to get fresh user approval and reset all counters. |

**Retry rules:**
- **Pre-PegIn, PegIn, NoPayout, Refund:** PSBT can be resent after any validation failure; state is unchanged. Session survives signing failures on these flows.
- **Payout:** any signing failure invalidates the session. The host must restart from `DERIVE_CONTEXT_HASH`.
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

`APPROVE_VAULT_INTENT` declares `keeper_count` keepers, `challenger_count` challengers, and
`vault_count` vaults. The total number of Payout PSBTs to sign per vault group is
`keeper_count + 2` (one per claimer), giving `vault_count × (keeper_count + 2)` in total.
PSBTs may be sent in any order across vault groups.

| Claimer | Input 1 leaf key | Outputs |
|---------|-----------------|---------|
| Vault Provider | VP key in Assert:0 Payout leaf | 3 (depositor, VP commission, VP CPFP anchor) |
| VaultKeeper 0 | VK_0 key in Assert:0 Payout leaf | 2 (VK claim, VK CPFP anchor) |
| VaultKeeper 1 | VK_1 key in Assert:0 Payout leaf | 2 (VK claim, VK CPFP anchor) |
| … | … | … |
| VaultKeeper N-1 | VK_{N-1} key in Assert:0 Payout leaf | 2 (VK claim, VK CPFP anchor) |
| Depositor | Depositor key in Assert:0 Payout leaf | 2 (depositor claim, depositor CPFP anchor) |

The device identifies the claimer from the Input 1 Assert:0 leaf key, not from output scripts.
After all Payout signatures have been issued the session remains in `INTENT_LOADED`; there is
no terminal state and no separate secret-release step.
