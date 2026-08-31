# Babylon Vault — App Specification

> **v22 HLD alignment:** This document reflects the device design as of HLD v22 (NAPPS-1466). For a full change history see [`CHANGELOG.md`](CHANGELOG.md).

## About

This document describes the APDU interface and transaction types supported by the **Babylon Vault** Ledger application (`app-babylon-vault`).

The app is a dedicated btcext extension for the [Babylon protocol](https://babylonlabs.io/). It enables a Ledger device to participate in the full Babylon vault lifecycle:

- Derive a 32-byte session root and bind it to on-chain commitments (`DERIVE_CONTEXT_HASH`)
- Review and approve vault parameters and participant keys (`APPROVE_VAULT_INTENT`)
- Sign eight Bitcoin transaction types: Pre-PegIn, PegIn, Payout, Refund, Claim, Assert, Wrongly-Challenged (WC), NoPayout

The app extends [app-btcext-boilerplate](https://github.com/LedgerHQ/app-btcext-boilerplate). Standard btcext APDUs (e.g. `GET_EXTENDED_PUBKEY`, `SIGN_PSBT`) are handled by the base app. Only the two custom INS codes below are specific to this app.

For full wire-format details see [`docs/apdu.md`](docs/apdu.md).

---

## APDUs

All custom APDUs use **CLA `0xE1`**.

| INS    | Name                    | Description |
|--------|-------------------------|-------------|
| `0x80` | `APPROVE_VAULT_INTENT`  | Three-phase APDU. **P1=`0x00`**: parse and validate 13 scalar TLV fields. **P1=`0x01`**: receive per-vault group TLV (6 fields per vault group, repeated `vault_count` times). **P1=`0x02`**: stream keeper then challenger x-only public keys (TLV-wrapped; tag `2B` + length `1B` + 32-byte key). After all keys are received the device displays the vault parameters for user approval and, on confirmation, transitions the session to `INTENT_LOADED`. |
| `0x81` | `DERIVE_CONTEXT_HASH`   | Chunked streaming APDU (**P1=`0x00`** initial chunk, **P1=`0x01`** continuation). Derives a 32-byte context root from the device's BIP-32 key at `m/73681862'` via HKDF-SHA-256 and stores it in the session context. **P2=`0x00`**: shows a user approval screen ("Allow derivation?") and, on confirmation, returns the raw 32-byte root to the host. **P2=`0x01`**: silent re-derivation; returns `SW_OK` with no data. |

### APPROVE_VAULT_INTENT — intent fields

#### P1=`0x00` — scalar fields (13)

The TLV payload in `P1=0x00` encodes the following 13 scalar fields (tag `2B` + length `1B` + value):

| Field | Validation rule |
|---|---|
| `structure_type` | must equal the vault structure type constant |
| `version` | must equal the current protocol version constant |
| `coin_type` | must equal `BIP44_COIN_TYPE` for the active network |
| `base_fee_rate` | present |
| `pegin_csv_timelock` | `[72, 1008]` blocks inclusive |
| `payout_timelock` | `(90, 4032)` blocks exclusive |
| `prepegin_txid` | 32-byte txid |
| `htlc_refund_timelock` | `[72, 4320]` blocks inclusive |
| `depositor_derivation_path` | BIP-86 path `m/86'/coin_type'/acct'/chg/idx`, exactly 5 levels |
| `keeper_count` | `[1, 32]` inclusive |
| `challenger_count` | `[1, 32]` inclusive |
| `vault_count` | `[1, 10]` inclusive |
| `prepegin_max_fee` | `uint64`; maximum allowed fee (satoshis) for the Pre-PegIn transaction; must be non-zero |

Duplicate tags, unknown tags, and non-canonical encodings are all rejected.

#### P1=`0x01` — per-vault group fields (6 per vault)

After P1=`0x00`, the host sends one APDU per vault group (repeated `vault_count` times). Each group payload encodes the following 6 fields, specific to one vault in a batch Pre-PegIn:

| Field | Validation rule |
|---|---|
| `htlc_vout` | output index of the HTLC in the Pre-PegIn transaction; must be strictly ascending across groups |
| `vault_provider_pk` | 32-byte x-only public key; must be a valid secp256k1 point |
| `vault_amount` | `> commission_fee + 2 × DUST` |
| `commission_fee` | `≥ DUST` (546 sat) |
| `depositor_claim_value` | present |
| `pegin_max_fee` | present |

Groups must arrive in strictly ascending `htlc_vout` order. Multiple group records may be packed back-to-back within one APDU payload.

#### P1=`0x02` — key batch

The key batch must deliver exactly `keeper_count` keeper keys followed by `challenger_count` challenger keys (x-only, 32 bytes each, TLV-wrapped with 2-byte tags). All keys must be:
- globally unique across all roles
- pairwise disjoint with `vault_provider_pk` (per group) and the depositor key
- sorted in ascending lexicographic order within each group

---

## Transaction Types

The app recognises eight Bitcoin transaction types via the `SIGN_PSBT` hook. The device independently reconstructs the expected scripts from the loaded `vault_intent_t` and rejects any PSBT whose scripts do not match.

### 1. Pre-PegIn

The depositor creates one or more HTLC outputs (one per vault group) that lock BTC until the vault is finalised.

**Requires:** `INTENT_LOADED` state.

**PSBT requirements:**
- Inputs: wallet inputs (BIP-86 P2TR), signed by the base app
- Output at `htlc_vout` (per group): P2TR matching the 2-leaf HTLC reconstructed from the intent; value in `[vault_amount + depositor_claim_value + 240, vault_amount + depositor_claim_value + 240 + pegin_max_fee]` (the minimum covers `vault_amount`, `depositor_claim_value`, and the 240-sat P2A anchor funded by the PegIn transaction)
- Optional OP_RETURN output (positioned strictly after all HTLC outputs): 34-byte scriptPubKey `0x6A 0x20 <auth_anchor_hash>`, value `0`; when present the device validates the 32-byte payload against `auth_anchor_hash = SHA256(Expand(root, "auth-anchor"))` computed at `APPROVE_VAULT_INTENT` time. At most one such output is permitted.
- Optional CPFP anchor output (positioned strictly after all HTLC outputs): P2TR(depositor_pk) BIP-86 key-path scriptPubKey, value exactly `VAULT_DUST_LIMIT` (546 sat). At most one such output is permitted.
- All other outputs: BIP-86 change outputs owned by this device (verified via `TAP_BIP32_DERIVATION`)
- Sighash: `SIGHASH_ALL` or `SIGHASH_DEFAULT`; version ≥ 2; locktime = 0
- Fee: `total_inputs − total_outputs ≤ prepegin_max_fee`

**User display:** Pre-PegIn signing is silent — no per-signing screen is shown. The fee bound (`prepegin_max_fee`) is displayed on the intent approval screen (Screen 2).

**HTLC scripts (2-leaf P2TR, NUMS internal key):**
- *Leaf 0 — Hashlock + All-Party:* `OP_SIZE <32> OP_EQUALVERIFY / OP_SHA256 <h> OP_EQUALVERIFY / <D> OP_CHECKSIGVERIFY / <VP> OP_CHECKSIGVERIFY / <VK N-of-N> / <UC M-of-M>`
- *Leaf 1 — Refund:* `<D> OP_CHECKSIGVERIFY / <T_refund> OP_CHECKSEQUENCEVERIFY`

---

### 2. PegIn (silent)

Spends the HTLC and creates the Vault UTXO + Depositor Claim UTXO + P2A anchor. No user display; parameters were already approved during `APPROVE_VAULT_INTENT`.

**Requires:** `INTENT_LOADED` state.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Input 0 prevout | `prepegin_txid:htlc_vout` from intent |
| Input 0 sequence | `0xFFFFFFFE` |
| Version / locktime | 3 / 0 |
| Output count | Exactly 3 |
| Output 0 | Reconstructed Vault UTXO scriptPubKey; value = `vault_amount` |
| Output 1 | Reconstructed Depositor Claim scriptPubKey; value = `depositor_claim_value` |
| Output 2 | P2A anchor; value = `P2A_ANCHOR_VALUE` (240 sat) |
| PSBT metadata | `TAP_LEAF_SCRIPT`, `TAP_INTERNAL_KEY`, `TAP_MERKLE_ROOT` must match reconstructed values |
| Secret hash binding | HTLC Leaf 0 in the PSBT must embed `h = htlc_hashlock` from the session context |
| Sighash | `SIGHASH_DEFAULT` only |
| Fee | `htlc_value − (vault_amount + depositor_claim_value + 240) ≤ pegin_max_fee` |

**Vault UTXO script (1-leaf P2TR, NUMS internal key):**
`<D> OP_CHECKSIGVERIFY / <VP> OP_CHECKSIGVERIFY / <VK N-of-N> / <UC M-of-M> / <P> OP_CHECKSEQUENCEVERIFY`

**Depositor Claim script (1-leaf P2TR, NUMS internal key):**
`<D> OP_CHECKSIG`

---

### 3. Payout (silent)

Pre-signs `vault_count × (keeper_count + 2)` payout transactions — one per potential claimer per vault group (VP, VK_1..VK_N, and Depositor). The device auto-detects the claimer identity and vault group from the PSBT structure (witness UTXO scriptPubKey and prevout txid); any signing order is accepted. No user display; parameters were already approved.

**Requires:** `INTENT_LOADED` state.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 2 |
| Input 0 prevout | `computed_pegin_txid:0` (computed deterministically from intent, matched against PSBT) |
| Input 0 sequence | `pegin_csv_timelock` (P) |
| Input 1 sequence | `payout_timelock` (t2) |
| Input 0 leaf script | Matches reconstructed Vault UTXO leaf |
| Input 1 leaf script | Matches reconstructed Assert:0 Payout leaf for detected claimer |
| Output count | 3 for VP claimer; 2 for VK or Depositor claimer |
| Fee bound | `actual_fee ≤ base_fee_rate × (500 + 55 × (N+M))` |
| Sighash | `SIGHASH_DEFAULT` only |
| Version / locktime | ≥ 2 / 0 |

The device signs Input 0 (Vault UTXO leaf). Input 1 (Assert:0) is verified but not signed by the device.

**Assert:0 Payout leaf script:**
`<Claimer> OP_CHECKSIGVERIFY / <AppChallengers K-of-K> / <UC M-of-M> / <t2> OP_CHECKSEQUENCEVERIFY`

where `AppChallengers = {VP, VK_1..VK_N} \ {Claimer}` for VP or VK claimers, or `{VK_1..VK_N}` for the Depositor claimer, sorted lexicographically.

---

### 4. Refund (standalone)

The depositor reclaims BTC from the HTLC before the vault is finalised (timelock branch).

**Requires:** any state (including `IDLE`); does not affect session progress.

**PSBT requirements:**
- Single input spending the HTLC; leaf script read from `TAP_LEAF_SCRIPT` in the PSBT
- Leaf script shape: `<key> OP_CHECKSIGVERIFY <n> OP_CHECKSEQUENCEVERIFY`; `<key>` must be owned by this device at the BIP-32 path in `TAP_BIP32_DERIVATION`; control block must produce a valid Taproot commitment
- CSV operand `<n>`: a positive CScriptNum push (`OP_1`–`OP_16`, `OP_PUSHBYTES_1`–`OP_PUSHBYTES_4`, or `OP_PUSHDATA1`; minimal encoding is not enforced), at most `0xFFFF` — the BIP-68 block-count field is the only part of the operand `OP_CHECKSEQUENCEVERIFY` acts on, so a larger value would display a delay the transaction does not enforce. `INTENT_LOADED` additionally requires `<n> == htlc_refund_timelock`; outside it, `<n> ≥ 72` (the protocol minimum)
- `PSBT_IN_SEQUENCE`: must equal `<n>` **exactly** (compared unmasked), with the BIP-68 disable (bit 31) and time-based (bit 22) flags clear. Bits consensus ignores are rejected rather than masked away, so the displayed timelock is always the one that will be enforced
- Single output: BIP-86 P2TR (`account_index ≤ 100`, `address_index ≤ 10000`)
- Sighash: `SIGHASH_DEFAULT`; version ≥ 2; locktime = 0

**User display:** Pre-PegIn txid, reclaimed amount, refund timelock (blocks), transaction fee, reclaim address.

---

### 5. NoPayout (silent)

The depositor pre-signs a NoPayout leaf for a specific challenger, authorising that challenger to claim the vault funds without a payout transaction.

**Requires:** `INTENT_LOADED` state; no wallet policy; exactly 3 inputs and 1 output.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 3 |
| Output count | Exactly 1 |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | 68 bytes: `<D>(32B) OP_CHECKSIGVERIFY <Cj>(32B) OP_CHECKSIG` |
| `<D>` key | Must match `intent.depositor_pk` |
| `<Cj>` key | Must be one of the keeper or challenger keys from the loaded intent |
| Full leaf | Reconstructed from intent and compared byte-for-byte (prevents parameter substitution) |
| WITNESS_UTXO value | Must be ≤ `VAULT_DUST_LIMIT` (546 sat) |
| Sighash | `SIGHASH_DEFAULT` only |
| Output 0 | P2TR of `Cj` (key-path tweak, no scripts); verified by device |
| Counter | At most `vault_count × (keeper_count + challenger_count)` NoPayout signings allowed per session |

**NoPayout leaf script:**
`<D> OP_CHECKSIGVERIFY <Cj> OP_CHECKSIG`

**User display:** none (silent signing).

---

### 6. Claim (standalone)

The depositor spends the Depositor Claim UTXO created by the PegIn transaction.

**Requires:** any state (including `IDLE`); no wallet policy; 34-byte leaf `<D> OP_CHECKSIG`.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Output count | Exactly 2 |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | 34 bytes: `<D>(32B) OP_CHECKSIG` |
| Internal key | NUMS (single-leaf P2TR) |
| `<D>` key | Verified via `TAP_BIP32_DERIVATION`; BIP-86 path (`m/86'/coin_type'/acct'/chg/idx`, `account_index ≤ 100`, `address_index ≤ 10000`); derived key must match leaf key |
| Taproot commitment | Control block must produce a valid commitment to the leaf |
| Sighash | `SIGHASH_DEFAULT` only |
| Output 0 | ClaimAssertConnector; not verified by device (host-provided) |
| Output 1 | BIP-86 P2TR(`<D>`); value = `VAULT_DUST_LIMIT` (CPFP anchor) |
| Fee | `input_value − total_outputs > 0` (positive fee required) |

**Depositor Claim leaf script:**
`<D> OP_CHECKSIG`

**User display:** amount spent (input UTXO value), connector amount (Output 0 value), fee, PegIn txid (from `PSBT_IN_PREVIOUS_TXID`).

---

### 7. Assert (standalone)

The depositor asserts the claim by spending a ClaimAssertConnector UTXO.

**Requires:** `INTENT_LOADED`; no wallet policy; Assert leaf whose signer prefix matches the approved intent (see the leaf script below).

> Assert is the one standalone flow that is **not** state-independent. The keys its leaf must be checked against — the VaultKeepers and UniversalChallengers — exist nowhere but the approved intent, so outside `INTENT_LOADED` the device cannot distinguish a genuine Assert leaf from a hand-crafted one and refuses to sign. Shape bytes cannot substitute: the ~11 KB WOTS body is host-chosen and cannot be derived on-device, so an attacker pads around any fixed offsets the device checks. See the leaf script below.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Output count | Not enforced (host-provided connector tree) |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | Total length strictly greater than the NoPayout leaf (68 bytes); `OP_CHECKSIGVERIFY` at byte 33; `OP_PUSHBYTES_32` at byte 34 and `OP_CHECKSIG` at byte 67 (`VAULT_LEAF_GROUP0_*`, within the 68-byte captured prefix); last byte `OP_TRUE`. Shape only — separates the Assert leaf from the app's other leaves, and nothing more |
| Input 0 signer prefix | Compared byte for byte, while the leaf streams, against a reconstruction from the approved intent: `<intent.depositor_pk> OP_CHECKSIGVERIFY` + VaultKeepers N-of-N + UniversalChallengers M-of-M. 106 bytes at 1/1, 2,216 at the 32/32 maximum. A mismatch is rejected outright, never allowed to fall through to another pattern |
| `<D>` key (prefix) | Verified via `TAP_BIP32_DERIVATION` (BIP-86 path) **and** pinned to `intent.depositor_pk` by the signer-prefix comparison — an Assert for a device-owned key other than the approved depositor is rejected |
| Remainder | WOTS verifier body only; content not verified by device (host-chosen chain tips, not derivable). The two challenger multisig groups ARE verified, as part of the signer prefix |
| Taproot commitment | Verified unconditionally (binds the unvalidated remainder to the spent scriptPubKey) |
| Leaf size | Up to `VAULT_ASSERT_SCRIPT_MAX_LEN` (16384). A leaf that does not fit the read buffer (`VAULT_SCRIPT_MAX_LEN`, 2560) is hashed by streaming instead of being buffered; beyond 16384 it is rejected |
| Sighash | `SIGHASH_DEFAULT` only |
| Fee | `inputs_total − outputs_total ≥ 0` |

**Assert leaf script (btc-vault `claim_assert.rs`):**
```
<D> OP_CHECKSIGVERIFY                                          ┐
<VK_1> OP_CHECKSIG <VK_2..N> OP_CHECKSIGADD <N> OP_NUMEQUALVERIFY   │ signer prefix:
<UC_1> OP_CHECKSIG <UC_2..M> OP_CHECKSIGADD <M> OP_NUMEQUALVERIFY   ┘ verified vs. intent
OP_DEPTH <WOTS_witness_items> OP_EQUALVERIFY
[WOTS verifier body for 4 big blocks]
OP_TRUE
```
Both multisig groups are **intermediate** (`OP_NUMEQUALVERIFY`, not `OP_NUMEQUAL`), and the
VaultKeepers group comes first. The device depends on that ordering. It holds for the
depositor-as-claimer case, which is the only one it can sign: btc-vault's
`derive_full_challengers` (`transactions/claim.rs`) has a dedicated depositor branch yielding the
VaultKeepers alone, with the VaultProvider excluded. The general `{VP, VK_1..VK_N} \ {Claimer}`
rule is the VP/VK-claimer branch and does not apply here.

Because both groups are enforced by hard-failing opcodes, a leaf whose prefix matches the intent
cannot be spent without every keeper and challenger signature from that intent — whatever its body
contains. That is what makes the unverified WOTS body safe to sign over; the taproot commitment
alone only binds the leaf to the output being spent.

> **The binding is session-scoped.** Keeper and challenger keys arrive as host-supplied TLV and
> cannot be derived from the seed, so the device cannot recognise the intent the vault was actually
> funded under — only the one loaded now. An Assert is normally signed after a power cycle, so the
> host supplies a fresh intent and could substitute the challenger set. The user's review of the key
> list on Screen 2 is what prevents that, and is therefore load-bearing for Assert safety rather
> than informational.

Real leaf size is **11,526–13,636 bytes** (11,662 for the 3 local / 3 universal challenger
configuration in `tests/vectors/depositor-as-claimer/assert.txt`). The body is fixed at compile
time by `BIG_BLOCK_DIGIT_COUNTS = [64, 64]` and `ASSERT_WOTS_NUM_STREAMS = 1`; only the signer
prefix varies with the challenger counts — and the signer prefix is exactly the part the device
reconstructs.

**Long-leaf handling (L-11).** A leaf larger than `VAULT_SCRIPT_MAX_LEN` cannot be buffered, so the
device does not try. It streams the PSBT value with `call_stream_merkleized_map_value` and folds it
into the BIP-341 TapLeaf hash incrementally, keeping only what it actually needs in constant memory:

| Kept | Source |
|---|---|
| TapLeaf hash | Folded chunk by chunk; `varint(script_len)` can be emitted first because the stream reports its length before any data |
| 68-byte prefix (`VAULT_LEAF_PREFIX_LEN`) | First chunk(s) — shape discriminator (reaches `VAULT_LEAF_GROUP0_OP_OFF`, byte 67) and the `<D>` key |
| Assert signer-prefix verdict (`assert_prefix_ok`) | Compared byte by byte against the intent as the chunks arrive, then discarded — up to 2,216 bytes, so the bytes themselves are never all resident. A single sticky flag is all that survives |
| Script length | The stream's length callback |
| Terminating byte | Last script byte, tracked across chunk boundaries |
| Leaf version | Final byte of the value; must equal `0xC0` |

`call_stream_preimage` hash-verifies the complete preimage exactly as the buffered path does, so a
streamed leaf is no less trustworthy than a buffered one. The taproot commitment is then verified
against the streamed hash — unconditionally, and identically to the buffered case.

These facts live in `G_leaf_meta`, outside the `G_scratch` union: every byte of the leaf state past
`leaf_script` aliases `leaf_check.actual_buf`, and `_detect_payout_claimer` rebuilds an expected leaf
there before the commitment check runs, which would otherwise destroy the hash.

Flows that compare a leaf byte-for-byte against a script they reconstruct (Refund, Claim, WC,
NoPayout, PayoutFinalize) require `G_leaf_meta.buffered` and reject when it is unset. Their leaves
are ≤2296 bytes by construction, so this is unreachable in practice; it exists so a future oversized
leaf can never be compared against a partial buffer.

Assert cannot take that route — its leaf never fits — so it compares **during** the stream instead:
`vault_assert_prefix_byte` yields the expected signer-prefix byte at any offset without
materialising the prefix, and the stream callback checks each script byte against it as it passes.
Same byte-for-byte guarantee over the prefix, in constant memory, with no dependency on
`buffered`.

> The device must never relax the taproot commitment check for large leaves instead: a host-chosen
> leaf length would then select whether verification runs at all.

**User display:** claim txid (from `PSBT_IN_PREVIOUS_TXID`), amount carried (WITNESS_UTXO value), fee.

---

### 8. Wrongly Challenged / WC (standalone)

The depositor reclaims funds from a wrongly-challenged vault by spending the ChallengeAssert output.

**Requires:** any state (including `IDLE`). Two dispatch paths:
- No wallet policy: leaf must be 73 bytes matching the WC shape.
- Wallet policy present, Input 0 external (not owned by this device): treated as WC regardless of leaf.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | ≥ 1 (Input 0 = WC UTXO; Inputs 1+ = optional BIP-86 wallet inputs for fees) |
| Output count | Exactly 1 |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | 73 bytes (see below) |
| `<D>` key | Verified via `TAP_BIP32_DERIVATION` in Input 0; BIP-86 path |
| `<output_label_hash>` | Read as-is from leaf bytes [40..71]; not verified against intent |
| Taproot commitment | Control block in Input 0 must produce a valid commitment |
| Sighash (Input 0) | `SIGHASH_DEFAULT` only |
| Output 0 | BIP-86 P2TR(`<D>`); value verified |
| Fee | `inputs_total − output_0_value ≥ 0` |

**WC leaf script (73 bytes):**
`<D> OP_CHECKSIGVERIFY OP_SIZE OP_PUSHBYTES_1 0x20 OP_EQUALVERIFY OP_SHA256 <output_label_hash>(32B) OP_EQUAL`

**User display:** amount reclaimed (Output 0 value), wallet inputs amount (sum of Inputs 1+ values), fee, depositor address (bech32m of BIP-86 P2TR(`<D>`)).

---

## Status Words

| SW     | Name                  | Meaning |
|--------|-----------------------|---------|
| `0x9000` | `SW_OK`             | Success |
| `0x6985` | `SW_DENY`           | User rejected on device |
| `0x6A80` | `SW_INCORRECT_DATA` | Invalid APDU data or validation failure |
| `0x6D00` | `SW_INS_NOT_SUPPORTED` | Unknown INS for CLA `0xE1` |
| `0x6E00` | `SW_CLA_NOT_SUPPORTED` | Unknown CLA |
| `0xB007` | `SW_BAD_STATE`      | Command not allowed in current session state |
| `0xB009` | `SW_BAD_CPFP_ANCHOR` | Depositor payout Output 1 scriptPubKey does not match BIP-86 P2TR(depositor) |
| `0xB00A` | `SW_CAP_EXCEEDED`    | Per-type signature cap exceeded; intent nullified. Caps per approved intent: Pre-PegIn=1, PegIn=`vault_count`, Payout=`vault_count×(N+2)`, NoPayout=`vault_count×(N+M)`. Assert is intent-bound but **uncapped and un-deduped** — it is the only intent-bound flow without a bound, and each Assert is user-reviewed on Screen 5 rather than signed silently. |
