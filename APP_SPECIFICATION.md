# Babylon Vault — App Specification

## About

This document describes the APDU interface and transaction types supported by the **Babylon Vault** Ledger application (`app-babylon-vault`).

The app is a dedicated btcext extension for the [Babylon protocol](https://babylonlabs.io/). It enables a Ledger device to participate in the full Babylon vault lifecycle:

- Derive a session secret and bind it to an on-chain hash (`DERIVE_CONTEXT_HASH`)
- Review and approve vault parameters and participant keys (`APPROVE_VAULT_INTENT`)
- Sign eight Bitcoin transaction types: Pre-PegIn, PegIn, Payout, Refund, Claim, Assert, Wrongly-Challenged (WC), NoPayout
- Release the session secret once all pre-signatures are complete (`RELEASE_CONTEXT_SECRET`)

The app extends [app-btcext-boilerplate](https://github.com/LedgerHQ/app-btcext-boilerplate). Standard btcext APDUs (e.g. `GET_EXTENDED_PUBKEY`, `SIGN_PSBT`) are handled by the base app. Only the three custom INS codes below are specific to this app.

For full wire-format details see [`docs/apdu.md`](docs/apdu.md).

---

## APDUs

All custom APDUs use **CLA `0xE1`**.

| INS    | Name                    | Description |
|--------|-------------------------|-------------|
| `0x80` | `APPROVE_VAULT_INTENT`  | Two-phase APDU. Phase `P1=0x00`: parse and validate the vault intent TLV (17 scalar fields). Phase `P1=0x01`: stream keeper and challenger x-only public keys. After all keys are received the device displays the vault parameters for user approval and, on confirmation, transitions the session to `INTENT_LOADED`. |
| `0x81` | `DERIVE_CONTEXT_HASH`   | Chunked streaming APDU. Derives a 32-byte session secret `s` from the device's BIP-32 key at `m/73681862'` via HKDF-SHA-256, stores `s` in the session context, and returns `h = SHA256(s)`. No user display. |
| `0x82` | `RELEASE_CONTEXT_SECRET`| Returns the 32-byte session secret `s` to the host, but only when the session has reached `SESSION2_COMPLETE` (all N+2 pre-signatures done). After returning `s`, zeroes it with `explicit_bzero` and resets the session to `IDLE`. Rejected in all other states. |

### APPROVE_VAULT_INTENT — intent fields

The TLV payload in `P1=0x00` encodes the following 18 scalar fields (tag `2B` + length `1B` + value):

| Field | Validation rule |
|---|---|
| `structure_type` | must equal the vault structure type constant |
| `version` | must equal the current protocol version constant |
| `coin_type` | must equal `BIP44_COIN_TYPE` for the active network |
| `pegin_csv_timelock` | `[72, 1008]` blocks inclusive |
| `htlc_refund_timelock` | `[72, 4320]` blocks inclusive |
| `payout_timelock` | `(90, 4032)` blocks exclusive |
| `keeper_count` | `[1, 32]` inclusive |
| `challenger_count` | `[1, 32]` inclusive |
| `depositor_derivation_path` | BIP-86 path `m/86'/coin_type'/acct'/chg/idx`, exactly 5 levels |
| `vault_amount` | `> commission_fee + DUST + DUST` |
| `commission_fee` | present and non-zero |
| `depositor_claim_value` | present |
| `base_fee_rate` | present |
| `pegin_max_fee` | present |
| `vault_provider_pk` | 32-byte x-only public key |
| `htlc_vout` | output index of the HTLC in the Pre-PegIn transaction |
| `prepegin_txid` | 32-byte txid |
| `prepegin_max_fee` | `uint64`; maximum allowed fee (satoshis) for the Pre-PegIn transaction; must be non-zero |

Duplicate tags, unknown tags, and non-canonical encodings are all rejected.

The `P1=0x01` key batch must deliver exactly `keeper_count` keeper keys followed by `challenger_count` challenger keys (x-only, 32 bytes each). All keys must be:
- globally unique across all roles
- pairwise disjoint with `vault_provider_pk` and the depositor key
- sorted in ascending lexicographic order within each group

---

## Transaction Types

The app recognises four Bitcoin transaction types via the `SIGN_PSBT` hook. The device independently reconstructs the expected scripts from the loaded `vault_intent_t` and rejects any PSBT whose scripts do not match.

### 1. Pre-PegIn (Session 1)

The depositor creates an HTLC output that locks BTC until the vault is finalised.

**Requires:** `INTENT_LOADED` state.

**PSBT requirements:**
- Inputs: wallet inputs (BIP-86 P2TR), signed by the base app
- Output at `htlc_vout`: P2TR matching the 2-leaf HTLC reconstructed from the intent; value in `[vault_amount + depositor_claim_value, vault_amount + depositor_claim_value + pegin_max_fee]`
- All other outputs: BIP-86 change outputs owned by this device (verified via `TAP_BIP32_DERIVATION`)
- Sighash: `SIGHASH_ALL` or `SIGHASH_DEFAULT`; version ≥ 2
- Fee: `total_inputs − total_outputs ≤ prepegin_max_fee`

**User display:** vault amount, total fee, HTLC address.

**HTLC scripts (2-leaf P2TR, NUMS internal key):**
- *Leaf 0 — Hashlock + All-Party:* `OP_SIZE <32> OP_EQUALVERIFY / OP_SHA256 <h> OP_EQUALVERIFY / <D> OP_CHECKSIGVERIFY / <VP> OP_CHECKSIGVERIFY / <VK N-of-N> / <UC M-of-M>`
- *Leaf 1 — Refund:* `<D> OP_CHECKSIGVERIFY / <T_refund> OP_CHECKSEQUENCEVERIFY`

---

### 2. PegIn (Session 2 — silent)

Spends the HTLC and creates the Vault UTXO + Depositor Claim UTXO. No user display; parameters were already approved during `APPROVE_VAULT_INTENT`.

**Requires:** `SESSION2_PEGIN_EXPECTED` state.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Input 0 prevout | `prepegin_txid:htlc_vout` from intent |
| Input 0 sequence | `0xFFFFFFFE` |
| Version / locktime | 2 / 0 |
| Output count | Exactly 3 |
| Output 0 | Reconstructed Vault UTXO scriptPubKey; value = `vault_amount` |
| Output 1 | Reconstructed Depositor Claim scriptPubKey; value = `depositor_claim_value` |
| Output 2 | P2A anchor; value = `P2A_ANCHOR_VALUE` (240 sat) |
| PSBT metadata | `TAP_LEAF_SCRIPT`, `TAP_INTERNAL_KEY`, `TAP_MERKLE_ROOT` must match reconstructed values |
| Secret hash binding | HTLC Leaf 0 in the PSBT must embed `h = SHA256(s)` from the session context |
| Sighash | `SIGHASH_DEFAULT` only |
| Fee | `htlc_value − (vault_amount + depositor_claim_value) ≤ pegin_max_fee` |

**Vault UTXO script (1-leaf P2TR, NUMS internal key):**
`<D> OP_CHECKSIGVERIFY / <VP> OP_CHECKSIGVERIFY / <VK N-of-N> / <UC M-of-M> / <P> OP_CHECKSEQUENCEVERIFY`

**Depositor Claim script (1-leaf P2TR, NUMS internal key):**
`<D> OP_CHECKSIG`

---

### 3. Payout (Session 2 — N+2 PSBTs, silent)

Pre-signs N+2 payout transactions — one per potential claimer (VP first, then VK_1..VK_N in ascending lexicographic key order, then Depositor last). No user display per iteration; parameters were already approved.

**Requires:** `SESSION2_PAYOUT_i_EXPECTED` state (i tracks which claimer is next).

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 2 |
| Input 0 prevout | `computed_pegin_txid:0` (computed deterministically from intent) |
| Input 0 sequence | `pegin_csv_timelock` (P) |
| Input 1 sequence | `payout_timelock` (t2) |
| Input 0 leaf script | Matches reconstructed Vault UTXO leaf |
| Input 1 leaf script | Matches reconstructed Assert:0 Payout leaf for expected claimer |
| Output count | 3 for VP claimer; 2 for VK or Depositor claimer |
| Claimer ordering | VP first, then VK_1..VK_N lexicographically, then Depositor; out-of-order rejected |
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
- Single output: BIP-86 P2TR (`account_index ≤ 100`, `address_index ≤ 10000`)
- Sighash: `SIGHASH_DEFAULT`; version ≥ 2; locktime = 0

**User display:** amount reclaimed, fee.

---

### 5. NoPayout (Session 2 — silent)

The depositor pre-signs a NoPayout leaf for a specific challenger, authorising that challenger to claim the vault funds without a payout transaction.

**Requires:** `SESSION2_PAYOUT_EXPECTED` or `SESSION2_COMPLETE` state; no wallet policy; exactly 3 inputs and 1 output.

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
| WITNESS_UTXO value | Must equal `VAULT_DUST_LIMIT` (546 sat) |
| Sighash | `SIGHASH_DEFAULT` only |
| Output | Not verified (challenger-controlled destination) |
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

**Requires:** any state (including `IDLE`); no wallet policy; 68-byte leaf `<D> OP_CHECKSIGVERIFY <key> OP_CSV`.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Output count | Not enforced (host-provided connector tree) |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | 68 bytes: `<D>(32B) OP_CHECKSIGVERIFY <key>(32B) OP_CSV` |
| `<D>` key (prefix) | Verified via `TAP_BIP32_DERIVATION`; BIP-86 path |
| `<key>` | Not verified against intent; host-provided assert connector key |
| Taproot commitment | Control block must produce a valid commitment to the leaf |
| Sighash | `SIGHASH_DEFAULT` only |
| Fee | `inputs_total − outputs_total ≥ 0` |

**Assert leaf script:**
`<D> OP_CHECKSIGVERIFY <key> OP_CSV`

**User display:** claim txid (from `PSBT_IN_PREVIOUS_TXID`), amount carried (WITNESS_UTXO value), output count, fee.

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
| `0xB00A` | `SW_CAP_EXCEEDED`    | Per-type signature cap exceeded; intent nullified. Caps per approved intent: Pre-PegIn=1, PegIn=`vault_count`, Payout=`vault_count×(N+2)`, NoPayout=`vault_count×(N+M)`. |
