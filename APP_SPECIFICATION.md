# Babylon Vault — App Specification

## About

This document describes the APDU interface and transaction types supported by the **Babylon Vault** Ledger application (`app-babylon-vault`).

The app is a dedicated btcext extension for the [Babylon protocol](https://babylonlabs.io/). It enables a Ledger device to participate in the full Babylon vault lifecycle:

- Derive a session secret and bind it to an on-chain hash (`DERIVE_CONTEXT_HASH`)
- Review and approve vault parameters and participant keys (`APPROVE_VAULT_INTENT`)
- Sign four Bitcoin transaction types: Pre-PegIn, PegIn, Payout, Refund
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

The TLV payload in `P1=0x00` encodes the following 17 scalar fields (tag `1B` + length `1B` + value):

| Field | Validation rule |
|---|---|
| `structure_type` | must equal the vault structure type constant |
| `version` | must equal the current protocol version constant |
| `coin_type` | must equal `BIP44_COIN_TYPE` for the active network |
| `pegin_csv_timelock` | `[72, 1008]` blocks inclusive |
| `htlc_refund_timelock` | `[72, 1008]` blocks inclusive |
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
| Output count | Exactly 2 |
| Output 0 | Reconstructed Vault UTXO scriptPubKey; value = `vault_amount` |
| Output 1 | Reconstructed Depositor Claim scriptPubKey; value = `depositor_claim_value` |
| PSBT metadata | `TAP_LEAF_SCRIPT`, `TAP_INTERNAL_KEY`, `TAP_MERKLE_ROOT` must match reconstructed values |
| Secret hash binding | HTLC Leaf 0 in the PSBT must embed `h = SHA256(s)` from the session context |
| Sighash | `SIGHASH_DEFAULT` only |
| Fee | `htlc_value − (vault_amount + depositor_claim_value) ≤ pegin_max_fee` |

**Vault UTXO script (1-leaf P2TR, NUMS internal key):**
`<D> OP_CHECKSIGVERIFY / <VP> OP_CHECKSIGVERIFY / <VK N-of-N> / <UC M-of-M> / <P> OP_CHECKSEQUENCEVERIFY`

**Depositor Claim script (1-leaf P2TR, NUMS internal key):**
`<D> OP_CHECKSIG`

---

### 3. Payout (Session 2 — N+1 PSBTs, silent)

Pre-signs N+1 payout transactions — one per potential claimer (VP first, then VK_1..VK_N in ascending lexicographic key order). No user display per iteration; parameters were already approved.

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
| Output count | 3 for VP claimer; 2 for VK claimer |
| Claimer ordering | VP first, then VK_1..VK_N lexicographically; out-of-order rejected |
| Fee bound | `actual_fee ≤ base_fee_rate × (500 + 55 × (N+M))` |
| Sighash | `SIGHASH_DEFAULT` only |
| Version / locktime | ≥ 2 / 0 |

The device signs Input 0 (Vault UTXO leaf). Input 1 (Assert:0) is verified but not signed by the device.

**Assert:0 Payout leaf script:**
`<Claimer> OP_CHECKSIGVERIFY / <AppChallengers K-of-K> / <UC M-of-M> / <t2> OP_CHECKSEQUENCEVERIFY`

where `AppChallengers = {VP, VK_1..VK_N} \ {Claimer}`, sorted lexicographically.

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

## Status Words

| SW     | Name                  | Meaning |
|--------|-----------------------|---------|
| `0x9000` | `SW_OK`             | Success |
| `0x6985` | `SW_DENY`           | User rejected on device |
| `0x6A80` | `SW_INCORRECT_DATA` | Invalid APDU data or validation failure |
| `0x6D00` | `SW_INS_NOT_SUPPORTED` | Unknown INS for CLA `0xE1` |
| `0x6E00` | `SW_CLA_NOT_SUPPORTED` | Unknown CLA |
| `0xB007` | `SW_BAD_STATE`      | Command not allowed in current session state |
