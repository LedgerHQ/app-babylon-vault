# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased] - NAPPS-1416: Signet ticker

### Changed

- The test build (`COIN=babylon_vault_testnet`) now displays amounts with the **`sBTC`**
  ticker instead of `TEST`. Babylon's test network is Bitcoin signet, which is
  indistinguishable from testnet on-device (same `tb` prefix, BIP-32 version bytes, coin
  type 1), so the single testnet build targets signet; the `sBTC` ticker reflects that. The
  base submodule hardcodes `COIN_COINID_SHORT="TEST"` for the testnet network, so the app
  Makefile overrides it after the `include` (DEFINES is expanded into `-D` flags at compile
  time, so the override wins), with no `bitcoin_app_base` change. The official app name is
  unchanged — it stays "Babylon Vault Testnet" (pinned by the guideline enforcer), as do the
  `babylon_vault_testnet` variant name and `BITCOIN_NETWORK = testnet`.
- Golden snapshots updated to show `sBTC` amounts.

## [Unreleased] - NAPPS-1376: Payout validation

### Added

- `_validate_payout` in `sign_psbt_validate.c`: validates both Payout PSBT inputs (Vault UTXO
  + Assert:0 Payout) and all outputs; enforces claimer ordering via `payout_index`;
  fee bounded by `base_fee_rate * max_vsize`.
- Real-world Payout cross-validation unit tests against on-chain signet fixtures.

### Security

- Fixed missing length guard before `memmove` in `_tap_leaf_script_callback`: oversized
  leaf scripts (> `VAULT_SCRIPT_MAX_LEN`) now set `ambiguous = true` instead of writing
  past the destination buffer.
- Deferred PegIn state transition (`SESSION2_PEGIN_EXPECTED → SESSION2_PAYOUT_EXPECTED`)
  from `validate_and_display_transaction` to `sign_custom_inputs` (NAPPS-1377), so the
  state only advances when the HTLC input is actually signed and the host can retry on
  signing failure.
- `vault_tlv.c` now rejects `commission_fee < VAULT_DUST_LIMIT` (previously only `0`), so
  the VP commission payout output can no longer be a below-dust P2TR output, keeping the
  payout transaction standard/relayable as documented in `vault_constants.h`.

---

## [0.4.0] - 2026-06-23 — NAPPS-1375: Pre-PegIn, PegIn, and Refund transaction validation

### Added

- `sign_psbt_validate.c` / `sign_psbt_validate.h`: public dispatch hook
  `validate_and_display_transaction` routing to per-type validators.
- `_validate_display_prepegin`: validates all Pre-PegIn PSBT inputs (BIP-86 wallet-owned),
  reconstructs and compares HTLC scriptPubKey, checks HTLC output amount bounds
  `[vault_amount + depositor_claim_value, … + pegin_max_fee]`, advances session state
  `INTENT_LOADED → SESSION1_PREPEGIN_EXPECTED`.
- `_validate_display_refund`: validates Refund PSBT (1-in / 1-out), parses HTLC Leaf 1
  script, verifies depositor key ownership via BIP-32 derivation, verifies BIP-341
  taproot commitment (NUMS internal key + sibling hash path), checks CSV sequence.
- `_validate_pegin`: silent PegIn validator — checks `prepegin_txid`/`htlc_vout`/sequence,
  reconstructs and compares both PSBT tap-leaf scripts (Leaf 0 with hashlock, Leaf 1),
  verifies merkle root and tweaked output key.
- `sign_psbt_validate_helpers.c`: `parse_refund_leaf_script` (decodes
  `<key> OP_CHECKSIGVERIFY <csv> OP_CSV` from raw bytes) and
  `parse_tap_bip32_deriv_value` (decodes fingerprint + BIP-32 path).
- Screen 2 (`display_prepegin_transaction`): shows Vault amount, Depositor claim,
  Transaction fee, and HTLC address.
- Screen 3 (`display_refund_transaction`): shows Reclaimed amount, Transaction fee,
  and Reclaim address.
- Display string buffers moved from static locals to `G_scratch.display_tx` union
  so NBGL pointers remain valid across `io_ui_process`.
- Unit and Ragger tests for all three transaction types including error cases.

---

## [0.3.0] - 2026-06-18 — NAPPS-1374: Script construction layer

### Added

- `vault_script.c` / `vault_script.h`: full tapscript builder suite:
  - `vault_build_htlc_leaf0` — HTLC Leaf 0 (hashlock + keeper N-of-N + challenger M-of-M).
  - `vault_build_htlc_leaf1` — HTLC Leaf 1 (depositor CSV refund path).
  - `vault_build_htlc_merkle_root` — BIP-341 taptree root for the HTLC.
  - `vault_build_htlc_scriptpubkey` — tweaked P2TR output for Pre-PegIn HTLC output.
  - `vault_build_vault_utxo_leaf` / `vault_build_vault_utxo_scriptpubkey` — Vault UTXO
    single-leaf taptree (all signers N-of-N multisig).
  - `vault_build_depositor_claim_scriptpubkey` — BIP-86 P2TR for depositor claim output.
  - `vault_build_assert0_payout_leaf` — Assert:0 Payout leaf for VP or VK claimer.
  - `vault_compute_pegin_txid` — serialises the PegIn transaction and double-SHA256s it.
  - `vault_taproot_leaf_hash` / `vault_taproot_scriptpubkey` — BIP-341 primitives.
- `encode_multisig_group` helper: generates `<k0> OP_CHECKSIG <k1> OP_CHECKSIGADD … N OP_NUMEQUALVERIFY/NUMEQUAL` for intermediate/final groups.
- `VAULT_NUMS_XONLY` constant — BIP-341 NUMS internal key used for all script-path-only outputs.
- `vault_intent_t`: added `payout_timelock`, `commission_fee`, `base_fee_rate` fields.
- `vault_context_invalidate` now requires `INTENT_LOADED` state before zeroing the intent
  struct; clears `htlc_hashlock` alongside the preimage.
- `G_hkdf_stream` extracted into a dedicated global to avoid union aliasing with script scratch.
- Key display string buffers moved to stack inside `display_vault_intent` to eliminate stale-pointer risk.
- Unit tests: 36 tests covering all script builders including real-world golden vectors
  (315-byte HTLC Leaf 0, BIP-341 leaf hashes) cross-validated against on-chain signet
  transaction `41bd883b…`.

---

## [0.2.0] - 2026-06-09 — NAPPS-1373: RELEASE_CONTEXT_SECRET and vault intent display

### Added

- `release_context_secret.c`: full handler for `INS 0x82` — validates
  `state == SESSION2_COMPLETE`, stages `htlc_preimage` in the response buffer,
  `explicit_bzero`s the secret from device RAM, resets session to `IDLE`.
- `display_vault_intent`: NBGL review screen showing all vault intent fields —
  VP key (hex), vault amount, commission fee, depositor claim, base fee rate,
  max PegIn fee, PegIn/payout/refund timelocks, and all keeper + challenger x-only keys.
- `format_timelock_blocks` helper: converts block count to human-readable string
  with approximate wall-clock time ("432 blocks (~3 days)").
- `approve_vault_intent.c`: preserves `htlc_preimage`/`htlc_hashlock` across the
  session reset when called from `HASH_DERIVED` state, so Session 2 survives an
  `APPROVE_VAULT_INTENT` call mid-flow.
- Ragger snapshot tests for the vault intent approval screen on all supported devices
  (Nano S+, Stax, Flex) for both mainnet and testnet variants.
- Network auto-detection from the ELF binary in `conftest.py`.

---

## [0.1.0] - 2026-06-04 — NAPPS-1372: APPROVE_VAULT_INTENT

### Added

- `vault_tlv.c` / `vault_tlv.h`: two-pass TLV parser for the `APPROVE_VAULT_INTENT` payload.
  - P1=0x00: parses and validates 17 scalar fields (amounts, timelocks, fee rate, counts).
  - P1=0x01: streams x-only pubkeys; enforces lexicographic ordering, uniqueness, and
    VP/depositor key collision check; transitions to `INTENT_LOADED`.
- `vault_intent_tags.h`: TLV tag byte definitions (`0x01`–`0x11`) for all scalar fields.
- `vault_constants.h`: shared constants (`VAULT_DUST_LIMIT`, `TAPSCRIPT_LEAF_VERSION`, etc.).
- libFuzzer targets for the TLV parser with ClusterFuzzLite CI integration.
- Unit tests for the TLV parser covering valid payloads and all rejection cases.

---

## [0.0.2] - 2026-06-02 — NAPPS-1367: DERIVE_CONTEXT_HASH

### Added

- `derive_context_hash.c`: full handler for `INS 0x81` — chunked HKDF-SHA-256 stream
  over vault intent fields; returns `htlc_hashlock = SHA256(htlc_preimage)` to the host.
- `derive_context_hash_core.h`: stateless HKDF stream implementation; explicit wipe of
  HKDF intermediates after derivation.
- `vault_context_t`: added `htlc_hashlock[32]` field; `vault_context_invalidate` now
  zeroes it alongside the preimage.
- Unit tests and Ragger functional tests for the HKDF output.

---

## [0.0.1] - 2026-05-27 — NAPPS-1366: App scaffold

### Added

- App scaffold forked from `app-btcext-boilerplate`; renamed to `app-babylon-vault`.
- Makefile configured: variant names `app_babylon_vault` / `app_babylon_vault_testnet`,
  developer "Hoodies"; Babylon icons and glyphs for all 5 supported devices.
- Stub APDU handlers registered in `custom_apdu_handler` for `INS 0x80/0x81/0x82`.
- `vault_intent_t`: 17 scalar fields + `keeper_pks[32][32]` + `challenger_pks[32][32]`;
  compile-time `sizeof` assertions validating fit within Nano S+ RAM budget.
- `vault_context_t` + `vault_state_t`: session secret `s[32]`, hashlock `h[32]`, state enum.
- Session state machine with full transition table enforced via `-Wswitch`:
  `IDLE → HASH_DERIVED → INTENT_LOADED → SESSION1_PREPEGIN_EXPECTED`
  `IDLE → HASH_DERIVED → INTENT_LOADED → SESSION2_PEGIN_EXPECTED → SESSION2_PAYOUT_EXPECTED → SESSION2_COMPLETE`
  `explicit_bzero` on `s` and full intent on every invalidation.
- `vault_context_init`, `vault_context_invalidate`, `vault_context_transition` API.
- 14 unit tests covering all valid state transitions and all illegal transition attempts.
- `docs/apdu.md`: APDU INS registry table shared reference for the DMK Babylon Signer team.
