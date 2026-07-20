# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.7.0] - NAPPS-1442–1445: Multi-vault end-to-end — P1=0x02 approval, script group-indexing, validation, payout & signing

Completes multi-vault support across the full session flow for `vault_count > 1`.
NAPPS-1442 wired the P1=0x02 handler and streaming display; NAPPS-1443 made all script
builders group-index-aware; NAPPS-1444 extended Pre-PegIn/PegIn validation over all
groups; NAPPS-1445 extended payout validation and signing and fixed the
`vault_group_index` cursor reset at the PegIn→Payout transition.

### Added

- **Streaming vault-group review** (`vault_stream_group`, `display.c`): each vault group
  is presented as a separate NBGL streaming segment with a `"N of M"` header and 6 fields
  (VP key, vault amount, commission fee, depositor claim, max PegIn fee).  The display path
  is uniform for all `vault_count` values — single-vault intents also go through
  `vault_stream_group`.  File-scope static buffers keep NBGL pointers live across
  `io_ui_process` callbacks.
- **`group_idx` parameter** on all vault script builders: `vault_build_vault_utxo_leaf`,
  `vault_build_vault_utxo_scriptpubkey`, `vault_build_assert0_payout_leaf` (also gains
  `claimer_idx`), `vault_build_htlc_leaf0`, `vault_build_htlc_merkle_root`,
  `vault_build_htlc_scriptpubkey`, `vault_compute_pegin_txid`.  Each selects
  `intent->groups[group_idx]` fields; bounds-checked by `ASSERT_GROUP_IDX`.
- `SW_BAD_CPFP_ANCHOR` (0xB009): distinct status word for CPFP anchor output scriptPubKey
  mismatches, differentiating them from generic `SW_INCORRECT_DATA`.
- Ragger integration tests for multi-vault (2-vault) Pre-PegIn, PegIn, and payout
  sequences including happy paths, wrong-group, and state-ordering violations.

### Changed

- **Pre-PegIn validator**: iterates all `vault_count` groups; `htlc_hashlock[gi]` is
  computed per group from the derived root and the group's `htlc_vout`.
- **PegIn validator**: uses the per-group HTLC txid and scripts for each group.
- **`_validate_payout`**: uses `vault_group_index` as the current-group cursor for all
  per-group fields.  `ASSERT_GROUP_IDX` guards the cursor before every group access.
  After the last claimer of a group (`payout_index > keeper_count`), `payout_index` resets
  to 0 and `vault_group_index` increments; `SESSION2_COMPLETE` is set only once
  `vault_group_index` reaches `vault_count`.
- **`sign_custom_inputs`**: vault UTXO leaf and scriptPubKey are built for `sgi`; when
  `payout_index` is 0 the group advance has already happened so `sgi = vault_group_index - 1`.
- **PegIn→Payout transition**: `vault_group_index` reset to 0 in `sign_custom_inputs` so
  the payout cursor starts at group 0 regardless of how many groups were ingested.

---

## [0.6.0] - NAPPS-1441: DERIVE_CONTEXT_HASH rev 2.1 — multi-chunk streaming, P2 mode, Screen 1

Upgrades `DERIVE_CONTEXT_HASH` (INS `0x81`) to the rev 2.1 wire format: chunked context
streaming over multiple APDUs, a silent re-derivation mode, and an optional approval screen
that displays the requesting app name.

### Changed

- **Wire format** (breaking): P1=0x00 payload is now
  `app_name_len(1B) | app_name | path_len(1B) | path(4·n B BE) | context_total_len(2B BE) | first_context_chunk`.
  The 2-byte `context_total_len` field is new; clients must send it before the context bytes.
- **P2 semantics**: P2=0x00 shows Screen 1 and returns the 32-byte root; P2=0x01 performs a
  silent re-derivation (no screen, SW_OK only). Previously P2 was unused.
- **Context streaming**: context up to `VAULT_CONTEXT_MAX_LEN` (1024 B) is spread across an
  initial P1=0x00 APDU and zero or more P1=0x01 continuation APDUs.  The device accumulates
  bytes in `G_scratch.derive_ctx.context_buf` and finalizes on the last chunk.  A new P1=0x00
  while streaming cancels the in-flight session and starts fresh.
- **Handler structure**: `handler_derive_context_hash` is now a thin P1 dispatcher (mirrors
  `handler_approve_vault_intent`); logic lives in `handle_initial_chunk`,
  `handle_continuation_chunk`, and the shared `_finalize` helper.

### Added

- **Screen 1** (`display_derive_context_hash`): shown on finalization when P2=0x00; presents
  a single `TYPE_OPERATION` review with the `"App name"` field; confirm text `"Allow
  derivation?"`.  User rejection returns `SW_DENY` (0x6985).
- `VAULT_APP_NAME_MAX_LEN` (64), `VAULT_CONTEXT_MAX_LEN` (1024) constants in
  `vault_constants.h`; `app_name_charset_valid` inline in `derive_context_hash_core.h`
  (allowed set: `[a-z0-9\-]`).
- `derive_context_hash_reject_nav` navigation helper in `tests/instructions.py`.
- 11 new Ragger integration tests covering: invalid P2, empty / invalid-charset app_name,
  path too deep, context_total_len overflow, continuation chunk overflow, empty continuation,
  reset-during-streaming, max context (1024 B) correctness, screen snapshot, and user
  rejection.

## [0.5.0] - NAPPS-1376–1422, 1440: Payout validation, signing session, fee-bumpable PegIn, DERIVE_CONTEXT_HASH realignment, signet ticker, v19 data model

Omnibus release covering all work between 0.4.0 and the v19 data model.

### Added (NAPPS-1376: Payout validation)

- `_validate_payout` in `sign_psbt_validate.c`: validates both Payout PSBT inputs (Vault
  UTXO + Assert:0 Payout) and all outputs; enforces claimer ordering via `payout_index`;
  fee bounded by `base_fee_rate * max_vsize`.
- Real-world Payout cross-validation unit tests against on-chain signet fixtures.

### Security (NAPPS-1376)

- Fixed missing length guard before `memmove` in `_tap_leaf_script_callback`: oversized
  leaf scripts (> `VAULT_SCRIPT_MAX_LEN`) now set `ambiguous = true` instead of writing
  past the destination buffer.
- Deferred PegIn state transition (`SESSION2_PEGIN_EXPECTED → SESSION2_PAYOUT_EXPECTED`)
  from `validate_and_display_transaction` to `sign_custom_inputs` (NAPPS-1377), so the
  state only advances when the HTLC input is actually signed and the host can retry on
  signing failure.
- `vault_tlv.c` now rejects `commission_fee < VAULT_DUST_LIMIT` (previously only `0`), so
  the VP commission payout output can no longer be a below-dust P2TR output.

### Added (NAPPS-1377: Signing session)

- `sign_custom_inputs.c`: full PSBT signing hook — `read_p2tr_witness_utxo` reads and
  validates the witness UTXO for each custom input, binding the scriptPubKey the sighash
  commits to against the device-reconstructed script from the approved intent; signs the
  vault UTXO input (Assert:0 signing follows from payout validation).

### Added (NAPPS-1415: 32 × 32 transaction test vectors)

- Ragger test vectors and fixtures for 32-keeper × 32-challenger intents and
  depositor-as-claimer scenarios; validates the full signing flow at maximum key counts.

### Changed (NAPPS-1416: Signet ticker)

- The test build (`COIN=babylon_vault_testnet`) now displays amounts with the **`sBTC`**
  ticker instead of `TEST`.  The base submodule hardcodes `COIN_COINID_SHORT="TEST"`;
  the app Makefile overrides it at compile time.  App name and `BITCOIN_NETWORK` are
  unchanged; golden snapshots updated.

### Added (NAPPS-1419: Skip navigation for long intents)

- Skip/fast-forward NBGL navigation callbacks for the vault intent approval screen on
  touch devices (Stax/Flex); allows stepping past key sections when `keeper_count` or
  `challenger_count` is large.  Ragger tests for skip flow and snapshots.

### Added (NAPPS-1421: Fee-bumpable PegIn — P2A anchor)

- `vault_intent_t.pegin_anchor_value` (u64, `TAG_PEGIN_ANCHOR_VALUE` 0x12): satoshi value
  of the P2A anchor output (`OP_1 OP_PUSHBYTES_2 0x4e73`) in the PegIn transaction.
- `vault_intent_t.htlc_vout` (u8): HTLC output index in the Pre-PegIn transaction; used
  by `APPROVE_VAULT_INTENT` to recompute the per-vault HKDF-derived hashlock.
- `_validate_pegin` enforces Output 2 as a valid P2A anchor with `pegin_anchor_value` sats
  and includes it in the fee-bound sum.
- `AUTH_ANCHOR_SPK_LEN` (34) static assert: auth-anchor OP_RETURN and P2TR scriptPubKey
  share the same byte length, allowing `_read_output` to reuse one buffer.
- `VAULT_TARGET_SIGNET` build sentinel in `vault_constants.h`: forces an explicit
  `#define` at build time to confirm the target network, preventing a silent
  testnet3/4 misconfiguration.

### Changed (NAPPS-1422: DERIVE_CONTEXT_HASH realignment — breaking)

- `DERIVE_CONTEXT_HASH` now returns the **32-byte root** instead of a hashlock.  The HKDF
  `info` is `SHA256(app_name) || SHA256(canonicalNetworkName) || connectedPubkey[33] || context`;
  `canonicalNetworkName` is `"bitcoin-mainnet"` / `"bitcoin-signet"`.
- The on-chain HTLC hashlock is `SHA256(HKDF-Expand(root, "hashlock" || I2OSP(htlc_vout, 4)))`.
  The device recomputes it at `APPROVE_VAULT_INTENT` once `htlc_vout` is known and binds it
  in Pre-PegIn and PegIn Leaf 0 validation.
- Session context stores `root` (zeroed on invalidation) instead of the HTLC preimage;
  `vault_context_t` gains `auth_anchor_hash`.

### Added (NAPPS-1422)

- Pre-PegIn validation requires the shared auth-anchor `OP_RETURN`
  (`0x6A 0x20 || SHA256(authAnchor)`, value 0) and binds it to the value expanded from
  the derived root, preventing host substitution.
- On-device HKDF-Expand commitment helper (`derive_vault_secrets_core.h`) for
  `"hashlock"` and `"auth-anchor"` labels under the `"babylonbtcvault"` domain tag.

### Removed (NAPPS-1422)

- `RELEASE_CONTEXT_SECRET` (INS `0x82`) and the `SESSION2_COMPLETE` custody gating.
  The host holds the root; `SESSION2_COMPLETE` is now a terminal state with no
  secret-release step.

### Added (NAPPS-1440: v19 data model)

- `vault_group_t` struct in `vault_intent.h` holding the 6 per-vault fields: `htlc_vout`,
  `vault_provider_pk`, `vault_amount`, `commission_fee`, `depositor_claim_value`,
  `pegin_max_fee`, `pegin_anchor_value` (propagated from the global P1=0x00 scalar).
- `vault_intent_t.vault_count` scalar field (`[1, 10]`); `groups[VAULT_MAX_VAULTS]` array
  replaces the former flat per-vault fields.
- `VAULT_MAX_VAULTS 10` constant in `vault_constants.h`.
- P1=0x02 per-vault group TLV parser `vault_tlv_parse_group()` in `vault_tlv.c`/`.h`:
  6 mandatory group tags (`0x01`–`0x06`), independent tag namespace from P1=0x00; validates
  `commission_fee ≥ VAULT_DUST_LIMIT` and `vault_amount > commission_fee + 2 × DUST` per group.
- New P1=0x00 scalar tags: `TAG_PEGIN_ANCHOR_VALUE` (0x12) and `TAG_VAULT_COUNT` (0x13).
- `vault_context_t` gains `htlc_hashlock[VAULT_MAX_VAULTS][VAULT_HASH256_LEN]`,
  `vault_group_index`, `derivation_path[VAULT_MAX_PATH_DEPTH]`, and `derivation_path_len`.
- `docs/apdu.md` updated with the three-phase wire format and both tag tables.

### Changed (NAPPS-1440)

- `vault_tlv_parse()` (P1=0x00) now rejects old per-vault scalar tags (`0x04`–`0x07`, `0x09`,
  `0x0D`) via a whitelist bitmask (`VAULT_INTENT_ALL_TAGS_MASK`); those fields must be sent
  in P1=0x02 instead.
- `TAG_PEGIN_ANCHOR_VALUE` (global scalar) is stored temporarily in `groups[0].pegin_anchor_value`
  by the P1=0x00 parser; the P1=0x02 handler propagates it to all groups.
- All callers updated to use `groups[0]` for per-vault fields: `vault_script.c`, `display.c`,
  `sign_psbt_validate.c`, `sign_custom_inputs.c`, `approve_vault_intent.c`,
  `approve_vault_intent_core.h`; `htlc_hashlock` references updated to `htlc_hashlock[0]`.
- `vault_context_t` size budget raised from 128 B to 512 B in `globals.c` (`_Static_assert`)
  to accommodate `htlc_hashlock[10][32]` (320 B).
- Unit tests in `test_vault_tlv.c` updated: `build_valid_tlv()` emits the 13 scalar tags;
  3 stale per-vault-in-scalar tests removed; 8 new tests added.

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
