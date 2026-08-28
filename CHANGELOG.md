# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.10.0] - Assert leaf bound to the approved intent (F-6 second pass)

### Security

- **Assert leaf bound to the approved intent (F-6, second pass)**: the `[0.9.6]` F-6 fix added `OP_CHECKSIG` at `VAULT_LEAF_GROUP0_OP_OFF`, arguing a no-op middle could not satisfy it. It can, two bytes further right: the 70-byte leaf `<D> OP_CHECKSIGVERIFY <32 junk> OP_CHECKSIG OP_DROP OP_TRUE` clears every conjunct — the `OP_DROP` sits at byte 68, one past the captured prefix, so no shape test can see it — and is spendable on the depositor signature alone, since `OP_CHECKSIG` with an empty signature pushes false without failing (BIP-342) and `OP_TRUE` then satisfies CLEANSTACK. No shape test can close this: ~11 KB of the leaf is a WOTS verifier over host-chosen chain tips the device cannot derive, so whatever offsets are checked, an attacker pads around them. A minimum-length floor does not help either — `_realistic_assert_leaf` at 11,662 B is one `OP_NOP`→`OP_DROP` away from the same bypass. Fixed instead by verifying what actually governs custody: the leaf's signer prefix — `<intent.depositor_pk> OP_CHECKSIGVERIFY`, the VaultKeepers N-of-N group and the UniversalChallengers M-of-M group — is now compared byte for byte against the approved intent. Both groups are enforced by hard-failing `OP_CHECKSIGVERIFY`/`OP_NUMEQUALVERIFY`, so a matching leaf cannot be spent without every keeper and challenger signature from the loaded intent, whatever its body contains; the WOTS body stays unverified and does not need to be, governing challengeability rather than who can spend. The prefix reaches 2,216 B at 32/32 and real leaves are never buffered, so `vault_assert_prefix_byte` yields the expected byte at any offset without materialising it and the stream callback compares each byte as it passes — constant memory, verdict kept in the new `G_leaf_meta.assert_prefix_ok`. Shape testing moved to `leaf_has_assert_shape`, shared with the signing path, which re-asserts the same invariant off an independent re-read. Verified byte-exact against btc-vault (`claim_assert.rs`, `script_utils.rs`, `claim.rs` `derive_full_challengers`) and against the real signet leaf in `tests/vectors/depositor-as-claimer/assert.txt` (`sign_psbt_validate.c`, `sign_psbt_validate_helpers.c`, `sign_custom_inputs.c`, `vault_script.c`, `vault_script.h`, `globals.h`)

  **Scope of the guarantee.** The binding is to the intent loaded in the *current session*, not to the intent the vault was funded under — the device cannot recognise the latter, since keeper and challenger keys arrive as host-supplied TLV and are not derivable from the seed. In practice an Assert is signed after a power cycle, so the host supplies a fresh intent and an attacker gets an opportunity to present a substituted challenger set. What stops that is the user's review of the key list on Screen 2, which is therefore load-bearing for Assert safety and not merely informational. This is a real improvement over the previous state — where no check existed at all and the bypass was silent — but it is not equivalent to binding against the funding intent. Displaying the challenger set on Screen 5 would remove the reliance on a screen reviewed earlier in the session; not done here.

### Changed

- **BREAKING — Assert now requires `INTENT_LOADED`**: it was previously accepted from any state, including `IDLE`. Note the tension with the `[0.9.6]` F-7 entry, which cites an HLD requirement that standalone flows stay state-independent — and HLD v22 says so directly for Assert in three places (lines 134, 722, 879: *"can be signed at any time, with or without a loaded intent"*). F-7's remedy is unavailable here: its discriminator was present in the leaf itself (a challenger multisig vs. a second lone signer), whereas the Assert leaf's challenger *identities* are not in the leaf and exist nowhere but the intent. So the choice was a state gate or leaving the hole open, and the app fails closed. Because `APPROVE_VAULT_INTENT` requires `HASH_DERIVED`, a host signing an Assert in a fresh session must replay `DERIVE_CONTEXT_HASH` → `APPROVE_VAULT_INTENT`. Three compatibility consequences, all intended but none of them free:

  1. **Wire behaviour changes with no negotiation path.** A host that previously signed an Assert from `IDLE` now receives `SW_INCORRECT_DATA`. `VAULT_PROTOCOL_VERSION` is a value the host must *match*, not a capability the device advertises, so an existing integration cannot detect the new requirement except by failing. Any host that signs Asserts needs updating in lockstep with this firmware.
  2. **Intent re-approval becomes a routine step of the Assert flow, and it resets every signature cap** (`pre_pegin_signed`, `pegin_signed`, `payout_signed`, `nopayout_signed`) plus the Payout and PegIn dedup bitmasks — `vault_context_invalidate` clears the whole context. This grants no new capability, since a host could always re-approve from any state, but it moves cap resetting from exceptional to expected. Each reset still costs a user approval on Screen 2.
  3. **The guarantee is session-scoped**, not funding-scoped — see the Security entry above.

  Also note HLD line 722 states that pattern identification *"establishes the transaction's shape, not the provenance of the spent UTXO"* — i.e. the residual this change closes was previously accepted by design. **Reclassifying Assert as intent-bound needs HLD sign-off, not just a spec edit** — see the Assert section of `APP_SPECIFICATION.md` and `docs/integration-guide.md`.

### Fixed

- **Stale Assert documentation**: `APP_SPECIFICATION.md` still described the captured leaf prefix as 35 bytes, though `VAULT_LEAF_PREFIX_LEN` grew to 68 in `[0.9.6]`, and listed the challenger multisig as unverified content. Both corrected, along with the state requirement, the `<D>` pinning, the leaf-script layout (which now names the two groups and their ordering, since the device depends on it), the long-leaf "Kept" table, and the `SW_CAP_EXCEEDED` cap taxonomy.


## [0.9.6] - external security audit remediation (run `feb4b487`, 2026-08-26)

### Security

- **Screen 8 identifies the Vault UTXO, not the Assert connector (F-3/F-12)**: `_validate_display_payout_finalize` read `PSBT_IN_PREVIOUS_TXID` from Input 1 — the Assert:0 connector — and passed it to a display parameter documented as, and labelled, the Vault UTXO prevout. Input 0, the input the depositor's funds actually leave from, was never shown, so a depositor cross-checking which vault was being finalized saw a mismatch on a legitimate transaction. Screen 8 now reads Input 0's prevout; Input 1 needs no on-screen identity, being pinned by the leaf-script and taproot-commitment checks. Label, value and API contract now agree (`sign_psbt_validate.c`, `display.h`)
- **PayoutFinalize displays the transaction's own fee (F-4/F-5/F-9)**: the fee shown on Screen 8 was the intent-derived bound `vault_amount − DUST − amount_received`, which omits Input 1's value and so understates the real fee; with no intent loaded or a multi-vault intent it was hard-coded to `0`, and `display_payout_finalize` then dropped the row entirely, making an unknown fee indistinguishable from a zero one. Both are accepted, signable states. The device already holds the true figure — the base app validates `inputs_total_amount` and `outputs.total_amount` — so that is now what is displayed, with a checked subtraction, and the fee row is unconditional. The intent-derived value is retained unchanged as the *enforcement* bound per the HLD, renamed `implied_fee` so the two roles cannot be confused. Input 0's value is host-stated but `SIGHASH_DEFAULT` commits to every prevout amount, so a misstatement yields an unusable signature rather than a misleading display (`sign_psbt_validate.c`, `display.c`, `display.h`)
- **Assert dispatch predicate no longer a catch-all (F-6)**: the Assert branch routed on `leaf[34] == OP_PUSHBYTES_32` plus a length and `OP_TRUE` terminator, and the comment argued byte 34 must be the first challenger key's push. It need not be: `OP_PUSHBYTES_32` followed by 32 arbitrary bytes is a data push, and a trailing `OP_DROP` makes it a no-op, so the 69-byte leaf `<D> OP_CHECKSIGVERIFY <32 junk> OP_DROP OP_TRUE` satisfied every conjunct while being spendable with the depositor's signature alone. It then reached the app's weakest validator — no output enforcement, no cap, no dedup, no intent binding, and a screen showing no destination. The predicate now also requires `OP_CHECKSIG` at the offset closing the first multisig key (`VAULT_LEAF_GROUP0_OP_OFF`), which every real Assert leaf satisfies and a no-op middle cannot. Real Assert leaves are streamed, not buffered, so `VAULT_LEAF_PREFIX_LEN` grew from 35 to 68 bytes (+33 B BSS) to make that byte available, pinned by a `_Static_assert` (`sign_psbt_validate.c`, `vault_script.h`, `vault_constants.h`, `globals.c`, `globals.h`)
- **PayoutFinalize no longer accepts the Vault UTXO leaf (F-7)**: `parse_payout_leaf_script` accepted any script over 68 bytes shaped `OP_PUSHBYTES_32 <D> OP_CHECKSIGVERIFY … <t> OP_CSV` — exactly what `vault_build_vault_utxo_leaf` emits, with `pegin_csv_timelock ∈ [72,1008]` overlapping the accepted payout range `[90,4032]`. Because PayoutFinalize is a standalone flow reachable from `VAULT_STATE_IDLE` (by HLD design), a host could present the live Vault UTXO as Input 1 with its genuine leaf and control block: the taproot commitment passes, and outside `INTENT_LOADED` the CSV equality, the Input 1 value ceiling and the implied-fee cap are all skipped. A colluding N-of-N participant set could thereby obtain the depositor's Vault UTXO signature with no fee bound and no signing cap, burning the balance to miner fees. Fixed in the parser rather than with a session-state gate — the HLD requires standalone flows to stay state-independent — by requiring the challenger-multisig shape that a Vault UTXO leaf (a second lone signer, `<VP> OP_CHECKSIGVERIFY`) cannot satisfy. The signing path re-asserts the same shape (`sign_psbt_validate_helpers.c`, `sign_custom_inputs.c`)
- **NoPayout fee bound and Output 0 dust floor (F-8)**: Output 0's value was read and discarded — its scriptPubKey was pinned to `P2TR(Challenger_j)` but its amount was free, and the flow had no fee computation at all. Since Input 0's ceiling had been widened to `VAULT_DUST_LIMIT + base_fee_rate × MAX_COUNCIL_NOPAYOUT_VSIZE` (see the WITNESS_UTXO value range entry above) without the compensating output bound the HLD's "at most 3×DUST at stake" argument relied on, a host could set Output 0 to any value down to zero and burn the whole Assert:0 connector — depositor money, funded from Claim:0 — to miner fees, with no user screen since NoPayout is intent-bound silent signing. The implied fee `(in0 + in1 + in2) − out0` is now computed with a checked subtraction and bounded by `base_fee_rate × MAX_COUNCIL_NOPAYOUT_VSIZE`, mirroring Payout and PayoutFinalize, and Output 0 must be at least `VAULT_DUST_LIMIT` (`sign_psbt_validate.c`)
- **Screen 3 "Refund timelock" no longer renders blank (F-10)**: the value was formatted with `snprintf("%lu blocks", …)`, but the BOLOS `snprintf` implements only `%ll{u,d,x,X}` for the `l` modifier — a lone `%lu` abandons the conversion and returns −1, leaving a zero-length string. The committed goldens for Flex, Stax and Nano S+ all show the label with no value. One of the five fields the Refund review is designed to present was therefore absent on every device, and in the standalone path `_validate_display_refund` enforces only `csv_value >= 72` with no upper bound, making that screen the sole user-visible control on how long the reclaim is deferred. Screen 3 now uses the same `format_timelock_blocks()` helper as Screen 2, so a transaction's timelock can be compared by eye against the approved intent; the helper widened to `uint32_t` with 64-bit minutes, and `extra_str` grew to a new `TX_DISPLAY_EXTRA_STR_SIZE` (40 B) sized for its widest output (`display.c`, `display.h`, `globals.h`)
- **Pre-PegIn requires a native SegWit wallet policy (F-11)**: `_compute_prepegin_txid` serialises every input with a zero-length scriptSig, but nothing enforced a policy that produces one — without an HMAC the base app accepts `pkh()` (BIP-44), `sh(wpkh())` (BIP-49), `wpkh()` (BIP-84) and `tr()` (BIP-86) alike, and `_validate_prepegin` never inspected the policy type. Funding from a legacy or P2SH-wrapped account attaches a scriptSig at broadcast, so the real txid could not equal the device-computed one the intent commits to, yet the txid gate passed and every input was signed — burning the one-shot `pre_pegin_signed` slot and stranding the deposit at an outpoint no PegIn, Payout or NoPayout can reference (both key off `intent->prepegin_txid`), recoverable only through the HTLC refund leaf after `htlc_refund_timelock`. The assumption is now an enforced precondition: the top-level policy node must be native SegWit — `wpkh()`/`wsh()` (v0) or `tr()` (v1) — with `sh(...)` wrappers excluded explicitly, since `get_policy_segwit_version` reports 0 for wrapped SegWit too. Rejection is `SW_INCORRECT_DATA`, matching the neighbouring Pre-PegIn shape checks (`sign_psbt_validate.c`)


### Fixed

- **Stale PayoutFinalize fee-cap comment corrected (F-9)**: the note above the Screen 8 txid read described the cap as applying "when Input 0 txid matches a vault group". No such match can reach this function — the dispatcher routes any Input 0 txid matching a computed PegIn txid to `_validate_payout`, which is precisely why the cap keys off `vault_count == 1`. Corrected to "the single-vault fee cap" (`sign_psbt_validate.c`)
- **Screen 8 API documentation matches what is rendered (F-12)**: `display_payout_finalize`'s doc comment described the pre-fix field set and did not record that every field is now unconditionally rendered with no "unknown" encoding (`display.h`)
- **Streamed leaf length rejection made explicit (F-13/F-14)**: `_leaf_stream_len_cb` enforced `VAULT_ASSERT_SCRIPT_MAX_LEN` by returning without setting `len_known`, which only disabled the data callback and left the failure indistinguishable from a length callback that never fired. The rejection is now recorded in a `len_rejected` flag: the data callback returns immediately for every subsequent chunk — no hashing, no buffering, no bookkeeping — and `_stream_tap_leaf_value` fails on the flag directly. This bounds the *work*, not the *round-trips*: `call_stream_preimage`'s length callback returns `void`, so the app cannot terminate an exchange the host has already started, and a declared length still costs one `CCMD_GET_MORE_ELEMENTS` per chunk. The real fix belongs in the base app and is written up in `docs/upstream-stream-preimage-abort.md`; impact is availability only — nothing unverified is accepted, no state is corrupted, and the device recovers on a power cycle (`sign_psbt_validate.c`, `vault_constants.h`)
- **`VAULT_ASSERT_SCRIPT_MAX_LEN` and the 0.9.5 streaming entry no longer claim a bound they do not implement**: both stated the cap prevents "an unbounded read loop". It does not — it refuses to *process* an over-length value but cannot end the exchange. Both corrected to say what the cap does and what it does not (`vault_constants.h`, `CHANGELOG.md`)
- **`vault_leaf_meta_t` docstring corrected (D-5/D-6/D-7)**: it told consumers that when a leaf is unbuffered "only the fields below, plus `leaf_script_len`, are meaningful" — but `leaf_script_len` is not a member of `vault_leaf_meta_t`. It lives in `G_scratch.tls`, physically inside `leaf_check.actual_buf` (at `actual_buf[264..267]`), and any `actual_buf` reconstruction destroys it. No consumer reads a clobbered value today — every one is preceded by a fresh `vault_read_*` call, which `memset`s `G_scratch.tls` first — but the docstring blessed reliance on a field the layout does not keep safe. It now states plainly which fields survive union reuse and which do not, and that `leaf_script`, `leaf_script_len` and `leaf_version` are valid only between a `vault_read_*` return and the next write to `leaf_check` (`globals.h`)
- **`test_sign_psbt_assert_leaf_over_stream_cap_is_rejected` boundary tightened**: parametrised over 16384 and 16385. The cap applies to the PSBT *value* (`<script> || <leaf_version>`), so a 16384-byte script is already one too many — the previous single 16385 case sat two past the true boundary. Its docstring repeated the same false "unbounded read loop" claim and now states what the test does and does not prove (`tests/test_screen5_assert.py`)
- **Payout-leaf builder maximum pinned to the union overlap threshold**: `_detect_payout_claimer` rebuilds the expected leaf into `leaf_check.actual_buf` and compares it byte-for-byte against `tls.leaf_script`, which alias at a distance of 2298 bytes. `globals.c` pinned that distance but nothing pinned `vault_build_assert0_payout_leaf`'s worst-case output (2228 B at `VAULT_MAX_KEEPERS = VAULT_MAX_CHALLENGERS = 32`) against it, so raising either count would have silently made the reconstruction overwrite the bytes under comparison. A `_Static_assert` alongside the existing layout assertions now breaks the build instead (`globals.c`)
- **Pre-PegIn policy tests never ran (F-11)**: `test_sign_psbt_prepegin_nested_segwit_wallet_rejected` and `..._legacy_wallet_rejected` unpacked two values from `_setup_prepegin_ecdsa_case`, which returns three (`psbt, coin_type, pubkey`). Both raised `ValueError` during setup, before any PSBT reached the device, so the rejection path they exist to cover was never exercised (`tests/test_sign_psbt_validate.py`)
- **Screen 8 touch navigation missed the new fee page**: `sign_psbt_payout_finalize_approve_nav` hard-coded three taps and documented Screen 8 as having three fields; it has five, and making the fee row unconditional pushed flex and apex_p to a fourth content page, so all three approve-path tests timed out waiting for a screen change. Now branches per device the way the PoP helper does — stax keeps three taps, flex and apex_p get four (`tests/instructions.py`)

## [0.9.5]

### Security

- **Assert leaf discriminator restored**: the Assert router had been reduced to a single `leaf[34] == OP_PUSHBYTES_32` test, which the 68-byte NoPayout leaf also satisfies — it shares the whole 35-byte prefix. Since NoPayout is routed only by transaction shape (3-in/1-out), an Assert:0 UTXO re-presented as 1-in/1-out reached `_validate_display_assert` and was signed with no cap, no per-(group, challenger) dedup and no intent binding, bypassing the NoPayout replay protections entirely. Assert now additionally requires a leaf longer than the NoPayout leaf and an `OP_TRUE` terminator, per the HLD invariant that standalone leaf patterns remain mutually exclusive (`sign_psbt_validate.c`)
- **Assert taproot commitment unconditional**: a "truncation" branch assumed `call_get_merkleized_map_value` performs a partial read when the value fills the buffer. It does not — `call_get_merkle_preimage` returns `-4` for an oversized preimage and hash-verifies the whole value. The branch therefore only ever fired on a leaf sized to exactly `VAULT_SCRIPT_MAX_LEN`, where it fabricated the leaf version, folded the real version byte into the script, and caused `_refund_verify_taproot_commitment` to be skipped — letting the host choose whether the commitment was verified at all. Branch removed; the commitment check is unconditional (`sign_psbt_validate.c`)
- **Unknown per-group TLV tags rejected again**: `vault_tlv_parse_group` had been changed to skip unrecognised tags for "forward compatibility", contradicting the HLD's canonical-encoding rule and `APP_SPECIFICATION.md` / `docs/apdu.md`, which both state unknown tags are rejected. Reverted; the scalar and group parsers are strict again (`vault_tlv.c`, `vault_tlv.h`)
- **DERIVE_CONTEXT_HASH stream is exclusive**: a multi-chunk stream accumulates into `G_scratch.derive_ctx`, but `context_buf` lies entirely inside `tls.leaf_script` and the session gates live outside the union. Any `SIGN_PSBT` in between (Refund/Claim/Assert/WC have no state gate) overwrote the buffer with host-supplied leaf bytes while leaving `streaming_in_progress` and `context_received_len` intact, so the continuation was accepted and hashed into a poisoned buffer — yielding a root that does not match the approved context. Such a PSBT is now rejected and the stream aborted (`sign_psbt_validate.c`)
- **NoPayout cap exhaustion nullifies the intent**: exceeding the cap returned `SW_INCORRECT_DATA` and left the session live, unlike the PegIn and Payout paths. Now invalidates the context and returns `SW_CAP_EXCEEDED`, per the HLD rule that any error in a signature flow nullifies the intent (`sign_psbt_validate.c`)
- **NoPayout signer re-checks the challenger key**: the signing path re-verified leaf shape and the depositor key but not `leaf[35..66]` against the stashed `nopayout_challenger_index`, so a divergence would mean the signature and the consumed dedup bit referred to different challengers. Now bounds-checked and compared (`sign_custom_inputs.c`)
- **`handle_continuation_chunk` guard corrected**: the defence-in-depth check tested `context_received_len > VAULT_CONTEXT_MAX_LEN`, but the dangerous condition is `received >= total` — a `uint16_t` `total - received` would wrap to ~65535, pass the `lc > remaining` check, and memcpy past the declared length (`derive_context_hash.c`)
- **PayoutFinalize 3-input fallthrough closed**: the signer's outer predicate admitted any 3-input PSBT while the inner NoPayout branch required 3-in/1-out, so a 3-in PSBT with a different output count fell through to the Payout signing code with a stale `vault_group_index`. Unreachable today, but the safety rested on dispatcher statement ordering rather than anything local; now rejected explicitly (`sign_custom_inputs.c`)
- **PayoutFinalize `amount_received` floor**: reject zero Output 0 value — a valid on-chain path not covered by `SIGHASH_DEFAULT` (`sign_psbt_validate.c`)
- **PayoutFinalize single-vault fee cap**: when `vault_count == 1`, bound the implied fee against `base_fee_rate × MAX_PAYOUTFINALIZE_VSIZE` using the attested `vault_amount` (`sign_psbt_validate.c`)
- **VP commission sub-dust rejection**: reject Out1 in `(0, VAULT_DUST_LIMIT)` — produces a non-standard output; valid values are 0 or `[VAULT_DUST_LIMIT, Fc]` (`sign_psbt_validate.c`)
- **Payout Assert:0 taproot commitment**: switched to `vault_read_payout_leaf_script` + `_refund_verify_taproot_commitment` to handle multi-leaf Huffman control blocks (`sign_psbt_validate.c`)
- **Pre-PegIn CPFP anchor validation**: accept an optional P2TR(depositor_pk) BIP-86 key-path output at exactly `VAULT_DUST_LIMIT` (546 sat); enforce at-most-one; reject any unrecognised non-HTLC, non-change, non-anchor output (`sign_psbt_validate.c`)
- **NoPayout WITNESS_UTXO value range**: Input 0 (Assert:0) and Input 1 (Assert:0 for Payout/PayoutFinalize) now enforce a lower-bound floor of `VAULT_DUST_LIMIT` with a fee-scaled ceiling of `VAULT_DUST_LIMIT + base_fee_rate × MAX_COUNCIL_NOPAYOUT_VSIZE`; the previous exact `== VAULT_DUST_LIMIT` / `> VAULT_DUST_LIMIT` checks are removed (`sign_psbt_validate.c`)
- **PoP intent key check**: when `VAULT_STATE_INTENT_LOADED`, the PSBT's BIP-86 internal key must equal `depositor_pk` from the approved intent; mismatches are rejected with `SW_INCORRECT_DATA` (`sign_psbt_validate.c`)
- **`base_fee_rate` max tightened to 10,000 sat/vB**: previous upper bound was `UINT32_MAX`; capped at 10,000 to match the btc-vault daemon's accepted range, blocking implausibly high fee rates at intent-load time (`vault_tlv.c`)

### Added

- **Long Assert leaf support (L-11)**: real Assert leaves are 11,526–13,636 bytes (btc-vault `claim_assert.rs`; the vector in `tests/vectors/depositor-as-claimer/assert.txt` carries an 11,662-byte one) against a 2560-byte read buffer, so every real Assert transaction was previously rejected. The device now falls back to `call_stream_merkleized_map_value` when the buffered read reports the value is oversized, folding the script into the BIP-341 TapLeaf hash incrementally and retaining only the hash, the 35-byte prefix, the length and the terminating byte — constant memory, no partial buffer. The taproot commitment is then verified against the streamed hash, unconditionally and identically to the buffered path. Streamed leaves are capped at `VAULT_ASSERT_SCRIPT_MAX_LEN` (16384): a value declaring more is refused before any byte of it is hashed or buffered, and the read fails. The cap bounds the work, not the exchange — `call_stream_preimage`'s length callback returns `void`, so the app cannot abort a read the host has already started (see `docs/upstream-stream-preimage-abort.md`). No APDU interface change: the streaming path uses the same `CCMD_GET_PREIMAGE` / `CCMD_GET_MORE_ELEMENTS` client commands as before, only more round-trips, and only for oversized leaves (`sign_psbt_validate.c`, `vault_script.c`, `globals.h`)
- **`G_leaf_meta`**: leaf hash, prefix, terminating byte and the `buffered` flag moved outside the `G_scratch` union. Every byte of the leaf state past `leaf_script` aliases `leaf_check.actual_buf`, and `_detect_payout_claimer` rebuilds an expected leaf there before the commitment check runs — which would have destroyed the hash that check depends on. Flows that compare a leaf byte-for-byte now require `buffered` and fail closed otherwise (`globals.h`, `globals.c`, `sign_psbt_validate.c`, `sign_custom_inputs.c`)

### Fixed

- **NoPayout accepts the real Assert:0 prevout**: Input 0's `PSBT_IN_PREVIOUS_TXID` was matched against each group's computed PegIn txid, which no real NoPayout can satisfy — Input 0 spends Assert:0, whose txid the device cannot reconstruct. Every NoPayout from btc-vault failed with `SW_INCORRECT_DATA`. Lookup removed, and with it the per-slot dedup it keyed: a NoPayout PSBT cannot identify its vault group, so `nopayout_signed` is the only bound (drops `nopayout_claimer_mask` and `nopayout_group_index`, 80 B). `vout == 0` still enforced (`sign_psbt_validate.c`, `vault_context.h`, `sign_custom_inputs.c`, `globals.c`)
- **Payout output script bound tied to what can be signed**: host-provided VP/VK scriptPubKeys were read into a 100-byte buffer, implying a limit the device cannot honour — the base app hashes output scripts into `MAX_OUTPUT_SCRIPTPUBKEY_LEN` (83), so longer ones fail there anyway. Bound now derives from that constant. Effective range 22–83 is unchanged and covers every standard address type; the contract's 128-byte `MAX_PAYOUT_ADDRESS_LENGTH` stays out of reach for 3+-key bare multisig (`sign_psbt_validate.c`, `vault_script.h`)
- **PayoutFinalize reachable again with an intent loaded**: the fee bound had been re-keyed to identify the vault group by matching Input 0's `PSBT_IN_PREVIOUS_TXID` against the groups' computed PegIn txids — but that is exactly what the dispatcher already does to tell a VK/Depositor Payout from a PayoutFinalize, so a match never reaches this handler. The accompanying `pf_group_idx < 0` rejection therefore made PayoutFinalize fail unconditionally whenever an intent was loaded, and the fee cap was dead code. Restored the HLD rule: the bound applies when `vault_count == 1`, using the sole group's attested `vault_amount`, and an intent being loaded is no longer a rejection reason (`sign_psbt_validate.c`)
- **PayoutFinalize fee bound back to its own vsize**: the cap had been switched to the participant-scaled Payout formula `500 + 55 × (N + M)`, reaching 4020 vs the HLD-specified `MAX_PAYOUTFINALIZE_VSIZE`. Restored (`sign_psbt_validate.c`)

### Changed

- **VP commission relaxed to `<= Fc`**: accept Out1 ≤ `commission_fee`; exact match no longer required (`sign_psbt_validate.c`)
- **PayoutFinalize conservation check removed**: check against Input 1 value was unconditionally violated after Input 1 was fixed to `VAULT_DUST_LIMIT`; replaced by the floor and fee cap above (`sign_psbt_validate.c`)
- **`encode_multisig_group` N=1 encoding**: removed the N=1 shortcut that emitted `<key> OP_CHECKSIG[VERIFY]`; always emits `<key> OP_CHECKSIG [OP_CHECKSIGADD…] N OP_NUMEQUAL[VERIFY]`, matching the on-chain encoding from btc-vault for single-key groups (`vault_script.c`)
- **Screen 2 (intent) split into two streaming reviews**: the global scalar params are now shown in a non-skippable phase 1 (no `SKIPPABLE_OPERATION`), which a single streaming review cannot express; the per-vault groups and key list follow in a skippable phase 2. "Skip" on a vault-group page advances to the *next group* rather than to the approval page, so no group's vault amount, commission fee, depositor claim or PegIn fee can be bypassed; `g_stream_vault_idx` is reset on entry so both confirm and skip paths start from vault group 0 (`display.c`)

### Added

- **`prepegin_max_fee` on Screen 2**: "Max Pre-PegIn fee" is now shown on the vault intent approval screen, giving the user a visible bound on the Pre-PegIn transaction fee (`display.c`)
- **Screen 4 (Claim) Output 0 address**: bech32m address of the ClaimAssertConnector output (Output 0) is decoded from its scriptPubKey and shown as an "Output 0 address" field (`display.c`, `sign_psbt_validate.c`)
- **Screen 7 (PoP) depositor Bitcoin address**: the depositor's BIP-86 tweaked bech32m address is derived and displayed as a "Bitcoin address" field on the PoP review screen (`display.c`, `sign_psbt_validate.c`)
- **Screen 8 (PayoutFinalize) fee and vault txid**: `display_payout_finalize` now shows "Vault UTXO txid" (Input 1 prevout) and "Transaction fee"; fee is attested from `vault_amount` for single-vault intent-loaded flows (`display.c`, `sign_psbt_validate.c`)

### Fixed

- **Nano snapshot path** for `test_payout_finalize_vault_amount_too_small`: missing `testname` argument sent snapshots to `_0_0` instead of the correct directory
- **Added** `test_payout_finalize_input1_wrong_value`: covers `SW_INCORRECT_DATA` when Input 1 `witness_utxo` ≠ `VAULT_DUST_LIMIT`
- **Added** `test_sign_psbt_payout_vp_commission_sub_dust`: covers `SW_INCORRECT_DATA` for sub-dust VP Out1
- **Added** `test_sign_psbt_payout_multileaf_assert0`: covers the multi-leaf Assert:0 control block path
- **Added** `test_sign_psbt_nopayout_zero_output_value`, `test_sign_psbt_nopayout_sub_dust_output_value`, `test_sign_psbt_nopayout_fee_above_bound` and `test_sign_psbt_nopayout_fee_at_bound`: cover the NoPayout Output 0 dust floor and the fee bound at and above the cap. `_build_nopayout_psbt` gained an `out_value` parameter; its default now leaves a fee inside the cap instead of the previous fixed 1000 sat
- **Navigation step counts updated** for Screen 2 intent skip (one extra skip/confirm pair), Screen 4 Claim (one extra tap for Output 0 address), and Screen 7 PoP (two extra clicks on Nano, one extra tap on Stax/Flex/Apex) (`tests/instructions.py`)
- **`bip322.h` to_spend txid comment**: corrected "reversed to Bitcoin wire format" → "in PSBT/wire byte order (not byte-reversed)" (`bip322.h`)
- **`vault_script.h` NUMS key comment**: replaced incorrect SHA256("nothing_up_my_sleeve") description with the accurate BIP-341 `lift_x(…)` construction (`vault_script.h`)
- **Integration guide Payout annotation**: state diagram entry corrected from `(Screen 8)` to `(silent)`; Step 5 body now states Payout signing is silent per APP_SPECIFICATION.md §3 (`docs/integration-guide.md`)
- **PayoutFinalize unmatched group fall-through**: when `VAULT_STATE_INTENT_LOADED`, `_validate_display_payout_finalize` now rejects immediately with `SW_INCORRECT_DATA` if Input 0 PREVIOUS_TXID matches no vault group's computed PegIn TXID (`sign_psbt_validate.c`)
- **`_validate_display_claim` magic output count**: replaced hardcoded `2` with `st->n_outputs` in both `_read_output` calls; `st->n_outputs == 2` is already enforced above (`sign_psbt_validate.c`)

## [0.9.4] - NAPPS-1466: v22 HLD alignment — Connection 2 flow, session-state removal, spec discrepancy fixes

Aligns the device application with HLD v22 across twenty tracked discrepancies identified during
a full spec-vs-code audit.  No wire-format or SW changes for the host; all changes are internal
security hardening, protocol-correctness fixes, and documentation alignment.

### Security

- **VK / Depositor Payout routing** (`sign_psbt_validate.c`, `sign_custom_inputs.c`): PSBTs with
  `n_inputs==2 && n_outputs==2` are now routed to `_validate_payout` when Input 0 is internal
  (`bitvector_get(internal_inputs, 0)`), not to `_validate_display_payout_finalize`.  Previously
  both VK and Depositor Payout shapes were misrouted to the PayoutFinalize path and signed
  Input 1 instead of Input 0.
- **NoPayout input-count guard** (`_validate_nopayout`): rejects any PSBT where `n_inputs != 3`
  or `n_outputs != 1`.  Previously only output count was implicit and extra inputs were silently accepted.
- **NoPayout Output 0 P2TR verification** (`_validate_nopayout`): Output 0 scriptPubKey is now
  verified against `P2TR(Challenger_j)` via `crypto_tr_tweak_pubkey` with no scripts.  Previously
  the output script was not checked and funds could have been redirected to an arbitrary address.
- **Payout fee-bound overflow guard** (`_validate_payout`): `vsize` is computed as an intermediate
  `uint64_t`; overflow (`base_fee_rate * vsize > UINT64_MAX`) and zero-fee (`fee == 0`) are now
  explicitly rejected.
- **Payout per-slot deduplication** (`sign_psbt_validate.c`, `sign_custom_inputs.c`,
  `vault_context.h`): Payout is a silent signing with no confirmation screen.  A malicious host
  could replay the same `(group, claimer)` PSBT to exhaust the flat `payout_signed` cap and
  prevent legitimate claimers from receiving signatures.  Added `payout_claimer_mask`
  (43-byte bitmask) to `vault_context_t`; bit `gi*(keeper_count+2)+claimer_idx` is checked in
  `_validate_payout` before accepting the signing and set in `sign_custom_inputs` after the
  signature is produced.  A duplicate triggers `vault_context_invalidate` and `SW_CAP_EXCEEDED`.
- **PegIn per-group deduplication** (`sign_psbt_validate.c`, `sign_custom_inputs.c`,
  `vault_context.h`): the flat `pegin_signed` cap allowed a malicious host to replay the same
  group's PegIn PSBT with `vault_count > 1`, exhausting the cap while wasting one slot.  Added
  `pegin_group_mask` (2-byte bitmask) to `vault_context_t`; bit `gi` is checked in
  `_validate_pegin` before accepting the signing and set in `sign_custom_inputs` after the
  signature is produced.  A duplicate triggers `vault_context_invalidate` and `SW_CAP_EXCEEDED`.
- **Payout claimer detection: O(keeper_count) key scan instead of O(keeper_count) ECC ops**
  (`sign_psbt_validate.c`, `_detect_payout_claimer`): the previous implementation identified
  the claimer by trying every candidate's full tapscript commitment — up to 34 secp256k1 tweak
  operations (~3.4 s at maximum keeper count), risking BLE timeout.  The new implementation
  reads `PSBT_IN_TAP_LEAF_SCRIPT` for Input 1 directly (the host must supply it for any
  script-path spend), extracts the claimer key from the fixed offset 1 of the Assert:0 payout
  leaf, matches it against intent keys with `memcmp`, then reconstructs the full leaf from the
  intent and verifies byte-for-byte so the host cannot forge a different leaf shape.  Detection
  is now 2 PSBT lookups + 34 `memcmp` + 1 leaf rebuild, followed by a single ECC tweak for the
  WITNESS_UTXO scriptPubKey check.  No wire-format or PSBT protocol change.
- **Refund SIGHASH_DEFAULT only** (`_validate_display_refund`): `SIGHASH_ALL` (`0x01`) is no longer
  accepted for Refund inputs; only `SIGHASH_DEFAULT` (`0x00`, absent or explicit) is valid.
- **Refund nSequence exact match** (`_validate_display_refund`): Input 0 `nSequence` must equal the
  CSV timelock value exactly; values greater than the timelock are now rejected (`!=` instead of `<`).
- **NoPayout Input 0 UTXO dust alignment** (`_validate_nopayout`): Input 0 witness UTXO value
  check changed from `!= VAULT_DUST_LIMIT` to `> VAULT_DUST_LIMIT`, consistent with Inputs 1–2.
- **Payout Output 0 dust check** (`_validate_payout`): Output 0 value is now verified to be
  strictly greater than `VAULT_DUST_LIMIT`.
- **PoP TAP_MERKLE_ROOT absence enforced** (`_validate_display_pop`): an explicit
  `call_get_merkleized_map_value` check rejects any PoP PSBT that carries a `PSBT_IN_TAP_MERKLE_ROOT`
  entry, confirming key-path-only spend.
- **Pre-PegIn txid binding** (`_validate_prepegin`): the device now serialises the non-witness
  Pre-PegIn transaction from PSBT fields and double-SHA256s it, comparing the result against
  `intent->prepegin_txid`.  Previously the txid was not independently verified; a malicious host
  could supply a mismatched PSBT and the device would sign a transaction inconsistent with the
  approved intent.
- **PegIn TRUC version enforcement** (`_validate_pegin`): `tx_version` must be exactly `3` (TRUC);
  values `1`, `2`, or `≥ 4` are now rejected.  Previously `tx_version >= 2` was accepted.
- **VP commission fee exact match** (`_validate_payout`): Output 1 (VP commission) must equal
  `intent->groups[gi].commission_fee` exactly; `<= commission_fee` is no longer accepted.  This
  closes a path where a host could inflate the commission and under-pay the depositor.
- **NoPayout connector UTXO dust checks** (`_validate_nopayout`): Inputs 1 and 2 witness UTXO
  values are now verified to be `<= VAULT_DUST_LIMIT`.  Previously only the structural shape of
  those inputs was checked.
- **Claim/Assert/WC sequence == 0xFFFFFFFF** (`_validate_display_claim/assert/wc`): Input 0
  `nSequence` must be exactly `0xFFFFFFFF`.  The spec requires this for all three flows; the
  check was previously absent.
- **Pre-PegIn locktime == 0** (`_validate_prepegin`): `locktime` is now required to be `0`.
  Previously only `tx_version` and `n_inputs / n_outputs` counts were verified.
- **Multi-vault PegIn group auto-detection** (`_validate_pegin`): `vault_group_index` is now
  derived from `PSBT_IN_OUTPUT_INDEX` matched against `intent->groups[g].htlc_vout` instead of
  being hardcoded to `0`.  This fixes signing for PSBTs belonging to vault group `g > 0`.
- **Payout group/claimer auto-detection** (`_validate_payout`): `vault_group_index` (gi) is
  derived from `PSBT_IN_PREVIOUS_TXID` vs `vault_compute_pegin_txid`; `payout_index` (claimer)
  is derived from Input 1's witness UTXO SPK vs `vault_build_assert0_payout_leaf`.  Previously
  both cursors were advanced sequentially from a fixed start, requiring strict host ordering.

### Changed

- **Multi-group per APDU** (`approve_vault_intent.c`, `vault_tlv.c`): `vault_tlv_parse_group` now
  accepts a `size_t *consumed` output parameter and stops as soon as all 6 fields are seen, allowing
  back-to-back group records in one APDU payload.  `handle_group_payload` loops over all complete
  groups in the APDU instead of returning after the first.  Per-group TLV fields must now appear in
  strictly ascending tag order (htlc_vout first); out-of-order or duplicate tags are rejected.
- **`_pegin_validate_outputs` group index** (`sign_psbt_validate.c`): `group_idx` is now passed as
  a parameter rather than hardcoded to `0`.  PegIn outputs for `vault_count > 1` are validated
  against the correct vault group's VP key, vault amount, and fee parameters.
- **Connection 2 flow enabled** (`APPROVE_VAULT_INTENT`, `DERIVE_CONTEXT_HASH`): removed the
  `root_user_approved` gate that blocked `APPROVE_VAULT_INTENT` when `DERIVE_CONTEXT_HASH` was
  called with `P2=0x01` (silent re-derivation).  Connection 2 — where the host re-derives the
  root silently after reconnecting — is now fully supported.
- **Session state machine simplified** (`vault_context.h/c`, all signing handlers): removed
  `VAULT_STATE_SESSION1_PREPEGIN_EXPECTED`, `SESSION2_PEGIN_EXPECTED`, `SESSION2_PAYOUT_EXPECTED`,
  and `SESSION2_COMPLETE`.  The state machine is now three states: `IDLE → HASH_DERIVED →
  INTENT_LOADED`.  `INTENT_LOADED` is the terminal active state; all signing flows (Pre-PegIn,
  PegIn, Payout, NoPayout, Refund, Claim, Assert, WC) are dispatched solely by PSBT structure
  with no inter-transaction ordering requirement (v22).
- **`sign_custom_inputs` routing** (`sign_custom_inputs.c`): replaced session-state gates with
  PSBT-structure dispatch: PegIn identified by `n_inputs==1 && n_outputs==3`; Payout by
  `n_inputs==2`; NoPayout by `n_inputs==3 && n_outputs==1`.  The `sgi--` step-back kludge
  (previously needed because `_validate_payout` advanced `vault_group_index` past the last
  claimer) is removed — `vault_group_index` and `payout_index` are now written directly by the
  validator and read as-is by the signer.
- **`validate_and_display_transaction` dispatch** (`sign_psbt_validate.c`): replaced
  `SESSION2_PEGIN_EXPECTED / SESSION2_PAYOUT_EXPECTED / SESSION2_COMPLETE` branches with a
  unified `INTENT_LOADED + has_no_wallet_policy` block that routes by `n_inputs / n_outputs`
  and, for PegIn disambiguation, matches Input 0's witness UTXO against the HTLC scriptPubKeys
  reconstructed from the approved intent.

### Fixed

- **Screen 7 (PoP) field labels** (`display.c`): corrected "ETH address" → "Ethereum address",
  "Chain ID" → "Chain id", "Registry contract" → "Registry address" to match HLD v22 screen spec.
- **Screen 5 (Assert) field count** (`display.c`, `display.h`, `sign_psbt_validate.c`): removed the
  spurious "Output count" field; Assert screen now shows exactly three fields: Claim txid, Amount,
  Transaction fee.  `display_assert_transaction` no longer takes an `n_outputs` parameter.
- **`approve_vault_intent.h` docstring**: updated from "Two-phase APDU / 17 fields / tag 1B" to
  "Three-phase APDU / 13 fields / tag 2B" with correct P1=0x01 description.
- **`vault_tlv.h` scalar-count docstring**: corrected "12 mandatory scalar tags" → "13".
- **`vault_script.c` comment constant**: corrected `VAULT_TIMELOCK_MAX=1008` →
  `VAULT_HTLC_REFUND_TIMELOCK_MAX=4320` in the `vault_build_htlc_leaf1` size comment.
- **Assert:0 leaf naming**: renamed "NoPayout leaf" → "Assert:0 leaf" in comments across
  `vault_script.h`, `sign_custom_inputs.c`, and `sign_psbt_validate.c` to match HLD v22 terminology.
- HTLC refund timelock constant comment: corrected `[72, 1008]` → `[72, 4320]` blocks in
  `vault_intent_tags.h`.
- Scalar field count comment: corrected `12` → `13` in `vault_intent_tags.h`.
- Removed dead `display_payout_transaction` declaration from `display.h`.
- `cx_hash_no_throw` return values in the Pre-PegIn txid block now suppressed with `(void)`
  casts via block-scoped `_HASH_FEED` / `_HASH_FINAL` macros, fixing `-Werror,-Wunused-result`
  build errors on all target devices.

### Changed (HLD audit round 2)

- **NoPayout is silent**: removed user-confirmation screen; NoPayout is approved implicitly
  at `APPROVE_VAULT_INTENT` time per HLD v22.
- **PoP signature cap removed**: standalone flows carry no intent-bound cap per HLD v22.
- **VP/VK Payout non-depositor outputs accept any standard script** (`sign_psbt_validate.c`):
  Out1 (VP commission / VK CPFP anchor) and VP Out2 (VP CPFP anchor) were read with
  `_read_output`, which hard-fails on any non-P2TR scriptPubKey.  VP, VK, and Keeper registered
  addresses may be any standard type (P2WPKH, P2SH-P2WPKH, etc.) per HLD v22.  Switched to
  `_read_output_varlen` (value enforced, script accepted as any standard type); Depositor Out1
  retains `_read_output` (BIP-86 P2TR script verified).
- **PayoutFinalize**: nSequence must now match the CSV timelock exactly; display extended
  to show both output addresses so the user can verify all funds go to their BIP-86 address.
- **`APPROVE_VAULT_INTENT` prerequisite**: P1=0x00 now rejects with `SW_BAD_STATE` if no
  prior `DERIVE_CONTEXT_HASH` has run, consistent with the HLD sequencing requirement.
- `docs/apdu.md`, `APP_SPECIFICATION.md`, and `docs/integration-guide.md` aligned with
  HLD v22 (corrected tags, phase labels, field counts, state names, HTLC value bounds).

## [0.9.3] - NAPPS-1465: v22 per-type signature caps

Implements the per-type signature-count caps introduced in HLD v22 as a sampling
countermeasure.  Within one approved intent the device now signs at most the expected
number of each intent-bound transaction type; exceeding any cap nullifies the intent
and returns the new `SW_CAP_EXCEEDED` status word.

### Added

- **Per-type signature counters** in `vault_context_t` (`src/vault_context.h`):
  `pre_pegin_signed`, `pegin_signed`, `payout_signed`, `nopayout_signed` (all `uint16_t`).
  All four are zero-initialised on every `vault_context_init` / `vault_context_invalidate`
  call, so a fresh `APPROVE_VAULT_INTENT` always starts from zero.
- **`SW_CAP_EXCEEDED` (`0xB00A`)**: returned when a cap is exceeded; intent and
  `context_root` are nullified and the device returns to IDLE.  Documented in
  `docs/apdu.md`.
- Cap enforcement in `sign_psbt_validate.c`:
  - Pre-PegIn: cap = 1
  - PegIn: cap = `vault_count`
  - Payout: cap = `vault_count × (keeper_count + 2)`
  - NoPayout: cap = `vault_count × (keeper_count + challenger_count)` (previously enforced
    but returned `SW_BAD_STATE`; now returns `SW_CAP_EXCEEDED`).

### Changed

- NoPayout cap violation now returns `SW_CAP_EXCEEDED` (`0xB00A`) instead of
  `SW_BAD_STATE` (`0xB007`).  Hosts must update their error handling accordingly.

### Fixed

- **NoPayout dispatch without active intent** (`sign_psbt_validate.c`): 3-in/1-out
  no-wallet-policy route moved before the `INTENT_LOADED` guard; was falling through
  to the leaf dispatcher and returning `SW_INCORRECT_DATA` instead of `SW_BAD_STATE`.
- **PegIn dispatch without active intent** (`sign_psbt_validate.c`): 1-in/3-out
  no-wallet-policy route likewise moved before the `INTENT_LOADED` guard.  HTLC Leaf 0
  begins with `OP_SIZE` (`0x82`), not `OP_PUSHBYTES_32`, so the leaf dispatcher returned
  `SW_INCORRECT_DATA` instead of the expected `SW_BAD_STATE`.
- **PayoutFinalize Input 1 `nSequence` exact match** (`_validate_display_payout_finalize`):
  `nSequence` must encode the CSV timelock exactly (`!= csv_value` → `SW_INCORRECT_DATA`),
  consistent with the Refund flow and the HLD requirement that the sequence "encode" the
  timelock value.  Previously any `nSequence >= csv_value` was accepted.
- **VK/Depositor Payout routing** (`sign_psbt_validate.c`): The `bitvector_get(internal_inputs, 0)`
  test is always zero for no-wallet-policy flows (`preprocess_inputs` only sets internal-input
  bits for wallet-policy inputs).  Routing for the ambiguous 2-in/2-out case now peeks at
  Input 0's `PSBT_IN_PREVIOUS_TXID` and compares it against `vault_compute_pegin_txid` for
  every vault group; a match routes to `_validate_payout`, a mismatch falls through to
  `_validate_display_payout_finalize`.
- **`test_sign_psbt_payout_wrong_claimer_order`** (`tests/`): Corrected from expecting
  `SW_INCORRECT_DATA` to expecting success; the HLD (v22) specifies no inter-transaction
  ordering requirement, so VK presented before VP must be accepted.
- **`test_sign_psbt_payout_vp_reduced_commission`** (`tests/`): Corrected from expecting
  success to expecting `SW_INCORRECT_DATA`; reflects the exact-match commission check
  documented in the Security section above.
- **`_build_nopayout_psbt` output SPK** (`tests/`): Output 0 corrected to
  `P2TR(key-path-tweak(challenger_pk))`; the all-zero placeholder failed the firmware's
  output-script check.
- **`test_sign_psbt_refund_wrong_sighash` hang** (`tests/`): `sighash_type` (phantom
  attribute, silently ignored) corrected to `sighash`; the absent sighash field caused
  firmware to bypass the check and block on the display call.

### Refactored

- Replaced magic numbers with named constants across `src/` and `unit-tests/`.

## [0.9.2] - NAPPS-1464: PayoutFinalize depositor self-claim (Screen 8)

Adds Screen 8 — the depositor reclaims their deposit after the Claim+Assert chain by
spending the payout leaf (Input 1) of the PayoutFinalize PSBT.  This is the only flow
where the device signs Input 1 rather than Input 0.

### Added

- **Screen 8 — PayoutFinalize** (`_validate_display_payout_finalize`, `display_payout_finalize`):
  standalone flow identified by `has_no_wallet_policy && n_inputs == 2 && n_outputs == 2`.
  Input 0 is the external Assert:0 UTXO (not signed); Input 1 is the payout tapscript leaf
  (signed by the device's BIP-86 D key).  Displays "Amount received" and "Destination: Your
  address" before the final approval screen.  Verifies: payout leaf structure (`> 68 bytes`,
  D-key match, t2 ∈ `[VAULT_PAYOUT_TIMELOCK_MIN, VAULT_PAYOUT_TIMELOCK_MAX]`), BIP-341
  taproot commitment on Input 1, nSequence ≥ t2, Output 0 P2TR(BIP-86(D)), Output 1
  P2TR(BIP-86(D)) with value == `VAULT_DUST_LIMIT`.
- `vault_read_payout_leaf_script` in `sign_psbt_validate.h/.c`: re-reads Input 1's
  `PSBT_IN_TAP_LEAF_SCRIPT` during the sign phase after `G_scratch.tls` has been consumed
  by display.
- `parse_payout_leaf_script` in `sign_psbt_validate_helpers.c/.h`: parses the payout leaf
  to extract the D key and t2 CSV value; rejects leaves ≤ 68 bytes (Assert leaf shape).
- `VAULT_PAYOUT_TIMELOCK_MIN` (90) and `VAULT_PAYOUT_TIMELOCK_MAX` (4032) in
  `vault_constants.h`.
- Ragger golden-snapshot and error-path tests (`tests/test_screen8_payout_finalize.py`):
  19 tests covering happy path, user rejection, and all validated rejection cases.

### Security

- **Input 0 internal guard**: `validate_and_display_transaction` rejects any PayoutFinalize
  PSBT where `bitvector_get(internal_inputs, 0)` is set — Input 0 must always be external.
- **BIP-68 nSequence flag checks**: `nSequence` for Input 1 is rejected if the BIP-68
  disable flag (bit 31) or time-based flag (bit 22) is set; only block-count relative
  timelocks are accepted.
- **WITNESS_UTXO bounds check**: Input 1's `witness_utxo` value is extracted and verified
  to satisfy `amount_received + VAULT_DUST_LIMIT ≤ input1_value`, preventing a fabricated
  `witness_utxo` from concealing an over-spend.

### Fixed

- `display.c`: seven `assert(n <= MAX_N_PAIRS)` / `assert(n <= VAULT_INTENT_MAX_PAIRS)` calls replaced
  with `LEDGER_ASSERT(...)`.  Plain `assert` is a no-op when `NDEBUG` is defined (release
  builds); `LEDGER_ASSERT` always terminates the app.
- `sign_psbt_validate_helpers.c`: removed unreachable `if (script_len < 4) return false`
  branch in `parse_payout_leaf_script`; the preceding `script_len <= 68` guard already
  ensures `script_len ≥ 69`.

## [0.9.1] - NAPPS-1463: BIP-322 proof-of-possession signing (Screen 7)

Adds Screen 7 — the depositor proves ownership of their Ethereum address by
signing a BIP-322 `bip322-simple` to_sign PSBT before registering with the
Babylon Vault contract.

### Added

- **Screen 7 — Register ETH address** (`_validate_display_pop`, `display_pop_transaction`):
  standalone flow identified by `tx_version == 0`. Parses and displays the PoP
  message (`<eth_addr>:<chain_id>:pegin:<registry>`) as ETH address, Chain ID,
  and Registry contract fields. Validates BIP-86 key derivation and tweaked-key
  commitment, verifies the to_sign prevout against the computed BIP-322 to_spend
  txid, and enforces value=0 / OP_RETURN output.
- `src/bip322.h` / `src/bip322.c`: PoP message parser (`bip322_parse_pop_message`)
  and BIP-322 to_spend txid computation (`bip322_compute_to_spend_txid`).
- Ragger golden-snapshot and error-path tests for Screen 7 (`tests/test_screen7_pop.py`).

## [0.9.0] - NAPPS-1462: depositor-as-claimer NoPayout screens, v22 protocol alignment

Adds standalone Claim (Screen 4), Assert (Screen 5), and WronglyChallenged (Screen 6) flows
for the depositor-as-claimer path, and aligns the validator with HLD v22.

### Added

- **Screen 4 — Claim** (`_validate_display_claim`, `display_claim_transaction`): standalone
  flow spending `PegIn:1` (Depositor Claim UTXO). Displays spent amount and fee; verifies
  depositor key ownership via BIP-32 derivation and Taproot commitment.
- **Screen 5 — Assert** (`_validate_display_assert`, `display_assert_transaction`): standalone
  flow spending `Claim:0`. Displays Claim txid, amount carried, and fee; verifies depositor
  key in the claimer leaf position and Taproot commitment.
- **Screen 6 — WronglyChallenged** (`_validate_display_wc`, `display_wc_transaction`):
  standalone flow spending a `ChallengeAssert` connector. Displays reclaimed amount and fee;
  verifies BIP-86 P2TR(depositor) output.
- Reject-path Ragger tests for Screens 4–6 on all supported devices.

### Changed (v22 protocol alignment — **breaking**)

- **OP_RETURN auth-anchor optional** (`_validate_prepegin`): the Pre-PegIn OP_RETURN carrying
  `SHA256(authAnchor)` is no longer mandatory. PSBTs without it are accepted (v22 removes the
  auth-anchor ordering guarantee).
- **PegIn sighash tightened** (`_pegin_validate_input`): `SIGHASH_ALL` (explicit value `0x01`)
  is now **rejected** for PegIn inputs; only `SIGHASH_DEFAULT` (absent or `0x00`) is accepted.
  Clients sending explicit `SIGHASH_ALL` must be updated to omit the `PSBT_IN_SIGHASH_TYPE`
  field or set it to `0x00`.
- **Non-depositor payout output scripts value-checked only** (`_validate_payout`): per v22,
  VaultProvider and VaultKeeper output addresses are registered in the vault contract and
  accepted as-is from the PSBT; only values are enforced. Depositor-destined outputs (VP
  claimer Out0, Depositor claimer Out0/Out1) continue to require BIP-86 P2TR verification.
- **`TAG_PREPEGIN_MAX_FEE` (0x010F) added** to the intent TLV (13 scalar fields, 128 bytes
  total); the field is now required.

## [0.8.0] - NAPPS-1461: v21 protocol alignment — 2-byte TLV tags, P1 phase swap, P2A constant

Aligns the APPROVE_VAULT_INTENT wire format with HLD v21.

### Changed

- **2-byte TLV tags** (`vault_intent_tags.h`, `vault_tlv.c`): all TLV tags are now 2 bytes
  (big-endian `uint16_t`) on the wire. Scalar tags renumbered per the v21 table (e.g.
  `coin_type` 0x03→0x21, `base_fee_rate` 0x08→0x0100, etc.). Per-vault group tags move to
  the 0x0109–0x010E range. Key-batch tags 0x0107/0x0108 are now on the wire (not doc-only).
- **P1 phase swap** (`approve_vault_intent.c`): per-vault groups now arrive on P1=0x01 (was
  P1=0x02); key batches on P1=0x02 (was P1=0x01).
- **Key batch format** (`approve_vault_intent.c`): P1=0x02 keys are now TLV-wrapped
  (TAG_KEEPER_PK=0x0107 or TAG_CHALLENGER_PK=0x0108), with tag-enforced keeper-before-challenger
  ordering. Raw packed keys no longer accepted.
- **`pegin_anchor_value` removed** (`vault_intent.h`, `vault_tlv.c`, all callers): field
  removed from the TLV and from `vault_group_t`. Replaced by the `P2A_ANCHOR_VALUE = 240`
  build constant in `vault_constants.h`.
- **Scalar field count**: 13 → 12 (pegin_anchor_value removed).

---

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
