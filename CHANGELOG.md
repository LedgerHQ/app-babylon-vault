# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-05-25

### Added

- App scaffold forked from `app-btcext-boilerplate`; renamed to `app-babylon-vault`.
- Makefile configured: variant names `app_babylon_vault` / `app_babylon_vault_testnet`, developer "Hoodies".
- Stub handlers for the three custom APDUs registered in `custom_apdu_handler`:
  - `APPROVE_VAULT_INTENT` (`INS 0x80`)
  - `DERIVE_CONTEXT_HASH` (`INS 0x81`)
  - `RELEASE_CONTEXT_SECRET` (`INS 0x82`)
- `vault_intent_t` struct: 17 scalar fields + `keeper_pks[32][32]` + `challenger_pks[32][32]`; compile-time `sizeof` assertions validating fit within Nano S+ RAM budget.
- `vault_context_t` struct: session secret `s[32]`, hash `h[32]`, session state enum.
- Session state machine with full transition table:
  `IDLE → INTENT_LOADED → SESSION1_PREPEGIN_EXPECTED`
  `IDLE → INTENT_LOADED → SESSION2_PEGIN_EXPECTED → SESSION2_PAYOUT_i_EXPECTED → SESSION2_COMPLETE`
  Invalidation on signing error, intent reload, or `DERIVE_CONTEXT_HASH` while intent is active (`explicit_bzero` on `s`, reset to `IDLE`).
- Unit tests covering all valid state transitions, all invalid transitions (wrong state / wrong order), and all invalidation triggers.
- `APP_SPECIFICATION.md` documenting all three custom APDUs and all four supported transaction types (Pre-PegIn, PegIn, Payout, Refund).
- `docs/apdu.md` with APDU INS registry table (`CLA`, `INS`, name, purpose) as a shared reference for the DMK Babylon Signer team.
