# Babylon Vault — Ledger Firmware App

This application enables a Ledger device to participate in the [Babylon](https://babylonlabs.io/) vault lifecycle: locking BTC into an HTLC, pre-signing vault exit transactions, and releasing the session secret once all pre-signatures are complete.

The app is a btcext extension — standard commands (`SIGN_PSBT`, `GET_EXTENDED_PUBKEY`, etc.) are handled by the bitcoin base app. Three custom `INS` codes (`CLA 0xE1`) implement Babylon-specific vault operations.

## The Babylon Vault Protocol

The vault lifecycle spans two sessions:

**Session 1 — Lock:** The depositor creates an HTLC output locking BTC on-chain.

1. `DERIVE_CONTEXT_HASH` — derives an `htlc_preimage` bound to the on-chain context hash; returns `htlc_hashlock = SHA256(htlc_preimage)` to the host.
2. `APPROVE_VAULT_INTENT` — streams vault parameters (17 scalar fields + keeper/challenger public keys) and shows an approval screen; the device stores the `vault_intent_t` in RAM.
3. `SIGN_PSBT` (Pre-PegIn) — validates the HTLC PSBT, displays vault amount, fee, and HTLC address, then signs.

**Session 2 — Pre-sign:** Before BTC is committed on-chain, all vault exit transactions are pre-signed.

1. `DERIVE_CONTEXT_HASH` + `APPROVE_VAULT_INTENT` — re-derives and re-loads the intent (no new approval screen).
2. `SIGN_PSBT` (PegIn) — silent; verifies `htlc_hashlock` binding, script reconstruction, and fee.
3. `SIGN_PSBT` (Payout × N+1) — silent; VP first, then keeper keys in lexicographic order.
4. `RELEASE_CONTEXT_SECRET` — returns `htlc_preimage` to the host and zeroes it on-device immediately.

A **Refund** transaction (HTLC timelock branch) can be signed from any session state without loading an intent.

### Security properties

- The device always **reconstructs scripts** from the loaded `vault_intent_t` and rejects any PSBT that does not match — it never trusts scripts provided by the host.
- `htlc_preimage` is **zeroed immediately** (`explicit_bzero`) on any signing error, intent reload, or early `RELEASE_CONTEXT_SECRET` call. In the source code and headers, `htlc_preimage` is `vault_context_t.s` and `htlc_hashlock` is `vault_context_t.h`.
- Payout order is **enforced by the device**: VP first, then VK keys in lexicographic order.
- All vault P2TR outputs use a **NUMS internal key** (`lift_x(0x50929b74...)`) — no key-path spend is possible.

## Hooks

The app overrides two hooks exposed by the bitcoin base app via weak symbols.

### `validate_and_display_transaction`

Called during `SIGN_PSBT`. The app determines which of the four transaction types (Pre-PegIn, PegIn, Payout, Refund) is being signed, validates all external inputs against the loaded `vault_intent_t`, and displays the relevant UX screens.

### `sign_custom_inputs`

Signs external inputs that belong to the vault protocol (e.g., the HTLC input in PegIn). The base app provides:
- `compute_sighash_segwitv1` / `sign_sighash_schnorr_and_yield` for SegWit v1 (taproot) inputs
- `compute_sighash_segwitv0` / `sign_sighash_ecdsa_and_yield` for SegWit v0 inputs

See [sign_psbt.h](https://github.com/LedgerHQ/app-bitcoin-new/blob/baseapp/src/handler/sign_psbt.h) and [txhashes.h](https://github.com/LedgerHQ/app-bitcoin-new/blob/baseapp/src/handler/sign_psbt/txhashes.h) for the full API.

### `custom_apdu_handler`

Handles the three Babylon-specific INS codes on `CLA 0xE1`:

| INS | Command |
|-----|---------|
| `0x80` | `APPROVE_VAULT_INTENT` |
| `0x81` | `DERIVE_CONTEXT_HASH` |
| `0x82` | `RELEASE_CONTEXT_SECRET` |

## Build variants

The app builds two variants, selected with `COIN=<variant>`:

| `COIN` | App name | Network params | Ticker |
|--------|----------|----------------|--------|
| `babylon_vault` | Babylon Vault | mainnet | `BTC` |
| `babylon_vault_testnet` (default) | Babylon Vault **Signet** | testnet | `sBTC` |

**Babylon's test network runs on Bitcoin signet, and the test build *is* the signet app.**
From the device's point of view signet and testnet3 are indistinguishable — same `tb`
address prefix, BIP-32 version bytes and coin type (1), and the app has no network stack to
notice the consensus/magic-byte differences. So a separate signet variant would compile the
identical code path; instead the single test build serves as the signet app. The variant
keeps its internal `babylon_vault_testnet` name and `BITCOIN_NETWORK = testnet` for the
shared coin params, but it presents to the user as **"Babylon Vault Signet"**, and its
golden snapshots reflect that label.

The amount ticker reads **`sBTC`**. The base submodule hardcodes `COIN_COINID_SHORT="TEST"`
for the testnet network, so the app Makefile overrides it *after* the `include`: `DEFINES`
is expanded into `-D` flags at compile time, so the post-include value wins (the base entry
is filtered out first to avoid a redefinition). No submodule change is required.

## Compiling the app

Initialize the submodule with:

```
$ git submodule update --init --recursive
```

Compile the app [as usual](https://github.com/LedgerHQ/app-boilerplate#quick-start-guide). You should be able to launch it using Speculos.

## Running the tests

Create a Python virtual environment and install the requirements:

```
$ python -m venv venv
$ source venv/bin/activate
$ pip install -r tests/requirements.txt
```

Launch the test suite; for example, if you compiled the app for Ledger Flex:

```
$ pytest --device=flex
```
