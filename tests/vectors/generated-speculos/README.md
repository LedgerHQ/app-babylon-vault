# Speculos-Signable PSBT Vectors

This directory holds PSBT vectors produced by `crates/ledger-vector-gen` from the
`btc-vault` repository under the **Speculos test mnemonic**, so the test device can
actually sign them. `test_device_signs_speculos_pegin` in `tests/test_sample_vectors.py`
drives the on-device review and asserts SW_OK with a 64-byte Schnorr signature, rather
than a clean rejection.

## Why a separate directory is needed

The standard vectors in `tests/vectors/generated/` use `dummy_pubkey_seeded(5)` as the
depositor — a key that does not match the one the Speculos test device derives. Because
the depositor key is embedded in every leaf script the device reconstructs, none of those
vectors can be signed by the test device. Signable vectors require running
`ledger-vector-gen` with the same BIP-39 mnemonic Speculos loads.

## Contents

- `metadata.json` — intent parameters to pass to `APPROVE_VAULT_INTENT` before signing
- `deposit-flow/pre_pegin.txt` — Pre-PegIn PSBT hex
- `deposit-flow/pegin.json` — PegIn PSBT hex array
- `deposit-flow/claimer_payout.json` — Payout PSBT hex array
- `deposit-flow/depositor_graph.json` — NoPayout PSBT hex array

## How to regenerate

```bash
# From the btc-vault repository root:
SPECULOS_MNEMONIC="glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

# signet / testnet build (coin_type 1)
cargo run -p ledger-vector-gen -- \
  --mnemonic "${SPECULOS_MNEMONIC}" \
  --network signet \
  --out /path/to/app-babylon-vault/tests/vectors/generated-speculos/test/

# mainnet build (coin_type 0)
cargo run -p ledger-vector-gen -- \
  --mnemonic "${SPECULOS_MNEMONIC}" \
  --network mainnet \
  --out /path/to/app-babylon-vault/tests/vectors/generated-speculos/main/
```

## Layout: one set per network

A vector set is bound to a single coin type. The depositor key is derived at
`m/86'/<coin_type>'/0'/0/0` and baked into every leaf script the device reconstructs, and
the canonical network name (`bitcoin-mainnet` / `bitcoin-signet`) is hashed into the
`DERIVE_CONTEXT_HASH` root — so a set generated for one network can never validate on a
build of the other. The mainnet binary's BIP-32 path allowlist also refuses the `1'` path
outright, which surfaces as `SW_BIP32_FAIL` (0x6F00) before any vault logic runs.

`_speculos_set_for()` in `tests/test_sample_vectors.py` picks the directory named after the
network the app under test was built for (`conftest.py` auto-detects it from the binary):

- `generated-speculos/main/` — mainnet set (`coin_type: 0`)
- `generated-speculos/test/` — signet / testnet set (`coin_type: 1`)

A missing set skips the test. A set whose `metadata.json` declares the wrong `coin_type`
— generated with the wrong `--network` — fails loudly instead, because the device would
otherwise reject every vector in ways that look like a firmware bug.

The Speculos mnemonic above is the standard Ledger test seed used by every
`pytest --device` run; it is not a secret.

## Test coverage caveat

`test_device_signs_speculos_pegin` asserts the returned signature's length, input index
and signing pubkey — it does **not** verify the signature cryptographically against the
sighash. No test in this repository does. `bip_utils` (already in
`tests/requirements.txt`) pulls in `coincurve`, so BIP-340 verification is reachable
without adding a dependency.
