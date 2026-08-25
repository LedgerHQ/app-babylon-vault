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

cargo run -p ledger-vector-gen -- \
  --mnemonic "${SPECULOS_MNEMONIC}" \
  --output /path/to/app-babylon-vault/tests/vectors/generated-speculos/
```

The Speculos mnemonic above is the standard Ledger test seed used by every
`pytest --device` run; it is not a secret.

## Test coverage caveat

`test_device_signs_speculos_pegin` asserts the returned signature's length, input index
and signing pubkey — it does **not** verify the signature cryptographically against the
sighash. No test in this repository does. `bip_utils` (already in
`tests/requirements.txt`) pulls in `coincurve`, so BIP-340 verification is reachable
without adding a dependency.
