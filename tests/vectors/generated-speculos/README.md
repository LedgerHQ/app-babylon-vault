# Speculos-Signable PSBT Vectors

This directory must be populated by running `crates/ledger-vector-gen` from the
`btc-vault` repository under the **Speculos test mnemonic**.  Once populated, the
`test_device_signs_speculos_psbt` test in `tests/test_sample_vectors.py` asserts
SW_OK and a valid Schnorr signature rather than a clean rejection.

## Why this directory is empty

The standard `generated/` vectors in `tests/vectors/generated/` use
`dummy_pubkey_seeded(5)` as the depositor — a key that does not match the key
derived by the Speculos test device.  Because the depositor key is embedded in
every leaf script the device reconstructs, none of those vectors can be signed
by the test device.

Producing signable vectors requires running `ledger-vector-gen` with the same
BIP-39 mnemonic that Speculos loads.

## How to generate

```bash
# From the btc-vault repository root:
SPECULOS_MNEMONIC="glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

cargo run -p ledger-vector-gen -- \
  --mnemonic "${SPECULOS_MNEMONIC}" \
  --output /path/to/app-babylon-vault/tests/vectors/generated-speculos/
```

The tool writes one JSON file per transaction type:
- `deposit-flow/pre_pegin.txt`  — Pre-PegIn PSBT hex
- `deposit-flow/pegin.json`     — PegIn PSBT hex array
- `deposit-flow/claimer_payout.json` — Payout PSBT hex array
- `deposit-flow/depositor_graph.json` — NoPayout PSBT hex array

The Speculos mnemonic above is the standard Ledger test seed used by every
`pytest --device` run; it is not a secret.

## Expected test structure once populated

When this directory exists and contains a `deposit-flow/pegin.json`, the
`test_device_signs_speculos_psbt` test in `test_sample_vectors.py` calls
`APPROVE_VAULT_INTENT` first (using the parameters embedded in the vector file's
companion metadata), then `SIGN_PSBT`, and asserts:
- SW = 0x9000 (SW_OK)
- Exactly one signature returned, 64 bytes (SIGHASH_DEFAULT Schnorr)
- Signed by the expected depositor x-only pubkey

Until this directory is populated the test is skipped automatically via
`pytest.mark.skip`.
