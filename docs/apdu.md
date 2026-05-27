# Babylon Vault — APDU Reference

**CLA:** `0xE1` for all commands.

---

## Vault APDUs

| INS    | Name                     | Status         | Story       | Brief purpose |
|--------|--------------------------|----------------|-------------|---------------|
| `0x80` | `APPROVE_VAULT_INTENT`   | stub           | NAPPS-1372  | Parse and validate vault intent TLV (scalars + key batches); show approval screen; transition to `INTENT_LOADED`. |
| `0x81` | `DERIVE_CONTEXT_HASH`    | stub           | NAPPS-1367  | Derive session secret `s` via HKDF-SHA-256 at `m/73681862'`; return `h = SHA256(s)`. No display. |
| `0x82` | `RELEASE_CONTEXT_SECRET` | stub           | NAPPS-1373  | Return `s` (32 B) once state = `SESSION2_COMPLETE`; zero `s`; reset to `IDLE`. Rejected in all other states. |

All three stubs currently return `SW_INS_NOT_SUPPORTED` (`0x6D00`).

---

## Base app APDUs (pass-through)

Handled by `bitcoin_app_base`. Listed here for completeness.

| INS    | Name                      | Brief purpose |
|--------|---------------------------|---------------|
| `0x00` | `GET_EXTENDED_PUBKEY`     | Return BIP-32 extended public key at a given path. |
| `0x01` | `GET_ADDRESS`             | Return a wallet address for a given wallet policy and index. |
| `0x02` | `REGISTER_WALLET`         | Register a wallet policy on the device. |
| `0x03` | `GET_WALLET_ADDRESS`      | Return an address for a registered wallet policy. |
| `0x04` | `SIGN_PSBT`               | Sign a PSBT; calls `validate_and_display_transaction` and `sign_custom_inputs` hooks. |
| `0x10` | `GET_MASTER_FINGERPRINT`  | Return the master key fingerprint. |
| `0x11` | `SIGN_MESSAGE`            | Sign an arbitrary message under a BIP-32 path. |

---

## Status words

| SW       | Name                    | Meaning |
|----------|-------------------------|---------|
| `0x9000` | `SW_OK`                 | Success. |
| `0x6985` | `SW_DENY`               | User rejected on device. |
| `0x6A80` | `SW_INCORRECT_DATA`     | Invalid APDU data or validation failure. |
| `0x6D00` | `SW_INS_NOT_SUPPORTED`  | INS not yet implemented (stub) or unknown. |
| `0x6E00` | `SW_CLA_NOT_SUPPORTED`  | Unknown CLA. |
| `0xB007` | `SW_BAD_STATE`          | Command not allowed in current session state. |

---

> Full wire-format specification (TLV layout, chunked streaming protocol, request/response byte maps) is in [`APP_SPECIFICATION.md`](../APP_SPECIFICATION.md).
