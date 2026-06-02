# Babylon Vault — APDU Reference

**CLA:** `0xE1` for all commands.

---

## Vault APDUs

| INS    | Name                     | Status         | Story       | Brief purpose |
|--------|--------------------------|----------------|-------------|---------------|
| `0x80` | `APPROVE_VAULT_INTENT`   | stub           | NAPPS-1372  | Parse and validate vault intent TLV (scalars + key batches); show approval screen; transition to `INTENT_LOADED`. |
| `0x81` | `DERIVE_CONTEXT_HASH`    | implemented    | NAPPS-1367  | Derive HTLC preimage via HKDF-SHA-256 at `m/73681862'`; return `htlc_hashlock = SHA256(htlc_preimage)`. No display. |
| `0x82` | `RELEASE_CONTEXT_SECRET` | stub           | NAPPS-1373  | Return `htlc_preimage` (32 B) once state = `SESSION2_COMPLETE`; zero it; reset to `IDLE`. Rejected in all other states. |

---

## INS 0x81 — DERIVE_CONTEXT_HASH — Wire Format

### P1=0x00 — Initial chunk

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | `app_name_len` | 1 B | Length of `app_name`; must be ≤ 64 |
| 1 | `app_name` | `app_name_len` B | UTF-8 app name |
| 1+`app_name_len` | `context_total_len` | 2 B BE | Total byte count of context to follow in P1=0x01 chunks; may be 0 |

If `context_total_len == 0` the derivation completes immediately and the response carries `htlc_hashlock`.
Otherwise the device responds `SW_OK` (`0x9000`) with no data and waits for P1=0x01 chunks.

### P1=0x01 — Continuation chunk

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | `context_data` | `Lc` B | Next slice of context (up to 255 B per APDU) |

The device accumulates chunks until `context_received == context_total_len`, then finalises and returns `htlc_hashlock`.
Intermediate chunks receive `SW_OK` with no data.
Sending more bytes than `context_total_len` returns `SW_INCORRECT_DATA` (`0x6A80`).

### Response (final chunk or zero-context)

| Field | Size | Value |
|-------|------|-------|
| Data  | 32 B | `htlc_hashlock = SHA256(htlc_preimage)` |
| SW    | 2 B  | `0x9000` |

### Error conditions

| SW     | Condition |
|--------|-----------|
| `0x6A80` | `app_name_len > 64`, malformed initial chunk, or chunk exceeds declared length |
| `0x6A86` | P1 is not `0x00` or `0x01` |
| `0x6A87` | Initial chunk too short to contain all mandatory fields |
| `0xB007` | P1=0x01 received before P1=0x00 (no active stream) |
| `0xB007` | BIP-32 derivation or HMAC operation failed |

### Crypto detail

- **IKM**: 32-byte private key derived at `m/73681862'` (hardened, `CX_CURVE_SECP256K1`)
- **HKDF-Extract**: `PRK = HMAC-SHA256(salt="derive-context-hash", ikm)`
- **HKDF-Expand** (single block, L=32): `htlc_preimage = HMAC-SHA256(PRK, SHA256(app_name) || context || 0x01)`
- **Hashlock**: `htlc_hashlock = SHA256(htlc_preimage)`

Implementation: `src/handler/derive_context_hash_core.h` (static inline, unit-testable without APDU layer).

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
