# Babylon Vault — APDU Reference

**CLA:** `0xE1` for all commands.

---

## Vault APDUs

| INS    | Name                     | Brief purpose |
|--------|--------------------------|---------------|
| `0x80` | `APPROVE_VAULT_INTENT`   | Parse and validate vault intent TLV (scalars + key batches); show approval screen; transition to `INTENT_LOADED`. |
| `0x81` | `DERIVE_CONTEXT_HASH`    | Derive HTLC preimage via HKDF-SHA-256 at `m/73681862'`; return `htlc_hashlock = SHA256(htlc_preimage)`. No display. |
| `0x82` | `RELEASE_CONTEXT_SECRET` | Return `htlc_preimage` (32 B) once state = `SESSION2_COMPLETE`; zero it; reset to `IDLE`. Rejected in all other states. |

---

## INS 0x80 — APPROVE_VAULT_INTENT — Wire Format

Two-phase command. **P1=0x00** must be sent exactly once (scalar fields); **P1=0x01** is sent
one or more times until all `keeper_count + challenger_count` public keys are delivered.
Any error from either phase resets the in-flight state; a fresh P1=0x00 is required to retry.

### P1=0x00 — Scalar TLV payload

Single APDU (total payload ≈ 179 B, well within the 255 B limit).

Each field is encoded as:
```
[ tag: 1 B ][ length: 1 B ][ value: length B ]
```

All numeric values are **big-endian**. Tags may arrive in any order. All 17 tags are mandatory.
Duplicate tags, unknown tags, and wrong-length fields are rejected.

| Tag    | Field                      | Length | Type     | Validation rule |
|--------|----------------------------|--------|----------|-----------------|
| `0x01` | `structure_type`           | 1 B    | `u8`     | Must equal `VAULT_STRUCTURE_TYPE` |
| `0x02` | `version`                  | 1 B    | `u8`     | Must equal `VAULT_PROTOCOL_VERSION` (= `0x01`) |
| `0x03` | `coin_type`                | 4 B    | `u32 BE` | Must equal `BIP44_COIN_TYPE` |
| `0x04` | `vault_provider_pk`        | 32 B   | bytes    | x-only Schnorr public key (BIP-340) |
| `0x05` | `vault_amount`             | 8 B    | `u64 BE` | `> commission_fee + 2 × DUST` (660 sat) |
| `0x06` | `commission_fee`           | 8 B    | `u64 BE` | Must be `> 0` |
| `0x07` | `depositor_claim_value`    | 8 B    | `u64 BE` | Any value |
| `0x08` | `base_fee_rate`            | 8 B    | `u64 BE` | Any value (sat/vbyte) |
| `0x09` | `pegin_max_fee`            | 8 B    | `u64 BE` | Any value |
| `0x0A` | `pegin_csv_timelock`       | 4 B    | `u32 BE` | `[72, 1008]` inclusive |
| `0x0B` | `payout_timelock`          | 4 B    | `u32 BE` | `(90, 4032)` exclusive |
| `0x0C` | `prepegin_txid`            | 32 B   | bytes    | Little-endian txid |
| `0x0D` | `htlc_vout`                | 1 B    | `u8`     | Output index of HTLC in Pre-PegIn tx |
| `0x0E` | `htlc_refund_timelock`     | 4 B    | `u32 BE` | `[72, 1008]` inclusive |
| `0x0F` | `depositor_derivation_path`| 20 B   | `u32[5] BE` | BIP-86: `m/86'/coin_type'/acct'/chg/idx`; `path[1]` must match `coin_type`; `path[2]` hardened; `path[3]`, `path[4]` not hardened |
| `0x10` | `keeper_count`             | 1 B    | `u8`     | `[1, 32]` inclusive |
| `0x11` | `challenger_count`         | 1 B    | `u8`     | `[1, 32]` inclusive |

**Cross-field constraints** (checked after all tags parsed):
- `depositor_path[1] == coin_type | 0x80000000` (hardened coin type must match `coin_type` field)
- `vault_amount > commission_fee + 660` (two P2TR dust limits = 2 × 330 sat)

**Response:** `SW_OK` (`0x9000`), no data. Key streaming may now begin.

**State context:**
This command is accepted from any session state. The meaningful distinction is:

- **Called from `HASH_DERIVED`** (after a successful `DERIVE_CONTEXT_HASH`) — Session 2 path.
  The `htlc_preimage` and `htlc_hashlock` produced by `DERIVE_CONTEXT_HASH` are copied to
  a stack buffer before the internal session reset, then restored afterwards. They remain
  held in the session context through `INTENT_LOADED` → `SESSION2_PEGIN_EXPECTED` →
  `SESSION2_PAYOUT_EXPECTED` → `SESSION2_COMPLETE`, at which point `RELEASE_CONTEXT_SECRET`
  will return the preimage to the host and zero it.
- **Called from any other state** — Session 1 path (or intent replacement).
  The session is reset normally; no preimage is preserved. A prior `DERIVE_CONTEXT_HASH`
  result is discarded if the device was not in `HASH_DERIVED` state at call time.

---

### P1=0x01 — Key batch

Raw packed 32-byte x-only public keys; no TLV wrapper. `Lc` must be a non-zero multiple of 32.
May be split across multiple APDUs; the device accumulates until
`keys_received == keeper_count + challenger_count`.

**Layout within a single P1=0x01 APDU:**
```
[ key_0: 32 B ][ key_1: 32 B ] … [ key_n: 32 B ]
```

Keys must be delivered **in order**: first all `keeper_count` keeper keys, then all
`challenger_count` challenger keys. Constraints enforced per key as it arrives:

- Strictly ascending lexicographic order **within** each group (reject if `key ≤ prev` in same group)
- Not equal to `vault_provider_pk`
- Globally unique across all keys received so far

After the final key is accepted the device also derives the depositor public key from
`depositor_derivation_path` and verifies it does not appear in any key group.

**Response (partial — more keys expected):** `SW_OK`, no data.

**Response (complete — all keys received):**
The device displays the vault parameters for user review. On approval the session
transitions to `INTENT_LOADED` and `SW_OK` is returned. On rejection `SW_DENY`
(`0x6985`) is returned and the session remains `IDLE`.

---

### Error conditions

| SW       | Condition |
|----------|-----------|
| `0x6A80` | Duplicate tag, unknown tag, field validation failure, wrong field length, key ordering/uniqueness violation, extra keys beyond declared count |
| `0x6A86` | P1 is not `0x00` or `0x01` |
| `0x6A87` | P1=0x01 payload length is not a multiple of 32 |
| `0x6985` | User rejected the approval screen |
| `0xB007` | P1=0x01 received without a prior successful P1=0x00 |
| `0x6F00` | BIP-32 derivation of depositor key failed |

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

## INS 0x82 — RELEASE_CONTEXT_SECRET — Wire Format

Single-APDU command; no payload. Returns the 32-byte session secret `s`
(`htlc_preimage`) exactly once, then zeroes it and resets the session to `IDLE`.

| Field | Value |
|-------|-------|
| P1    | `0x00` (no sub-commands; any other value → `SW_WRONG_P1P2`) |
| P2    | `0x00` (reserved; any other value → `SW_WRONG_P1P2`) |
| Lc    | `0` (no data; any non-zero value → `SW_WRONG_DATA_LENGTH`) |

**State requirement:** session must be in `SESSION2_COMPLETE`.
Calling from any other state returns `SW_BAD_STATE` and leaves the session unchanged.

### Response

| Field | Size | Value |
|-------|------|-------|
| Data  | 32 B | `htlc_preimage` (the session secret `s`) |
| SW    | 2 B  | `0x9000` |

After sending the response the device calls `explicit_bzero` on `htlc_preimage` and
resets the session to `VAULT_STATE_IDLE`, clearing all session globals.
The secret is zeroed in device RAM before the packet leaves the device — the response
buffer holds a copy staged before the zero operation.

### Error conditions

| SW       | Condition |
|----------|-----------|
| `0x6A86` | P1 or P2 is non-zero |
| `0x6A87` | Lc is non-zero (payload present) |
| `0xB007` | Session state is not `SESSION2_COMPLETE` |

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
| `0x6A86` | `SW_WRONG_P1P2`         | P1 or P2 value not valid for this command. |
| `0x6A87` | `SW_WRONG_DATA_LENGTH`  | Lc value not valid for this command. |
| `0x6D00` | `SW_INS_NOT_SUPPORTED`  | Unknown INS. |
| `0x6E00` | `SW_CLA_NOT_SUPPORTED`  | Unknown CLA. |
| `0x6F00` | `SW_BIP32_FAIL`         | BIP-32 key derivation failed (invalid key at path). |
| `0xB007` | `SW_BAD_STATE`          | Command not allowed in current session state. |

---

> Full wire-format specification (TLV layout, chunked streaming protocol, request/response byte maps) is in [`APP_SPECIFICATION.md`](../APP_SPECIFICATION.md).
