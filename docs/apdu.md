# Babylon Vault — APDU Reference

**CLA:** `0xE1` for all commands.

---

## Vault APDUs

| INS    | Name                     | Brief purpose |
|--------|--------------------------|---------------|
| `0x80` | `APPROVE_VAULT_INTENT`   | Three-phase: P1=0x00 scalar TLV (13 fields), P1=0x02 per-vault group TLV (6 fields × vault_count), P1=0x01 raw key batches; show approval screen; transition to `INTENT_LOADED`. |
| `0x81` | `DERIVE_CONTEXT_HASH`    | Derive the 32-byte root via HKDF-SHA-256 at `m/73681862'` over `info = SHA256(appName) ‖ SHA256(networkName) ‖ connectedPubkey ‖ context`; optional Screen 1 (P2=0x00); chunked context up to 1024 B. |

---

## INS 0x80 — APPROVE_VAULT_INTENT — Wire Format

Three-phase command (v19). **P1=0x00** must be sent exactly once (13 scalar fields);
**P1=0x02** must be sent `vault_count` times (one per-vault group each); **P1=0x01** is
sent one or more times until all `keeper_count + challenger_count` public keys are delivered.
Any error from any phase resets the in-flight state; a fresh P1=0x00 is required to retry.

### P1=0x00 — Scalar TLV payload

Single APDU (total payload ≈ 122 B, well within the 255 B limit).

Each field is encoded as:
```
[ tag: 1 B ][ length: 1 B ][ value: length B ]
```

All numeric values are **big-endian**. Tags may arrive in any order. All 13 tags are mandatory.
Duplicate tags, unknown tags, and wrong-length fields are rejected.

| Tag    | Field                       | Length | Type        | Validation rule |
|--------|-----------------------------|--------|-------------|-----------------|
| `0x01` | `structure_type`            | 1 B    | `u8`        | Must equal `VAULT_STRUCTURE_TYPE` |
| `0x02` | `version`                   | 1 B    | `u8`        | Must equal `VAULT_PROTOCOL_VERSION` (= `0x01`) |
| `0x03` | `coin_type`                 | 4 B    | `u32 BE`    | Must equal `BIP44_COIN_TYPE` |
| `0x08` | `base_fee_rate`             | 8 B    | `u64 BE`    | Any value (sat/vbyte) |
| `0x0A` | `pegin_csv_timelock`        | 4 B    | `u32 BE`    | `[72, 1008]` inclusive |
| `0x0B` | `payout_timelock`           | 4 B    | `u32 BE`    | `(90, 4032)` exclusive |
| `0x0C` | `prepegin_txid`             | 32 B   | bytes       | Little-endian txid |
| `0x0E` | `htlc_refund_timelock`      | 4 B    | `u32 BE`    | `[72, 1008]` inclusive |
| `0x0F` | `depositor_derivation_path` | 20 B   | `u32[5] BE` | BIP-86: `m/86'/coin_type'/acct'/chg/idx`; `path[1]` must match `coin_type`; `path[2]` hardened; `path[3]`, `path[4]` not hardened |
| `0x10` | `keeper_count`              | 1 B    | `u8`        | `[1, 32]` inclusive |
| `0x11` | `challenger_count`          | 1 B    | `u8`        | `[1, 32]` inclusive |
| `0x12` | `pegin_anchor_value`        | 8 B    | `u64 BE`    | Global P2A anchor value (sat); propagated to all vault groups |
| `0x13` | `vault_count`               | 1 B    | `u8`        | `[1, 10]` inclusive |

**Cross-field constraint** (checked after all tags parsed):
- `depositor_path[1] == coin_type | 0x80000000` (hardened coin type must match `coin_type` field)

**Response:** `SW_OK` (`0x9000`), no data. Per-vault group streaming (P1=0x02) may now begin.

---

### P1=0x02 — Per-vault group TLV payload

One APDU per vault group; must be sent exactly `vault_count` times in order (group 0, 1, …).
Each group payload uses the same TLV encoding as P1=0x00 but in an **independent tag namespace**
(`TAG_GRP_*`). All 6 group tags are mandatory per group. Tags `0x04`–`0x06` here are different
fields from the old P1=0x00 scalars at those byte values.

| Tag    | Field                    | Length | Type     | Validation rule |
|--------|--------------------------|--------|----------|-----------------|
| `0x01` | `htlc_vout`              | 1 B    | `u8`     | HTLC output index in Pre-PegIn tx |
| `0x02` | `vault_provider_pk`      | 32 B   | bytes    | x-only Schnorr public key (BIP-340) |
| `0x03` | `vault_amount`           | 8 B    | `u64 BE` | `> commission_fee + 2 × DUST` (660 sat); checked per-group |
| `0x04` | `commission_fee`         | 8 B    | `u64 BE` | `≥ VAULT_DUST_LIMIT` (330 sat) |
| `0x05` | `depositor_claim_value`  | 8 B    | `u64 BE` | Any value |
| `0x06` | `pegin_max_fee`          | 8 B    | `u64 BE` | Any value |

**Cross-field constraint** (checked per group after all 6 tags parsed):
- `vault_amount > commission_fee + 660` (two P2TR dust limits = 2 × 330 sat)

**Response:** `SW_OK` (`0x9000`), no data. After all `vault_count` groups are received, key
streaming (P1=0x01) may begin.

**State context:**
This command is accepted from any session state. The meaningful distinction is:

- **Called from `HASH_DERIVED`** (after a successful `DERIVE_CONTEXT_HASH`).
  The 32-byte `root` produced by `DERIVE_CONTEXT_HASH` is copied to a stack buffer before
  the internal session reset, then restored afterwards. Once `htlc_vout` is known (after
  the P1=0x02 group for vault 0 is processed) the device recomputes the on-chain commitments
  from the root — `htlc_hashlock[i] = SHA256(Expand(root, "hashlock" ‖ I2OSP(htlc_vout_i,4)))`
  and `auth_anchor_hash = SHA256(Expand(root, "auth-anchor"))` — and binds them during
  Pre-PegIn / PegIn validation. The root stays held through `INTENT_LOADED` →
  `SESSION2_PEGIN_EXPECTED` → `SESSION2_PAYOUT_EXPECTED` → `SESSION2_COMPLETE`, which is
  terminal. The host already holds the root (returned by `DERIVE_CONTEXT_HASH`) and expands
  the per-vault secrets itself, so there is **no on-device secret-release step**.
- **Called from any other state** — intent replacement / no-derive path.
  The session is reset normally; no root is preserved, so `htlc_hashlock`/`auth_anchor_hash`
  stay zero and Pre-PegIn/PegIn signing is rejected until a `DERIVE_CONTEXT_HASH` runs first.

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
- Not equal to any `vault_provider_pk` (checked across all `vault_count` vault groups)
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
| `0x6A80` | Duplicate tag, unknown tag, field validation failure, wrong field length, key ordering/uniqueness violation, extra keys beyond declared count, extra vault groups beyond `vault_count`, `htlc_vout` not strictly ascending across groups, depositor path in intent does not match path used in `DERIVE_CONTEXT_HASH` |
| `0x6A86` | P1 is not `0x00`, `0x01`, or `0x02` |
| `0x6A87` | P1=0x01 payload length is not a multiple of 32 |
| `0x6985` | User rejected the approval screen |
| `0xB007` | P1=0x01 or P1=0x02 received out of sequence (e.g. P1=0x01 before all P1=0x02 groups, or P1=0x01 before `DERIVE_CONTEXT_HASH` completes) |
| `0x6F00` | BIP-32 derivation of depositor key failed |

---

## INS 0x81 — DERIVE_CONTEXT_HASH — Wire Format (rev 2.1)

Multi-chunk streaming command. P1=0x00 opens the stream; P1=0x01 delivers continuation
chunks. Returns the 32-byte **root** on the final chunk (P2=0x00) or SW_OK only (P2=0x01).
The host expands the root into the per-vault secrets (see `derive-vault-secrets`).
The device retains no preimage and has **no release step**.

### P1 / P2 encoding

| P1     | P2     | Meaning |
|--------|--------|---------|
| `0x00` | `0x00` | Initial chunk; show Screen 1 on final chunk; return 32-byte root. |
| `0x00` | `0x01` | Initial chunk; silent re-derivation; return SW_OK only on final chunk. |
| `0x01` | same as P1=0x00 | Continuation chunk; P2 must match the value sent in P1=0x00. |

P2 must be consistent across all APDUs of one streaming sequence.

### P1=0x00 — initial chunk payload

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | `app_name_len` | 1 B | Length of `app_name`; `1..64` |
| 1 | `app_name` | `L` B | UTF-8 app name (host sends `"babylon-btc-vault"`) |
| 1+`L` | `path_len` | 1 B | connectedPubkey BIP-32 depth in levels; `1..10` |
| 2+`L` | `path` | `path_len`×4 B | each level as u32 **big-endian** (hardened bit set as usual) |
| 2+`L`+4·`path_len` | `context_total_len` | 2 B | total context byte count, **big-endian**; `1..1024` |
| 4+`L`+4·`path_len` | first context chunk | remaining `Lc` | first `≤Lc` bytes of `vaultContext`; may be empty if `context_total_len > Lc` |

(`L = app_name_len`.) If all `context_total_len` bytes fit in the initial APDU, the stream
finalizes immediately and returns the response (P2=0x00: 32-byte root; P2=0x01: SW_OK).
Otherwise returns SW_OK with no data and expects P1=0x01 continuation APDUs.

### P1=0x01 — continuation chunk payload

| Field | Size | Notes |
|-------|------|-------|
| context bytes | `Lc` B | Next chunk of `vaultContext`; must be non-empty |

Returns SW_OK with no data until `context_received == context_total_len`, then finalizes.
Must be preceded by a valid P1=0x00 in the same session; P1=0x01 without a prior P1=0x00
returns SW_BAD_STATE.

### Response (final chunk only)

| P2     | Data | SW |
|--------|------|----|
| `0x00` | 32 B `root` (the 32-byte HKDF output) | `0x9000` |
| `0x01` | empty | `0x9000` |

Both modes store the derivation path in the session context for path-match validation.

### Screen 1 (P2=0x00 only)

Shown on the final chunk, before the root is derived and returned. Displays `app_name`
and asks the user to approve. Rejection returns SW_DENY without deriving the root.

### Error conditions

| SW     | Condition |
|--------|-----------|
| `0x6A80` | `app_name_len` 0 or > 64; `app_name` charset invalid; `path_len` 0 or > 10; `context_total_len` 0 or > 1024; continuation chunk exceeds declared total; truncated fields |
| `0x6A86` | P1 is not `0x00` or `0x01`; P2 is not `0x00` or `0x01` |
| `0x6A87` | P1=0x00 payload shorter than the mandatory fixed fields; P1=0x01 payload empty |
| `0x6985` | User rejected Screen 1 (P2=0x00 only) |
| `0x6F00` | connected-pubkey BIP-32 derivation at `path` failed |
| `0xB007` | P1=0x01 received without a prior P1=0x00; HMAC / HKDF operation failed |

### Crypto detail

- **IKM**: 32-byte private key at `m/73681862'` (hardened, `CX_CURVE_SECP256K1`)
- **HKDF-Extract**: `PRK = HMAC-SHA256(salt="derive-context-hash", ikm)`
- **info**: `SHA256(app_name) || SHA256(canonicalNetworkName) || connectedPubkey[33] || context`
  - `canonicalNetworkName`: `"bitcoin-mainnet"` (mainnet build) / `"bitcoin-signet"` (testnet build)
  - `connectedPubkey`: 33-byte compressed SEC1 key the device derives at `path`
  - `context`: full reassembled context (up to 1024 B, spanning all chunks)
- **HKDF-Expand** (single block, L=32): `root = HMAC-SHA256(PRK, info || 0x01)`

The on-chain HTLC hashlock is `SHA256(Expand(root, info("hashlock", I2OSP(htlc_vout, 4))))`
and the Pre-PegIn OP_RETURN binds `SHA256(Expand(root, info("auth-anchor", [])))`; both are
recomputed on-device at `APPROVE_VAULT_INTENT` (`src/handler/derive_vault_secrets_core.h`).
The auth-anchor `OP_RETURN` output (`0x6A 0x20 || SHA256(authAnchor)`) MUST carry zero value:
it is provably unspendable, so the Pre-PegIn validator rejects any non-zero amount to prevent
a host from silently burning the depositor's change into it.

Implementation: `src/handler/derive_context_hash_core.h` (static inline, unit-testable).

Upstream specs (captured in `docs/specs/`):
[derive-context-hash.md](https://github.com/babylonlabs-io/babylon-toolkit/blob/main/docs/specs/derive-context-hash.md),
[derive-vault-secrets.md](https://github.com/babylonlabs-io/babylon-toolkit/blob/main/docs/specs/derive-vault-secrets.md)

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
