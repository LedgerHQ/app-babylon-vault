> **Captured copy — for reference only.** Canonical source:
> <https://github.com/babylonlabs-io/babylon-toolkit/blob/main/docs/specs/derive-vault-secrets.md>
> Captured 2026-06-30 (spec revision 0.1 draft, dated 2026-04-22). The upstream document is
> authoritative — re-fetch before relying on exact bytes. Companion to
> [`derive-context-hash.md`](derive-context-hash.md); both tracked for device realignment in
> NAPPS-1422. Device-relevant point: the on-chain hashlock is
> `SHA256(HKDF-Expand(root, info("hashlock", I2OSP(htlcVout,4)), 32))`, **not** `SHA256(root)`.

---

# `deriveVaultSecrets` Specification

**Spec revision**: 0.1 (draft)
**Date**: 2026-04-22
**Authors**: Jerome Wang (Babylon Labs)
**Status**: Draft

---

## Abstract

`deriveVaultSecrets` is an SDK-level helper for the Babylon Trustless
Bitcoin Vaults (TBV) protocol. It turns a single wallet
`deriveContextHash` call into the three
domain-separated secrets a Babylon BTC vault needs: the HTLC
**hashlock preimage**, the depositor **auth anchor**, and the
**WOTS seed**. It runs one HKDF-Expand (RFC 5869) per secret over
the 32-byte wallet-derived root, using distinct prefix-free `info`
labels so the outputs are computationally independent under the
assumption that HMAC-SHA-256 is a PRF.

The scheme exists because each Babylon BTC vault needs several
deterministic secrets whose disclosure or loss has protocol-level
impact, and calling the wallet three times would mean three
user-approval popups per BTC vault creation — multiplied across
every BTC vault funded by the Pre-PegIn. One wallet call + three local
HKDF-Expand calls replaces that without weakening independence of
the three outputs.

**Scope.** Secrets derived under this scheme MUST NOT, on their own,
authorize unilateral fund movement, cause irreversible on-chain
state-change outside the depositor's own scope, or act as the sole
gate on key material. `hashlockSecret` is the partial case — once a
BTC vault reaches `VERIFIED`, leaking the preimage lets anyone broadcast
the pre-authorized PegIn tx (no theft; depositor still mints vBTC).
See §3 for the per-label gates.

**Generality note.** The HKDF-Expand pattern in §2.2 is generic — any
caller of `deriveContextHash` can use it for multiple domain-separated
sub-keys from one wallet approval. This spec stays TBV-shaped (fixed
`appName`, three labels) because TBV is the only current consumer.

---

## Terminology

| Term | Meaning |
|------|---------|
| **BTC vault** | A single TBV vault: one Bitcoin HTLC output committed to a hashlock + depositor WOTS commitment, paired with an Ethereum registration. |
| **Pre-PegIn transaction** | The Bitcoin transaction the depositor signs to fund one or more BTC vaults. Contains one HTLC output per BTC vault plus a single shared `OP_RETURN` output carrying the auth-anchor commitment. |
| **HTLC output** | The taproot output in the Pre-PegIn that locks BTC into one BTC vault. Identified by its output index (`htlcVout`) within the Pre-PegIn. |
| **`htlcVout`** | The output index (0-based) of a BTC vault's HTLC output within the Pre-PegIn. On-chain `uint8`; encoded as 4 bytes big-endian in the HKDF `info` label for prefix-free domain separation. |
| **Funding outpoints** | The `(txid, vout)` UTXOs the Pre-PegIn spends as inputs. Their canonical commitment is part of `vaultContext`. |
| **`vaultContext`** | The per-Pre-PegIn opaque byte string the SDK constructs and hex-encodes before passing to the wallet's `deriveContextHash`. Encoded per §2.3. |
| **`rootDerivation`** (or **root**) | The 32-byte output of `wallet.deriveContextHash("babylon-btc-vault", hex(vaultContext))`. Used as the HKDF `PRK`. |
| **`PRK`** | Pseudorandom key, the keyed input to HKDF-Expand (RFC 5869 §2.3). In this spec, `PRK = rootDerivation` (Extract is skipped per RFC 5869 §3.3 — see §2.4). |
| **`label`** | A short ASCII string identifying which of the three secrets a derivation produces. Defined values: `auth-anchor`, `hashlock`, `wots-seed` (see Appendix A.2). |
| **`info(label, ctx)`** | The byte string passed as HKDF-Expand's `info` argument. Encoded per Appendix A.1 — prefix-free across labels and across context lengths. |
| **Vault provider (VP)** | Off-chain TBV operator the depositor exchanges the auth-anchor preimage with for a short-lived bearer token. |

---

## 1. Motivation

Each Pre-PegIn transaction in Babylon's Trustless Bitcoin Vaults
protocol funds one or more BTC vaults. For each Pre-PegIn the
depositor produces three kinds of secret material:

1. One 32-byte **hashlock preimage** per BTC vault: committed as
   `SHA256(preimage)` in that BTC vault's HTLC output; later revealed
   on Ethereum via `activateVaultWithSecret` to move the BTC vault
   from `VERIFIED` → `ACTIVE`.
2. A single 32-byte **auth anchor** per Pre-PegIn transaction:
   committed as `SHA256(anchor)` in the single `OP_RETURN` output of
   the Pre-PegIn (shared across every BTC vault funded by the
   transaction); revealed off-chain to the vault provider's
   `auth_createDepositorToken` RPC to obtain a short-lived CWT bearer
   token for depositor-facing RPCs.
3. One 64-byte **WOTS seed** per BTC vault: expanded by
   `deriveWotsBlockPublicKeys` into the one-time signature keypairs
   used for that BTC vault's BaBe / claim-graph commitments and
   Assert-path signing; only the `keccak256` hash of the derived
   public keys appears on-chain as `depositorWotsPkHash`.

A naive use of `deriveContextHash` would prompt the wallet for each
secret, for every BTC vault. This spec prompts **once per Pre-PegIn**
for the `rootDerivation`, then derives the three secrets locally via
HKDF-Expand with prefix-free `info` labels. The outputs are
computationally independent under the PRF assumption for
HMAC-SHA-256, so disclosure of one does not leak the others or the
root.

The per-BTC-vault parameter (`htlcVout`) is carried in the HKDF
`info` label rather than the wallet context — that's what lets one
wallet popup serve every BTC vault in the Pre-PegIn.

---

## 2. Specification

### 2.1 Derivation Operation

Inputs:

- `appName`: fixed to `"babylon-btc-vault"` across all Babylon BTC
  vault derivations under this scheme.
- `vaultContext`: opaque bytes composed per §2.3. Keyed per Pre-PegIn
  transaction, NOT per BTC vault.
- `htlcVout`: HTLC output index of a single BTC vault within the
  Pre-PegIn. On-chain it's `uint8`; encoded as 4 bytes big-endian in
  the HKDF `info` label. Required for the per-BTC-vault values
  (`hashlockSecret`, `wotsSeed`).

Outputs (conceptual — SDK API shapes vary, see §2.5):

- **`hashlockSecret[htlcVout]`** — 32 bytes, keyed per BTC vault
  (`htlcVout` in `info`). `SHA256(hashlockSecret)` is committed as
  the HTLC hashlock, later revealed via `activateVaultWithSecret`.
- **`authAnchor`** — 32 bytes, shared across the Pre-PegIn.
  `SHA256(authAnchor)` is committed in the Pre-PegIn `OP_RETURN`.
- **`wotsSeed[htlcVout]`** — 64 bytes, keyed per BTC vault. Fed
  unchanged to `deriveWotsBlockPublicKeys`.

The derivation invokes the wallet's `deriveContextHash` **at most
once per `(appName, vaultContext)` pair**.

### 2.2 Derivation Algorithm

```
rootDerivation = deriveContextHash("babylon-btc-vault", hex(vaultContext))

// RFC 5869 §3.3: when IKM is already a cryptographically strong key
// of HashLen bytes, HKDF-Extract is omitted and IKM is used directly
// as the PRK. rootDerivation is the 32-byte output of an earlier
// HKDF-SHA-256 invocation (by the wallet), so this precondition is met.
PRK = rootDerivation                                    // 32 bytes

// Shared across the Pre-PegIn — no per-BTC-vault parameter:
authAnchor        = HKDF-Expand-SHA-256(
                        PRK, info("auth-anchor", []), 32)

// Per BTC vault, at HTLC output index `i` within the Pre-PegIn:
hashlockSecret[i] = HKDF-Expand-SHA-256(
                        PRK, info("hashlock",  I2OSP(i, 4)), 32)
wotsSeed[i]       = HKDF-Expand-SHA-256(
                        PRK, info("wots-seed", I2OSP(i, 4)), 64)
```

Output lengths are fixed at 32 bytes for `hashlockSecret[i]` and
`authAnchor`, and 64 bytes for `wotsSeed[i]`.

The three labels (`hashlock`, `auth-anchor`, `wots-seed`) and the
byte-level encoding of `info(label, ctx)` are specified in Appendix A.

### 2.3 vaultContext Encoding Guidance

`vaultContext` is opaque to the wallet. The SDK SHOULD construct it
using the length-prefixed canonical form:

```
vaultContext := I2OSP(len(f1), 4) || f1
             || I2OSP(len(f2), 4) || f2
             || …
```

The canonical fields for `vaultContext`, in order, are:

1. The depositor's x-only BTC public key (32 bytes)
2. The **funding-outpoints commitment** (32 bytes) — a SHA-256 digest
   over the canonically-ordered serialization of the funding
   outpoints of the Pre-PegIn transaction:

   ```
   Each funding outpoint serialized as:
     outpoint := txid (32 bytes, display/RPC order — i.e. the form
                       shown in block explorers, NOT internal little-endian)
              || vout (4 bytes, u32 big-endian)
     // 36 bytes total

   Sort the N serialized outpoints in ascending lexicographic byte
   order over their 36-byte form, then:

   fundingOutpointsCommitment := SHA-256(
         outpoint_0 || outpoint_1 || ... || outpoint_{N-1}
   )    // 32 bytes
   ```

The commitment form keeps `vaultContext` at a fixed 72-byte length.
The raw outpoints remain recoverable from the broadcast Pre-PegIn
transaction's inputs.

The **`htlcVout`** parameter does NOT appear in `vaultContext` — it
is carried through the HKDF-Expand `info` label for the
per-BTC-vault values.

A commitment over funding outpoints is used rather than
`prePeginTxid` because the Pre-PegIn txid depends on the outputs
(which embed the derived commitments) — using `prePeginTxid` would be
circular.

### 2.4 HKDF-Expand

HKDF (RFC 5869) separates derivation into two stages: Extract
(`PRK = HMAC-SHA-256(salt, IKM)`) and Expand
(`T(i) = HMAC-SHA-256(PRK, T(i-1) || info || i)`).

Per RFC 5869 §3.3, when IKM is already a cryptographically strong
`HashLen`-byte key, Extract is skipped and IKM is used directly as
the PRK. `deriveContextHash` returns exactly such a key, so this spec
uses **Expand only**.

Implementations MUST use a well-audited HKDF library. **Web Crypto's
`deriveBits({ name: "HKDF" })` and Node's `crypto.hkdf` always run
the Extract step and are therefore NOT byte-for-byte equivalent to
this spec** — they MUST NOT be presented as conforming. The reference
TypeScript primitive is `@noble/hashes/hkdf`'s `expand(...)`.

### 2.5 SDK Implementation Guidance

This spec pins the algorithm, not the API surface. Two requirements:

1. The number of `wallet.deriveContextHash` calls for a given
   `(appName, vaultContext)` MUST NOT exceed one.
2. The bytes returned for each named secret MUST be identical to
   those produced by §2.2 for the same inputs.

Recommended shape (root + pure expanders):

```
deriveVaultRoot(wallet, vaultContext) → Promise<Uint8Array[32]>  // one wallet call

expandAuthAnchor(root)                    → Uint8Array[32]  // shared
expandHashlockSecret(root, htlcVout: u32) → Uint8Array[32]  // per BTC vault
expandWotsSeed(root, htlcVout: u32)       → Uint8Array[64]  // per BTC vault
```

`htlcVout` MUST be the BTC vault's actual HTLC output index, encoded
as `I2OSP(htlcVout, 4)`.

---

## 3. Scope

A secret MUST NOT be added to this scheme if any of the following
hold: (1) unilateral fund movement or unauthorized spend; (2)
control-plane action with monetary, state-change, or third-party
privacy consequence; (3) sole gate on key material.

| Label | Rule 1 | Rule 2 | Rule 3 |
|-------|--------|--------|--------|
| `hashlockSecret` | **Partial — pre-authorized spend, no theft.** Pegin sigs use `SIGHASH_ALL`/`SIGHASH_DEFAULT` (fixed outputs); `activateVaultWithSecret` re-checks `msg.sender == depositor`. Once `VERIFIED`, all participant sigs are public in `peginInputSignatures`, so a leaked preimage can broadcast the pegin tx and destroy the depositor's refund leaf — but the depositor still holds the same preimage and can mint vBTC, so no theft. | No. Only on-chain consumer is the depositor-bound `activateVaultWithSecret`. | No. |
| `authAnchor`     | No. Token gates depositor-scoped RPCs only. | No. Artifacts returned are the depositor's own operational data. | No. |
| `wotsSeed`       | No. WOTS signs one leaf of a multi-party co-signed graph. | No. WOTS commitments are public. | No. |

### 3.1 Non-repudiation caveat

A SHA-256 commitment to a derived secret appearing on-chain is **not
cryptographic proof that the publisher knows the preimage**. Any party
handed the secret can compute the same commitment.

### 3.2 Transparency gap

`deriveContextHash` exposes the root; the three secrets are
HKDF-Expand outputs computed in the dApp's JavaScript context and are
not visible to the wallet or surfaced back to the user at signing
time.

---

## 4. Test Vectors

Conformance vectors share the wallet test setup with
`derive-context-hash.md` §4:

- BIP-39 mnemonic (no passphrase): `abandon abandon ... about`
- BIP-32 private key at `m/73681862'` (hex):
  `391cdb922097ec9c96fc13cadb01d5745ccf31f5dbec3a3810344071 4779ec85`
- `appName` for Vectors 1–3: `"test-app"`; Vector 4 uses
  `"babylon-btc-vault"`.

### Label info encodings

```
// Shared across the Pre-PegIn (no per-BTC-vault ctx bytes):
info("auth-anchor", []) :=
    62 61 62 79 6c 6f 6e 62 74 63 76 61 75 6c 74   // "babylonbtcvault"
    0b                                             // label length = 11
    61 75 74 68 2d 61 6e 63 68 6f 72               // "auth-anchor"
    00 00                                          // ctx length = 0

// Per BTC vault, for htlcVout = 0:
info("hashlock", I2OSP(0, 4)) :=
    62 61 62 79 6c 6f 6e 62 74 63 76 61 75 6c 74   // "babylonbtcvault"
    08                                             // label length = 8
    68 61 73 68 6c 6f 63 6b                        // "hashlock"
    00 04                                          // ctx length = 4
    00 00 00 00                                    // I2OSP(0, 4)

info("wots-seed", I2OSP(0, 4)) :=
    62 61 62 79 6c 6f 6e 62 74 63 76 61 75 6c 74   // "babylonbtcvault"
    09                                             // label length = 9
    77 6f 74 73 2d 73 65 65 64                     // "wots-seed"
    00 04                                          // ctx length = 4
    00 00 00 00                                    // I2OSP(0, 4)

// Per BTC vault, for htlcVout = 2:
info("hashlock", I2OSP(2, 4)) :=
    62 61 62 79 6c 6f 6e 62 74 63 76 61 75 6c 74   // "babylonbtcvault"
    08                                             // label length = 8
    68 61 73 68 6c 6f 63 6b                        // "hashlock"
    00 04                                          // ctx length = 4
    00 00 00 02                                    // I2OSP(2, 4)
```

### Vector 1 — single-HTLC (vout = 0)

```
vaultContext (hex): deadbeef
rootDerivation (from derive-context-hash §4.1 Vector 1):
  3b0e2d90a01122eed8a520648073892f6b2d8f4419216023d63cdbd49500fca3
authAnchor        := HKDF-Expand-SHA-256(root, info("auth-anchor", []),        32)
hashlockSecret[0] := HKDF-Expand-SHA-256(root, info("hashlock",  I2OSP(0, 4)), 32)
wotsSeed[0]       := HKDF-Expand-SHA-256(root, info("wots-seed", I2OSP(0, 4)), 64)
```

### Vector 2 — batch (vouts 0, 1, 2)

```
vaultContext (hex): 00
rootDerivation (from derive-context-hash §4.1 Vector 2):
  50775126782c1a5e4d60daa4666b2c7590f0b5a445a4115b0abd411467c92597
```

The three `hashlockSecret[i]` and three `wotsSeed[i]` values MUST be
pairwise distinct; `authAnchor` MUST match the single value
regardless of which HTLC index is processed.

### Vector 3 — canonical Babylon BTC vault context shape (`appName = "test-app"`)

```
depositorBtcPubkey (32 bytes, x-only):
  0101010101010101010101010101010101010101010101010101010101010101

outpoint_a:  txid aa..aa (32B, display order)  vout 00000000
outpoint_b:  txid bb..bb (32B, display order)  vout 00000001
(sorted ascending lexicographically before hashing)

fundingOutpointsCommitment := SHA-256(outpoint_a(36) || outpoint_b(36))

vaultContext :=
    I2OSP(32, 4) || depositorBtcPubkey
 || I2OSP(32, 4) || fundingOutpointsCommitment
```

### Vector 4 — production `appName`

Same `vaultContext` as Vector 3 but `appName = "babylon-btc-vault"`.

### Promotion criteria

Draft → RFC requires pinning the concrete 32-byte `hashlockSecret` /
`authAnchor` and 64-byte `wotsSeed` outputs, cross-validated against
two independent **Expand-only** HKDF implementations (`@noble/hashes`
`expand`, Rust `hkdf` `from_prk().expand()`, or a manual HMAC loop).
Full-HKDF (Extract+Expand) APIs are NOT usable for conformance.

---

## 5. References

- `derive-context-hash.md` (companion spec)
- RFC 5869 — HKDF — <https://datatracker.ietf.org/doc/html/rfc5869>
- RFC 8017 §4.1 — I2OSP — <https://datatracker.ietf.org/doc/html/rfc8017>
- RFC 9180 §4 — HPKE `LabeledExpand` pattern — <https://datatracker.ietf.org/doc/html/rfc9180>
- `@noble/hashes` — <https://github.com/paulmillr/noble-hashes>

---

## Appendix A. `info` Encoding

### A.1 Encoding

```
info(label, ctx) :=
       "babylonbtcvault"        // fixed 15-byte ASCII domain tag
    || I2OSP(len(label), 1)     // 1-byte label length
    || label                    // ASCII bytes of the label
    || I2OSP(len(ctx),   2)     // 2-byte big-endian ctx length
    || ctx                      // opaque per-label context bytes
                                // (may be empty)
```

`I2OSP(n, k)` is the big-endian `k`-byte encoding of `n` (RFC 8017
§4.1). Both length prefixes are fixed-width, removing the
"one info is a prefix of another" hazard. Follows RFC 9180 §4
(HPKE `LabeledExpand`).

### A.2 Defined labels

- **`hashlock`** (ASCII `68 61 73 68 6c 6f 63 6b`) — ctx =
  `I2OSP(htlcVout, 4)`. HTLC preimage, per BTC vault.
- **`auth-anchor`** (ASCII `61 75 74 68 2d 61 6e 63 68 6f 72`) —
  ctx = *(empty)*. VP bearer-token `OP_RETURN` preimage, shared
  across Pre-PegIn.
- **`wots-seed`** (ASCII `77 6f 74 73 2d 73 65 65 64`) — ctx =
  `I2OSP(htlcVout, 4)`. WOTS block-key PRF seed, per BTC vault.

Any additional labels MUST NOT be equal to, nor a prefix of, any
existing label. Label length MUST be in `[1, 255]`, context length
in `[0, 65535]`.
