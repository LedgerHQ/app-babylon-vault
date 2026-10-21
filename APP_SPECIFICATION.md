# Babylon Vault — App Specification

> **v22 HLD alignment:** This document reflects the device design as of HLD v22. For a full change history see [`CHANGELOG.md`](CHANGELOG.md).

## About

This document describes the APDU interface and transaction types supported by the **Babylon Vault** Ledger application (`app-babylon-vault`).

The app is a dedicated btcext extension for the [Babylon protocol](https://babylonlabs.io/). It enables a Ledger device to participate in the full Babylon vault lifecycle:

- Derive a 32-byte session root and bind it to on-chain commitments (`DERIVE_CONTEXT_HASH`)
- Review and approve vault parameters and participant keys (`APPROVE_VAULT_INTENT`)
- Report whether that session is still in device memory, so the host can resume it (`GET_VAULT_STATE`)
- Sign ten Bitcoin transaction types: Pre-PegIn, PegIn, Payout, PayoutFinalize, Refund, Claim, Reclaim, Assert, Wrongly-Challenged (WC), NoPayout

The app extends [app-btcext-boilerplate](https://github.com/LedgerHQ/app-btcext-boilerplate). Standard btcext APDUs (e.g. `GET_EXTENDED_PUBKEY`, `SIGN_PSBT`) are handled by the base app. Only the three custom INS codes below are specific to this app.

For full wire-format details see [`docs/apdu.md`](docs/apdu.md).

---

## APDUs

All custom APDUs use **CLA `0xE1`**.

| INS    | Name                    | Description |
|--------|-------------------------|-------------|
| `0x80` | `APPROVE_VAULT_INTENT`  | Three-phase APDU. **P1=`0x00`**: parse and validate 13 scalar TLV fields. **P1=`0x01`**: receive per-vault group TLV (6 fields per vault group, repeated `vault_count` times). **P1=`0x02`**: stream keeper then challenger x-only public keys (TLV-wrapped; tag `2B` + length `1B` + 32-byte key). After all keys are received the device displays the vault parameters for user approval and, on confirmation, transitions the session to `INTENT_LOADED`. |
| `0x81` | `DERIVE_CONTEXT_HASH`   | Chunked streaming APDU (**P1=`0x00`** initial chunk, **P1=`0x01`** continuation). Derives a 32-byte context root from the device's BIP-32 key at `m/73681862'` via HKDF-SHA-256 and stores it in the session context. **P2=`0x00`**: shows a user approval screen ("Allow derivation?") and, on confirmation, returns the raw 32-byte root to the host. **P2=`0x01`**: silent re-derivation; returns `SW_OK` with no data. |
| `0x82` | `GET_VAULT_STATE`       | Read-only and silent (ADR-001). **P1=P2=`0x00`**, empty CData. Returns `len_i ‖ intent_fp ‖ len_r ‖ context_fp`, each length `0` (not held) or `4`: `00 00` in `IDLE`, `00 04 <context_fp>` in `HASH_DERIVED`, `04 <intent_fp> 04 <context_fp>` in `INTENT_LOADED`. `context_fp` is the last 4 bytes of `SHA-256(context_root)`; `intent_fp` the last 4 bytes of SHA-256 over the concatenated CData of every `APPROVE_VAULT_INTENT` APDU. No user presence, no screen, no state change. A malformed call gets `0x6A86` (P1/P2 ≠ `0x00`) or `0x6A87` (CData not empty). Wire format and fingerprint definitions: [`docs/apdu.md`](docs/apdu.md#ins-0x82--get_vault_state--wire-format). |

#### DERIVE_CONTEXT_HASH — caller identity is not authenticated

Screen 1 (P2=`0x00`) shows the host-supplied `appName` and the warning "Only approve on a
trusted website or application" — as the intro subtitle on touch devices, as a page of its own
on Nano. Nothing else identifies the caller. This is a **known, accepted deviation** from the
bundled protocol specification, which requires more:

> `docs/specs/derive-context-hash.md` §2.1 — "The dialog MUST display the `appName` **and
> the requesting origin**. The dialog SHOULD also display the context bytes."

The device cannot satisfy that MUST. It speaks raw APDU over USB/BLE/NFC, a transport that
carries no browser or application origin, and the same spec states plainly that `appName`
"is not, by itself, an authenticated identity signal; a malicious application can choose
any allowed string". Validation here restricts only length and character set
(`[a-z0-9\-]`), so any caller may claim `babylon-btc-vault`.

Consequences a reviewer and an integrator should both be aware of:

- A phishing application that reconstructs a known vault's public context and derivation
  path can produce a Screen 1 indistinguishable from the legitimate one, and on approval
  receives the same deterministic 32-byte root — from which every Babylon sub-secret
  (hashlock, auth anchor, WOTS seed) expands.
- The screen says "Allow derivation?", which understates what is released: a deterministic
  **secret root**, not a hash of public data.
- The physical approval gesture is the only remaining control, and it is being made on
  incomplete information. The warning tells the user the decision is theirs; it does not
  give them anything to check the caller against.

Closing this needs identity established outside the raw APDU — an origin assertion from a
wallet or transport layer that the device can verify — which is an ecosystem change, not an
app one. The integrator's position is that no wallet can verify which application is calling
and that this app is platform-agnostic, so the root is still returned for P2=`0x00`:
integrators need it, and the command is not blocked. The warning above is the mitigation
adopted. The stronger in-app one — display the connected public key (or a short fingerprint
of it) and a digest of the context, and reword the prompt to state that a secret root will be
exported — is not implemented; it changes Screen 1 further and requires HLD sign-off.

#### GET_VAULT_STATE — answers an unauthenticated caller

`GET_VAULT_STATE` answers any host, with no user interaction and no screen, so a host can
poll it at will. This is **accepted by design** (ADR-001) rather than a deviation, and is
recorded here for the same reason as the Screen 1 entry above: the next reviewer should find
the reasoning next to the command, not reconstruct it.

What an arbitrary caller learns:

- Whether a session exists, and whether it has reached `HASH_DERIVED` or `INTENT_LOADED`.
- `context_fp`, 4 bytes of `SHA-256(context_root)`. The host that ran the session received
  the full root from `DERIVE_CONTEXT_HASH` P2=`0x00`, so it learns nothing new.
- `intent_fp`, 4 bytes of SHA-256 over bytes the legitimate host sent. It confirms knowledge
  of the intent, it does not reveal it.

**A host with no approval at all can read a root-derived value.** `DERIVE_CONTEXT_HASH`
P2=`0x01` derives a root silently, from an app name, path and context the host chooses,
and `GET_VAULT_STATE` then returns `SHA-256(root)[28..32]` for it — before, a silent
derivation returned nothing. This is accepted: it is 32 bits of a hash of a 256-bit secret,
it cannot be inverted, and `SHA-256(root)` is used nowhere else (the on-chain commitments are
`SHA-256(Expand(root, …))`), so it confirms nothing a host could act on. As a per-seed tag it
adds no linkability beyond the silent `GET_EXTENDED_PUBKEY` the base app already allows.
ADR-001's "not a new disclosure" holds only for the P2=`0x00` case.

Signature counters are not returned (ADR-001 Option 3): without the host's own record of
what it signed they give no aid, and they would tell a polling caller how far the vault
flow has progressed.

The fingerprints are an aid to resumption, not an authenticator. A match means the host may
skip re-derivation and re-approval; it grants nothing the loaded session did not already
allow, and every signature remains bound to the approved intent and its caps. At 32 bits a
hostile host can grind an intent with a colliding fingerprint in about 2³² hashes, so a match
tells a host that the device holds an intent with that fingerprint, not that it holds the
host's own.

#### Session lifetime across a disconnection — open divergence from HLD v23

HLD v23 §Safety UX nullifies the intent, the root, the counters and the state machine when
"the device connection is lost (app switch, unplug, power-off)", and requires that "a new
connection requires re-derivation and a fresh intent approval". The app nullifies only when
the app exits or the device loses power. Nothing handles a USB or BLE disconnection, so on a
battery-powered device (Nano X, Stax, Flex, Apex P) left in the app the session survives an
unplug. A Nano S+ loses power when unplugged, so there the HLD holds.

ADR-001 depends on exactly this: `GET_VAULT_STATE` exists so a host can resume after "the USB
connection returns while the application still runs". It also lets any host that connects
next see that a session is live. That host can then sign silently within the remaining caps
of the approved intent, without the fresh approval the HLD requires. The signatures stay
bound to the intent the user approved, so funds cannot be redirected; what is lost is the
HLD's second bound on silent signing, "the intent approval on the same connection".

> ⚠️ **Decision: PENDING.** Either this divergence is accepted — citing Arch (Pierre Pollastri)
> and Donjon (Baptistin Boilot) sign-off here by name and date — or the app nullifies the
> session on transport loss, which leaves `GET_VAULT_STATE` useful only after an auto-lock.
> The behaviour predates `GET_VAULT_STATE`; the command makes it load-bearing.

#### `context_root` lifetime — divergence from HLD v23

HLD v23 describes the root as held in session memory for the whole session: "The device
stores the context_root in session memory and derives the following from it", with the
Pre-PegIn and PegIn checks "recomputed by the device from the `context_root`", and the
invalidation list nullifying "the stored secret `context_root`". The app is stricter. It
zeroes the root as soon as `APPROVE_VAULT_INTENT` has derived the two on-chain commitments
(`htlc_hashlock` per vault, `auth_anchor_hash`), and the signing checks compare against those
commitments. In `INTENT_LOADED` no root is held.

This is why `GET_VAULT_STATE` cannot compute `context_fp` on demand: the fingerprint is
captured in `DERIVE_CONTEXT_HASH` at the moment the root is produced, and carried across the
`APPROVE_VAULT_INTENT` reset alongside the root it describes. The hardening is kept; the HLD
is not being amended.

### APPROVE_VAULT_INTENT — intent fields

#### P1=`0x00` — scalar fields (13)

The TLV payload in `P1=0x00` encodes the following 13 scalar fields (tag `2B` + length `1B` + value):

| Field | Validation rule |
|---|---|
| `structure_type` | must equal the vault structure type constant |
| `version` | must equal the current protocol version constant |
| `coin_type` | must equal `BIP44_COIN_TYPE` for the active network |
| `base_fee_rate` | present |
| `pegin_csv_timelock` | `[72, 1008]` blocks inclusive |
| `payout_timelock` | `(90, 4032)` blocks exclusive |
| `prepegin_txid` | 32-byte txid |
| `htlc_refund_timelock` | `[72, 4320]` blocks inclusive |
| `depositor_derivation_path` | BIP-86 path `m/86'/coin_type'/acct'/chg/idx`, exactly 5 levels |
| `keeper_count` | `[1, 32]` inclusive |
| `challenger_count` | `[1, 32]` inclusive |
| `vault_count` | `[1, 10]` inclusive |
| `prepegin_max_fee` | `uint64`; maximum allowed fee (satoshis) for the Pre-PegIn transaction; must be non-zero |

Duplicate tags, unknown tags, and non-canonical encodings are all rejected.

#### P1=`0x01` — per-vault group fields (6 per vault)

After P1=`0x00`, the host sends one APDU per vault group (repeated `vault_count` times). Each group payload encodes the following 6 fields, specific to one vault in a batch Pre-PegIn:

| Field | Validation rule |
|---|---|
| `htlc_vout` | output index of the HTLC in the Pre-PegIn transaction; must be strictly ascending across groups |
| `vault_provider_pk` | 32-byte x-only public key; must be a valid secp256k1 point |
| `vault_amount` | `> commission_fee + 2 × DUST` |
| `commission_fee` | `≥ DUST` (546 sat) |
| `depositor_claim_value` | present |
| `pegin_max_fee` | present |

Groups must arrive in strictly ascending `htlc_vout` order. Multiple group records may be packed back-to-back within one APDU payload.

#### P1=`0x02` — key batch

The key batch must deliver exactly `keeper_count` keeper keys followed by `challenger_count` challenger keys (x-only, 32 bytes each, TLV-wrapped with 2-byte tags). All keys must be:
- globally unique across all roles
- pairwise disjoint with `vault_provider_pk` (per group) and the depositor key
- sorted in ascending lexicographic order within each group

#### Screen 2 — the intent review is only partly mandatory

On touch devices the review is split into two streaming reviews, and only the first is
mandatory. This is a **known, accepted deviation** from HLD v23 §Safety UX, which is not
being amended and continues to read:

> Screen 2 "Displays the intent fields marked ✅ in the TLV table. The user must approve
> before any signing can proceed."

| Review | Rows displayed | Skippable |
|---|---|---|
| 1 | The global scalars: app name, base fee rate, PegIn timelock, Payout timelock, Refund timelock, max Pre-PegIn fee, keeper count, challenger count; then the per-vault groups (VP key, vault amount, commission fee, depositor claim, max PegIn fee), repeated `vault_count` times | No |
| 2 | The keeper/challenger key list | **Yes** |

Of the eight global rows, the app name comes from the session context established by
`DERIVE_CONTEXT_HASH` (so it is shown even when P2=`0x01` suppressed Screen 1) and the other
seven are scalar `P1=0x00` fields. The remaining scalar TLV fields are validated without
being displayed, which this deviation does not change.

The deviation is precisely that the individual keeper and challenger keys may be bypassed;
their number is still displayed. Nano devices are unaffected — the SDK offers no skip
affordance there, so the whole review is mandatory.

Approval itself is never bypassed: Skip lands on the approve/reject page, so "chose not to
read the details" stays distinct from "never approved". The split into two streaming reviews
exists solely to keep this boundary enforceable — NBGL arms `SKIPPABLE_OPERATION` for a
whole streaming review and excludes per-page narrowing for `STREAMING_NAV`. The approval
page is reachable only through review 2, which starts only after the last vault group has
been confirmed, so no Skip can reach it before every global row and every group row has
been shown.

What the boundary preserves: every value that governs the *silent* signing following
approval is guaranteed to have been shown — `prepegin_max_fee`, the timelocks and the base
fee rate, as well as each vault's amount, commission fee, depositor claim and max PegIn fee.
What review 2 gives up is the identity of the participants: a user who skips sees how many
keepers and challengers the intent names, but not which keys.

**This reverses an earlier audit fix** (S-01 / Govard #5 / D7), which removed the affordance
on the grounds that Screen 2 is the sole anchor for the *silent* signing that follows it —
Pre-PegIn signs with no further screen. Restoring it was requested by Babylon (Jerome Wang,
option 1 of two proposed boundaries) for usability on large intents, where the key list can
run to 64 entries. That option also put the per-vault groups inside the skippable section;
they were moved back into the mandatory review because a Skip on a group page reached the
approval page without the remaining groups' amounts, commission fees, claim values or fee
limits having been shown. The key list, which is what makes large intents long, stays
skippable.

**This is the intended behaviour.** The key list is skippable by design, the parameters and
vault groups stay mandatory, and Skip always lands on the approve/reject page, so approval
is never bypassed.

**Interaction with Assert.** The Assert leaf binding is session-scoped, and the note under
[Assert](#7-assert-standalone) identifies the user's review of the key list on Screen 2 as
what prevents a substituted challenger set. That review is skippable, so a user who skips
it loses that protection; the displayed challenger count exposes a substitution that changes
the set's size, not one that keeps it. The binding still holds against the intent loaded in
the session; what weakens is the assurance that the loaded intent is the funded one.
Displaying the challenger set on Screen 5 would remove the dependency on the key list
entirely; it is not implemented.

---

## User-facing screens

The app has **nine** user-facing screens. Every other command and signature is silent.

| Screen | Shown by | Specified in |
|---|---|---|
| 1 | `DERIVE_CONTEXT_HASH` with P2=`0x00` | [DERIVE_CONTEXT_HASH](#derive_context_hash--caller-identity-is-not-authenticated) |
| 2 | `APPROVE_VAULT_INTENT` | [Screen 2](#screen-2--the-intent-review-is-only-partly-mandatory) |
| 3 | Refund | [§4](#4-refund-standalone) |
| 4 | Claim | [§6](#6-claim-standalone) |
| 5 | Assert | [§7](#7-assert-standalone) |
| 6 | Wrongly Challenged | [§8](#8-wrongly-challenged--wc-standalone) |
| 7 | Proof of Possession (BIP-322) | — |
| 8 | PayoutFinalize | — |
| 9 | Reclaim | [§9](#9-reclaim-standalone) |

Screen 9 is the only consent screen: it asks the user to judge what the device cannot see —
whether the vault is redeemed — rather than to confirm values the device has checked.

#### Screen 9 — divergence from HLD v23

HLD v23 §Safety UX specifies exactly 8 user-facing screens. ADR-002 adds Screen 9 for
Reclaim. The divergence is recorded here; the HLD is not amended.

---

## Transaction Types

The app recognises ten Bitcoin transaction types via the `SIGN_PSBT` hook. The device independently reconstructs the expected scripts from the loaded `vault_intent_t` and rejects any PSBT whose scripts do not match.

For the standalone flows (no wallet policy), the leaf script alone does not always pick a unique pattern: Claim and Reclaim share the exact same 34-byte `<D> OP_CHECKSIG` leaf. Where that happens, the dispatch rule is stated on the pair (leaf script, output count), not on the leaf script alone — see Claim and Reclaim below.

### 1. Pre-PegIn

The depositor creates one or more HTLC outputs (one per vault group) that lock BTC until the vault is finalised.

**Requires:** `INTENT_LOADED` state.

**PSBT requirements:**
- Inputs: wallet inputs (BIP-86 P2TR), signed by the base app
- Output at `htlc_vout` (per group): P2TR matching the 2-leaf HTLC reconstructed from the intent; value in `[vault_amount + depositor_claim_value + 240, vault_amount + depositor_claim_value + 240 + pegin_max_fee]` (the minimum covers `vault_amount`, `depositor_claim_value`, and the 240-sat P2A anchor funded by the PegIn transaction)
- Optional OP_RETURN output (positioned strictly after all HTLC outputs): 34-byte scriptPubKey `0x6A 0x20 <auth_anchor_hash>`, value `0`; when present the device validates the 32-byte payload against `auth_anchor_hash = SHA256(Expand(root, "auth-anchor"))` computed at `APPROVE_VAULT_INTENT` time. At most one such output is permitted.
- Optional depositor outputs (positioned strictly after all HTLC outputs), paying P2TR(depositor_pk) — the BIP-86 key-path scriptPubKey of the key the device derived from `depositor_path`, i.e. the address the dApp shows:
  - at most one CPFP anchor, value exactly `VAULT_DUST_LIMIT` (546 sat);
  - after the anchor, at most one change output, value above `VAULT_DUST_LIMIT`, and only when `depositor_path` is the first receive address (`m/86'/coin'/account'/0/0`) of the BIP-86 account the inputs are signed from, which the base app verifies against the device's own key: the path is chosen by the host and never shown on the device, so change is accepted only where a wallet looks for it;
  - a change output with no preceding anchor, a second anchor, a change output under any other `depositor_path` (another address index, the change branch, or another account), and a depositor output below `VAULT_DUST_LIMIT` are rejected. The anchor does not depend on the path.
- No other output is accepted. In particular, change on the wallet policy's change branch (`…/1/*`) is rejected. The base app treats receive-branch outputs (`…/0/*`) as external, which is why change to the depositor's own address is matched by script above instead.
- Ordering: the device enforces that every non-HTLC output follows all HTLC outputs and that the change follows the anchor. The anchor and the change share one scriptPubKey, so that order is what lets a reader of the transaction tell them apart. The device does not order the auth-anchor OP_RETURN against the depositor outputs; the canonical layout, which btc-vault builds and reads, is `[HTLC…, OP_RETURN?, anchor, change?]`.
- Sighash: `SIGHASH_ALL` or `SIGHASH_DEFAULT`; version ≥ 2; locktime = 0
- Fee: `total_inputs − total_outputs ≤ prepegin_max_fee`

**User display:** Pre-PegIn signing is silent — no per-signing screen is shown. The fee bound (`prepegin_max_fee`) is displayed on the intent approval screen (Screen 2).

**Relation to HLD v23.** The HLD admits "Depositor outputs (zero or more)" under any BIP-86 path and
does not distinguish change from the anchor. The device is narrower, never looser: a depositor output
must pay `depositor_pk` itself, at most one anchor and one change output are accepted, the change
must follow the anchor, and the change is accepted only when `depositor_path` is `m/86'/coin'/account'/0/0` of a BIP-86 signing account.
Every depositor output returns value to a key the device derived, so the count
and order limits do not affect where value goes; the fee remains bounded by `prepegin_max_fee`.

**HTLC scripts (2-leaf P2TR, NUMS internal key):**
- *Leaf 0 — Hashlock + All-Party:* `OP_SIZE <32> OP_EQUALVERIFY / OP_SHA256 <h> OP_EQUALVERIFY / <D> OP_CHECKSIGVERIFY / <VP> OP_CHECKSIGVERIFY / <VK N-of-N> / <UC M-of-M>`
- *Leaf 1 — Refund:* `<D> OP_CHECKSIGVERIFY / <T_refund> OP_CHECKSEQUENCEVERIFY`

---

### 2. PegIn (silent)

Spends the HTLC and creates the Vault UTXO + Depositor Claim UTXO + P2A anchor. No user display; parameters were already approved during `APPROVE_VAULT_INTENT`.

**Requires:** `INTENT_LOADED` state.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Input 0 prevout | `prepegin_txid:htlc_vout` from intent |
| Input 0 sequence | `0xFFFFFFFE` |
| Version / locktime | 3 / 0 |
| Output count | Exactly 3 |
| Output 0 | Reconstructed Vault UTXO scriptPubKey; value = `vault_amount` |
| Output 1 | Reconstructed Depositor Claim scriptPubKey; value = `depositor_claim_value` |
| Output 2 | P2A anchor; value = `P2A_ANCHOR_VALUE` (240 sat) |
| PSBT metadata | `TAP_LEAF_SCRIPT`, `TAP_INTERNAL_KEY`, `TAP_MERKLE_ROOT` must match reconstructed values |
| Secret hash binding | HTLC Leaf 0 in the PSBT must embed `h = htlc_hashlock` from the session context |
| Sighash | `SIGHASH_DEFAULT` only |
| Fee | `htlc_value − (vault_amount + depositor_claim_value + 240) ≤ pegin_max_fee` |

**Vault UTXO script (1-leaf P2TR, NUMS internal key):**
`<D> OP_CHECKSIGVERIFY / <VP> OP_CHECKSIGVERIFY / <VK N-of-N> / <UC M-of-M> / <P> OP_CHECKSEQUENCEVERIFY`

**Depositor Claim script (1-leaf P2TR, NUMS internal key):**
`<D> OP_CHECKSIG`

---

### 3. Payout (silent)

Pre-signs `vault_count × (keeper_count + 2)` payout transactions — one per potential claimer per vault group (VP, VK_1..VK_N, and Depositor). The device auto-detects the claimer identity and vault group from the PSBT structure (witness UTXO scriptPubKey and prevout txid); any signing order is accepted. No user display; parameters were already approved.

**Requires:** `INTENT_LOADED` state.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 2 |
| Input 0 prevout | `computed_pegin_txid:0` (computed deterministically from intent, matched against PSBT) |
| Input 0 sequence | `pegin_csv_timelock` (P) |
| Input 1 sequence | `payout_timelock` (t2) |
| Input 0 leaf script | Matches reconstructed Vault UTXO leaf |
| Input 1 leaf script | Matches reconstructed Assert:0 Payout leaf for detected claimer |
| Output count | 3 for VP claimer; 2 for VK or Depositor claimer |
| Fee bound | `actual_fee ≤ base_fee_rate × (500 + 55 × (N+M))` |
| Sighash | `SIGHASH_DEFAULT` only |
| Version / locktime | ≥ 2 / 0 |

The device signs Input 0 (Vault UTXO leaf). Input 1 (Assert:0) is verified but not signed by the device.

**Assert:0 Payout leaf script:**
`<Claimer> OP_CHECKSIGVERIFY / <AppChallengers K-of-K> / <UC M-of-M> / <t2> OP_CHECKSEQUENCEVERIFY`

where `AppChallengers = {VP, VK_1..VK_N} \ {Claimer}` for VP or VK claimers, or `{VK_1..VK_N}` for the Depositor claimer, sorted lexicographically.

---

### 4. Refund (standalone)

The depositor reclaims BTC from the HTLC before the vault is finalised (timelock branch).

**Requires:** any state (including `IDLE`); does not affect session progress.

**PSBT requirements:**
- Single input spending the HTLC; leaf script read from `TAP_LEAF_SCRIPT` in the PSBT
- Leaf script shape: `<key> OP_CHECKSIGVERIFY <n> OP_CHECKSEQUENCEVERIFY`; `<key>` must be owned by this device at the BIP-32 path in `TAP_BIP32_DERIVATION`; control block must produce a valid Taproot commitment
- CSV operand `<n>`: a positive CScriptNum push (`OP_1`–`OP_16`, `OP_PUSHBYTES_1`–`OP_PUSHBYTES_4`, or `OP_PUSHDATA1`; minimal encoding is not enforced), at most `0xFFFF` — the BIP-68 block-count field is the only part of the operand `OP_CHECKSEQUENCEVERIFY` acts on, so a larger value would display a delay the transaction does not enforce. `INTENT_LOADED` additionally requires `<n> == htlc_refund_timelock`; outside it, `<n> ≥ 72` (the protocol minimum)
- `PSBT_IN_SEQUENCE`: must equal `<n>` **exactly** (compared unmasked), with the BIP-68 disable (bit 31) and time-based (bit 22) flags clear. Bits consensus ignores are rejected rather than masked away, so the displayed timelock is always the one that will be enforced
- Single output: BIP-86 P2TR (`account_index ≤ 100`, `address_index ≤ 10000`)
- Sighash: `SIGHASH_DEFAULT`; version ≥ 2; locktime = 0

**User display:** Pre-PegIn txid, reclaimed amount, refund timelock (blocks), transaction fee, reclaim address.

---

### 5. NoPayout (silent)

The depositor pre-signs a NoPayout leaf for a specific challenger, authorising that challenger to claim the vault funds without a payout transaction.

**Requires:** `INTENT_LOADED` state; no wallet policy; exactly 3 inputs and 1 output.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 3 |
| Output count | Exactly 1 |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | 68 bytes: `<D>(32B) OP_CHECKSIGVERIFY <Cj>(32B) OP_CHECKSIG` |
| `<D>` key | Must match `intent.depositor_pk` |
| `<Cj>` key | Must be one of the keeper or challenger keys from the loaded intent |
| Full leaf | Reconstructed from intent and compared byte-for-byte (prevents parameter substitution) |
| Input 0 WITNESS_UTXO value | In `[VAULT_DUST_LIMIT, VAULT_DUST_LIMIT + base_fee_rate × MAX_COUNCIL_NOPAYOUT_VSIZE]` — Assert:0 is funded to cover the CouncilNoPayout that may spend it instead, so its value scales with the fee rate. Defence-in-depth only; the fee bound below is the operative control |
| Inputs 1, 2 WITNESS_UTXO value | **Not constrained individually.** Read from the PSBT and used only to compute `actual_fee`. Committed by Input 0's `SIGHASH_DEFAULT`, so no trust is placed in them: a misstated value produces an unusable signature (DoS only). These connectors are funded to cover the WronglyChallenged transaction that may spend them, so their value scales with `base_fee_rate` and exceeds `VAULT_DUST_LIMIT` above 1 sat/vB — the device deliberately does not re-derive that funding formula |
| Fee bound | `actual_fee = Σ inputs − Σ outputs`; must be non-negative and `≤ base_fee_rate × MAX_NOPAYOUT_VSIZE` (450, checked arithmetic). This is the control that prevents the Assert:0 connector being burned to miner fees, and it must not be replaced by tightening the input ranges |
| Sighash | `SIGHASH_DEFAULT` only |
| Output 0 | P2TR of `Cj` (key-path tweak, no scripts); verified by device; value ≥ `VAULT_DUST_LIMIT` |
| Counter | At most `vault_count × (keeper_count + challenger_count)` NoPayout signings allowed per session |

**NoPayout leaf script:**
`<D> OP_CHECKSIGVERIFY <Cj> OP_CHECKSIG`

**User display:** none (silent signing).

---

### 6. Claim (standalone)

The depositor spends the Depositor Claim UTXO created by the PegIn transaction.

**Requires:** any state (including `IDLE`); no wallet policy; 34-byte leaf `<D> OP_CHECKSIG` with exactly 2 outputs. The same leaf with exactly 1 output is Reclaim (below) instead; any other output count matches neither pattern and is rejected.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Output count | Exactly 2 |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | 34 bytes: `<D>(32B) OP_CHECKSIG` |
| Internal key | NUMS (single-leaf P2TR) |
| `<D>` key | Verified via `TAP_BIP32_DERIVATION`; BIP-86 path (`m/86'/coin_type'/acct'/chg/idx`, `account_index ≤ 100`, `address_index ≤ 10000`); derived key must match leaf key |
| Taproot commitment | Control block must produce a valid commitment to the leaf |
| Sighash | `SIGHASH_DEFAULT` only |
| Output 0 | ClaimAssertConnector. Its script is **not reconstructed** by the device — the WOTS connector tree is outside the device's model — but it is not unconstrained either: the read requires exactly `VAULT_P2TR_SCRIPTPUBKEY_LEN` (34 B), so Output 0 must be a witness-v1 P2TR (a P2WPKH or legacy substitution is rejected), and the script is rendered as a bech32m address on the review screen for the user to check. Substitution by another P2TR remains possible and is visible, not silent |
| Output 1 | BIP-86 P2TR(`<D>`); value = `VAULT_DUST_LIMIT` (CPFP anchor) |
| Fee | `input_value − total_outputs > 0` (positive fee required) |

**Depositor Claim leaf script:**
`<D> OP_CHECKSIG`

**User display:** amount spent (input UTXO value), connector amount (Output 0 value), fee, PegIn txid (from `PSBT_IN_PREVIOUS_TXID`), Output 0 address (bech32m).

---

### 7. Assert (standalone)

The depositor asserts the claim by spending a ClaimAssertConnector UTXO.

**Requires:** `INTENT_LOADED`; no wallet policy; Assert leaf whose signer prefix matches the approved intent (see the leaf script below).

> Assert is the one standalone flow that is **not** state-independent. The keys its leaf must be checked against — the VaultKeepers and UniversalChallengers — exist nowhere but the approved intent, so outside `INTENT_LOADED` the device cannot distinguish a genuine Assert leaf from a hand-crafted one and refuses to sign. Shape bytes cannot substitute: the ~11 KB WOTS body is host-chosen and cannot be derived on-device, so an attacker pads around any fixed offsets the device checks. See the leaf script below.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Output count | Not enforced (host-provided connector tree) |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | Total length strictly greater than the NoPayout leaf (68 bytes); `OP_CHECKSIGVERIFY` at byte 33; `OP_PUSHBYTES_32` at byte 34 and `OP_CHECKSIG` at byte 67 (`VAULT_LEAF_GROUP0_*`, within the 68-byte captured prefix); last byte `OP_TRUE`. Shape only — separates the Assert leaf from the app's other leaves, and nothing more |
| Input 0 signer prefix | Compared byte for byte, while the leaf streams, against a reconstruction from the approved intent: `<intent.depositor_pk> OP_CHECKSIGVERIFY` + VaultKeepers N-of-N + UniversalChallengers M-of-M. 106 bytes at 1/1, 2,216 at the 32/32 maximum. A mismatch is rejected outright, never allowed to fall through to another pattern |
| `<D>` key (prefix) | Verified via `TAP_BIP32_DERIVATION` (BIP-86 path) **and** pinned to `intent.depositor_pk` by the signer-prefix comparison — an Assert for a device-owned key other than the approved depositor is rejected |
| Remainder | WOTS verifier body only; content not verified by device (host-chosen chain tips, not derivable). The two challenger multisig groups ARE verified, as part of the signer prefix |
| Taproot commitment | Verified unconditionally (binds the unvalidated remainder to the spent scriptPubKey) |
| Leaf size | Up to `VAULT_ASSERT_SCRIPT_MAX_LEN` (16384). A leaf that does not fit the read buffer (`VAULT_SCRIPT_MAX_LEN`, 2560) is hashed by streaming instead of being buffered; beyond 16384 it is rejected |
| Sighash | `SIGHASH_DEFAULT` only |
| Fee | `inputs_total − outputs_total ≥ 0` |

**Assert leaf script (btc-vault `claim_assert.rs`):**
```
<D> OP_CHECKSIGVERIFY                                          ┐
<VK_1> OP_CHECKSIG <VK_2..N> OP_CHECKSIGADD <N> OP_NUMEQUALVERIFY   │ signer prefix:
<UC_1> OP_CHECKSIG <UC_2..M> OP_CHECKSIGADD <M> OP_NUMEQUALVERIFY   ┘ verified vs. intent
OP_DEPTH <WOTS_witness_items> OP_EQUALVERIFY
[WOTS verifier body for 4 big blocks]
OP_TRUE
```
Both multisig groups are **intermediate** (`OP_NUMEQUALVERIFY`, not `OP_NUMEQUAL`), and the
VaultKeepers group comes first. The device depends on that ordering. It holds for the
depositor-as-claimer case, which is the only one it can sign: btc-vault's
`derive_full_challengers` (`transactions/claim.rs`) has a dedicated depositor branch yielding the
VaultKeepers alone, with the VaultProvider excluded. The general `{VP, VK_1..VK_N} \ {Claimer}`
rule is the VP/VK-claimer branch and does not apply here.

Because both groups are enforced by hard-failing opcodes, a leaf whose prefix matches the intent
cannot be spent without every keeper and challenger signature from that intent — whatever its body
contains. That is what makes the unverified WOTS body safe to sign over; the taproot commitment
alone only binds the leaf to the output being spent.

> **The binding is session-scoped.** Keeper and challenger keys arrive as host-supplied TLV and
> cannot be derived from the seed, so the device cannot recognise the intent the vault was actually
> funded under — only the one loaded now. An Assert is normally signed after a power cycle, so the
> host supplies a fresh intent and could substitute the challenger set. The user's review of the key
> list on Screen 2 is what prevents that, and is therefore load-bearing for Assert safety rather
> than informational.
>
> **That review can be skipped.** The key list is Screen 2's skippable second review (see
> [Screen 2](#screen-2--the-intent-review-is-only-partly-mandatory)), so this protection is
> contingent on the user not skipping it. Nano devices offer no skip affordance and always
> review it in full.

Real leaf size is **11,526–13,636 bytes** (11,662 for the 3 local / 3 universal challenger
configuration in `tests/vectors/depositor-as-claimer/assert.txt`). The body is fixed at compile
time by `BIG_BLOCK_DIGIT_COUNTS = [64, 64]` and `ASSERT_WOTS_NUM_STREAMS = 1`; only the signer
prefix varies with the challenger counts — and the signer prefix is exactly the part the device
reconstructs.

**Long-leaf handling (L-11).** A leaf larger than `VAULT_SCRIPT_MAX_LEN` cannot be buffered, so the
device does not try. It streams the PSBT value with `call_stream_merkleized_map_value` and folds it
into the BIP-341 TapLeaf hash incrementally, keeping only what it actually needs in constant memory:

| Kept | Source |
|---|---|
| TapLeaf hash | Folded chunk by chunk; `varint(script_len)` can be emitted first because the stream reports its length before any data |
| 68-byte prefix (`VAULT_LEAF_PREFIX_LEN`) | First chunk(s) — shape discriminator (reaches `VAULT_LEAF_GROUP0_OP_OFF`, byte 67) and the `<D>` key |
| Assert signer-prefix verdict (`assert_prefix_ok`) | Compared byte by byte against the intent as the chunks arrive, then discarded — up to 2,216 bytes, so the bytes themselves are never all resident. A single sticky flag is all that survives |
| Script length | The stream's length callback |
| Terminating byte | Last script byte, tracked across chunk boundaries |
| Leaf version | Final byte of the value; must equal `0xC0` |

`call_stream_preimage` hash-verifies the complete preimage exactly as the buffered path does, so a
streamed leaf is no less trustworthy than a buffered one. The taproot commitment is then verified
against the streamed hash — unconditionally, and identically to the buffered case.

These facts live in `G_leaf_meta`, outside the `G_scratch` union: every byte of the leaf state past
`leaf_script` aliases `leaf_check.actual_buf`, and `_detect_payout_claimer` rebuilds an expected leaf
there before the commitment check runs, which would otherwise destroy the hash.

Flows that compare a leaf byte-for-byte against a script they reconstruct (Refund, Claim, WC,
NoPayout, PayoutFinalize) require `G_leaf_meta.buffered` and reject when it is unset. Their leaves
are ≤2296 bytes by construction, so this is unreachable in practice; it exists so a future oversized
leaf can never be compared against a partial buffer.

Assert cannot take that route — its leaf never fits — so it compares **during** the stream instead:
`vault_assert_prefix_byte` yields the expected signer-prefix byte at any offset without
materialising the prefix, and the stream callback checks each script byte against it as it passes.
Same byte-for-byte guarantee over the prefix, in constant memory, with no dependency on
`buffered`.

> The device must never relax the taproot commitment check for large leaves instead: a host-chosen
> leaf length would then select whether verification runs at all.

**User display:** claim txid (from `PSBT_IN_PREVIOUS_TXID`), amount carried (WITNESS_UTXO value), fee.

---

### 8. Wrongly Challenged / WC (standalone)

The depositor reclaims funds from a wrongly-challenged vault by spending the ChallengeAssert output.

**Requires:** any state (including `IDLE`). Two dispatch paths:
- No wallet policy: leaf must be 73 bytes matching the WC shape.
- Wallet policy present, Input 0 external (not owned by this device): treated as WC regardless of leaf.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | ≥ 1 (Input 0 = WC UTXO; Inputs 1+ = optional BIP-86 wallet inputs for fees) |
| Output count | Exactly 1 |
| Version / locktime | ≥ 2 / 0 |
| Input 0 leaf shape | 73 bytes (see below) |
| `<D>` key | Verified via `TAP_BIP32_DERIVATION` in Input 0; BIP-86 path |
| `<output_label_hash>` | Read as-is from leaf bytes [40..71]; not verified against intent |
| Taproot commitment | Control block in Input 0 must produce a valid commitment |
| Sighash (Input 0) | `SIGHASH_DEFAULT` only |
| Output 0 | BIP-86 P2TR(`<D>`); value verified |
| Fee | `inputs_total − output_0_value ≥ 0` |

**WC leaf script (73 bytes):**
`<D> OP_CHECKSIGVERIFY OP_SIZE OP_PUSHBYTES_1 0x20 OP_EQUALVERIFY OP_SHA256 <output_label_hash>(32B) OP_EQUAL`

**User display:** amount reclaimed (Output 0 value), wallet inputs amount (sum of Inputs 1+ values), fee, depositor address (bech32m of BIP-86 P2TR(`<D>`)).

---

### 9. Reclaim (standalone)

Reclaim sweeps the depositor claim reserve (PegIn Output 1) back to the depositor once the
vault is redeemed and the reserve would otherwise be lost. It shares its leaf byte-for-byte
with Claim; the dispatcher tells them apart by output count alone.

**Consent, not validation.** The device cannot know whether PegIn Output 0 has been spent, so
it cannot establish that the sweep is safe — reclaiming early permanently kills the
depositor's self-claim path. The review screen carries that risk to the user; the device
guarantees only that the funds go to the depositor's own proven key.

**Requires:** any state (including `IDLE`); no wallet policy; 34-byte leaf `<D> OP_CHECKSIG`
with exactly 1 output. The same leaf with exactly 2 outputs is Claim instead; any other
output count matches neither pattern and is rejected.

**PSBT requirements:**

| Field | Rule |
|---|---|
| Input count | Exactly 1 |
| Output count | Exactly 1 |
| Version / locktime | ≥ 2 / 0 — the PegIn is deeply confirmed by reclaim time, so the TRUC constraints on PegIn do not apply |
| Input 0 leaf shape | 34 bytes: `<D>(32B) OP_CHECKSIG` — byte-identical to Claim's leaf |
| Internal key | NUMS (single-leaf P2TR) |
| `<D>` key | Verified via `TAP_BIP32_DERIVATION`; BIP-86 path; derived key must match leaf key |
| Control block | Exactly 33 bytes (depth 0): PegIn Output 1 is a single-leaf tree, so a sibling proves some other tree. Must produce a valid commitment to the leaf |
| Input 0 sequence | Exactly `0xFFFFFFFD` (unmasked equality); the field **must be present** — an absent `PSBT_IN_SEQUENCE` decodes as `0xFFFFFFFF`, which is not replaceable |
| Input 0 value | Plausibility only: `WITNESS_UTXO` value strictly above `VAULT_DUST_LIMIT`. `SIGHASH_DEFAULT` commits it, so a false value only yields an unusable signature (DoS, no fund redirection) |
| Output 0 | BIP-86 P2TR(`<D>`) — the depositor's own address, as in Claim, WC and PayoutFinalize. No `PSBT_OUT_TAP_BIP32_DERIVATION` is read: the host would choose the path and the device never shows it, so any other address of this device could sit where no wallet scans |
| Fee | `input_value − output_value > 0` (checked subtraction; rejects on underflow) |
| Prevout binding | **Not enforced** — without an intent the device cannot compute the expected PegIn txid. Displayed on the review screen for the user to check by eye |
| Sighash | `SIGHASH_DEFAULT` only |
| Signing cap | None — standalone flows are uncapped; Bitcoin consensus makes the spend a one-time event |

**Sequence policy note.** Reclaim is the first accepted pattern with an RBF sequence
(`0xFFFFFFFD`). Claim keeps `0xFFFFFFFF` (`SEQUENCE_FINAL`) for the very same leaf shape, per
the Babylon rule for graph transactions — both are correct for their own pattern, and neither
bound relaxes the other.

**Depositor Claim / Reclaim leaf script:**
`<D> OP_CHECKSIG`

**User display — Screen 9 (explicit approval, consent posture):**

| Row | Source |
|---|---|
| Amount reclaimed | Output 0 value |
| Transaction fee | Input 0 value − Output 0 value |
| Reclaim address | bech32m of Output 0 — the depositor's own address, BIP-86 P2TR(`<D>`) |
| PegIn txid | Input 0 prevout txid, display only (see *Prevout binding*). Shown in block-explorer byte order (the reverse of `PSBT_IN_PREVIOUS_TXID`), like every txid the app displays |

The rows are preceded by an intro page, titled "Reclaim reserve", that states the one risk
the device cannot rule out: *"Recover the reserve that protects your deposit. Continue only
if your vault is redeemed. This action removes the protection permanently."* The copy
weights that risk more heavily than the neutral Refund review on purpose — it is the only
mitigation for an early sweep. Approval signs Input 0; rejection returns `SW_DENY` and
nothing is signed. The exact wording is a product decision and may change without changing
the rows.

---

## Status Words

| SW     | Name                  | Meaning |
|--------|-----------------------|---------|
| `0x9000` | `SW_OK`             | Success |
| `0x6985` | `SW_DENY`           | User rejected on device |
| `0x6A80` | `SW_INCORRECT_DATA` | Invalid APDU data or validation failure |
| `0x6A86` | `SW_WRONG_P1P2`     | P1 or P2 not valid for this command |
| `0x6A87` | `SW_WRONG_DATA_LENGTH` | Lc not valid for this command |
| `0x6D00` | `SW_INS_NOT_SUPPORTED` | Unknown INS for CLA `0xE1` |
| `0x6E00` | `SW_CLA_NOT_SUPPORTED` | Unknown CLA |
| `0xB007` | `SW_BAD_STATE`      | Command not allowed in current session state |
| `0xB009` | `SW_BAD_CPFP_ANCHOR` | Depositor payout Output 1 scriptPubKey does not match BIP-86 P2TR(depositor) |
| `0xB00A` | `SW_CAP_EXCEEDED`    | Per-type signature cap exceeded; intent nullified. Caps per approved intent: Pre-PegIn=1, PegIn=`vault_count`, Payout=`vault_count×(N+2)`, NoPayout=`vault_count×(N+M)`. Assert is intent-bound but **uncapped and un-deduped** — it is the only intent-bound flow without a bound, and each Assert is user-reviewed on Screen 5 rather than signed silently. |
