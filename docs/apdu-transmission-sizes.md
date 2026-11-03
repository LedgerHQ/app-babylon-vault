# Babylon Vault — APDU Transmission Sizes

How much data crosses the APDU interface during a deposit, and in how many
round-trips. Companion to [`apdu.md`](apdu.md) (which defines the wire formats);
this doc focuses on **volume and scaling**, driven by participant counts.

All numbers below are for the **PegIn step** of a deposit (the heaviest single
transaction the depositor signs). Sizes are computed analytically from the TLV
field layout in [`apdu.md`](apdu.md) and the PSBT structure; figures are payload
bytes unless noted (APDU header = 5 B, trailing `SW` = 2 B per exchange).

> **Key takeaway:** a deposit transmits a few KB across **dozens of small
> APDUs**, but the device never holds it all at once. The device **signs inputs —
> it does not build, hold, or broadcast the whole transaction**, so the on-chain
> tx size (which can reach ~1 MB on the BitVM / Assert path) is decoupled from
> what the device actually receives. The two phases use completely different
> transmission models, and total bytes-on-the-wire is **not** the same as peak
> device RAM. See [What reaches the device](#what-reaches-the-device--and-what-does-not)
> and [Transmitted ≠ resident](#transmitted--resident).

---

## Two transmission models

| Phase | INS | Model | Who drives |
|-------|-----|-------|------------|
| 1. Load the vault | `0x80` `APPROVE_VAULT_INTENT` | **Direct push** — host streams the payload in fixed chunks | Host |
| 2. Sign the PegIn | `SIGN_PSBT` (bitcoin app) | **Interactive pull** — host sends only Merkle roots; the device requests each element on demand | Device |

The distinction matters: in Phase 1 transmitted ≈ payload. In Phase 2 the PSBT is
**never sent as one blob** — the device pulls fields via the client-command loop
(each request returns `SW=0xE000`, the host answers with the next APDU), so total
bytes = PSBT content pulled **+ Merkle-proof overhead + per-round-trip framing**.

---

## What reaches the device — and what does not

The device **signs inputs; it does not build, finalize, or broadcast
transactions**. The host (dApp + Ledger bitcoin SDK) constructs the full tx and
*all* witness data, drives the device for signature(s), then stitches them in and
broadcasts. So the bytes that cross the APDU interface are only what the device
needs to compute a sighash — never the finished transaction.

| Transmitted **to** the device | **Not** transmitted (host-only) |
|---|---|
| Unsigned tx skeleton: input outpoints, sequences, version, locktime | Input **witness** data of any input (including its own) |
| Each input's `witness_utxo` = amount (8 B) + scriptPubKey (~34 B P2TR) | **WOTS reveals** / BitVM execution-trace commitments |
| The **one tapleaf script** + control block for the input being signed | Large BitVM disprove / verifier scripts not being signed |
| All **outputs** (amount + scriptPubKey) | Finalized `FINAL_SCRIPTWITNESS`, assembled signatures |
| Taproot internal key / Merkle root for the signed input | Other parties' signatures |

Why the split is safe: a BIP-341 sighash commits to the tx's **prevouts,
amounts, scriptPubKeys, sequences, and outputs** — all KB-scale — plus the single
tapleaf hash. It does **not** commit to witness data. The megabyte-class material
in a Babylon Vault graph lives entirely in the witness, so it is irrelevant to any
signature and is appended by the host *after* the device responds.

### Large transactions (Claim / Assert / BitVM path)

On-chain, an **Assert** transaction can be very large — potentially approaching
~1 MB — because it reveals **WOTS (Winternitz) commitments** to the SNARK-verifier
execution trace, plus large BitVM scripts. This scales with the *proof circuit*,
not with keeper/challenger counts, so it is unrelated to the deposit PSBT sizes
tabled below (and dwarfs the ~16 KB sample Assert in `tests/vectors/`).

**That size never reaches the device.** When the device signs an Assert (the
depositor-as-claimer path), it produces **one ~64-byte Schnorr** over a small
connector tapleaf; the WOTS data is software-derived and lives in the witness. For
a 1 MB on-chain Assert the device still ingests only KB (tx skeleton +
`witness_utxo`s + the one leaf) and returns 64 bytes. The host assembles the
megabyte.

**Caveat — a host design requirement, not a device limit:** this holds only if the
host sends a **minimal signing PSBT** (sighash essentials only). If the host were
to include finalized / WOTS witness data in the PSBT handed to the device, the
merkleized pull would be forced to stream past ~1 MB it does not need. The fix is
host-side: strip the witness from the signing PSBT.

---

## Phase 1 — `APPROVE_VAULT_INTENT` (direct push)

Two sub-phases: one P1=0x00 APDU with the 17 scalar fields, then P1=0x01 key
batches of **≤ 7 keys (224 B)** each — the batch size exists because the APDU
data field caps at 255 B.

| Part | Size | Notes |
|------|------|-------|
| Scalar TLV (17 fields) | **179 B** | 1 APDU, P1=0x00. Fixed — independent of participant count. |
| Public keys | **(N + M) × 32 B** | N keepers + M challengers, P1=0x01. |
| Key APDUs | **⌈(N + M) / 7⌉** | 7 keys = 224 B per APDU. |

Worst case (32 keepers / 32 challengers): 179 + 2048 = **2227 B** across **11
APDUs** (1 scalar + 10 key batches).

---

## Phase 2 — `SIGN_PSBT` (interactive pull)

The serialized PegIn PSBT content is the **floor** of what the device pulls. It is
dominated by **HTLC Leaf 0**, which embeds depositor + VP + every keeper + every
challenger (~34 B/key), so it scales linearly with `N + M`.

PegIn PSBT content breakdown (32/32 case):

| Element | Size | Notes |
|---------|------|-------|
| PSBT magic | 5 B | `70736274ff` |
| Global unsigned tx | ~140 B | 1 input, 2 outputs, version/locktime |
| Input: `WITNESS_UTXO` | 45 B | value (8) + P2TR spk (34) + framing |
| Input: `TAP_INTERNAL_KEY` | 34 B | NUMS x-only key |
| Input: `TAP_MERKLE_ROOT` | 34 B | |
| Input: `TAP_LEAF_SCRIPT` | **~2329 B** | control block (33) + **Leaf 0 (2289 B)** + leaf version |
| Outputs (×2) | 2 B | empty maps (separators only) |
| **Total PSBT content** | **~2589 B** | the floor of bytes pulled |

Leaf 0 alone (2289 B) is returned in **~9 preimage chunks** (≤ 255 B each), i.e.
~9 round-trips just for that one field. On top of the content:

- **Merkle-proof overhead**: a few hundred bytes (sibling hashes). Small here —
  the input/output maps have only a handful of keys.
- **Framing**: 5 B header + 2 B `SW` per exchange, across ~30–50 exchanges.

---

## Scaling by vault size

| Vault (keepers / challengers) | HTLC Leaf 0 | Phase 1 payload | Phase 1 APDUs | Phase 2 PSBT content | Leaf 0 chunks |
|---|---|---|---|---|---|
| 1 / 1 (minimum) | 175 B | 243 B | 2 | ~473 B | 1 |
| 4 / 4 (sample capture) | 383 B | 435 B | 3 | ~683 B | 2 |
| **32 / 32 (firmware max)** | **2289 B** | **2227 B** | **11** | **~2589 B** | **9** |

**Whole 32/32 PegIn step over the wire:** ~2227 B (approve) + ~2589 B (sign
content) + Merkle/framing overhead ≈ **~5 KB**, in dozens of APDUs.

Caps come from `VAULT_MAX_KEEPERS` / `VAULT_MAX_CHALLENGERS` = 32 each
(`src/vault_intent.h`). Leaf 0 at 32/32 is 2289 B, ~89 % of the
`VAULT_SCRIPT_MAX_LEN` = 2560 B device buffer (`src/vault_script.h`).

---

## Transmitted ≠ resident

The ~5 KB is **cumulative wire volume across many small APDUs**, not a single
transfer and not the device's memory footprint. Because Phase 2 is a pull loop,
the device only ever holds **one element at a time**. The largest thing it
assembles is the **2289 B Leaf 0** into its 2560 B buffer; everything else
(`WITNESS_UTXO` 43 B, a key 32 B, an output 43 B) is far smaller.

So transmission is large-ish and chatty, but peak RAM is bounded by that one
buffer — which is what
`tests/test_sign_psbt_validate.py::test_sign_psbt_pegin_max_participants`
exercises at the 32/32 maximum.

---

## Notes

- Figures are analytical (TLV layout + PSBT structure), validated against the
  helper builders in `tests/test_sign_psbt_validate.py`. For the **exact** APDU
  count and byte total on a given build, instrument the ragger backend's
  `exchange` on Speculos and log each call.
- The captured sample vectors in `tests/vectors/` are a *different* concern: they
  test parser round-trip / clean rejection, and reject at the state guard before
  the large-leaf pull — they do not represent a full deposit's transmission.
