"""
Parser / size-robustness tests over Babylon Vault vectors in tests/vectors/.

Two vector sets are covered by the foreign-seed tests:

  signet/    Captured from the real signet `sample_tx` run (4 VK / 4 UC).
             See tests/vectors/README.txt for the full description.
             Signet batches: claimer_payout ×5, depositor_graph ×9.

  generated/ Produced offline by `crates/ledger-vector-gen` (btc-vault repo)
             using deterministic dummy keys (1 VK / 1 UC).
             Generated batches: claimer_payout ×1, depositor_graph ×3.

Goal: confirm that both the host-side PSBT/transaction parsers and the device's
sign_psbt front-end ingest vectors of varying sizes and return a *defined* result
rather than crashing, hanging, or mis-parsing.

Both sets use a DIFFERENT seed from the Speculos test mnemonic (see conftest.py):
the signet capture uses a real signet seed; the generated vectors use
`dummy_pubkey_seeded(5)` as depositor. Neither can be signed by the test device.
We therefore assert a clean, defined rejection (a known vault status word), NOT
a successful signature.

A third vector set — generated-speculos/ — contains vectors produced by
`crates/ledger-vector-gen` under the Speculos test mnemonic.  Those vectors CAN
be signed by the test device, so the tests for them assert SW_OK.
See tests/vectors/generated-speculos/README.md for how to generate them.

The finalized raw transactions (refund / claim / assert / wrongly_challenged)
are not PSBTs and cannot be fed to sign_psbt — they are covered as host-side
format-reference parses only.

NOTE: this is a round-trip / clean-rejection check for the foreign-seed sets.
These captures use a foreign seed/context, so the device rejects at the vault
state guard before reaching the large-leaf reconstruction path. The buffer
ceiling (VAULT_SCRIPT_MAX_LEN) is exercised by
test_sign_psbt_validate.py::test_sign_psbt_pegin_max_participants, which loads a
matching 32-keeper / 32-challenger context so validation actually reconstructs
the ~2.3 KB HTLC Leaf 0.

Run:  pytest tests/test_sample_vectors.py -k flex
"""

from __future__ import annotations

import base64
import json
from io import BufferedReader, BytesIO
from pathlib import Path
from typing import List, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ledger_bitcoin import WalletPolicy
from ledger_bitcoin.psbt import PSBT
from ledger_bitcoin.tx import CTransaction
from ragger.error import ExceptionRAPDU

from .vault_client import (
    SW_BAD_STATE,
    SW_DENY,
    SW_INCORRECT_DATA,
    SW_WRONG_DATA_LENGTH,
    SW_WRONG_P1P2,
)

VECTORS_DIR = Path(__file__).parent.resolve() / "vectors"

# Device-signable PSBT vectors (BIP-174). .json holds a JSON array of PSBT hexes
# signed together in one signPsbts call; .txt holds a single PSBT hex.
PSBT_FILES = [
    # Signet captures (4 VK / 4 UC — foreign signet seed)
    "deposit-flow/pre_pegin.txt",
    "deposit-flow/pegin.json",
    "deposit-flow/claimer_payout.json",
    "deposit-flow/depositor_graph.json",
    # Generated vectors (1 VK / 1 UC — dummy_pubkey_seeded(5) depositor)
    "generated/deposit-flow/pre_pegin.txt",
    "generated/deposit-flow/pegin.json",
    "generated/deposit-flow/claimer_payout.json",
    "generated/deposit-flow/depositor_graph.json",
]

# Finalized raw transactions (format references only — cannot be signed).
RAW_TX_FILES = [
    "deposit-flow/refund.txt",
    "depositor-as-claimer/claim.txt",
    "depositor-as-claimer/assert.txt",
    "depositor-as-claimer/wrongly_challenged.txt",
]

# Status words that count as a clean, defined rejection of a vector the device
# can neither own nor contextualise. Any of these proves the firmware parsed the
# request and returned deterministically; a hang/crash would surface as a
# timeout or a different exception, and an unexpected SW fails the assertion.
KNOWN_REJECT_SWS = frozenset(
    {SW_DENY, SW_BAD_STATE, SW_INCORRECT_DATA, SW_WRONG_DATA_LENGTH, SW_WRONG_P1P2}
)


class _NoWalletPolicy(WalletPolicy):
    """WalletPolicy whose id is all-zero bytes.

    Sending wallet_id = b'\\x00' * 32 makes the firmware set
    has_no_wallet_policy = true, routing the PSBT through the vault's tapscript
    validation path (mirrors the helper in test_sign_psbt_validate.py).
    """

    @property
    def id(self) -> bytes:
        return b"\x00" * 32


def _load_hexes(rel: str) -> List[str]:
    """Return the list of hex strings in a vector file (1-element for .txt)."""
    path = VECTORS_DIR / rel
    if path.suffix == ".json":
        return [h.strip() for h in json.loads(path.read_text())]
    # .txt: a single hex blob, possibly with surrounding/line-wrap whitespace.
    return ["".join(path.read_text().split())]


def _psbt_from_hex(psbt_hex: str) -> PSBT:
    """Deserialize a raw PSBT hex (PSBT.deserialize expects base64)."""
    psbt = PSBT()
    psbt.deserialize(base64.b64encode(bytes.fromhex(psbt_hex)).decode())
    return psbt


def _tx_from_hex(tx_hex: str) -> CTransaction:
    tx = CTransaction()
    tx.deserialize(BufferedReader(BytesIO(bytes.fromhex(tx_hex))))
    return tx


def _enumerate_psbts() -> List[Tuple[str, int, str]]:
    """Flatten every PSBT vector into (file, index_in_file, hex) tuples."""
    out: List[Tuple[str, int, str]] = []
    for rel in PSBT_FILES:
        for idx, psbt_hex in enumerate(_load_hexes(rel)):
            out.append((rel, idx, psbt_hex))
    return out


PSBT_VECTORS = _enumerate_psbts()
PSBT_IDS = [f"{rel}#{idx}" for rel, idx, _ in PSBT_VECTORS]


# ===========================================================================
# Host-side parse coverage (deterministic; no device needed)
# ===========================================================================

@pytest.mark.parametrize("rel,idx,psbt_hex", PSBT_VECTORS, ids=PSBT_IDS)
def test_sample_psbt_parses(rel: str, idx: int, psbt_hex: str) -> None:
    """Every captured PSBT deserializes fully and is self-contained.

    Walking all of PSBT.deserialize exercises the global tx plus every input and
    output map, including the large depositor_graph / claimer_payout batches.
    The README guarantees each input carries a witness_utxo (taproot script-path
    spends, no nonWitnessUtxo) — assert that holds.
    """
    psbt = _psbt_from_hex(psbt_hex)

    assert len(psbt.tx.vin) >= 1
    assert len(psbt.tx.vout) >= 1
    assert len(psbt.inputs) == len(psbt.tx.vin)
    assert len(psbt.outputs) == len(psbt.tx.vout)
    for pin in psbt.inputs:
        assert pin.witness_utxo is not None, "expected a witness_utxo on every input"


def test_sample_batch_counts() -> None:
    """The batch sizes encode the participant counts in each captured vault.

    claimer_payout = 1 (VP) + N_VaultKeepers; depositor_graph = 1 (payout)
    + N_local_challengers + N_universal_challengers (one NoPayout per challenger).
    Guards against truncated/extended copies of the vector files.

    Signet captures:  4 VK / 4 UC → claimer_payout ×5, depositor_graph ×9.
    Generated vectors: 1 VK / 1 UC → claimer_payout ×1, depositor_graph ×3.
    """
    assert len(_load_hexes("deposit-flow/pre_pegin.txt")) == 1
    assert len(_load_hexes("deposit-flow/pegin.json")) == 1
    assert len(_load_hexes("deposit-flow/claimer_payout.json")) == 5
    assert len(_load_hexes("deposit-flow/depositor_graph.json")) == 9

    assert len(_load_hexes("generated/deposit-flow/pre_pegin.txt")) == 1
    assert len(_load_hexes("generated/deposit-flow/pegin.json")) == 1
    assert len(_load_hexes("generated/deposit-flow/claimer_payout.json")) == 1
    assert len(_load_hexes("generated/deposit-flow/depositor_graph.json")) == 3


@pytest.mark.parametrize("rel", RAW_TX_FILES)
def test_sample_raw_tx_parses(rel: str) -> None:
    """Each finalized raw-tx reference deserializes and carries its witness."""
    tx = _tx_from_hex(_load_hexes(rel)[0])

    assert len(tx.vin) >= 1
    assert len(tx.vout) >= 1
    assert not tx.wit.is_null(), "finalized tx should carry a witness"


# ===========================================================================
# Device ingest robustness (Speculos)
# ===========================================================================

@pytest.mark.parametrize("rel,idx,psbt_hex", PSBT_VECTORS, ids=PSBT_IDS)
def test_device_ingests_sample_psbt(
    client: "RaggerClient", rel: str, idx: int, psbt_hex: str
) -> None:
    """The device front-end ingests each real PSBT and rejects it cleanly.

    The capture's depositor key and vault context don't exist on the test seed,
    so the firmware can't sign — it must return a defined vault status word
    instead of crashing or hanging. Routed through the vault path via the
    all-zero wallet id (_NoWalletPolicy).
    """
    psbt = _psbt_from_hex(psbt_hex)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)

    assert exc.value.status in KNOWN_REJECT_SWS, (
        f"{rel}#{idx}: unexpected status word {exc.value.status:#06x}"
    )


# ===========================================================================
# Speculos-signable vector tests (generated-speculos/)
#
# This section is ready for when tests/vectors/generated-speculos/ is
# populated by running `crates/ledger-vector-gen` under the Speculos test
# mnemonic.  See tests/vectors/generated-speculos/README.md for instructions.
#
# Contract: when the directory contains deposit-flow/pegin.json AND a
# companion metadata.json with the vault intent parameters, the test below
# asserts SW_OK (the device can sign these vectors).  Until the directory is
# populated the test is skipped automatically.
#
# metadata.json schema (flat object, all fields required):
#   {
#     "coin_type": 1,
#     "base_fee_rate": 1,
#     "pegin_csv_timelock": 144,
#     "payout_timelock": 200,
#     "htlc_refund_timelock": 144,
#     "prepegin_txid_hex": "<64 hex chars>",
#     "keeper_pks_hex": ["<64 hex>", ...],
#     "challenger_pks_hex": ["<64 hex>", ...],
#     "groups": [
#       {
#         "htlc_vout": 0,
#         "vault_provider_pk_hex": "<64 hex>",
#         "vault_amount": 9876543,
#         "commission_fee": 54321,
#         "depositor_claim_value": 12345,
#         "pegin_max_fee": 567891
#       }
#     ]
#   }
# ===========================================================================

_SPECULOS_VECTORS_DIR = VECTORS_DIR / "generated-speculos"
_SPECULOS_PEGIN_FILE = _SPECULOS_VECTORS_DIR / "deposit-flow" / "pegin.json"
_SPECULOS_METADATA_FILE = _SPECULOS_VECTORS_DIR / "metadata.json"

_speculos_vectors_available = _SPECULOS_PEGIN_FILE.exists() and _SPECULOS_METADATA_FILE.exists()


def _load_speculos_metadata() -> dict:
    """Return the parsed metadata.json for the speculos vector set."""
    import json as _json
    return _json.loads(_SPECULOS_METADATA_FILE.read_text())


@pytest.mark.skipif(
    not _speculos_vectors_available,
    reason=(
        "tests/vectors/generated-speculos/ not populated — "
        "see tests/vectors/generated-speculos/README.md to generate"
    ),
)
def test_device_signs_speculos_pegin(
    client: "RaggerClient",
) -> None:
    """The device signs the Speculos-mnemonic PegIn vector and returns SW_OK.

    Asserts a valid 64-byte SIGHASH_DEFAULT Schnorr signature — NOT a rejection.
    This is the positive counterpart to test_device_ingests_sample_psbt: it proves
    that when the depositor key matches the test device's derived key, the firmware
    validates and signs the transaction rather than rejecting it.

    Prerequisite: populate tests/vectors/generated-speculos/ by running
    crates/ledger-vector-gen with the Speculos test mnemonic (see README.md).
    The companion metadata.json must be present to provide vault intent parameters.
    """
    from .vault_client import (
        approve_vault_intent,
        build_intent_tlv,
        build_group_tlv,
        derive_context_hash,
        vault_hashlock,
        VAULT_APP_NAME,
        depositor_path,
        HARDENED,
    )

    meta = _load_speculos_metadata()
    coin_type = meta["coin_type"]
    keeper_pks = [bytes.fromhex(k) for k in meta["keeper_pks_hex"]]
    challenger_pks = [bytes.fromhex(k) for k in meta["challenger_pks_hex"]]
    prepegin_txid = bytes.fromhex(meta["prepegin_txid_hex"])

    # Derive the vault root (silent re-derivation — no screen shown).
    from .vault_client import P2_SILENT
    root = derive_context_hash(
        client, VAULT_APP_NAME, depositor_path(coin_type),
        b"speculos-vector-gen",  # fixed context matching the generator's input
        navigator=None, device=None, p2=P2_SILENT,
    )

    # Build and send the intent.
    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=meta["base_fee_rate"],
        pegin_csv_timelock=meta["pegin_csv_timelock"],
        payout_timelock=meta["payout_timelock"],
        prepegin_txid=prepegin_txid,
        htlc_refund_timelock=meta["htlc_refund_timelock"],
        depositor_path=depositor_path(coin_type),
        keeper_count=len(keeper_pks),
        challenger_count=len(challenger_pks),
        vault_count=len(meta["groups"]),
    )
    groups_tlv = [
        build_group_tlv(
            htlc_vout=g["htlc_vout"],
            vault_provider_pk=bytes.fromhex(g["vault_provider_pk_hex"]),
            vault_amount=g["vault_amount"],
            commission_fee=g["commission_fee"],
            depositor_claim_value=g["depositor_claim_value"],
            pegin_max_fee=g["pegin_max_fee"],
        )
        for g in meta["groups"]
    ]
    approve_vault_intent(client, scalars_tlv, keeper_pks, challenger_pks, groups=groups_tlv)

    # Load and sign each PegIn PSBT — expect SW_OK and a 64-byte signature.
    psbt_hexes = _load_hexes("generated-speculos/deposit-flow/pegin.json")
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    for idx, psbt_hex in enumerate(psbt_hexes):
        psbt = _psbt_from_hex(psbt_hex)
        result = client.sign_psbt(psbt, dummy_wallet, None)
        assert len(result) == 1, (
            f"pegin[{idx}]: expected exactly 1 signature, got {len(result)}"
        )
        _input_index, partial_sig = result[0]
        assert len(partial_sig.signature) == 64, (
            f"pegin[{idx}]: expected 64-byte SIGHASH_DEFAULT Schnorr sig, "
            f"got {len(partial_sig.signature)}"
        )
