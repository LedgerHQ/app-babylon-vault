"""
Parser / size-robustness tests over the real captured Babylon Vault vectors in
tests/vectors/ (sourced from the signet `sample_tx` capture — see
tests/vectors/README.txt for the full description of each artifact).

Goal: confirm that both the host-side PSBT/transaction parsers and the device's
sign_psbt front-end ingest real-world, full-size vectors — in particular the
multi-PSBT deposit batches (claimer_payout ×5, depositor_graph ×9, the latter
being the largest deposit-flow payload) — and return a *defined* result rather
than crashing, hanging, or mis-parsing.

These captures were produced with a DIFFERENT seed than the Speculos test
mnemonic (see conftest.py), so the device cannot own the depositor key nor hold
a matching vault context. We therefore assert a clean, defined rejection (a
known vault status word), NOT a successful signature: the point is robustness on
real-world input, not signing it.

The finalized raw transactions (refund / claim / assert / wrongly_challenged)
are not PSBTs and cannot be fed to sign_psbt — they are covered as host-side
format-reference parses only.

NOTE: this is a round-trip / clean-rejection check, NOT a memory-ceiling test.
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
    "deposit-flow/pre_pegin.txt",
    "deposit-flow/pegin.json",
    "deposit-flow/claimer_payout.json",
    "deposit-flow/depositor_graph.json",
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
    """The batch sizes encode the participant counts in the captured vault.

    claimer_payout = 1 (VP) + N_VaultKeepers; depositor_graph = 1 + (N_VK + N_UC).
    The capture is the README's 4 VK / 4 UC sample → 5 and 9 PSBTs respectively.
    Guards against a truncated/extended copy of the vectors.
    """
    assert len(_load_hexes("deposit-flow/pre_pegin.txt")) == 1
    assert len(_load_hexes("deposit-flow/pegin.json")) == 1
    assert len(_load_hexes("deposit-flow/claimer_payout.json")) == 5
    assert len(_load_hexes("deposit-flow/depositor_graph.json")) == 9


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
