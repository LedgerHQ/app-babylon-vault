"""Screen 3 — Refund: golden-snapshot tests for the Refund display.

Refund is a standalone SIGN_PSBT flow: the device shows the reclaimed amount
and transaction fee before the user approves or rejects.

Run with --golden_run to regenerate reference snapshots:

    pytest tests/test_screen3_refund.py --golden_run -k flex
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from ledger_bitcoin.key import ExtendedKey
from ledger_bitcoin.psbt import PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTxIn, CTxOut

from .vault_client import SW_INCORRECT_DATA, sign_psbt_with_nav_and_compare
from .instructions import sign_psbt_refund_approve_instructions, sign_psbt_refund_approve_nav
from .test_sign_psbt_validate import _build_refund_psbt, _NoWalletPolicy

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


def test_sign_psbt_refund_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Show Screen 3 (Refund) and capture all review pages as golden snapshots.

    Sends a valid Refund PSBT (1 input tapscript spend, 1 P2TR output with BIP-86
    derivation) to the device.  The validation passes and the review screen is
    shown.  The test navigates through every page and approves, ending on the
    "Transaction signed" status screen.  Run once with --golden_run to create the
    reference images.
    """
    coin_type = 0 if bitcoin_network == "main" else 1

    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen3_refund/screen_" + bitcoin_network

    if device.is_nano:
        client.sign_psbt(psbt, dummy_wallet, None, navigator,
                         testname=tname, instructions=sign_psbt_refund_approve_instructions(device))
    else:
        sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                       testname=tname, nav_instructions=sign_psbt_refund_approve_nav(device))


# ===========================================================================
# Screen 3 — Refund: error-path tests
# ===========================================================================

_REFUND_CSV_TIMELOCK = 144  # default csv_timelock in _build_refund_psbt


def _refund_keys(client: "RaggerClient", bitcoin_network: str):
    """Return (fingerprint, leaf_key, out_key, coin_type) for the standard Refund keys."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]
    return fingerprint, leaf_key, out_key, coin_type


def test_sign_psbt_refund_wrong_sighash(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when PSBT_IN_SIGHASH_TYPE is SIGHASH_ALL; only SIGHASH_DEFAULT accepted."""
    fingerprint, leaf_key, out_key, coin_type = _refund_keys(client, bitcoin_network)
    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.inputs[0].sighash = 1  # SIGHASH_ALL
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


@pytest.mark.parametrize("bad_seq", [_REFUND_CSV_TIMELOCK + 1, 0])
def test_sign_psbt_refund_wrong_nsequence(
    client: "RaggerClient",
    bitcoin_network: str,
    bad_seq: int,
) -> None:
    """Refund fails when nSequence is not exactly the leaf CSV timelock."""
    fingerprint, leaf_key, out_key, coin_type = _refund_keys(client, bitcoin_network)
    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.tx.vin[0].nSequence = bad_seq
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_extra_output(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when n_outputs != 1."""
    fingerprint, leaf_key, out_key, coin_type = _refund_keys(client, bitcoin_network)
    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.tx.vout.append(CTxOut(546, bytes([0x51, 0x20]) + bytes(32)))
    psbt.outputs.append(PartiallySignedOutput(0))
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_extra_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when n_inputs != 1."""
    fingerprint, leaf_key, out_key, coin_type = _refund_keys(client, bitcoin_network)
    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_wrong_tx_version(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when nVersion < 2."""
    fingerprint, leaf_key, out_key, coin_type = _refund_keys(client, bitcoin_network)
    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.tx.nVersion = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA
