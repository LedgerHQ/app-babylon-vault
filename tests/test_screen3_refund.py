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

from .vault_client import SW_DENY, sign_psbt_with_nav_and_compare
from .instructions import sign_psbt_refund_instructions, sign_psbt_refund_nav
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
    shown.  The test navigates through every page and then rejects, expecting
    SW_DENY.  Run once with --golden_run to create the reference images.
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

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, dummy_wallet, None, navigator,
                             testname=tname, instructions=sign_psbt_refund_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                           testname=tname, nav_instructions=sign_psbt_refund_nav(device))
    assert exc.value.status == SW_DENY
