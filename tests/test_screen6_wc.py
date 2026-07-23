"""Screen 6 — WC (Wrongly Challenged): golden-snapshot tests for the WC display.

The Wrongly Challenged flow is a standalone SIGN_PSBT flow: a wrongly
challenged depositor reclaims funds via a tapscript spend.  The device shows
the reclaimed amount and transaction fee before the user approves.

Snapshots are stored under:
    tests/snapshots/<device>/screen6_wc/<test_case>_<network>/

Run with --golden_run to regenerate reference snapshots:

    pytest tests/test_screen6_wc.py --golden_run -k flex
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

from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness

from test_utils.taproot import taproot_tweak_pubkey

from .vault_client import SW_DENY, sign_psbt_with_nav_and_compare
from .instructions import sign_psbt_wc_instructions, sign_psbt_wc_nav
from .test_sign_psbt_validate import (
    _NoWalletPolicy,
    _bip86_p2tr_spk,
    _tapleaf_hash,
    HARDENED,
    VAULT_NUMS_XONLY,
)

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

# Arbitrary 32-byte output_label_hash embedded in the WC leaf.
_OUTPUT_LABEL_HASH = bytes([0xCC] * 32)


def _build_wc_leaf(leaf_key: bytes) -> bytes:
    """Assemble the 73-byte WC tapscript leaf.

    Layout (from firmware source):
        0x20 D(32B) 0xAD 0x82 0x01 0x20 0x88 0xA8 0x20 hash(32B) 0x87
    Dispatched when leaf[34] == OP_SIZE (0x82).
    """
    wc_leaf = (
        bytes([0x20]) + leaf_key          # OP_PUSHBYTES_32  D
        + bytes([0xAD])                    # OP_CHECKSIGVERIFY
        + bytes([0x82])                    # OP_SIZE
        + bytes([0x01, 0x20])              # OP_PUSHBYTES_1  32
        + bytes([0x88])                    # OP_EQUALVERIFY
        + bytes([0xA8])                    # OP_SHA256
        + bytes([0x20]) + _OUTPUT_LABEL_HASH  # OP_PUSHBYTES_32  hash
        + bytes([0x87])                    # OP_EQUAL
    )
    assert len(wc_leaf) == 73
    return wc_leaf


def _build_wc_psbt(
    fingerprint: bytes,
    leaf_key: bytes,
    coin_type: int,
    input_value: int = 5_000_000,
    out_value: int = 4_900_000,
) -> PSBT:
    """Build a WC PSBTv0 for Screen 6.

    Input 0: WronglyChallenge UTXO — 73-byte WC leaf, single-leaf P2TR with
             NUMS internal key.  The taproot commitment IS verified by the device.
             D is verified via TAP_BIP32_DERIVATION.
    Output 0: BIP-86 P2TR(D) — verified by the device.
    """
    wc_leaf = _build_wc_leaf(leaf_key)
    leaf_hash = _tapleaf_hash(wc_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    wc_spk = bytes([0x51, 0x20]) + tweaked
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    out0_spk = _bip86_p2tr_spk(leaf_key)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xef' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [CTxOut(out_value, out0_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(input_value, wc_spk)
    psbt.inputs[0].tap_scripts[(wc_leaf, 0xC0)] = {control_block}
    psbt.inputs[0].tap_bip32_paths[leaf_key] = (
        {leaf_hash},
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
    )

    return psbt


def test_sign_psbt_wc_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Show Screen 6 (WC) and capture all review pages as golden snapshots.

    Sends a valid WC PSBT to the device.  Validation passes and the review
    screen is shown.  The test navigates through every page and then rejects,
    expecting SW_DENY.  Run once with --golden_run to create the reference images.
    """
    coin_type = 0 if bitcoin_network == "main" else 1

    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]

    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen6_wc/screen_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, dummy_wallet, None, navigator,
                             testname=tname, instructions=sign_psbt_wc_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                           testname=tname, nav_instructions=sign_psbt_wc_nav(device))
    assert exc.value.status == SW_DENY
