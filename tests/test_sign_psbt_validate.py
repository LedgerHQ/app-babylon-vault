"""
Snapshot tests for sign_psbt validation screens added in NAPPS-1375.

Screen 3 — Refund transaction review: a pure tapscript spend (has_no_wallet_policy=true)
that shows "Reclaimed amount" and "Transaction fee" fields.

Run with --golden_run to generate reference snapshots:

    pytest tests/test_sign_psbt_validate.py --golden_run -k flex
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ragger.error import ExceptionRAPDU
from ragger.firmware import Firmware
from ragger.navigator import Navigator

from ledger_bitcoin import WalletPolicy
from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness

from test_utils.taproot import tagged_hash, taproot_tweak_pubkey, ser_script

from .vault_client import SW_DENY
from .instructions import sign_psbt_refund_instructions

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

HARDENED = 0x80000000
VAULT_NUMS_XONLY = bytes.fromhex(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
)


def _encode_script_num(n: int) -> bytes:
    """Return minimal Bitcoin Script push encoding for positive integer n."""
    if n == 0:
        return bytes([0x00])
    if 1 <= n <= 16:
        return bytes([0x51 + n - 1])
    data: List[int] = []
    v = n
    while v:
        data.append(v & 0xFF)
        v >>= 8
    if data[-1] & 0x80:
        data.append(0x00)
    return bytes([len(data)] + data)


class _NoWalletPolicy(WalletPolicy):
    """WalletPolicy subclass whose id is all-zero bytes.

    Sending wallet_id = b'\\x00' * 32 in the SIGN_PSBT APDU makes the firmware
    set has_no_wallet_policy = true, which routes the transaction through the
    vault's tapscript validation path (Refund / PegIn).
    """
    @property
    def id(self) -> bytes:
        return b'\x00' * 32


def _build_refund_psbt(
    fingerprint: bytes,
    leaf_key: bytes,
    out_key: bytes,
    coin_type: int,
    htlc_value: int = 1_000_000,
    reclaimed_value: int = 990_000,
    csv_timelock: int = 144,
) -> PSBT:
    """Build a minimal PSBTv0 for a Refund transaction.

    Input 0: spends the HTLC output (P2TR via refund leaf script).
    Output 0: reclaimed amount back to a BIP-86 P2TR output.
    """
    csv_push = _encode_script_num(csv_timelock)
    leaf_script = bytes([0x20]) + leaf_key + bytes([0xAD]) + csv_push + bytes([0xB2])

    leaf_hash = tagged_hash("TapLeaf", bytes([0xC0]) + ser_script(leaf_script))
    parity, tweaked_key = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    htlc_spk = bytes([0x51, 0x20]) + tweaked_key
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    out_script = bytes([0x51, 0x20]) + out_key

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\x42' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0
    tx.vout = [CTxOut(reclaimed_value, out_script)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(htlc_value, htlc_spk)
    psbt.inputs[0].tap_scripts[(leaf_script, 0xC0)] = {control_block}
    psbt.inputs[0].tap_bip32_paths[leaf_key] = (
        {leaf_hash},
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
    )

    psbt.outputs[0].tap_bip32_paths[out_key] = (
        set(),
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 1]),
    )

    return psbt


def test_sign_psbt_refund_screen(
    client: "RaggerClient",
    navigator: Navigator,
    firmware: Firmware,
    bitcoin_network: str,
    test_name: str,
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

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(
            psbt,
            dummy_wallet,
            None,
            navigator,
            testname=test_name + "_" + bitcoin_network,
            instructions=sign_psbt_refund_instructions(firmware),
        )
    assert exc.value.status == SW_DENY
