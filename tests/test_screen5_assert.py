"""Screen 5 — Assert: golden-snapshot tests for the Assert display.

The Assert transaction is a standalone SIGN_PSBT flow where the depositor
asserts a claim by spending a ChallengeAssert UTXO.  The device shows the
claim txid, amount, and transaction fee before the user approves.

Snapshots are stored under:
    tests/snapshots/<device>/screen5_assert/<test_case>_<network>/

Run with --golden_run to regenerate reference snapshots:

    pytest tests/test_screen5_assert.py --golden_run -k flex
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
from .instructions import sign_psbt_assert_instructions, sign_psbt_assert_nav
from .test_sign_psbt_validate import (
    _NoWalletPolicy,
    _tapleaf_hash,
    HARDENED,
    VAULT_NUMS_XONLY,
    VAULT_DUST_LIMIT,
)

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

# Arbitrary 32-byte claim txid used as the prevout of the ClaimAssertConnector input.
_FAKE_CLAIM_TXID = bytes(range(32))

# A fixed 32-byte xonly key for the second slot of the assert leaf (<key> OP_CSV).
_ASSERT_INNER_KEY = bytes([0x02] * 32)


def _build_assert_psbt(
    fingerprint: bytes,
    leaf_key: bytes,
    coin_type: int,
    claim_txid: bytes = _FAKE_CLAIM_TXID,
    amount_carried: int = 5_000_000,
    out_value: int = 4_990_000,
) -> PSBT:
    """Build an Assert PSBTv0 for Screen 5.

    The assert leaf shape is:
        <D>(33B) OP_CHECKSIGVERIFY <key>(33B) OP_CSV  — 68 bytes total.

    The device dispatches to Screen 5 when leaf[34] == OP_PUSHBYTES_32 and
    leaf[-1] == OP_CSV.  D is verified via TAP_BIP32_DERIVATION.

    WITNESS_UTXO is NOT taproot-verified for Assert (only its value is read).
    The claim txid comes from tx.vin[0].prevout.hash (PSBTv0).
    """
    assert len(claim_txid) == 32

    # Assert leaf: 0x20 D(32B) 0xAD 0x20 key(32B) 0xB2  — 68 bytes
    assert_leaf = (
        bytes([0x20]) + leaf_key
        + bytes([0xAD, 0x20]) + _ASSERT_INNER_KEY
        + bytes([0xB2])
    )
    assert len(assert_leaf) == 68

    leaf_hash = _tapleaf_hash(assert_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    assert_spk = bytes([0x51, 0x20]) + tweaked
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    dummy_out_spk = bytes([0x51, 0x20]) + bytes(32)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    # prevout.hash carries the claim txid (little-endian integer)
    tx.vin[0].prevout = COutPoint(int.from_bytes(claim_txid, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [CTxOut(out_value, dummy_out_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]

    # WITNESS_UTXO value is read as amount_carried; SPK is not taproot-verified.
    psbt.inputs[0].witness_utxo = CTxOut(amount_carried, assert_spk)
    psbt.inputs[0].tap_scripts[(assert_leaf, 0xC0)] = {control_block}
    psbt.inputs[0].tap_bip32_paths[leaf_key] = (
        {leaf_hash},
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
    )

    return psbt


def test_sign_psbt_assert_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Show Screen 5 (Assert) and capture all review pages as golden snapshots.

    Sends a valid Assert PSBT to the device.  Validation passes and the review
    screen is shown.  The test navigates through every page and then rejects,
    expecting SW_DENY.  Run once with --golden_run to create the reference images.
    """
    coin_type = 0 if bitcoin_network == "main" else 1

    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]

    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen5_assert/screen_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, dummy_wallet, None, navigator,
                             testname=tname, instructions=sign_psbt_assert_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                           testname=tname, nav_instructions=sign_psbt_assert_nav(device))
    assert exc.value.status == SW_DENY
