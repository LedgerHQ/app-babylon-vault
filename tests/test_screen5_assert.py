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

from .vault_client import SW_INCORRECT_DATA, sign_psbt_with_nav_and_compare
from .instructions import sign_psbt_assert_approve_instructions, sign_psbt_assert_approve_nav
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
    screen is shown.  The test navigates through every page and approves, ending
    on the "Transaction signed" status screen.  Run once with --golden_run to
    create the reference images.
    """
    coin_type = 0 if bitcoin_network == "main" else 1

    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]

    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen5_assert/screen_" + bitcoin_network

    if device.is_nano:
        client.sign_psbt(psbt, dummy_wallet, None, navigator,
                         testname=tname, instructions=sign_psbt_assert_approve_instructions(device))
    else:
        sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                       testname=tname, nav_instructions=sign_psbt_assert_approve_nav(device))


# ===========================================================================
# Screen 5 — Assert: error-path tests
# ===========================================================================

def _assert_keys(client: "RaggerClient", bitcoin_network: str):
    """Return (fingerprint, leaf_key, coin_type) for the standard Assert key."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    return fingerprint, leaf_key, coin_type


def test_sign_psbt_assert_wrong_version(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when nVersion < 2."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.nVersion = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_nonzero_locktime(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when nLockTime != 0."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.nLockTime = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_sighash_all(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when PSBT_IN_SIGHASH_TYPE is SIGHASH_ALL; only DEFAULT accepted."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    psbt.inputs[0].sighash = 1  # SIGHASH_ALL
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_extra_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when n_inputs != 1."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_wrong_fingerprint(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when TAP_BIP32_DERIVATION fingerprint belongs to a foreign device."""
    _, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    wrong_fingerprint = b'\xff\xff\xff\xff'
    psbt = _build_assert_psbt(wrong_fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_non_bip86_path(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when the derivation path is not BIP-86 (m/44' instead of m/86')."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    assert_leaf = (
        bytes([0x20]) + leaf_key
        + bytes([0xAD, 0x20]) + _ASSERT_INNER_KEY
        + bytes([0xB2])
    )
    leaf_hash = _tapleaf_hash(assert_leaf)
    psbt.inputs[0].tap_bip32_paths = {
        leaf_key: (
            {leaf_hash},
            KeyOriginInfo(fingerprint, [HARDENED | 44, HARDENED | coin_type, HARDENED | 0, 0, 0]),
        )
    }
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_foreign_key(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when the leaf D key is not derived from this device's seed."""
    fingerprint, _, coin_type = _assert_keys(client, bitcoin_network)
    foreign_key = bytes([0xBB] * 32)
    psbt = _build_assert_psbt(fingerprint, foreign_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_tampered_control_block(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when the taproot control block internal key is not VAULT_NUMS_XONLY."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    (leaf_bytes, leaf_ver), _ = next(iter(psbt.inputs[0].tap_scripts.items()))
    wrong_cb = bytes([0xC0]) + bytes([0x01] * 32)
    psbt.inputs[0].tap_scripts = {(leaf_bytes, leaf_ver): {wrong_cb}}
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_wrong_leaf_opcode(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when the leaf trailing opcode is not OP_CSV (0xB2)."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    # Replace the last byte (0xB2 OP_CSV) with 0xAC (OP_CHECKSIG) — wrong shape
    bad_leaf = (
        bytes([0x20]) + leaf_key
        + bytes([0xAD, 0x20]) + _ASSERT_INNER_KEY
        + bytes([0xAC])  # wrong trailing opcode
    )
    bad_leaf_hash = _tapleaf_hash(bad_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, bad_leaf_hash)
    bad_spk = bytes([0x51, 0x20]) + tweaked
    bad_cb = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY
    psbt.inputs[0].witness_utxo = CTxOut(5_000_000, bad_spk)
    psbt.inputs[0].tap_scripts = {(bad_leaf, 0xC0): {bad_cb}}
    psbt.inputs[0].tap_bip32_paths = {
        leaf_key: (
            {bad_leaf_hash},
            KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
        )
    }
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_output_exceeds_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when total output value exceeds the input WITNESS_UTXO amount (negative fee)."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    amount_carried = 5_000_000
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type,
                               amount_carried=amount_carried,
                               out_value=amount_carried + 1)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA
