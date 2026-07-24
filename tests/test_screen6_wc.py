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

from .vault_client import SW_DENY, SW_INCORRECT_DATA, sign_psbt_with_nav_and_compare
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


# ===========================================================================
# Screen 6 — WC (Wrongly Challenged): error-path tests
# ===========================================================================

def _wc_keys(client: "RaggerClient", bitcoin_network: str):
    """Return (fingerprint, leaf_key, coin_type) for the standard WC key."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    return fingerprint, leaf_key, coin_type


def test_sign_psbt_wc_wrong_version(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when nVersion < 2."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.nVersion = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_wc_nonzero_locktime(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when nLockTime != 0."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.nLockTime = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_wc_sighash_all(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when PSBT_IN_SIGHASH_TYPE is SIGHASH_ALL; only DEFAULT accepted."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    psbt.inputs[0].sighash = 1  # SIGHASH_ALL
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_wc_extra_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC (no-wallet variant) fails when n_inputs != 1."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_wc_wrong_fingerprint(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when TAP_BIP32_DERIVATION fingerprint belongs to a foreign device."""
    _, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    wrong_fingerprint = b'\xff\xff\xff\xff'
    psbt = _build_wc_psbt(wrong_fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_wc_non_bip86_path(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when the derivation path is not BIP-86 (m/44' instead of m/86')."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    wc_leaf = _build_wc_leaf(leaf_key)
    leaf_hash = _tapleaf_hash(wc_leaf)
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


def test_sign_psbt_wc_foreign_key(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when the leaf D key is not derived from this device's seed."""
    fingerprint, _, coin_type = _wc_keys(client, bitcoin_network)
    foreign_key = bytes([0xBB] * 32)
    psbt = _build_wc_psbt(fingerprint, foreign_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_wc_tampered_control_block(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when the taproot control block internal key is not VAULT_NUMS_XONLY."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    (leaf_bytes, leaf_ver), _ = next(iter(psbt.inputs[0].tap_scripts.items()))
    wrong_cb = bytes([0xC0]) + bytes([0x01] * 32)
    psbt.inputs[0].tap_scripts = {(leaf_bytes, leaf_ver): {wrong_cb}}
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_wc_wrong_output_spk(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when Out0 scriptPubKey is not BIP-86 P2TR(D)."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.vout[0].scriptPubKey = bytes([0x51, 0x20]) + bytes(32)  # wrong key
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_wc_wrong_leaf_length(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when the tap_scripts leaf is not 73 bytes (wrong shape)."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    # Truncate the leaf by one byte — dispatched as WC shape but size check fails
    wc_leaf = _build_wc_leaf(leaf_key)
    bad_leaf = wc_leaf[:-1]  # 72 bytes instead of 73
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


def test_sign_psbt_wc_output_exceeds_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """WC fails when out_value exceeds input_value (negative fee)."""
    fingerprint, leaf_key, coin_type = _wc_keys(client, bitcoin_network)
    input_value = 5_000_000
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type,
                           input_value=input_value,
                           out_value=input_value + 1)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA
