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

from .vault_client import SW_DENY, SW_INCORRECT_DATA, sign_psbt_with_nav_and_compare
from .instructions import (
    sign_psbt_assert_approve_instructions,
    sign_psbt_assert_approve_nav,
    sign_psbt_assert_reject_instructions,
    sign_psbt_assert_reject_nav,
)
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

# A fixed 32-byte xonly key used as the first challenger slot in the synthetic test leaf.
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

    Uses a synthetic leaf that reproduces the real Assert leaf's *shape* at a size that
    fits the device read buffer:
        OP_PUSHBYTES_32 <D[32]> OP_CHECKSIGVERIFY
        OP_PUSHBYTES_32 <key[32]> OP_CHECKSIG OP_1 OP_NUMEQUALVERIFY
        OP_TRUE

    The router dispatches to Screen 5 on leaf[33] == OP_CHECKSIGVERIFY and
    leaf[34] == OP_PUSHBYTES_32 (first byte of the challenger multisig), plus a length
    strictly greater than the 68-byte NoPayout leaf and an OP_TRUE terminator.  Those
    last two are load-bearing, not cosmetic: the NoPayout leaf shares the whole 35-byte
    prefix, so without them an Assert:0 UTXO in a 1-in/1-out PSBT would be signed down
    the Assert path with no cap and no dedup.  D is verified via TAP_BIP32_DERIVATION
    (BIP-86 path).

    Real Assert leaves are 11,526-13,636 bytes (btc-vault claim_assert.rs) and do NOT
    fit the read buffer, so no real Assert is signable yet (L-11).  This synthetic leaf
    fits, so the taproot commitment IS verified.
    The claim txid comes from tx.vin[0].prevout.hash (PSBTv0).
    """
    assert len(claim_txid) == 32

    # Synthetic Assert leaf, real shape: 35-byte prefix, a 1-of-1 challenger "multisig",
    # and the OP_TRUE terminator the WOTS verifier body ends with.
    assert_leaf = (
        bytes([0x20]) + leaf_key + bytes([0xAD])           # OP_PUSHBYTES_32 <D> OP_CHECKSIGVERIFY
        + bytes([0x20]) + _ASSERT_INNER_KEY + bytes([0xAC])  # OP_PUSHBYTES_32 <C> OP_CHECKSIG
        + bytes([0x51, 0x9D])                               # OP_1 OP_NUMEQUALVERIFY
        + bytes([0x51])                                     # OP_TRUE
    )
    assert len(assert_leaf) == 71
    assert len(assert_leaf) > 68 and assert_leaf[-1] == 0x51

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

    # Leaf fits in the read buffer → WITNESS_UTXO SPK is taproot-verified; value is read as amount_carried.
    psbt.inputs[0].witness_utxo = CTxOut(amount_carried, assert_spk)
    psbt.inputs[0].tap_scripts[(assert_leaf, 0xC0)] = {control_block}
    psbt.inputs[0].tap_bip32_paths[leaf_key] = (
        {leaf_hash},
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
    )

    return psbt


@pytest.mark.skip(reason="Assert screen changed in W7 fix (Output count field removed); "
                  "regenerate snapshots with --golden_run after rebuilding the app")
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


def test_sign_psbt_assert_wrong_nsequence(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Assert fails when Input 0 nSequence is not 0xFFFFFFFF."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.vin[0].nSequence = 0
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


def test_sign_psbt_assert_unrecognized_leaf_shape(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Leaf with unrecognized byte-34 opcode (not OP_SIZE, not OP_PUSHBYTES_32) and no
    trailing OP_CSV is rejected: it matches none of WC, Assert, or Refund."""
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    # Byte 34 = OP_PUSHBYTES_3 (0x03): not OP_SIZE → not WC; not OP_PUSHBYTES_32 → not Assert.
    # Last byte = OP_CHECKSIG (0xAC): not OP_CSV → not Refund.  → SW_INCORRECT_DATA.
    bad_leaf = (
        bytes([0x20]) + leaf_key
        + bytes([0xAD, 0x03, 0x01, 0x02, 0x03, 0xAC])  # unrecognized shape
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


def test_sign_psbt_assert_nopayout_shaped_leaf_is_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """A NoPayout-shaped leaf presented as a 1-in Assert must be rejected.

    The NoPayout leaf (`OP_PUSHBYTES_32 <D> OP_CHECKSIGVERIFY OP_PUSHBYTES_32 <Cj>
    OP_CHECKSIG`, 68 bytes) shares the Assert leaf's entire 35-byte prefix, and NoPayout
    is routed only by transaction shape (3 inputs / 1 output).  So the same Assert:0 UTXO
    re-presented in a 1-in/1-out PSBT must not be accepted down the Assert path, which
    applies no signing cap, no per-(group, challenger) dedup and no intent binding.

    The Assert router therefore requires a leaf longer than the NoPayout leaf and ending
    in OP_TRUE.  HLD "Standalone transactions": leaf patterns MUST remain mutually
    exclusive.  Regression guard for the reject->accept flip introduced when the router
    was reduced to a single byte-34 test.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    # Exactly the NoPayout leaf shape: byte 34 is OP_PUSHBYTES_32 (so the old single-byte
    # router matched it) and the trailing byte is OP_CHECKSIG rather than OP_TRUE.
    challenger_key = bytes([0x02] * 32)
    nopayout_leaf = (
        bytes([0x20]) + leaf_key + bytes([0xAD])      # OP_PUSHBYTES_32 <D> OP_CHECKSIGVERIFY
        + bytes([0x20]) + challenger_key + bytes([0xAC])  # OP_PUSHBYTES_32 <Cj> OP_CHECKSIG
    )
    assert len(nopayout_leaf) == 68, "NoPayout leaf must be 68 bytes"
    # Build a self-consistent single-leaf NUMS commitment so the taproot commitment check
    # cannot be what rejects it — the router must.
    leaf_hash = _tapleaf_hash(nopayout_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    psbt.inputs[0].witness_utxo = CTxOut(5_000_000, bytes([0x51, 0x20]) + tweaked)
    psbt.inputs[0].tap_scripts = {
        (nopayout_leaf, 0xC0): {bytes([0xC0 | parity]) + VAULT_NUMS_XONLY}
    }
    psbt.inputs[0].tap_bip32_paths = {
        leaf_key: (
            {leaf_hash},
            KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
        )
    }
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_leaf_without_op_true_terminator_is_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """An Assert-length leaf not ending in OP_TRUE is rejected.

    Companion to the NoPayout-shape guard above: the real Assert leaf terminates with
    OP_TRUE (btc-vault `claim_assert.rs`), so a leaf long enough to clear the NoPayout
    length but with a different terminator matches no pattern.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    # 35-byte Assert prefix, padded past 68 bytes, terminated with OP_CHECKSIG not OP_TRUE.
    bad_leaf = (
        bytes([0x20]) + leaf_key + bytes([0xAD])
        + bytes([0x20]) + bytes([0x03] * 32)
        + bytes([0x51] * 40)
        + bytes([0xAC])
    )
    assert len(bad_leaf) > 68, "leaf must exceed the NoPayout length to reach the terminator check"
    leaf_hash = _tapleaf_hash(bad_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    psbt.inputs[0].witness_utxo = CTxOut(5_000_000, bytes([0x51, 0x20]) + tweaked)
    psbt.inputs[0].tap_scripts = {(bad_leaf, 0xC0): {bytes([0xC0 | parity]) + VAULT_NUMS_XONLY}}
    psbt.inputs[0].tap_bip32_paths = {
        leaf_key: (
            {leaf_hash},
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


# ===========================================================================
# Screen 5 — Assert: user rejection test
# ===========================================================================

def test_reject_assert_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """User rejects Screen 5 (Assert) → SW_DENY."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen5_assert/reject_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, dummy_wallet, None, navigator,
                             testname=tname, instructions=sign_psbt_assert_reject_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                           testname=tname, nav_instructions=sign_psbt_assert_reject_nav(device))
    assert exc.value.status == SW_DENY
