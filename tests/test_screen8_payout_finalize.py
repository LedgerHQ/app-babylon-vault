"""Screen 8 — PayoutFinalize: golden-snapshot and validation tests (NAPPS-1464).

PayoutFinalize is the depositor self-claim after the Claim+Assert chain.  It is
the only flow in the app that asks the device to sign Input 1 (not Input 0).

Discriminator: n_inputs == 2 && n_outputs == 2 with has_no_wallet_policy=True
and Input 0 external (no TAP_LEAF_SCRIPT).

The device shows "Amount received" and "Destination: Your address" before the
user approves "Sign payout finalization?".

Snapshots are stored under:
    tests/snapshots/<device>/screen8_payout_finalize/<test_case>_<network>/

Run with --golden_run to regenerate reference snapshots:

    pytest tests/test_screen8_payout_finalize.py --golden_run -k flex
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

from .vault_client import SW_DENY, SW_INCORRECT_DATA, sign_psbt_with_nav_and_compare
from .instructions import (
    sign_psbt_payout_finalize_approve_instructions,
    sign_psbt_payout_finalize_approve_nav,
    sign_psbt_payout_finalize_reject_instructions,
    sign_psbt_payout_finalize_reject_nav,
)
from .test_sign_psbt_validate import (
    HARDENED,
    VAULT_NUMS_XONLY,
    _NoWalletPolicy,
    _PAYOUT_TIMELOCK,
    _VAULT_DUST_LIMIT,
    _build_payout_finalize_psbt,
    _tapleaf_hash,
    _payout_leaf,
    _assert_single_schnorr_sig,
    TEST_VALID_KEYS,
)
from test_utils.taproot import taproot_tweak_pubkey

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

_AMOUNT_RECEIVED = 1_234_567   # sats shown on the review screen


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def _payout_keys(client: "RaggerClient", bitcoin_network: str):
    """Return (fingerprint, d_key, coin_type) for standard PayoutFinalize tests.

    D is derived at m/86'/{coin_type}'/0'/0/0 — the same BIP-86 path the firmware
    verifies against the TAP_BIP32_DERIVATION entry on Input 1.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    d_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    return fingerprint, d_key, coin_type


# ===========================================================================
# Screen 8 — PayoutFinalize: golden-snapshot test (happy path)
# ===========================================================================

def test_sign_psbt_payout_finalize_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Show Screen 8 (PayoutFinalize) and capture all review pages as golden snapshots.

    Sends a valid PayoutFinalize PSBT (2 inputs, 2 outputs; Input 1 signed by the
    device's D key via payout leaf).  The device shows the review screen with
    'Amount received' and 'Destination: Your address'.  Run once with --golden_run
    to create the reference images.
    """
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type,
                                        amount_received=_AMOUNT_RECEIVED)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen8_payout_finalize/screen_" + bitcoin_network

    if device.is_nano:
        result = client.sign_psbt(
            psbt, dummy_wallet, None, navigator,
            testname=tname,
            instructions=sign_psbt_payout_finalize_approve_instructions(device),
        )
    else:
        sign_psbt_with_nav_and_compare(
            client, psbt, dummy_wallet, None, navigator,
            testname=tname,
            nav_instructions=sign_psbt_payout_finalize_approve_nav(device),
        )
        return

    # Nano: verify the returned signature is on Input 1, signed by D.
    _assert_single_schnorr_sig(result, d_key, expected_input=1)


# ===========================================================================
# Screen 8 — PayoutFinalize: user rejection test
# ===========================================================================

def test_reject_payout_finalize_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """User rejects Screen 8 (PayoutFinalize) → SW_DENY."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type,
                                        amount_received=_AMOUNT_RECEIVED)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen8_payout_finalize/reject_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, dummy_wallet, None, navigator,
                             testname=tname,
                             instructions=sign_psbt_payout_finalize_reject_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(
                client, psbt, dummy_wallet, None, navigator,
                testname=tname,
                nav_instructions=sign_psbt_payout_finalize_reject_nav(device),
            )
    assert exc.value.status == SW_DENY


# ===========================================================================
# Screen 8 — PayoutFinalize: error-path tests
# ===========================================================================

def test_payout_finalize_nonzero_locktime(client: "RaggerClient", bitcoin_network: str) -> None:
    """PayoutFinalize fails when nLockTime != 0."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    psbt.tx.nLockTime = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_wrong_version(client: "RaggerClient", bitcoin_network: str) -> None:
    """PayoutFinalize fails when nVersion < 2 (version 1 has no CSV semantics)."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    psbt.tx.nVersion = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_version3_accepted(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """PayoutFinalize succeeds with nVersion = 3 (firmware requires >= 2, not exactly 2).

    nVersion is not displayed on Screen 8, so the snapshots are identical to the
    happy-path test.  This test reuses the same reference images.
    """
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type,
                                        amount_received=_AMOUNT_RECEIVED)
    psbt.tx.nVersion = 3
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen8_payout_finalize/version3_" + bitcoin_network

    if device.is_nano:
        result = client.sign_psbt(
            psbt, dummy_wallet, None, navigator,
            testname=tname,
            instructions=sign_psbt_payout_finalize_approve_instructions(device),
        )
        _assert_single_schnorr_sig(result, d_key, expected_input=1)
    else:
        sign_psbt_with_nav_and_compare(
            client, psbt, dummy_wallet, None, navigator,
            testname=tname,
            nav_instructions=sign_psbt_payout_finalize_approve_nav(device),
        )


def test_payout_finalize_sequence_below_csv(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Input 1 nSequence < t2 (CSV timelock not satisfied)."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    psbt.tx.vin[1].nSequence = _PAYOUT_TIMELOCK - 1   # one block short of the timelock
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_sequence_above_csv(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Input 1 nSequence == t2 + 1 (not an exact match).

    HLD requires nSequence to encode exactly the CSV timelock t2 from the leaf.
    Any value other than t2 is rejected, including t2 + 1.
    """
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    psbt.tx.vin[1].nSequence = _PAYOUT_TIMELOCK + 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_output1_wrong_value(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Output 1 value != VAULT_DUST_LIMIT (546 sat)."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    from ledger_bitcoin.tx import CTxOut
    psbt.tx.vout[1] = CTxOut(_VAULT_DUST_LIMIT + 1, psbt.tx.vout[1].scriptPubKey)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_output0_wrong_key(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Output 0 SPK does not match BIP-86(D)."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    from ledger_bitcoin.tx import CTxOut
    # Replace Output 0 with a P2TR pointing to an all-zero key — not BIP-86(D).
    wrong_spk = bytes([0x51, 0x20]) + bytes(32)
    psbt.tx.vout[0] = CTxOut(_AMOUNT_RECEIVED, wrong_spk)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_output1_wrong_key(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Output 1 SPK does not match BIP-86(D)."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    from ledger_bitcoin.tx import CTxOut
    wrong_spk = bytes([0x51, 0x20]) + bytes(32)
    psbt.tx.vout[1] = CTxOut(_VAULT_DUST_LIMIT, wrong_spk)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_tampered_control_block(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when the control block uses a wrong internal key."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)

    (leaf_bytes, leaf_ver), _ = next(iter(psbt.inputs[1].tap_scripts.items()))
    wrong_internal_key = bytes([0x01] * 32)   # anything other than VAULT_NUMS_XONLY
    wrong_cb = bytes([0xC0]) + wrong_internal_key
    psbt.inputs[1].tap_scripts = {(leaf_bytes, leaf_ver): {wrong_cb}}

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_wrong_leaf_shape(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when the leaf is ≤ 68 bytes (looks like an Assert leaf)."""
    from test_utils.taproot import ser_script, tagged_hash as tt_tagged_hash

    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    coin_type_val = 0 if bitcoin_network == "main" else 1

    # Build a 68-byte leaf: OP_PUSHBYTES_32 <D> OP_CHECKSIGVERIFY <33 filler> OP_CSV
    # = 1+32+1+33+1 = 68 bytes → parse_payout_leaf_script rejects (script_len <= 68).
    short_leaf = bytes([0x20]) + d_key + bytes([0xAD]) + bytes(33) + bytes([0xB2])
    assert len(short_leaf) == 68

    leaf_hash = tt_tagged_hash("TapLeaf", bytes([0xC0]) + ser_script(short_leaf))
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    input1_spk = bytes([0x51, 0x20]) + tweaked
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    from ledger_bitcoin.key import KeyOriginInfo
    from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
    from ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness

    _, bip86_out_key = taproot_tweak_pubkey(d_key, b'')
    out_spk = bytes([0x51, 0x20]) + bip86_out_key

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(), CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xAA' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFE
    tx.vin[1].prevout = COutPoint(int.from_bytes(b'\xBB' * 32, 'little'), 0)
    tx.vin[1].nSequence = _PAYOUT_TIMELOCK
    tx.vout = [CTxOut(_AMOUNT_RECEIVED, out_spk), CTxOut(_VAULT_DUST_LIMIT, out_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0), PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0), PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(2_100_000, bytes([0x51, 0x20]) + bytes(32))
    psbt.inputs[1].witness_utxo = CTxOut(_VAULT_DUST_LIMIT, input1_spk)
    psbt.inputs[1].tap_scripts[(short_leaf, 0xC0)] = {control_block}
    psbt.inputs[1].tap_bip32_paths[d_key] = (
        {leaf_hash},
        KeyOriginInfo(
            client.get_master_fingerprint(),
            [HARDENED | 86, HARDENED | coin_type_val, HARDENED | 0, 0, 0],
        ),
    )

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_wrong_input_count(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when n_inputs != 2 (1-input PSBT routes to a different flow)."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    # Remove Input 0 — the PSBT now looks like a Refund (1 input, 2 outputs).
    # The Refund validator expects a different leaf shape and will reject it.
    psbt.tx.vin = [psbt.tx.vin[1]]
    psbt.inputs = [psbt.inputs[1]]
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_wrong_output_count(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when n_outputs != 2."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    # Remove Output 1 — now 2+1, which doesn't match any standalone flow.
    psbt.tx.vout = [psbt.tx.vout[0]]
    psbt.outputs = [psbt.outputs[0]]
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_sighash_all(client: "RaggerClient", bitcoin_network: str) -> None:
    """PayoutFinalize fails when Input 1 has SIGHASH_ALL; only SIGHASH_DEFAULT accepted."""
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    psbt.inputs[1].sighash = 1   # SIGHASH_ALL — must be rejected
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_foreign_d_key(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when D is not derived from this device's seed.

    The TAP_BIP32_DERIVATION carries a valid BIP-86 path but a fingerprint that
    doesn't match the device's master fingerprint, so the firmware's key-derivation
    check will fail.
    """
    _, d_key, coin_type = _payout_keys(client, bitcoin_network)
    wrong_fingerprint = b'\xff\xff\xff\xff'
    psbt = _build_payout_finalize_psbt(wrong_fingerprint, d_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_csv_out_of_range(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when t2 in the leaf is outside [90, 4032].

    Uses t2 = 89 (one below VAULT_PAYOUT_TIMELOCK_MIN) so the parser rejects the leaf.
    """
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    # Build a leaf with t2=89 (below minimum) — the leaf shape check must reject it.
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type, t2=89)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_input0_marked_internal(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Input 0 carries the payout leaf (inputs swapped).

    The firmware guards against Input 0 being signed via bitvector_get(internal_inputs, 0).
    Swapping the two inputs produces a PSBT where Input 0 has the payout leaf and
    TAP_BIP32_DERIVATION (so the sign_psbt framework marks it internal), while Input 1
    is external.  The guard fires before any further validation.
    """
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    # Swap inputs: payout leaf moves to Input 0, external UTXO moves to Input 1.
    psbt.tx.vin[0], psbt.tx.vin[1] = psbt.tx.vin[1], psbt.tx.vin[0]
    psbt.inputs[0], psbt.inputs[1] = psbt.inputs[1], psbt.inputs[0]
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_sequence_locktime_disabled(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Input 1 nSequence has BIP-68 disable flag set (H2).

    Setting bit 31 of nSequence disables relative locktime enforcement.  The firmware
    must reject this: sequence >= t2 with the disable flag set means the timelock is
    not actually enforced on-chain.
    """
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    psbt.tx.vin[1].nSequence = _PAYOUT_TIMELOCK | 0x80000000
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_sequence_time_based(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Input 1 nSequence has BIP-68 time-based flag set (H2).

    Setting bit 22 of nSequence switches the relative locktime unit from blocks to
    512-second intervals.  The payout leaf specifies a block-count CSV, so this flag
    means the sequence value encodes a different unit and must be rejected.
    """
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    psbt.tx.vin[1].nSequence = _PAYOUT_TIMELOCK | 0x00400000
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_input1_wrong_value(
    client: "RaggerClient", bitcoin_network: str,
) -> None:
    """PayoutFinalize fails when Input 1 witness_utxo value < VAULT_DUST_LIMIT."""
    from ledger_bitcoin.tx import CTxOut
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    psbt = _build_payout_finalize_psbt(fingerprint, d_key, coin_type)
    psbt.inputs[1].witness_utxo = CTxOut(
        _VAULT_DUST_LIMIT - 1,
        psbt.inputs[1].witness_utxo.scriptPubKey,
    )
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_finalize_vault_amount_too_small(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """PayoutFinalize accepts a PSBT with Input 0 value = amount_received + 1 sat (minimal fee).

    No intent is loaded, so only the amount_received > 0 floor applies.  Input 0's
    witness_utxo is unattested and the device does not validate it.
    """
    fingerprint, d_key, coin_type = _payout_keys(client, bitcoin_network)
    amount = 1_999_000
    psbt = _build_payout_finalize_psbt(
        fingerprint, d_key, coin_type,
        amount_received=amount,
        vault_amount=amount + 1,   # 1 sat fee; no intent loaded, so single-vault cap skipped
    )
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    tname = "screen8_payout_finalize/vault_amount_too_small_" + bitcoin_network
    if device.is_nano:
        result = client.sign_psbt(
            psbt, dummy_wallet, None, navigator,
            testname=tname,
            instructions=sign_psbt_payout_finalize_approve_instructions(device),
        )
    else:
        sign_psbt_with_nav_and_compare(
            client, psbt, dummy_wallet, None, navigator,
            testname=tname,
            nav_instructions=sign_psbt_payout_finalize_approve_nav(device),
        )
        return

    _assert_single_schnorr_sig(result, d_key, expected_input=1)
