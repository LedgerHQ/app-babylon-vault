"""Screen 4 — Claim: golden-snapshot tests for the Depositor Claim display.

The Claim transaction is a standalone SIGN_PSBT flow: the depositor spends the
Depositor Claim UTXO (leaf: <D> OP_CHECKSIG, 34 bytes) and the device shows
"Amount spent" + "Transaction fee" before the user approves.

Snapshots are stored under:
    tests/snapshots/<device>/screen4_claim/<test_case>_<network>/

Run with --golden_run to regenerate reference snapshots:

    pytest tests/test_screen4_claim.py --golden_run -k flex
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

from .vault_client import SW_DENY, SW_INCORRECT_DATA, TEST_VALID_KEYS, sign_psbt_with_nav_and_compare
from .instructions import (
    sign_psbt_claim_approve_instructions,
    sign_psbt_claim_approve_nav,
    sign_psbt_claim_reject_instructions,
    sign_psbt_claim_reject_nav,
)
from .test_sign_psbt_validate import (
    _NoWalletPolicy,
    _bip86_p2tr_spk,
    _tapleaf_hash,
    HARDENED,
    VAULT_NUMS_XONLY,
    VAULT_DUST_LIMIT,
)

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


def _build_claim_psbt(
    fingerprint: bytes,
    leaf_key: bytes,
    coin_type: int,
    input_value: int = 1_200_000,
    connector_value: int = 600_000,
) -> PSBT:
    """Build a Claim PSBTv0 for Screen 4.

    Input 0: Depositor Claim UTXO — leaf <D> OP_CHECKSIG (34 bytes), single-leaf
             P2TR with NUMS internal key.  D is verified via TAP_BIP32_DERIVATION.
    Output 0: ClaimAssertConnector — host-provided; not checked by the device.
    Output 1: BIP-86 P2TR(D) CPFP anchor, value = VAULT_DUST_LIMIT.
              The device derives this key from D (leaf_key), not a separate out key.
    """
    claim_leaf = bytes([0x20]) + leaf_key + bytes([0xAC])  # 34 bytes
    leaf_hash = _tapleaf_hash(claim_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    claim_spk = bytes([0x51, 0x20]) + tweaked
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    cpfp_spk = _bip86_p2tr_spk(leaf_key)

    dummy_connector_spk = bytes([0x51, 0x20]) + bytes(32)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xab' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [
        CTxOut(connector_value, dummy_connector_spk),
        CTxOut(VAULT_DUST_LIMIT, cpfp_spk),
    ]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0), PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(input_value, claim_spk)
    psbt.inputs[0].tap_scripts[(claim_leaf, 0xC0)] = {control_block}
    psbt.inputs[0].tap_bip32_paths[leaf_key] = (
        {leaf_hash},
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
    )

    return psbt


def test_sign_psbt_claim_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Show Screen 4 (Claim) and capture all review pages as golden snapshots.

    Sends a valid Claim PSBT to the device.  Validation passes and the review
    screen is shown.  The test navigates through every page and approves, ending
    on the "Transaction signed" status screen.  Run once with --golden_run to
    create the reference images.
    """
    coin_type = 0 if bitcoin_network == "main" else 1

    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]

    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen4_claim/screen_" + bitcoin_network

    if device.is_nano:
        client.sign_psbt(psbt, dummy_wallet, None, navigator,
                         testname=tname, instructions=sign_psbt_claim_approve_instructions(device))
    else:
        sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                       testname=tname, nav_instructions=sign_psbt_claim_approve_nav(device))


# ===========================================================================
# Screen 4 — Claim: error-path tests
# ===========================================================================

def _claim_keys(client: "RaggerClient", bitcoin_network: str):
    """Return (fingerprint, leaf_key, coin_type) for the standard Claim key."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    return fingerprint, leaf_key, coin_type


def test_sign_psbt_claim_wrong_version(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when nVersion < 2."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.nVersion = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_nonzero_locktime(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when nLockTime != 0."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.nLockTime = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_sighash_all(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when PSBT_IN_SIGHASH_TYPE is set to SIGHASH_ALL (1); only DEFAULT accepted."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    psbt.inputs[0].sighash = 1  # SIGHASH_ALL
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_extra_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when n_inputs != 1."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_wrong_output_count(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when n_outputs != 2 (CPFP anchor output missing)."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.vout = [psbt.tx.vout[0]]
    psbt.outputs = [psbt.outputs[0]]
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_wrong_fingerprint(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when TAP_BIP32_DERIVATION fingerprint belongs to a foreign device."""
    _, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    wrong_fingerprint = b'\xff\xff\xff\xff'
    psbt = _build_claim_psbt(wrong_fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_non_bip86_path(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when the derivation path is not a BIP-86 path (m/44' instead of m/86')."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    claim_leaf = bytes([0x20]) + leaf_key + bytes([0xAC])
    leaf_hash = _tapleaf_hash(claim_leaf)
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


def test_sign_psbt_claim_foreign_key(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when the leaf D key is not derived from this device's seed."""
    fingerprint, _, coin_type = _claim_keys(client, bitcoin_network)
    foreign_key = TEST_VALID_KEYS[0]  # valid EC point, not derived from this device
    psbt = _build_claim_psbt(fingerprint, foreign_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_tampered_control_block(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when the taproot control block internal key is not VAULT_NUMS_XONLY."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    (leaf_bytes, leaf_ver), _ = next(iter(psbt.inputs[0].tap_scripts.items()))
    wrong_cb = bytes([0xC0]) + bytes([0x01] * 32)
    psbt.inputs[0].tap_scripts = {(leaf_bytes, leaf_ver): {wrong_cb}}
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_cpfp_wrong_value(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when Out1 (CPFP anchor) value differs from VAULT_DUST_LIMIT."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.vout[1].nValue = VAULT_DUST_LIMIT + 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_cpfp_wrong_spk(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when Out1 scriptPubKey is not BIP-86 P2TR(D)."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    psbt.tx.vout[1].scriptPubKey = bytes([0x51, 0x20]) + bytes(32)  # wrong key
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_claim_output_equals_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Claim fails when total outputs equal the input value (zero fee disallowed)."""
    fingerprint, leaf_key, coin_type = _claim_keys(client, bitcoin_network)
    input_value = 1_000_000
    # connector_value set so total_out == input_value (the >= check fires)
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type,
                              input_value=input_value,
                              connector_value=input_value - VAULT_DUST_LIMIT)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# Screen 4 — Claim: user rejection test
# ===========================================================================

def test_reject_claim_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """User rejects Screen 4 (Claim) → SW_DENY."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen4_claim/reject_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, dummy_wallet, None, navigator,
                             testname=tname, instructions=sign_psbt_claim_reject_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                           testname=tname, nav_instructions=sign_psbt_claim_reject_nav(device))
    assert exc.value.status == SW_DENY
