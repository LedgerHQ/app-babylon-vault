"""Screen 7 — PoP (BIP-322 proof-of-possession): golden-snapshot tests.

The PoP flow is a standalone SIGN_PSBT that asks the depositor to sign a
BIP-322 to_sign PSBT proving ownership of their Ethereum address.  The device
shows "ETH address", "Chain ID", and "Registry contract" before the user
approves "Register ETH address".

Discriminator: the to_sign PSBT has nVersion == 0, which is unique across all
Babylon protocol transaction types.

Snapshots are stored under:
    tests/snapshots/<device>/screen7_pop/<test_case>_<network>/

Run with --golden_run to regenerate reference snapshots:

    pytest tests/test_screen7_pop.py --golden_run -k flex
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from ledger_bitcoin import WalletPolicy
from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness

from test_utils.taproot import taproot_tweak_pubkey

from .vault_client import SW_DENY, SW_INCORRECT_DATA, sign_psbt_with_nav_and_compare
from .instructions import (
    sign_psbt_pop_approve_nav,
    sign_psbt_pop_reject_instructions,
    sign_psbt_pop_reject_nav,
)
from .test_sign_psbt_validate import HARDENED

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

# PSBT global proprietary key for the PoP message:
#   0xFC (PSBT_GLOBAL_PROPRIETARY) || 0x06 (id_len) || "bvault" || 0x00 (subtype)
# Must match BIP322_PSBT_PROP_POP_MSG_KEY in src/bip322.h.
_POP_MSG_KEY = bytes([0xFC, 0x06, ord('b'), ord('v'), ord('a'), ord('u'), ord('l'), ord('t'), 0x00])

# Canonical test PoP message: <eth_addr>:<chain_id>:pegin:<registry>
_ETH_ADDR = "0xabcdef1234567890abcdef1234567890abcdef12"
_CHAIN_ID  = "11155111"   # Ethereum Sepolia testnet chain ID
_REGISTRY  = "0x1234567890abcdef1234567890abcdef12345678"
_POP_MSG   = f"{_ETH_ADDR}:{_CHAIN_ID}:pegin:{_REGISTRY}"


# ---------------------------------------------------------------------------
# BIP-322 helpers (mirrors bip322.c for test-side txid computation)
# ---------------------------------------------------------------------------

def _bip322_tagged_hash(message: bytes) -> bytes:
    """SHA256(tag_hash || tag_hash || message), tag = 'BIP0322-signed-message'."""
    tag = b"BIP0322-signed-message"
    tag_hash = hashlib.sha256(tag).digest()
    return hashlib.sha256(tag_hash + tag_hash + message).digest()


def _bip322_to_spend_txid(message: bytes, tweaked_key: bytes) -> bytes:
    """Compute the BIP-322 to_spend txid in Bitcoin wire format (reversed SHA256d).

    Builds the 128-byte legacy to_spend transaction, then returns
    SHA256(SHA256(to_spend)) reversed — matching the 32-byte value the firmware
    stores in PSBT_IN_PREVIOUS_TXID.
    """
    msg_hash = _bip322_tagged_hash(message)

    to_spend = bytearray()
    to_spend += struct.pack('<I', 0)            # version = 0
    to_spend += bytes([0x01])                   # vin_count = 1
    to_spend += bytes(32)                       # prevout txid = 0x00 * 32
    to_spend += struct.pack('<I', 0xFFFFFFFF)  # prevout vout = 0xFFFFFFFF
    to_spend += bytes([0x22])                   # scriptSig length = 34
    to_spend += bytes([0x00, 0x20])            # OP_0  PUSHBYTES_32
    to_spend += msg_hash                        # tagged_hash("BIP0322-signed-message", msg)
    to_spend += struct.pack('<I', 0)           # sequence = 0
    to_spend += bytes([0x01])                   # vout_count = 1
    to_spend += struct.pack('<q', 0)           # value = 0
    to_spend += bytes([0x22])                   # scriptPubKey length = 34
    to_spend += bytes([0x51, 0x20])            # OP_1  PUSHBYTES_32
    to_spend += tweaked_key                     # depositor BIP-86 output key
    to_spend += struct.pack('<I', 0)           # locktime = 0

    assert len(to_spend) == 128

    hash1 = hashlib.sha256(bytes(to_spend)).digest()
    hash2 = hashlib.sha256(hash1).digest()
    return hash2[::-1]   # reverse to Bitcoin wire format


# ---------------------------------------------------------------------------
# Wallet policy and PSBT builders
# ---------------------------------------------------------------------------

def _standard_taproot_wallet(client: "RaggerClient", coin_type: int) -> WalletPolicy:
    fingerprint = client.get_master_fingerprint()
    xpub = client.get_extended_pubkey(f"m/86'/{coin_type}'/0'", display=False)
    return WalletPolicy(
        name="",
        descriptor_template="tr(@0/**)",
        keys_info=[f"[{fingerprint.hex()}/86'/{coin_type}'/0']{xpub}"],
    )


def _build_pop_psbt(
    fingerprint: bytes,
    internal_key: bytes,
    coin_type: int,
    message: str = _POP_MSG,
) -> PSBT:
    """Build a PoP PSBTv0 for Screen 7.

    tx.nVersion == 0 is the unique PoP discriminator the firmware uses.
    The global proprietary field carries the PoP message, and the input's
    PREVIOUS_TXID is the computed BIP-322 to_spend txid.
    """
    msg_bytes = message.encode("ascii")
    _, tweaked_key = taproot_tweak_pubkey(internal_key, b"")  # BIP-86: empty script tree

    to_spend_txid = _bip322_to_spend_txid(msg_bytes, tweaked_key)  # 32 bytes, wire format

    # to_sign input scriptPubKey: P2TR(BIP-86 tweaked internal_key)
    witness_spk = bytes([0x51, 0x20]) + tweaked_key

    tx = CTransaction()
    tx.nVersion = 0                                                      # PoP discriminator
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(
        int.from_bytes(to_spend_txid, "little"),  # to_spend_txid in wire format
        0,
    )
    tx.vin[0].nSequence = 0                                              # BIP-322 nSequence = 0
    tx.vout = [CTxOut(0, bytes([0x6A]))]                                 # OP_RETURN, value = 0
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]

    # Global proprietary field: carries the raw PoP message bytes
    psbt.unknown[_POP_MSG_KEY] = msg_bytes

    # WITNESS_UTXO: the to_spend output 0 (value=0, P2TR scriptPubKey)
    psbt.inputs[0].witness_utxo = CTxOut(0, witness_spk)

    # TAP_INTERNAL_KEY: x-only BIP-86 internal key
    psbt.inputs[0].tap_internal_key = internal_key

    # TAP_BIP32_DERIVATION: key-path only (no leaf hashes), standard BIP-86 path
    psbt.inputs[0].tap_bip32_paths[internal_key] = (
        set(),   # no tapscripts — key-path spend
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
    )

    return psbt


def _pop_keys(client: "RaggerClient", bitcoin_network: str):
    """Return (fingerprint, internal_key, coin_type, wallet) for standard PoP tests."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    internal_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    wallet = _standard_taproot_wallet(client, coin_type)
    return fingerprint, internal_key, coin_type, wallet


# ===========================================================================
# Screen 7 — PoP: golden-snapshot test (happy path)
# ===========================================================================

def test_sign_psbt_pop_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Show Screen 7 (PoP) and capture all review pages as golden snapshots.

    Sends a valid PoP PSBT to the device.  Validation passes and the 'Register
    ETH address' review screen is shown.  Run once with --golden_run to create
    the reference images.
    """
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    tname = "screen7_pop/screen_" + bitcoin_network

    sign_psbt_with_nav_and_compare(client, psbt, wallet, None, navigator,
                                   testname=tname,
                                   nav_instructions=sign_psbt_pop_approve_nav(device))


# ===========================================================================
# Screen 7 — PoP: user rejection test
# ===========================================================================

def test_reject_pop_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """User rejects Screen 7 (PoP) → SW_DENY."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    tname = "screen7_pop/reject_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, wallet, None, navigator,
                             testname=tname,
                             instructions=sign_psbt_pop_reject_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, wallet, None, navigator,
                                           testname=tname,
                                           nav_instructions=sign_psbt_pop_reject_nav(device))
    assert exc.value.status == SW_DENY


# ===========================================================================
# Screen 7 — PoP: error-path tests
# ===========================================================================

def test_pop_nonzero_locktime(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when nLockTime != 0."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.tx.nLockTime = 1
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_sighash_all(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when PSBT_IN_SIGHASH_TYPE is set; only absent (SIGHASH_DEFAULT) accepted."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.inputs[0].sighash = 1   # SIGHASH_ALL
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_nonzero_sequence(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when nSequence is not 0 (BIP-322 to_sign nSequence must be exactly 0)."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.tx.vin[0].nSequence = 1   # must be 0
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_extra_input(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when n_inputs != 1."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_extra_output(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when n_outputs != 1."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.tx.vout.append(CTxOut(0, bytes([0x6A])))
    psbt.outputs.append(PartiallySignedOutput(0))
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_missing_message(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP PSBT without the proprietary message field is rejected (AC: generic path rejected).

    A version-0 PSBT submitted without BIP322_PSBT_PROP_POP_MSG_KEY never falls through
    to a generic transaction display — the firmware rejects it before signing proceeds.
    """
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    del psbt.unknown[_POP_MSG_KEY]
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_bad_grammar_no_colon(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when the message has fewer than 3 colons."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.unknown[_POP_MSG_KEY] = f"{_ETH_ADDR}:{_CHAIN_ID}:pegin".encode("ascii")
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_bad_grammar_wrong_literal(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when field 2 is not the literal 'pegin' (case-sensitive)."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    bad = f"{_ETH_ADDR}:{_CHAIN_ID}:PEGIN:{_REGISTRY}"  # uppercase — invalid
    psbt.unknown[_POP_MSG_KEY] = bad.encode("ascii")
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_bad_grammar_uppercase_eth_addr(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when eth_addr contains uppercase hex characters."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    bad = f"0xABCDEF1234567890abcdef1234567890abcdef12:{_CHAIN_ID}:pegin:{_REGISTRY}"
    psbt.unknown[_POP_MSG_KEY] = bad.encode("ascii")
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_bad_grammar_chain_id_leading_zero(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when chain_id has a leading zero (non-canonical encoding)."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    bad = f"{_ETH_ADDR}:01:pegin:{_REGISTRY}"   # leading zero — invalid
    psbt.unknown[_POP_MSG_KEY] = bad.encode("ascii")
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_prevout_txid_mismatch(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when PSBT_IN_PREVIOUS_TXID doesn't match the computed to_spend txid."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    # Replace prevout hash with all-zeros — won't match the computed to_spend txid
    psbt.tx.vin[0].prevout = COutPoint(0, 0)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_wrong_output_index(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when PSBT_IN_OUTPUT_INDEX != 0."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    txid_int = psbt.tx.vin[0].prevout.hash
    psbt.tx.vin[0].prevout = COutPoint(txid_int, 1)   # vout = 1, must be 0
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_wrong_output_value(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when output 0 value is not 0."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.tx.vout[0] = CTxOut(1, bytes([0x6A]))   # value = 1 sat, must be 0
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_wrong_output_script(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when output 0 scriptPubKey is not OP_RETURN (0x6A)."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.tx.vout[0] = CTxOut(0, bytes([0x51, 0x20]) + bytes(32))   # P2TR — not OP_RETURN
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_foreign_key(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when the internal key is not derived from this device's seed."""
    fingerprint, _, coin_type, wallet = _pop_keys(client, bitcoin_network)
    foreign_key = bytes.fromhex("F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9")
    psbt = _build_pop_psbt(fingerprint, foreign_key, coin_type)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_bad_grammar_empty_chain_id(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when chain_id is empty (consecutive colons: <eth>::pegin:<reg>)."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    bad = f"{_ETH_ADDR}::pegin:{_REGISTRY}"   # empty chain_id — grammar error
    psbt.unknown[_POP_MSG_KEY] = bad.encode("ascii")
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_witness_utxo_nonzero_value(client: "RaggerClient", bitcoin_network: str) -> None:
    """PoP fails when WITNESS_UTXO value is not 0 (BIP-322 to_spend output value must be 0)."""
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    _, tweaked_key = taproot_tweak_pubkey(internal_key, b"")
    witness_spk = bytes([0x51, 0x20]) + tweaked_key
    psbt.inputs[0].witness_utxo = CTxOut(1000, witness_spk)   # value must be 0
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pop_chain_id_zero(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """PoP accepts chain_id == '0' (the single character zero is a valid chain ID).

    Run once with --golden_run to create reference snapshots.
    """
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    msg = f"{_ETH_ADDR}:0:pegin:{_REGISTRY}"
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type, message=msg)
    tname = "screen7_pop/chain_id_zero_" + bitcoin_network
    sign_psbt_with_nav_and_compare(client, psbt, wallet, None, navigator,
                                   testname=tname,
                                   nav_instructions=sign_psbt_pop_approve_nav(device))


def test_pop_explicit_sighash_default(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """PoP accepts an explicit PSBT_IN_SIGHASH_TYPE = 0 (SIGHASH_DEFAULT).

    Absent key and explicit 0 are semantically equivalent for Taproot.
    Run once with --golden_run to create reference snapshots.
    """
    fingerprint, internal_key, coin_type, wallet = _pop_keys(client, bitcoin_network)
    psbt = _build_pop_psbt(fingerprint, internal_key, coin_type)
    psbt.inputs[0].sighash = 0   # explicit SIGHASH_DEFAULT — must be accepted
    tname = "screen7_pop/explicit_sighash_default_" + bitcoin_network
    sign_psbt_with_nav_and_compare(client, psbt, wallet, None, navigator,
                                   testname=tname,
                                   nav_instructions=sign_psbt_pop_approve_nav(device))
