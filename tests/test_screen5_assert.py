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
    _multisig_group,
    _setup_s1_state,
    _TEST_KEEPER_PKS,
    _TEST_CHALLENGER_PKS,
    HARDENED,
    VAULT_NUMS_XONLY,
    VAULT_DUST_LIMIT,
)

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

# Arbitrary 32-byte claim txid used as the prevout of the ClaimAssertConnector input.
_FAKE_CLAIM_TXID = bytes(range(32))

# A fixed 32-byte xonly key used where a test needs a key the intent does not contain.
_ASSERT_INNER_KEY = bytes([0x02] * 32)


@pytest.fixture(autouse=True)
def assert_intent(
    request: pytest.FixtureRequest,
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Approve the standard single-keeper / single-challenger intent before each test.

    Every Assert flow needs one: the device rebuilds the Assert leaf's signer prefix from
    the approved intent and compares it against the streamed leaf, so without an intent no
    leaf dispatches to the Assert validator at all.  Loading it here keeps each error-path
    test failing for the reason it names rather than at the intent gate.

    Tests marked `no_intent` opt out, to cover the gate itself.
    """
    if request.node.get_closest_marker("no_intent"):
        return
    _setup_s1_state(client, navigator, device, 0 if bitcoin_network == "main" else 1)


def _assert_signer_prefix(depositor_key: bytes) -> bytes:
    """The Assert leaf's signer prefix for the intent approved by the fixture above.

    Mirrors btc-vault claim_assert.rs: <Claimer> OP_CHECKSIGVERIFY, then the local
    challenger N-of-N group, then the universal challenger M-of-M group, both intermediate
    (OP_NUMEQUALVERIFY).  For a depositor claimer the local challengers are exactly the
    VaultKeepers (claim.rs derive_full_challengers), so the intent's keeper and challenger
    lists reproduce it.  106 bytes at 1 keeper + 1 challenger.
    """
    return (
        bytes([0x20]) + depositor_key + bytes([0xAD])
        + _multisig_group(_TEST_KEEPER_PKS, False)
        + _multisig_group(_TEST_CHALLENGER_PKS, False)
    )


def _build_assert_psbt(
    fingerprint: bytes,
    leaf_key: bytes,
    coin_type: int,
    claim_txid: bytes = _FAKE_CLAIM_TXID,
    amount_carried: int = 5_000_000,
    out_value: int = 4_990_000,
) -> PSBT:
    """Build an Assert PSBTv0 for Screen 5.

    Uses a synthetic leaf that reproduces the real Assert leaf's signer prefix exactly and
    stands in for the WOTS verifier body with nothing at all, so it fits the device read
    buffer:
        <D[32]> OP_CHECKSIGVERIFY <VK N-of-N> <UC M-of-M> OP_TRUE

    Dispatch to Screen 5 needs both halves of the router's test.  The shape bytes
    (leaf[33] == OP_CHECKSIGVERIFY, leaf[34] == OP_PUSHBYTES_32, length past the 68-byte
    NoPayout leaf, OP_TRUE terminator) separate this leaf from the app's others.  The
    signer prefix must then match the approved intent byte for byte, which is what stops a
    hand-crafted leaf of the same shape from reaching the Assert validator.  D is verified
    separately via TAP_BIP32_DERIVATION (BIP-86 path).

    Real Assert leaves are 11,526-13,636 bytes (btc-vault claim_assert.rs) and do NOT
    fit the read buffer, so no real Assert is signable yet (L-11).  This synthetic leaf
    fits, so the taproot commitment IS verified.
    The claim txid comes from tx.vin[0].prevout.hash (PSBTv0).
    """
    assert len(claim_txid) == 32

    # 106-byte signer prefix plus the OP_TRUE the WOTS verifier body ends with.  One byte
    # past the prefix is the minimum the device accepts: a leaf that stops at the prefix
    # carries no body and no terminator.
    assert_leaf = _assert_signer_prefix(leaf_key) + bytes([0x51])
    assert len(assert_leaf) == 107
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


def _realistic_assert_leaf(depositor_key: bytes, script_len: int) -> bytes:
    """Build an Assert-shaped leaf of exactly script_len bytes.

    Mirrors the btc-vault claim_assert.rs shape: the signer prefix rebuilt from the
    approved intent, a padding body standing in for the WOTS verifier, and the OP_TRUE
    terminator.  The device verifies the prefix and the terminator; the body is the part it
    cannot derive, so its content is irrelevant here — what matters is the total size.
    """
    prefix = _assert_signer_prefix(depositor_key)
    body_len = script_len - len(prefix) - 1
    assert body_len >= 0, f"script_len {script_len} too small for the Assert prefix"
    # OP_NOP (0x61) padding: valid script bytes that carry no consensus meaning here.
    leaf = prefix + bytes([0x61] * body_len) + bytes([0x51])  # ... OP_TRUE
    assert len(leaf) == script_len
    return leaf


def _rebuild_assert_commitment(psbt: PSBT, fingerprint: bytes, leaf_key: bytes,
                               coin_type: int, leaf: bytes, amount_carried: int) -> None:
    """Point the PSBT's input 0 at a single-leaf NUMS taptree committing to `leaf`."""
    leaf_hash = _tapleaf_hash(leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    psbt.inputs[0].witness_utxo = CTxOut(amount_carried, bytes([0x51, 0x20]) + tweaked)
    psbt.inputs[0].tap_scripts = {(leaf, 0xC0): {bytes([0xC0 | parity]) + VAULT_NUMS_XONLY}}
    psbt.inputs[0].tap_bip32_paths = {
        leaf_key: (
            {leaf_hash},
            KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
        )
    }


@pytest.mark.parametrize("script_len", [
    2559,   # largest leaf that still fits the device read buffer (buffered path)
    2560,   # first leaf that does NOT fit — streamed path
    2561,
    11662,  # the real Assert leaf size for 3 local / 3 universal challengers
])
def test_sign_psbt_assert_long_leaf_commitment_enforced(
    client: "RaggerClient",
    bitcoin_network: str,
    script_len: int,
) -> None:
    """A leaf whose taproot commitment does not match is rejected at every size.

    Real Assert leaves are 11,526-13,636 bytes (btc-vault claim_assert.rs) against a
    2560-byte read buffer, so they cannot be buffered; the device streams the PSBT value
    and folds it into the BIP-341 TapLeaf hash incrementally instead.  This is the test
    that proves the streamed hash is load-bearing: the scriptPubKey commits to a leaf
    differing from the PSBT's only in one interior body byte — same length, same 35-byte
    prefix, same OP_TRUE terminator — so nothing but a hash over the actual streamed bytes
    can tell them apart.

    Parametrised across the buffered/streamed boundary on purpose: 2559 takes the buffered
    path and 2560+ the streaming path, and both must reject identically.  Regression guard
    for the removed "truncated read" branch, which fabricated the leaf version and skipped
    the commitment check entirely once the value filled the buffer.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    leaf = _realistic_assert_leaf(leaf_key, script_len)

    other = bytearray(leaf)
    other[-2] ^= 0xFF  # interior body byte, not the prefix and not the terminator
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, _tapleaf_hash(bytes(other)))
    psbt.inputs[0].witness_utxo = CTxOut(5_000_000, bytes([0x51, 0x20]) + tweaked)
    psbt.inputs[0].tap_scripts = {(leaf, 0xC0): {bytes([0xC0 | parity]) + VAULT_NUMS_XONLY}}
    psbt.inputs[0].tap_bip32_paths = {
        leaf_key: (
            {_tapleaf_hash(leaf)},
            KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
        )
    }

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_real_size_leaf_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """A real-size (11,662-byte) Assert leaf with a correct commitment is signed.

    The positive direction of long-leaf support: the leaf cannot be buffered, so the
    device must stream it, hash it, verify the taproot commitment against the streamed
    hash, display Screen 5 and produce a signature.  Before streaming existed this PSBT
    was rejected outright, so this is the test that pins the new capability.

    Displayed fields (claim txid, amount carried, fee) are identical to the small-leaf
    Assert screen — the leaf itself is never displayed — so the goldens differ from
    screen5_assert/screen_* only in being a separate case.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    leaf = _realistic_assert_leaf(leaf_key, 11662)
    _rebuild_assert_commitment(psbt, fingerprint, leaf_key, coin_type, leaf, 5_000_000)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen5_assert/real_size_leaf_" + bitcoin_network
    if device.is_nano:
        client.sign_psbt(psbt, dummy_wallet, None, navigator,
                         testname=tname, instructions=sign_psbt_assert_approve_instructions(device))
    else:
        sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                       testname=tname,
                                       nav_instructions=sign_psbt_assert_approve_nav(device))


@pytest.mark.parametrize("script_len", [
    16384,  # first REJECTED script length: the PSBT value is script_len + 1 = 16385 > cap
    16385,
])
def test_sign_psbt_assert_leaf_over_stream_cap_is_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
    script_len: int,
) -> None:
    """A leaf whose PSBT value exceeds VAULT_ASSERT_SCRIPT_MAX_LEN is refused, not hashed.

    The cap is applied to the PSBT *value* — <script> || <leaf_version(1)> — so the largest
    accepted script is 16383 bytes and a 16384-byte script is already one too many.  16384
    pins that off-by-one; the accepted side of the streaming path is covered by
    test_sign_psbt_assert_real_size_leaf_screen (11,662 bytes, signs successfully).

    What this proves is that the device refuses to *process* an over-length value: no chunk
    of it is folded into the TapLeaf hash or buffered, and the read fails.  It does not, and
    cannot, prove the exchange is bounded — call_stream_preimage's length callback returns
    void, so the app cannot terminate a read the host has already started.  See
    docs/upstream-stream-preimage-abort.md.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    leaf = _realistic_assert_leaf(leaf_key, script_len)
    _rebuild_assert_commitment(psbt, fingerprint, leaf_key, coin_type, leaf, 5_000_000)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_spendable_catchall_leaf_is_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """A `<D> OP_CHECKSIGVERIFY <no-ops> OP_TRUE` leaf must not route to Assert.

    _validate_display_assert is the weakest validator in the app — no signing cap, no
    dedup, no output enforcement, and Screen 5 shows no destination.
    So it must match the Assert pattern only, never act as a catch-all: the HLD requires
    standalone leaf patterns to stay mutually exclusive and a PSBT matching no pattern to
    be rejected.

    This leaf is the dangerous shape specifically, not merely an unrecognised one: byte 34
    is OP_NOP rather than the challenger key's OP_PUSHBYTES_32, and the body is all no-ops,
    so the script is satisfied by the depositor signature alone — exactly the signature
    this path would hand out.  Regression guard for a router that required only
    `leaf_len > 68 && last == OP_TRUE`, which admitted it.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    # 0x20 <D> OP_CHECKSIGVERIFY then 34 x OP_NOP then OP_TRUE = 69 bytes.
    # byte 34 = 0x61 (OP_NOP): not OP_SIZE so not WC, not OP_PUSHBYTES_32 so not Assert.
    catchall_leaf = (
        bytes([0x20]) + leaf_key + bytes([0xAD])
        + bytes([0x61] * 34)
        + bytes([0x51])
    )
    assert len(catchall_leaf) == 69 and catchall_leaf[34] == 0x61
    assert len(catchall_leaf) > 68 and catchall_leaf[-1] == 0x51, "must clear the other two conjuncts"
    _rebuild_assert_commitment(psbt, fingerprint, leaf_key, coin_type, catchall_leaf, 5_000_000)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_shape_matching_crafted_leaf_is_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """A 70-byte leaf that satisfies every Assert *shape* byte must still be rejected.

    `<D> OP_CHECKSIGVERIFY <32B push> OP_CHECKSIG OP_DROP OP_TRUE` clears all four shape
    conjuncts: length 70 > 68, byte 34 == OP_PUSHBYTES_32, byte 67 == OP_CHECKSIG, terminal
    OP_TRUE.  The OP_DROP that defeats them sits at byte 68 — one past the captured prefix,
    so no shape test can ever see it.  Under consensus the leaf is spendable on the
    depositor signature alone: OP_CHECKSIGVERIFY consumes <sig_D>, OP_CHECKSIG with an empty
    signature pushes false without failing and without spending sigops budget (BIP-342),
    OP_DROP clears it, and OP_TRUE leaves the single true element tapscript CLEANSTACK
    wants.

    What rejects it is the signer-prefix comparison against the approved intent: byte 35
    begins a key the user never approved.  No length floor can substitute — the same
    structure works at any size, and `_realistic_assert_leaf` differs from a spendable
    11.6 KB variant by one OP_NOP.  Reported on PR #9.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    crafted_leaf = (
        bytes([0x20]) + leaf_key + bytes([0xAD])               # <D> OP_CHECKSIGVERIFY
        + bytes([0x20]) + bytes([0x03] * 32) + bytes([0xAC])   # <K> OP_CHECKSIG
        + bytes([0x75])                                        # OP_DROP  (byte 68)
        + bytes([0x51])                                        # OP_TRUE
    )
    assert len(crafted_leaf) == 70, "70 bytes is the shortest shape-matching bypass"
    assert crafted_leaf[34] == 0x20 and crafted_leaf[67] == 0xAC and crafted_leaf[-1] == 0x51, \
        "must clear every shape conjunct, or the test proves nothing"
    _rebuild_assert_commitment(psbt, fingerprint, leaf_key, coin_type, crafted_leaf, 5_000_000)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


@pytest.mark.no_intent
def test_sign_psbt_assert_without_approved_intent_is_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """A fully valid Assert PSBT is refused when the session holds no approved intent.

    The challenger set the leaf must be checked against exists nowhere but the intent, so
    outside VAULT_STATE_INTENT_LOADED the device cannot tell an Assert leaf from a
    hand-crafted one and refuses to sign rather than falling back to a shape-only test.
    Fail closed, per EMBEDDED "Security and Availability".

    Note this is a deliberate behaviour change: Assert was previously accepted from any
    state, including IDLE.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_unapproved_challenger_is_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """A real-shaped, real-sized Assert leaf whose challenger set is not the approved one.

    Everything the device can check structurally is correct: the full signer prefix layout,
    an 11,662-byte body, the OP_TRUE terminator, a self-consistent taproot commitment, and
    the device's own depositor key as claimer.  Only the keeper key inside the first
    multisig group differs from the intent the user approved.

    This is the case that carries the security property.  If it were accepted, a host that
    got the depositor to fund a taptree of its choosing could have the device sign a leaf
    whose N-of-N and M-of-M groups it controls, and spend without any real challenger.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    unapproved_keeper = bytes([0x07] * 32)
    assert unapproved_keeper not in _TEST_KEEPER_PKS
    prefix = (
        bytes([0x20]) + leaf_key + bytes([0xAD])
        + _multisig_group([unapproved_keeper], False)
        + _multisig_group(_TEST_CHALLENGER_PKS, False)
    )
    leaf = prefix + bytes([0x61] * (11_662 - len(prefix) - 1)) + bytes([0x51])
    assert len(leaf) == 11_662 and leaf[34] == 0x20 and leaf[67] == 0xAC and leaf[-1] == 0x51
    _rebuild_assert_commitment(psbt, fingerprint, leaf_key, coin_type, leaf, 5_000_000)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_assert_leaf_ending_at_signer_prefix_is_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """A leaf that is exactly the approved signer prefix and nothing more is rejected.

    Every prefix byte matches, but a leaf stopping there carries no WOTS verifier body and
    ends in OP_NUMEQUALVERIFY, so the shape test refuses it before the prefix result is
    consulted.  The two checks overlap here by design: assert_prefix_ok also requires the
    script to continue past the prefix, so neither check depends on the other to keep this
    leaf out.
    """
    fingerprint, leaf_key, coin_type = _assert_keys(client, bitcoin_network)
    psbt = _build_assert_psbt(fingerprint, leaf_key, coin_type)
    prefix_only_leaf = _assert_signer_prefix(leaf_key)
    assert len(prefix_only_leaf) == 106
    _rebuild_assert_commitment(psbt, fingerprint, leaf_key, coin_type, prefix_only_leaf, 5_000_000)

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
    OP_CHECKSIG`, 68 bytes) shares the Assert leaf's whole 34-byte head and both group-0
    shape bytes, and NoPayout is routed only by transaction shape (3 inputs / 1 output).  So
    the same Assert:0 UTXO re-presented in a 1-in/1-out PSBT must not be accepted down the
    Assert path, which applies no signing cap and no per-(group, challenger) dedup.

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
