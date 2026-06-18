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

from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from ledger_bitcoin import WalletPolicy
from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness

from test_utils.taproot import tagged_hash, taproot_tweak_pubkey, ser_script

from .vault_client import (
    SW_DENY,
    SW_BAD_STATE,
    SW_INCORRECT_DATA,
    derive_context_hash,
    approve_vault_intent_with_nav,
    sign_psbt_with_nav_and_compare,
    build_intent_tlv,
    TEST_VP_KEY,
    TEST_VALID_KEYS,
    TEST_DEPOSITOR_XONLY_MAINNET,
    TEST_DEPOSITOR_XONLY_TESTNET,
)
from .instructions import (
    sign_psbt_refund_instructions,
    sign_psbt_refund_nav,
    sign_psbt_prepegin_instructions,
    sign_psbt_prepegin_nav,
)

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


# ---------------------------------------------------------------------------
# Test intent parameters (shared by Pre-PegIn and PegIn tests)
# ---------------------------------------------------------------------------

_VAULT_AMOUNT         = 9_876_543   # 0.09876543 BTC — all 8 decimal places
_COMMISSION_FEE       = 54_321      # 0.00054321 BTC
_DEPOSITOR_CLAIM_VALUE = 12_345     # 0.00012345 BTC
_BASE_FEE_RATE        = 1
_PEGIN_MAX_FEE        = 567_891     # 0.00567891 BTC
_PEGIN_CSV_TIMELOCK   = 144
_PAYOUT_TIMELOCK      = 200
_HTLC_REFUND_TIMELOCK = 144
_HTLC_VOUT            = 0
# htlc_value must be in [vault_amount + depositor_claim_value,
#                         vault_amount + depositor_claim_value + pegin_max_fee]
_HTLC_VALUE           = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + 234_567  # 10_123_455

# Single keeper and challenger for all tests (sorted ascending — key[0] < key[1])
_TEST_KEEPER_PKS     = [TEST_VALID_KEYS[0]]
_TEST_CHALLENGER_PKS = [TEST_VALID_KEYS[1]]

# Session 2: the txid of the Pre-PegIn transaction committed to in the intent.
_PREPEGIN_TXID = bytes(range(32))


# ---------------------------------------------------------------------------
# Python replicas of the C vault_script.c leaf builders
# ---------------------------------------------------------------------------

def _multisig_group(keys: List[bytes], is_final: bool) -> bytes:
    """N-of-N multisig fragment.  is_final=True uses OP_NUMEQUAL; False uses OP_NUMEQUALVERIFY."""
    if len(keys) == 1:
        return bytes([0x20]) + keys[0] + bytes([0xac if is_final else 0xad])
    out = bytes([0x20]) + keys[0] + bytes([0xac])   # first key: OP_CHECKSIG
    for k in keys[1:]:
        out += bytes([0x20]) + k + bytes([0xba])     # remaining keys: OP_CHECKSIGADD
    out += _encode_script_num(len(keys))
    out += bytes([0x9c if is_final else 0x9d])       # OP_NUMEQUAL / OP_NUMEQUALVERIFY
    return out


def _htlc_leaf0(depositor_pk: bytes, vp_pk: bytes,
                keeper_pks: List[bytes], challenger_pks: List[bytes],
                h: bytes) -> bytes:
    """HTLC Leaf 0: OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <h> OP_EQUALVERIFY
                    <D> OP_CHECKSIGVERIFY <VP> OP_CHECKSIGVERIFY
                    <VK N-of-N intermediate> <UC M-of-M final>"""
    s  = bytes([0x82]) + _encode_script_num(32) + bytes([0x88])  # OP_SIZE 32 OP_EQUALVERIFY
    s += bytes([0xa8, 0x20]) + h + bytes([0x88])                  # OP_SHA256 <h> OP_EQUALVERIFY
    s += bytes([0x20]) + depositor_pk + bytes([0xad])             # <D> OP_CHECKSIGVERIFY
    s += bytes([0x20]) + vp_pk + bytes([0xad])                    # <VP> OP_CHECKSIGVERIFY
    s += _multisig_group(keeper_pks, False)
    s += _multisig_group(challenger_pks, True)
    return s


def _htlc_leaf1(depositor_pk: bytes, htlc_refund_timelock: int) -> bytes:
    """HTLC Leaf 1: <D> OP_CHECKSIGVERIFY <T_refund> OP_CSV"""
    return (bytes([0x20]) + depositor_pk + bytes([0xad])
            + _encode_script_num(htlc_refund_timelock) + bytes([0xb2]))


def _vault_utxo_leaf(depositor_pk: bytes, vp_pk: bytes,
                     keeper_pks: List[bytes], challenger_pks: List[bytes],
                     pegin_csv_timelock: int) -> bytes:
    """Vault UTXO leaf: <D> OP_CHECKSIGVERIFY <VP> OP_CHECKSIGVERIFY
                        <VK N-of-N int.> <UC M-of-M int.> <P> OP_CSV"""
    s  = bytes([0x20]) + depositor_pk + bytes([0xad])
    s += bytes([0x20]) + vp_pk + bytes([0xad])
    s += _multisig_group(keeper_pks, False)
    s += _multisig_group(challenger_pks, False)
    s += _encode_script_num(pegin_csv_timelock) + bytes([0xb2])
    return s


def _depositor_claim_leaf(depositor_pk: bytes) -> bytes:
    """Depositor Claim leaf: <D> OP_CHECKSIG"""
    return bytes([0x20]) + depositor_pk + bytes([0xac])


def _tapleaf_hash(script: bytes) -> bytes:
    return tagged_hash("TapLeaf", bytes([0xC0]) + ser_script(script))


def _taptree2_root(leaf0: bytes, leaf1: bytes) -> bytes:
    """TapBranch hash of two leaves, sorted (BIP-341)."""
    lh0 = _tapleaf_hash(leaf0)
    lh1 = _tapleaf_hash(leaf1)
    left, right = (lh0, lh1) if lh0 <= lh1 else (lh1, lh0)
    return tagged_hash("TapBranch", left + right)


def _p2tr_from_single_leaf(leaf: bytes) -> bytes:
    """P2TR scriptPubKey for a single-leaf taptree rooted at NUMS internal key."""
    lh = _tapleaf_hash(leaf)
    _, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, lh)
    return bytes([0x51, 0x20]) + tweaked


def _htlc_output(depositor_pk: bytes, vp_pk: bytes,
                 keeper_pks: List[bytes], challenger_pks: List[bytes],
                 htlc_refund_timelock: int,
                 h: bytes):
    """Build HTLC taptree output.  Returns (parity, merkle_root, leaf0, leaf1, htlc_spk)."""
    leaf0 = _htlc_leaf0(depositor_pk, vp_pk, keeper_pks, challenger_pks, h)
    leaf1 = _htlc_leaf1(depositor_pk, htlc_refund_timelock)
    merkle_root = _taptree2_root(leaf0, leaf1)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, merkle_root)
    return parity, merkle_root, leaf0, leaf1, bytes([0x51, 0x20]) + tweaked


# ---------------------------------------------------------------------------
# Wallet-policy helpers
# ---------------------------------------------------------------------------

def _standard_taproot_wallet(client: "RaggerClient", coin_type: int) -> WalletPolicy:
    """Standard BIP-86 P2TR wallet for the test device.  wallet_id != all-zeros →
    has_no_wallet_policy = false → SIGN_PSBT routes to Pre-PegIn validator."""
    fingerprint = client.get_master_fingerprint()
    xpub = client.get_extended_pubkey(f"m/86'/{coin_type}'/0'", display=False)
    return WalletPolicy(
        name="",
        descriptor_template="tr(@0/**)",
        keys_info=[f"[{fingerprint.hex()}/86'/{coin_type}'/0']{xpub}"],
    )


# ---------------------------------------------------------------------------
# PSBT builders
# ---------------------------------------------------------------------------

def _build_prepegin_psbt(
    htlc_spk: bytes,
    htlc_value: int = _HTLC_VALUE,
    htlc_vout: int = _HTLC_VOUT,
    tx_version: int = 2,
    locktime: int = 0,
) -> PSBT:
    """1-input / 1-output (HTLC) Pre-PegIn PSBTv0.

    The single output is the HTLC P2TR at htlc_vout=0.  With no other outputs,
    the 'all other outputs are internal' check trivially passes.
    """
    input_value = htlc_value + 3_456  # pre-pegin tx fee = 3456 sats = 0.00003456 BTC
    input_spk = bytes([0x51, 0x20]) + bytes(32)  # dummy P2TR

    tx = CTransaction()
    tx.nVersion = tx_version
    tx.nLockTime = locktime
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xaa' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [CTxOut(htlc_value, htlc_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(input_value, input_spk)

    return psbt


def _build_pegin_psbt(
    depositor_pk: bytes,
    hashlock: bytes,
    prepegin_txid: bytes,
    htlc_vout: int = _HTLC_VOUT,
    htlc_value: int = _HTLC_VALUE,
    vault_amount: int = _VAULT_AMOUNT,
    depositor_claim_value: int = _DEPOSITOR_CLAIM_VALUE,
) -> PSBT:
    """Build a correct PegIn PSBTv0.

    Input 0 spends the HTLC UTXO (previous txid = prepegin_txid, vout = htlc_vout).
    Output 0 = Vault UTXO, output 1 = Depositor Claim UTXO.
    TAP_LEAF_SCRIPT carries Leaf 0 (the hashlock leaf) keyed by the control block
    for spending via Leaf 0.
    """
    parity, merkle_root, leaf0, leaf1, htlc_spk = _htlc_output(
        depositor_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )

    vault_spk = _p2tr_from_single_leaf(_vault_utxo_leaf(
        depositor_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _PEGIN_CSV_TIMELOCK,
    ))
    claim_spk = _p2tr_from_single_leaf(_depositor_claim_leaf(depositor_pk))

    # Control block for spending Leaf 0: the sibling hash is Leaf 1's hash.
    lh1 = _tapleaf_hash(leaf1)
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY + lh1

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(prepegin_txid, 'little'), htlc_vout)
    tx.vin[0].nSequence = 0xFFFFFFFE
    tx.vout = [CTxOut(vault_amount, vault_spk), CTxOut(depositor_claim_value, claim_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0), PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(htlc_value, htlc_spk)
    psbt.inputs[0].tap_internal_key = VAULT_NUMS_XONLY
    psbt.inputs[0].tap_merkle_root = merkle_root
    psbt.inputs[0].tap_scripts[(leaf0, 0xC0)] = {control_block}

    return psbt


# ---------------------------------------------------------------------------
# Session setup helpers (both sessions require navigating the vault intent screen)
# ---------------------------------------------------------------------------

def _depositor_pk(bitcoin_network: str) -> bytes:
    return TEST_DEPOSITOR_XONLY_MAINNET if bitcoin_network == "main" else TEST_DEPOSITOR_XONLY_TESTNET


def _build_intent_tlv_for_test(
    coin_type: int,
    prepegin_txid: bytes,
) -> bytes:
    return build_intent_tlv(
        coin_type=coin_type,
        vault_provider_pk=TEST_VP_KEY,
        vault_amount=_VAULT_AMOUNT,
        commission_fee=_COMMISSION_FEE,
        depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
        base_fee_rate=_BASE_FEE_RATE,
        pegin_max_fee=_PEGIN_MAX_FEE,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=prepegin_txid,
        htlc_vout=_HTLC_VOUT,
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=[HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0],
        keeper_count=len(_TEST_KEEPER_PKS),
        challenger_count=len(_TEST_CHALLENGER_PKS),
    )


def _setup_s1_state(
    client: "RaggerClient",
    navigator: "Navigator",
    device,
    coin_type: int,
) -> bytes:
    """Derive hashlock + approve intent (Session 1).  Returns the 32-byte hashlock.

    After this call the device is in VAULT_STATE_INTENT_LOADED with htlc_hashlock set.
    """
    hashlock = derive_context_hash(client, b"BabylonVault", b"")
    scalars_tlv = _build_intent_tlv_for_test(coin_type, bytes(32))
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
    )
    return hashlock


def _setup_s2_state(
    client: "RaggerClient",
    navigator: "Navigator",
    device,
    coin_type: int,
    prepegin_txid: bytes = _PREPEGIN_TXID,
) -> bytes:
    """Derive hashlock + approve intent (Session 2).  Returns the 32-byte hashlock.

    After this call the device is in VAULT_STATE_SESSION2_PEGIN_EXPECTED.
    prepegin_txid must be non-zero to trigger the extra state transition.
    """
    assert any(prepegin_txid), "prepegin_txid must be non-zero for Session 2"
    hashlock = derive_context_hash(client, b"BabylonVault", b"")
    scalars_tlv = _build_intent_tlv_for_test(coin_type, prepegin_txid)
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
    )
    return hashlock


def _build_refund_psbt(
    fingerprint: bytes,
    leaf_key: bytes,
    out_key: bytes,
    coin_type: int,
    htlc_value: int = 1_235_801,
    reclaimed_value: int = 1_234_567,
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
    device: Device,
    bitcoin_network: str,
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
    tname = "refund/screen_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, dummy_wallet, None, navigator,
                             testname=tname, instructions=sign_psbt_refund_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                           testname=tname, nav_instructions=sign_psbt_refund_nav(device))
    assert exc.value.status == SW_DENY


# ===========================================================================
# Screen 2 — Pre-PegIn transaction review (NAPPS-1375)
# ===========================================================================

def test_sign_psbt_prepegin_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Golden snapshot for Screen 2 (Pre-PegIn review). Navigates and rejects."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )

    psbt = _build_prepegin_psbt(htlc_spk)
    wallet = _standard_taproot_wallet(client, coin_type)
    tname = "prepegin/screen_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, wallet, None, navigator,
                             testname=tname, instructions=sign_psbt_prepegin_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, wallet, None, navigator,
                                           testname=tname, nav_instructions=sign_psbt_prepegin_nav(device))
    assert exc.value.status == SW_DENY


def test_sign_psbt_prepegin_no_state(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Pre-PegIn fails with SW_BAD_STATE when no vault session is active."""
    coin_type = 0 if bitcoin_network == "main" else 1
    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(bytes([0x51, 0x20]) + bytes(32))

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_BAD_STATE


def test_sign_psbt_prepegin_no_hashlock(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails with SW_BAD_STATE when intent is loaded but no hashlock was derived."""
    coin_type = 0 if bitcoin_network == "main" else 1
    # Approve intent without calling derive_context_hash first → hashlock stays zero
    scalars_tlv = _build_intent_tlv_for_test(coin_type, bytes(32))
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
    )

    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(bytes([0x51, 0x20]) + bytes(32))

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_BAD_STATE


def test_sign_psbt_prepegin_wrong_htlc_spk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when the HTLC output scriptPubKey doesn't match the expected one."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_s1_state(client, navigator, device, coin_type)

    # Build HTLC SPK with a wrong h (zeros != actual hashlock) — SPK won't match
    _, _, _, _, wrong_htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, bytes(32),
    )

    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(wrong_htlc_spk)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_htlc_value_too_low(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when the HTLC output value is below vault_amount + depositor_claim_value."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )

    too_low = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE - 1
    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(htlc_spk, htlc_value=too_low)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# Screen 3 — Refund transaction review negative tests (NAPPS-1375)
# ===========================================================================

def test_sign_psbt_refund_wrong_fingerprint(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when the TAP_BIP32_DERIVATION fingerprint belongs to a foreign key."""
    coin_type = 0 if bitcoin_network == "main" else 1
    wrong_fingerprint = b'\xff\xff\xff\xff'

    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(wrong_fingerprint, leaf_key, out_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_nonzero_locktime(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when nLockTime != 0."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()

    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.tx.nLockTime = 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# PegIn transaction validation (NAPPS-1375)
# ===========================================================================

def test_sign_psbt_pegin(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn validation passes silently, state advances to SESSION2_PAYOUT_EXPECTED.

    sign_custom_inputs is not yet implemented (NAPPS-1377 stub returns false), so the
    btcext dispatcher emits SW_BAD_STATE after validation succeeds.  The test asserts
    SW_BAD_STATE to confirm that validation itself passed (any validation error would
    produce SW_INCORRECT_DATA or SW_BAD_STATE from a different code path earlier).
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_BAD_STATE


def test_sign_psbt_pegin_wrong_txid(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when PSBT_IN_PREVIOUS_TXID doesn't match intent->prepegin_txid."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    wrong_txid = bytes([0xff] * 32)
    psbt = _build_pegin_psbt(dep_pk, hashlock, wrong_txid)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_fee_too_high(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when htlc_value - vault_amount - depositor_claim_value > pegin_max_fee."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    excessive_htlc = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_MAX_FEE + 1
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID, htlc_value=excessive_htlc)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_leaf0(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when TAP_LEAF_SCRIPT contains a different h (h-substitution attack)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    # Build PSBT with a hashlock that differs from what the device derived
    wrong_h = bytes([0xde] * 32)
    psbt = _build_pegin_psbt(dep_pk, wrong_h, _PREPEGIN_TXID)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# Pre-PegIn — additional negative tests (NAPPS-1375)
# ===========================================================================

def test_sign_psbt_prepegin_external_output(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when a non-HTLC output is external (not owned by this device)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )

    psbt = _build_prepegin_psbt(htlc_spk)
    # Append a second output with no TAP_BIP32_DERIVATION — btcext marks it external.
    psbt.tx.vout.append(CTxOut(1000, bytes([0x51, 0x20]) + bytes(32)))
    psbt.outputs.append(PartiallySignedOutput(0))

    wallet = _standard_taproot_wallet(client, coin_type)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# Refund — additional negative tests (NAPPS-1375)
# ===========================================================================

def test_sign_psbt_refund_wrong_leaf_shape(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when the leaf script opcode is OP_CHECKSIG instead of OP_CHECKSIGVERIFY."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)

    # Replace the TAP_LEAF_SCRIPT entry: swap OP_CHECKSIGVERIFY (0xAD) → OP_CHECKSIG (0xAC).
    # The correct leaf is: 0x20 || leaf_key(32B) || 0xAD || csv_push || 0xB2.
    # Byte 33 is the opcode immediately after the 32-byte key push.
    (orig_leaf, leaf_ver), control_blocks = next(iter(psbt.inputs[0].tap_scripts.items()))
    wrong_leaf = orig_leaf[:33] + bytes([0xAC]) + orig_leaf[34:]
    psbt.inputs[0].tap_scripts = {(wrong_leaf, leaf_ver): control_blocks}

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_tampered_control_block(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when the control block uses a wrong internal key (taproot commitment mismatch)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)

    # Replace the control block with one that has a different internal key.
    # The witness_utxo HTLC SPK (from NUMS) is left unchanged, so the device's
    # taproot commitment check will produce a different tweaked key and reject.
    (leaf_bytes, leaf_ver), _ = next(iter(psbt.inputs[0].tap_scripts.items()))
    wrong_internal_key = bytes([0x01] * 32)  # anything other than NUMS_XONLY
    wrong_cb = bytes([0xC0]) + wrong_internal_key
    psbt.inputs[0].tap_scripts = {(leaf_bytes, leaf_ver): {wrong_cb}}

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_no_output_derivation(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when the output has no TAP_BIP32_DERIVATION (cannot verify ownership)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.outputs[0].tap_bip32_paths = {}

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# PegIn — additional negative tests (NAPPS-1375)
# ===========================================================================

def test_sign_psbt_pegin_extra_input(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when the PSBT has 2 inputs instead of exactly 1."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_sequence(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when input sequence is not 0xFFFFFFFE."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vin[0].nSequence = 0xFFFFFFFF

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_vault_spk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when output 0 scriptPubKey does not match the reconstructed Vault UTXO."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vout[0].scriptPubKey = bytes([0x51, 0x20]) + bytes(32)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_extra_output(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when the PSBT has 3 outputs instead of exactly 2."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vout.append(CTxOut(1000, bytes([0x51, 0x20]) + bytes(32)))
    psbt.outputs.append(PartiallySignedOutput(0))

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_vault_amount(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when output 0 amount does not equal vault_amount from the intent."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vout[0].nValue = _VAULT_AMOUNT - 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_depositor_claim_amount(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when output 1 amount does not equal depositor_claim_value from the intent."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vout[1].nValue = _DEPOSITOR_CLAIM_VALUE - 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA
