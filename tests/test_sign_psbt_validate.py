"""
Snapshot tests for sign_psbt validation screens added in NAPPS-1375.
Payout validation tests added in NAPPS-1376.

Screen 3 — Refund transaction review: a pure tapscript spend (has_no_wallet_policy=true)
that shows "Reclaimed amount" and "Transaction fee" fields.

Run with --golden_run to generate reference snapshots:

    pytest tests/test_sign_psbt_validate.py --golden_run -k flex
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional
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

from test_utils.taproot import tagged_hash, taproot_tweak_pubkey, ser_script, pubkey_gen

from .vault_client import (
    SW_DENY,
    SW_BAD_STATE,
    SW_INCORRECT_DATA,
    CLA_VAULT,
    INS_APPROVE_VAULT_INTENT,
    P1_SCALARS,
    P1_KEY_BATCH,
    P2_UNUSED,
    derive_context_hash,
    approve_vault_intent_with_nav,
    sign_psbt_with_nav_and_compare,
    build_intent_tlv,
    VAULT_APP_NAME,
    vault_hashlock,
    vault_auth_anchor,
    depositor_path,
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
# P2A anchor value in the v3 PegIn — must match PEGIN_P2A_ANCHOR_VALUE in vault_constants.h
_PEGIN_P2A_ANCHOR_VALUE = 240

# htlc_value must be in [vault_amount + depositor_claim_value + anchor,
#                         vault_amount + depositor_claim_value + anchor + pegin_max_fee]
_HTLC_VALUE           = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_P2A_ANCHOR_VALUE + 234_567

# Single keeper and challenger for all tests (sorted ascending — key[0] < key[1])
_TEST_KEEPER_PKS     = [TEST_VALID_KEYS[0]]
_TEST_CHALLENGER_PKS = [TEST_VALID_KEYS[1]]

# Firmware participant caps and script buffer ceiling — must match src/vault_intent.h
# (VAULT_MAX_KEEPERS / VAULT_MAX_CHALLENGERS) and src/vault_script.h
# (VAULT_SCRIPT_MAX_LEN).  At the 32/32 maximum, HTLC Leaf 0 — which embeds
# depositor + VP + every keeper + every challenger — is the largest single script
# the device reconstructs into its VAULT_SCRIPT_MAX_LEN buffer.
VAULT_MAX_KEEPERS     = 32
VAULT_MAX_CHALLENGERS = 32
VAULT_SCRIPT_MAX_LEN  = 2560

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
    input_internal_key: Optional[bytes] = None,
    input_fingerprint: Optional[bytes] = None,
    input_coin_type: int = 0,
    auth_anchor: Optional[bytes] = None,
    auth_anchor_value: int = 0,
) -> PSBT:
    """Pre-PegIn PSBTv0: HTLC output at htlc_vout, plus the mandatory auth-anchor
    OP_RETURN when auth_anchor is given.

    The device now requires the shared OP_RETURN = "OP_RETURN <SHA256(authAnchor)>"
    (= 0x6A 0x20 || auth_anchor); pass auth_anchor=vault_auth_anchor(root) for the
    happy path. Negative tests that reject before the output policy may omit it.

    When input_internal_key and input_fingerprint are provided the input is a
    proper BIP-86 key-path P2TR UTXO (required for the 'all inputs internal'
    validation check in _validate_display_prepegin).
    """
    input_value = htlc_value + 3_456  # pre-pegin tx fee = 3456 sats = 0.00003456 BTC

    if input_internal_key is not None and input_fingerprint is not None:
        _, input_tweaked = taproot_tweak_pubkey(input_internal_key, b'')
        input_spk = bytes([0x51, 0x20]) + input_tweaked
    else:
        input_spk = bytes([0x51, 0x20]) + bytes(32)  # dummy P2TR (only valid when state guard fires first)

    tx = CTransaction()
    tx.nVersion = tx_version
    tx.nLockTime = locktime
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xaa' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [CTxOut(htlc_value, htlc_spk)]
    if auth_anchor is not None:
        # Shared auth-anchor OP_RETURN: OP_RETURN OP_PUSHBYTES_32 <SHA256(authAnchor)>.
        # Value is 0 on the happy path; auth_anchor_value > 0 exercises the burn guard.
        tx.vout.append(CTxOut(auth_anchor_value, bytes([0x6A, 0x20]) + auth_anchor))
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0) for _ in tx.vout]

    psbt.inputs[0].witness_utxo = CTxOut(input_value, input_spk)

    if input_internal_key is not None and input_fingerprint is not None:
        psbt.inputs[0].tap_bip32_paths[input_internal_key] = (
            set(),
            KeyOriginInfo(
                input_fingerprint,
                [HARDENED | 86, HARDENED | input_coin_type, HARDENED | 0, 0, 0],
            ),
        )

    return psbt


def _build_pegin_psbt(
    depositor_pk: bytes,
    hashlock: bytes,
    prepegin_txid: bytes,
    htlc_vout: int = _HTLC_VOUT,
    htlc_value: int = _HTLC_VALUE,
    vault_amount: int = _VAULT_AMOUNT,
    depositor_claim_value: int = _DEPOSITOR_CLAIM_VALUE,
    keeper_pks: Optional[List[bytes]] = None,
    challenger_pks: Optional[List[bytes]] = None,
) -> PSBT:
    """Build a correct PegIn PSBTv0.

    Input 0 spends the HTLC UTXO (previous txid = prepegin_txid, vout = htlc_vout).
    Output 0 = Vault UTXO, output 1 = Depositor Claim UTXO, output 2 = P2A anchor.
    TAP_LEAF_SCRIPT carries Leaf 0 (the hashlock leaf) keyed by the control block
    for spending via Leaf 0.

    keeper_pks / challenger_pks default to the single-keeper / single-challenger
    test sets; pass larger sorted sets to grow Leaf 0 toward VAULT_SCRIPT_MAX_LEN.
    """
    if keeper_pks is None:
        keeper_pks = _TEST_KEEPER_PKS
    if challenger_pks is None:
        challenger_pks = _TEST_CHALLENGER_PKS

    parity, merkle_root, leaf0, leaf1, htlc_spk = _htlc_output(
        depositor_pk, TEST_VP_KEY, keeper_pks, challenger_pks,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )

    vault_spk = _p2tr_from_single_leaf(_vault_utxo_leaf(
        depositor_pk, TEST_VP_KEY, keeper_pks, challenger_pks, _PEGIN_CSV_TIMELOCK,
    ))
    claim_spk = _p2tr_from_single_leaf(_depositor_claim_leaf(depositor_pk))

    # Control block for spending Leaf 0: the sibling hash is Leaf 1's hash.
    lh1 = _tapleaf_hash(leaf1)
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY + lh1

    p2a_spk = bytes([0x51, 0x02, 0x4e, 0x73])

    tx = CTransaction()
    tx.nVersion = 3  # TRUC (BIP-431)
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(prepegin_txid, 'little'), htlc_vout)
    tx.vin[0].nSequence = 0xFFFFFFFE
    tx.vout = [
        CTxOut(vault_amount, vault_spk),
        CTxOut(depositor_claim_value, claim_spk),
        CTxOut(_PEGIN_P2A_ANCHOR_VALUE, p2a_spk),
    ]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0), PartiallySignedOutput(0), PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(htlc_value, htlc_spk)
    psbt.inputs[0].tap_internal_key = VAULT_NUMS_XONLY
    psbt.inputs[0].tap_merkle_root = merkle_root
    psbt.inputs[0].tap_scripts[(leaf0, 0xC0)] = {control_block}

    return psbt


# ---------------------------------------------------------------------------
# Pre-PegIn input key helpers
# ---------------------------------------------------------------------------

def _prepegin_input_key(client: "RaggerClient", coin_type: int):
    """Return (fingerprint, internal_key) for a BIP-86 P2TR input at m/86'/{coin_type}'/0'/0/0.

    The 'all inputs internal' check in _validate_display_prepegin requires the
    input witness_utxo to have a BIP-86 tweaked key derived from this device's
    wallet.  Pass the returned values as input_fingerprint/input_internal_key to
    _build_prepegin_psbt.
    """
    fingerprint = client.get_master_fingerprint()
    internal_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    return fingerprint, internal_key


# ---------------------------------------------------------------------------
# Session setup helpers (both sessions require navigating the vault intent screen)
# ---------------------------------------------------------------------------

def _depositor_pk(bitcoin_network: str) -> bytes:
    return TEST_DEPOSITOR_XONLY_MAINNET if bitcoin_network == "main" else TEST_DEPOSITOR_XONLY_TESTNET


def _assert_single_schnorr_sig(result, expected_xonly: bytes, expected_input: int = 0) -> None:
    """Assert a custom-input sign yielded exactly one usable signature.

    A successful vault custom-input sign (PegIn / Payout / Refund) returns a single
    BIP-340 Schnorr signature — 64 bytes, since the device signs SIGHASH_DEFAULT — for
    `expected_input`, produced by `expected_xonly`.  Checking the yielded value (not just
    the SW_OK) guards against a regression that returns success without a valid signature.
    """
    assert len(result) == 1, f"expected exactly one signature, got {len(result)}: {result}"
    input_index, partial_sig = result[0]
    assert input_index == expected_input, f"signed unexpected input {input_index}"
    assert partial_sig.pubkey[-32:] == expected_xonly, "signed with an unexpected key"
    assert len(partial_sig.signature) == 64, (
        f"expected 64-byte SIGHASH_DEFAULT Schnorr sig, got {len(partial_sig.signature)}")


def _build_intent_tlv_for_test(
    coin_type: int,
    prepegin_txid: bytes,
    keeper_pks: Optional[List[bytes]] = None,
    challenger_pks: Optional[List[bytes]] = None,
) -> bytes:
    if keeper_pks is None:
        keeper_pks = _TEST_KEEPER_PKS
    if challenger_pks is None:
        challenger_pks = _TEST_CHALLENGER_PKS
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
        depositor_path=depositor_path(coin_type),
        keeper_count=len(keeper_pks),
        challenger_count=len(challenger_pks),
    )


# DERIVE_CONTEXT_HASH session inputs. The context just needs to be non-empty (the
# device folds it into the root); the connectedPubkey path is any valid BIP-32 path
# the device can derive. The device returns the root, from which the host recomputes
# the same on-chain commitments via Expand (vault_hashlock / vault_auth_anchor).
_DERIVE_CONTEXT = bytes(range(72))  # fixed non-empty vaultContext-shaped blob



# Root returned by the most recent _setup_sN call — used to bind the Pre-PegIn
# OP_RETURN auth-anchor in _build_prepegin_psbt.
_DERIVED_ROOT: bytes = b""


def _derive_root_and_hashlock(client: "RaggerClient", navigator: "Navigator", device, coin_type: int) -> bytes:
    """Run DERIVE_CONTEXT_HASH, stash the root, and return the per-vault hashlock h."""
    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(client, VAULT_APP_NAME, depositor_path(coin_type),
                                        _DERIVE_CONTEXT, navigator, device)
    return vault_hashlock(_DERIVED_ROOT, _HTLC_VOUT)


def _setup_s1_state(
    client: "RaggerClient",
    navigator: "Navigator",
    device,
    coin_type: int,
) -> bytes:
    """Derive root + approve intent (Session 1).  Returns the 32-byte hashlock h.

    After this call the device is in VAULT_STATE_INTENT_LOADED with htlc_hashlock set.
    """
    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
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
    keeper_pks: Optional[List[bytes]] = None,
    challenger_pks: Optional[List[bytes]] = None,
) -> bytes:
    """Derive root + approve intent (Session 2).  Returns the 32-byte hashlock h.

    After this call the device is in VAULT_STATE_SESSION2_PEGIN_EXPECTED.
    prepegin_txid must be non-zero to trigger the extra state transition.

    keeper_pks / challenger_pks default to the single-keeper / single-challenger
    test sets; pass larger sorted sets to approve a many-participant vault.
    """
    if keeper_pks is None:
        keeper_pks = _TEST_KEEPER_PKS
    if challenger_pks is None:
        challenger_pks = _TEST_CHALLENGER_PKS
    assert any(prepegin_txid), "prepegin_txid must be non-zero for Session 2"
    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    scalars_tlv = _build_intent_tlv_for_test(coin_type, prepegin_txid, keeper_pks, challenger_pks)
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, keeper_pks, challenger_pks,
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

    # BIP-86: output key = taproot_tweak(internal_key, tagged_hash("TapTweak", internal_key))
    # taproot_tweak_pubkey(key, b'') applies the key-path-only (empty script tree) tweak.
    _, bip86_out_key = taproot_tweak_pubkey(out_key, b'')
    out_script = bytes([0x51, 0x20]) + bip86_out_key


    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\x42' * 32, 'little'), 0)
    tx.vin[0].nSequence = csv_timelock
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

    # PSBT_OUT_TAP_BIP32_DERIVATION is keyed by the tweaked output key (bip86_out_key),
    # but the derivation path records the internal (untweaked) key's path.
    psbt.outputs[0].tap_bip32_paths[bip86_out_key] = (
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

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt(htlc_spk,
                                input_internal_key=input_key,
                                input_fingerprint=fingerprint,
                                input_coin_type=coin_type,
                                auth_anchor=vault_auth_anchor(_DERIVED_ROOT))
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


def test_sign_psbt_prepegin_anchor_nonzero_value_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """The auth-anchor OP_RETURN must carry zero value.

    A non-zero value burns the depositor's own change into a provably-unspendable
    output, and neither the OP_RETURN nor the change is shown on the approval screen —
    so the device must reject it (WYSIWYS) rather than sign a hidden burn.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(htlc_spk,
                                input_internal_key=input_key,
                                input_fingerprint=fingerprint,
                                input_coin_type=coin_type,
                                auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
                                auth_anchor_value=1000)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


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
    bitcoin_network: str,
) -> None:
    """APPROVE_VAULT_INTENT key-batch is rejected with SW_BAD_STATE when DERIVE_CONTEXT_HASH
    was not called first.

    The state machine requires HASH_DERIVED before INTENT_LOADED.  The firmware detects
    this before showing the approval screen so no navigation is needed.  As a consequence,
    it is now impossible to reach INTENT_LOADED with an all-zero htlc_hashlock.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    scalars_tlv = _build_intent_tlv_for_test(coin_type, bytes(32))
    # P1=0x00 (scalars) succeeds — it does not enforce state.
    client.transport_client.exchange(
        cla=CLA_VAULT, ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_SCALARS, p2=P2_UNUSED, data=scalars_tlv,
    )
    # P1=0x01 (key batch) fails — state is IDLE, not HASH_DERIVED.
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(
            cla=CLA_VAULT, ins=INS_APPROVE_VAULT_INTENT,
            p1=P1_KEY_BATCH, p2=P2_UNUSED,
            data=_TEST_KEEPER_PKS[0] + _TEST_CHALLENGER_PKS[0],
        )
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

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(wrong_htlc_spk,
                                input_internal_key=input_key,
                                input_fingerprint=fingerprint,
                                input_coin_type=coin_type)

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
    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(htlc_spk,
                                htlc_value=too_low,
                                input_internal_key=input_key,
                                input_fingerprint=fingerprint,
                                input_coin_type=coin_type)

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
    """PegIn validation passes silently and sign_custom_inputs signs the HTLC Leaf 0 input.

    NAPPS-1377: sign_custom_inputs is fully implemented, so the SIGN_PSBT command returns
    SW_OK with the depositor's Schnorr signature over the HTLC Leaf 0 sighash.
    State advances to SESSION2_PAYOUT_EXPECTED after signing.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)  # HTLC Leaf 0 signed by the depositor key


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
    """PegIn fails when htlc_value - vault_amount - depositor_claim_value - anchor > pegin_max_fee."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    excessive_htlc = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_P2A_ANCHOR_VALUE + _PEGIN_MAX_FEE + 1
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

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt(htlc_spk,
                                input_internal_key=input_key,
                                input_fingerprint=fingerprint,
                                input_coin_type=coin_type)
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
    """PegIn fails when the PSBT has 4 outputs instead of exactly 3."""
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


# ===========================================================================
# Payout transaction validation (NAPPS-1376)
# ===========================================================================

VAULT_DUST_LIMIT = 546  # must match vault_constants.h (CPFP anchor = P2TR relay dust limit)

# Default fee for payout PSBT builders (safely within MAX_PAYOUT_VSIZE_BASE * BASE_FEE_RATE)
_PAYOUT_FEE = 400  # sat — well within 500 * 1 = 500 sat max for 1K+1C


def _bip86_p2tr_spk(xonly_key: bytes) -> bytes:
    """BIP-86 key-path-only P2TR scriptPubKey: OP_1 OP_PUSHBYTES_32 taproot_tweak(key, b'')."""
    _, tweaked = taproot_tweak_pubkey(xonly_key, b'')
    return bytes([0x51, 0x20]) + tweaked


def _assert0_payout_leaf(claimer_key: bytes,
                          app_challengers: List[bytes],
                          challenger_pks: List[bytes],
                          payout_timelock: int) -> bytes:
    """Assert:0 Payout leaf:
    <Claimer> OP_CHECKSIGVERIFY <AppChallengers K-of-K> <UC M-of-M> <t2> OP_CSV
    """
    s = bytes([0x20]) + claimer_key + bytes([0xAD])
    s += _multisig_group(app_challengers, False)
    s += _multisig_group(challenger_pks, False)
    s += _encode_script_num(payout_timelock) + bytes([0xB2])
    return s


def _build_app_challengers(vp_key: bytes,
                            keeper_pks: List[bytes],
                            claimer_idx: int) -> List[bytes]:
    """AppChallengers = {VP, VK_1..VK_N} \\ {Claimer}, sorted ascending lexicographically."""
    claimer_key = vp_key if claimer_idx == 0 else keeper_pks[claimer_idx - 1]
    all_keys = [vp_key] + list(keeper_pks)
    result = sorted(k for k in all_keys if k != claimer_key)
    return result


def _compute_pegin_txid(prepegin_txid: bytes,
                         htlc_vout: int,
                         vault_amount: int,
                         vault_utxo_spk: bytes,
                         depositor_claim_value: int,
                         claim_spk: bytes) -> bytes:
    """Double-SHA256 of the PegIn non-witness serialization (mirrors vault_compute_pegin_txid)."""
    buf = struct.pack('<I', 3)      # version (TRUC v3, BIP-431)
    buf += b'\x01'                  # input count
    buf += prepegin_txid            # prevout txid (raw bytes, LE as stored)
    buf += struct.pack('<I', htlc_vout)
    buf += b'\x00'                  # scriptSig empty
    buf += struct.pack('<I', 0xFFFFFFFE)  # sequence
    buf += b'\x03'                  # output count
    buf += struct.pack('<Q', vault_amount)
    buf += bytes([len(vault_utxo_spk)]) + vault_utxo_spk
    buf += struct.pack('<Q', depositor_claim_value)
    buf += bytes([len(claim_spk)]) + claim_spk
    buf += struct.pack('<Q', _PEGIN_P2A_ANCHOR_VALUE) + b'\x04\x51\x02\x4e\x73'  # P2A anchor
    buf += struct.pack('<I', 0)     # locktime
    return hashlib.sha256(hashlib.sha256(buf).digest()).digest()


def _build_payout_psbt(
    depositor_pk: bytes,
    prepegin_txid: bytes,
    claimer_idx: int,
    vault_amount: int = _VAULT_AMOUNT,
    commission_fee: int = _COMMISSION_FEE,
    depositor_claim_value: int = _DEPOSITOR_CLAIM_VALUE,
    pegin_csv_timelock: int = _PEGIN_CSV_TIMELOCK,
    payout_timelock: int = _PAYOUT_TIMELOCK,
    fee: int = _PAYOUT_FEE,
    htlc_vout: int = _HTLC_VOUT,
) -> PSBT:
    """Build a valid Payout PSBTv0 for the given claimer_idx (v18 output layout).

    Input 0 spends Vault UTXO from computed_pegin_txid:0 with sequence=pegin_csv_timelock.
    Input 1 spends Assert:0 UTXO (arbitrary txid, value=VAULT_DUST_LIMIT) with sequence=payout_timelock.
    VP claimer (idx==0): Out0=depositor (V-fee-Fc), Out1=VP (Fc), Out2=VP CPFP anchor (DUST).
    VK claimer (idx>0):  Out0=VaultKeeper_i (V-fee), Out1=VaultKeeper_i CPFP anchor (DUST).
    """
    # Reconstruct leaves to compute scriptPubKeys and txid
    vault_utxo_leaf = _vault_utxo_leaf(
        depositor_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, pegin_csv_timelock,
    )
    claim_leaf = _depositor_claim_leaf(depositor_pk)
    vault_utxo_spk = _p2tr_from_single_leaf(vault_utxo_leaf)
    claim_spk = _p2tr_from_single_leaf(claim_leaf)

    computed_pegin_txid = _compute_pegin_txid(
        prepegin_txid, htlc_vout,
        vault_amount, vault_utxo_spk,
        depositor_claim_value, claim_spk,
    )

    # Claimer key and Assert:0 Payout leaf
    claimer_key = TEST_VP_KEY if claimer_idx == 0 else _TEST_KEEPER_PKS[claimer_idx - 1]
    app_challengers = _build_app_challengers(TEST_VP_KEY, _TEST_KEEPER_PKS, claimer_idx)
    assert0_leaf = _assert0_payout_leaf(
        claimer_key, app_challengers, _TEST_CHALLENGER_PKS, payout_timelock,
    )
    assert0_spk = _p2tr_from_single_leaf(assert0_leaf)

    # Output values and scripts (v18 layout)
    if claimer_idx == 0:  # VP claimer
        out0_value = vault_amount + VAULT_DUST_LIMIT - fee - commission_fee - VAULT_DUST_LIMIT
        out1_value = commission_fee
        out2_value = VAULT_DUST_LIMIT
        out0_spk = _bip86_p2tr_spk(depositor_pk)    # depositor receives V - fee - Fc
        out1_spk = _bip86_p2tr_spk(TEST_VP_KEY)     # VP receives commission
        out2_spk = _bip86_p2tr_spk(TEST_VP_KEY)     # VP CPFP anchor (claimer = VP)
    else:  # VK claimer
        out0_value = vault_amount + VAULT_DUST_LIMIT - fee - VAULT_DUST_LIMIT
        out1_value = VAULT_DUST_LIMIT
        out0_spk = _bip86_p2tr_spk(claimer_key)     # VaultKeeper receives V - fee
        out1_spk = _bip86_p2tr_spk(claimer_key)     # VaultKeeper CPFP anchor (claimer = VK)

    # Control blocks for single-leaf taptrees
    vault_leaf_hash = _tapleaf_hash(vault_utxo_leaf)
    vault_parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, vault_leaf_hash)
    vault_cb = bytes([0xC0 | vault_parity]) + VAULT_NUMS_XONLY

    assert0_leaf_hash = _tapleaf_hash(assert0_leaf)
    assert0_parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, assert0_leaf_hash)
    assert0_cb = bytes([0xC0 | assert0_parity]) + VAULT_NUMS_XONLY

    # Build transaction
    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(), CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(computed_pegin_txid, 'little'), 0)
    tx.vin[0].nSequence = pegin_csv_timelock
    tx.vin[1].prevout = COutPoint(int.from_bytes(b'\xbb' * 32, 'little'), 0)
    tx.vin[1].nSequence = payout_timelock
    if claimer_idx == 0:
        tx.vout = [
            CTxOut(out0_value, out0_spk),
            CTxOut(out1_value, out1_spk),
            CTxOut(out2_value, out2_spk),
        ]
    else:
        tx.vout = [CTxOut(out0_value, out0_spk), CTxOut(out1_value, out1_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0), PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)] * len(tx.vout)

    psbt.inputs[0].witness_utxo = CTxOut(vault_amount, vault_utxo_spk)
    psbt.inputs[0].tap_scripts[(vault_utxo_leaf, 0xC0)] = {vault_cb}

    psbt.inputs[1].witness_utxo = CTxOut(VAULT_DUST_LIMIT, assert0_spk)
    psbt.inputs[1].tap_scripts[(assert0_leaf, 0xC0)] = {assert0_cb}

    return psbt


def _setup_payout_state(
    client: "RaggerClient",
    navigator: "Navigator",
    device,
    coin_type: int,
    prepegin_txid: bytes = _PREPEGIN_TXID,
) -> bytes:
    """Advance device to SESSION2_PAYOUT_EXPECTED, payout_index=0.
    Returns the 32-byte hashlock.
    """
    dep_pk = TEST_DEPOSITOR_XONLY_MAINNET if coin_type == 0 else TEST_DEPOSITOR_XONLY_TESTNET
    hashlock = _setup_s2_state(client, navigator, device, coin_type, prepegin_txid)
    pegin_psbt = _build_pegin_psbt(dep_pk, hashlock, prepegin_txid)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    # NAPPS-1377: PegIn signing is fully wired; SW_OK advances state to PAYOUT_EXPECTED.
    client.sign_psbt(pegin_psbt, dummy_wallet, None)
    return hashlock


def test_sign_psbt_payout_vp(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP Payout validation passes silently and sign_custom_inputs signs the Vault UTXO input."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)  # Vault UTXO signed by the depositor key


def test_sign_psbt_payout_vk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP then VK_1 Payout both succeed; each signs the Vault UTXO input."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    # VP payout — advances payout_index to 1
    vp_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    result = client.sign_psbt(vp_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)  # Vault UTXO signed by the depositor key

    # VK_1 payout — last payout, state transitions to SESSION2_COMPLETE
    vk_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    result = client.sign_psbt(vk_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)  # Vault UTXO signed by the depositor key


def test_sign_psbt_payout_extra_input(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when the PSBT has 3 inputs instead of exactly 2."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_claimer_order(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when VK PSBT is presented before VP (claimer ordering enforced)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    # Attempt VK_1 payout without signing VP first (payout_index == 0 expects VP)
    vk_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(vk_psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_fee_too_high(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when fee exceeds base_fee_rate * (500 + 55*(N+M))."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    # Max fee for 1K+1C: 1 * (500 + 55*2) = 610 sats; set fee = 611
    excessive_fee = 611
    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0, fee=excessive_fee)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_vault_utxo_spk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when Input 0 WITNESS_UTXO scriptPubKey is tampered."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    # Corrupt Input 0 witness UTXO scriptPubKey
    psbt.inputs[0].witness_utxo = CTxOut(
        psbt.inputs[0].witness_utxo.nValue,
        bytes([0x51, 0x20]) + bytes(32),
    )
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_assert0_spk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when Input 1 WITNESS_UTXO scriptPubKey is tampered."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    # Corrupt Input 1 witness UTXO scriptPubKey
    psbt.inputs[1].witness_utxo = CTxOut(
        psbt.inputs[1].witness_utxo.nValue,
        bytes([0x51, 0x20]) + bytes(32),
    )
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_assert0_leaf(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when Input 1 TAP_LEAF_SCRIPT contains the wrong claimer key."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)

    # Replace Input 1 TAP_LEAF_SCRIPT with a leaf using a different (wrong) key
    wrong_claimer_key = TEST_VALID_KEYS[2]  # not VP, not any keeper
    wrong_leaf = _assert0_payout_leaf(
        wrong_claimer_key,
        _build_app_challengers(TEST_VP_KEY, _TEST_KEEPER_PKS, 0),
        _TEST_CHALLENGER_PKS,
        _PAYOUT_TIMELOCK,
    )
    wrong_leaf_hash = _tapleaf_hash(wrong_leaf)
    wrong_parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, wrong_leaf_hash)
    wrong_cb = bytes([0xC0 | wrong_parity]) + VAULT_NUMS_XONLY

    psbt.inputs[1].tap_scripts = {(wrong_leaf, 0xC0): {wrong_cb}}
    # Update WITNESS_UTXO to match the wrong leaf's P2TR output
    wrong_assert0_spk = _p2tr_from_single_leaf(wrong_leaf)
    psbt.inputs[1].witness_utxo = CTxOut(VAULT_DUST_LIMIT, wrong_assert0_spk)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_vp_wrong_commission_amount(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP Payout fails when Out1 amount differs from commission_fee."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vout[1].nValue = _COMMISSION_FEE - 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_dust_output(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP Payout fails when Out2 (CPFP anchor) amount is not exactly VAULT_DUST_LIMIT."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vout[2].nValue = VAULT_DUST_LIMIT + 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_input0_txid(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when Input 0 prevout txid does not match computed_pegin_txid."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    # Replace Input 0 prevout with a wrong txid
    psbt.tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xff' * 32, 'little'), 0)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_input0_sequence(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when Input 0 sequence does not equal pegin_csv_timelock."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vin[0].nSequence = _PEGIN_CSV_TIMELOCK + 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_input1_sequence(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when Input 1 sequence does not equal payout_timelock."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vin[1].nSequence = _PAYOUT_TIMELOCK + 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# Signet vault regression — real on-chain keys and amounts
# Payout tx: 13d3f46888747c65d45b0ae8972e4ce6da86c8ad2584aefcbf03434071a99fab
# ===========================================================================

_SIGNET_VP_KEY = bytes.fromhex(
    "de38e2e78eaf0d62b5291d5110548088fda9ba3e1972b4b55f86a2634a765d08"
)
_SIGNET_KEEPER_PKS = [
    bytes.fromhex("9b03efc0a494b29e2ad5631ac15ec32c84c3a5295a64760c3b2ec9c0141c77c7"),
    bytes.fromhex("cf6828d099112c3ff87d4393e5c222540f6f5cec30be8ea073fc7829dd161ed8"),
    bytes.fromhex("daae4c4465ea84921a410c3a185bd003cdef9102c7f4760746413922cb478241"),
]
_SIGNET_CHALLENGER_PKS = [
    bytes.fromhex("1d40367bb1a1f64e0c7b3abb3a3b8a88fa8f34c24fe255d043b3abaed04adaca"),
    bytes.fromhex("ed94e11d6a9f04482009e16e30d1b9326f052212f5f0dae6b2c191e15be6e5c4"),
    bytes.fromhex("f4b542ac5aac10b6ead6bc00a5ffa0d162abbeda4c485ee50d6a77d7e83c9300"),
]

# Both timelocks are 432 blocks (pegin_csv == payout == htlc_refund).
_SIGNET_TIMELOCK = 432

# Amounts reproduce the exact on-chain output values:
#   Out0 = vault_amount - fee - commission_fee = 1_343_957 - 442 - 13_443 = 1_330_072
#   Out1 = commission_fee                                                  =    13_443
#   Out2 = VAULT_DUST_LIMIT (CPFP anchor)                                 =       546
_SIGNET_VAULT_AMOUNT   = 1_343_957
_SIGNET_COMMISSION_FEE = 13_443
_SIGNET_FEE            = 442   # within 500 + 55*(3+3) = 830 sat max at base_fee_rate=1


def _setup_signet_payout_state(
    client: "RaggerClient",
    navigator: "Navigator",
    device,
    coin_type: int,
) -> None:
    """Load signet vault intent and advance device to SESSION2_PAYOUT_EXPECTED."""
    dep_pk = TEST_DEPOSITOR_XONLY_MAINNET if coin_type == 0 else TEST_DEPOSITOR_XONLY_TESTNET

    # New spec: DERIVE_CONTEXT_HASH returns the root; the per-vault hashlock is
    # SHA256(Expand(root, "hashlock" || I2OSP(htlc_vout,4))), matching what the device
    # recomputes at APPROVE_VAULT_INTENT.
    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)

    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        vault_provider_pk=_SIGNET_VP_KEY,
        vault_amount=_SIGNET_VAULT_AMOUNT,
        commission_fee=_SIGNET_COMMISSION_FEE,
        depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
        base_fee_rate=1,
        pegin_max_fee=_PEGIN_MAX_FEE,
        pegin_csv_timelock=_SIGNET_TIMELOCK,
        payout_timelock=_SIGNET_TIMELOCK,
        prepegin_txid=_PREPEGIN_TXID,
        htlc_vout=_HTLC_VOUT,
        htlc_refund_timelock=_SIGNET_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=len(_SIGNET_KEEPER_PKS),
        challenger_count=len(_SIGNET_CHALLENGER_PKS),
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _SIGNET_KEEPER_PKS, _SIGNET_CHALLENGER_PKS,
    )

    # Build PegIn PSBT with signet keys and sign it to advance state.
    parity, merkle_root, leaf0, leaf1, htlc_spk = _htlc_output(
        dep_pk, _SIGNET_VP_KEY, _SIGNET_KEEPER_PKS, _SIGNET_CHALLENGER_PKS,
        _SIGNET_TIMELOCK, hashlock,
    )
    vault_spk = _p2tr_from_single_leaf(_vault_utxo_leaf(
        dep_pk, _SIGNET_VP_KEY, _SIGNET_KEEPER_PKS, _SIGNET_CHALLENGER_PKS, _SIGNET_TIMELOCK,
    ))
    claim_spk = _p2tr_from_single_leaf(_depositor_claim_leaf(dep_pk))
    lh1 = _tapleaf_hash(leaf1)
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY + lh1
    htlc_value = _SIGNET_VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_P2A_ANCHOR_VALUE + 1_000
    p2a_spk = bytes([0x51, 0x02, 0x4e, 0x73])

    tx = CTransaction()
    tx.nVersion = 3  # TRUC (BIP-431)
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(_PREPEGIN_TXID, 'little'), _HTLC_VOUT)
    tx.vin[0].nSequence = 0xFFFFFFFE
    tx.vout = [
        CTxOut(_SIGNET_VAULT_AMOUNT, vault_spk),
        CTxOut(_DEPOSITOR_CLAIM_VALUE, claim_spk),
        CTxOut(_PEGIN_P2A_ANCHOR_VALUE, p2a_spk),
    ]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0), PartiallySignedOutput(0), PartiallySignedOutput(0)]
    psbt.inputs[0].witness_utxo = CTxOut(htlc_value, htlc_spk)
    psbt.inputs[0].tap_internal_key = VAULT_NUMS_XONLY
    psbt.inputs[0].tap_merkle_root = merkle_root
    psbt.inputs[0].tap_scripts[(leaf0, 0xC0)] = {control_block}

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    client.sign_psbt(psbt, dummy_wallet, None)


def _build_signet_payout_psbt(depositor_pk: bytes, claimer_idx: int) -> PSBT:
    """Build a Payout PSBT for the signet vault (3 keepers, 3 challengers, timelock=432).

    VP claimer (idx=0): Out0=depositor(1_330_072), Out1=VP commission(13_443), Out2=VP CPFP(546).
    VK claimer (idx>0): Out0=VaultKeeper(V-fee), Out1=VaultKeeper CPFP anchor(546).
    """
    vault_utxo_leaf = _vault_utxo_leaf(
        depositor_pk, _SIGNET_VP_KEY, _SIGNET_KEEPER_PKS, _SIGNET_CHALLENGER_PKS,
        _SIGNET_TIMELOCK,
    )
    claim_leaf = _depositor_claim_leaf(depositor_pk)
    vault_utxo_spk = _p2tr_from_single_leaf(vault_utxo_leaf)
    claim_spk = _p2tr_from_single_leaf(claim_leaf)

    computed_pegin_txid = _compute_pegin_txid(
        _PREPEGIN_TXID, _HTLC_VOUT,
        _SIGNET_VAULT_AMOUNT, vault_utxo_spk,
        _DEPOSITOR_CLAIM_VALUE, claim_spk,
    )

    claimer_key = _SIGNET_VP_KEY if claimer_idx == 0 else _SIGNET_KEEPER_PKS[claimer_idx - 1]
    app_challengers = _build_app_challengers(_SIGNET_VP_KEY, _SIGNET_KEEPER_PKS, claimer_idx)
    assert0_leaf = _assert0_payout_leaf(
        claimer_key, app_challengers, _SIGNET_CHALLENGER_PKS, _SIGNET_TIMELOCK,
    )
    assert0_spk = _p2tr_from_single_leaf(assert0_leaf)

    if claimer_idx == 0:
        out0_value = _SIGNET_VAULT_AMOUNT - _SIGNET_FEE - _SIGNET_COMMISSION_FEE
        out1_value = _SIGNET_COMMISSION_FEE
        out2_value = VAULT_DUST_LIMIT
        out0_spk = _bip86_p2tr_spk(depositor_pk)
        out1_spk = _bip86_p2tr_spk(_SIGNET_VP_KEY)
        out2_spk = _bip86_p2tr_spk(_SIGNET_VP_KEY)
    else:
        out0_value = _SIGNET_VAULT_AMOUNT - _SIGNET_FEE
        out1_value = VAULT_DUST_LIMIT
        out0_spk = _bip86_p2tr_spk(claimer_key)
        out1_spk = _bip86_p2tr_spk(claimer_key)

    vault_leaf_hash = _tapleaf_hash(vault_utxo_leaf)
    vault_parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, vault_leaf_hash)
    vault_cb = bytes([0xC0 | vault_parity]) + VAULT_NUMS_XONLY

    assert0_leaf_hash = _tapleaf_hash(assert0_leaf)
    assert0_parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, assert0_leaf_hash)
    assert0_cb = bytes([0xC0 | assert0_parity]) + VAULT_NUMS_XONLY

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(), CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(computed_pegin_txid, 'little'), 0)
    tx.vin[0].nSequence = _SIGNET_TIMELOCK
    tx.vin[1].prevout = COutPoint(int.from_bytes(b'\xbb' * 32, 'little'), 0)
    tx.vin[1].nSequence = _SIGNET_TIMELOCK
    if claimer_idx == 0:
        tx.vout = [
            CTxOut(out0_value, out0_spk),
            CTxOut(out1_value, out1_spk),
            CTxOut(out2_value, out2_spk),
        ]
    else:
        tx.vout = [CTxOut(out0_value, out0_spk), CTxOut(out1_value, out1_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0), PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)] * len(tx.vout)
    psbt.inputs[0].witness_utxo = CTxOut(_SIGNET_VAULT_AMOUNT, vault_utxo_spk)
    psbt.inputs[0].tap_scripts[(vault_utxo_leaf, 0xC0)] = {vault_cb}
    psbt.inputs[1].witness_utxo = CTxOut(VAULT_DUST_LIMIT, assert0_spk)
    psbt.inputs[1].tap_scripts[(assert0_leaf, 0xC0)] = {assert0_cb}
    return psbt


def test_sign_psbt_payout_signet_params(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout passes with real signet vault keys (3 keepers, 3 challengers) and on-chain amounts.

    Keys sourced from payout tx 13d3f46888747c65d45b0ae8972e4ce6da86c8ad2584aefcbf03434071a99fab.
    Depositor key is substituted with the test device's derivation (device must sign).
    Verifies VP payout (Out0=depositor 1_330_072, Out1=VP 13_443, Out2=VP CPFP 546)
    and VK_1 payout (Out0=VK 1_343_515, Out1=VK CPFP 546) both pass validation.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_signet_payout_state(client, navigator, device, coin_type)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    # VP payout — advances payout_index 0 → 1
    vp_psbt = _build_signet_payout_psbt(dep_pk, claimer_idx=0)
    result = client.sign_psbt(vp_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)  # Vault UTXO signed by the depositor key

    # VK_1 payout — advances payout_index 1 → 2
    vk_psbt = _build_signet_payout_psbt(dep_pk, claimer_idx=1)
    result = client.sign_psbt(vk_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)  # Vault UTXO signed by the depositor key


# ===========================================================================
# Maximum-participant memory stress (NAPPS — VAULT_SCRIPT_MAX_LEN ceiling)
# ===========================================================================

def _distinct_sorted_keys(count: int, exclude: List[bytes]) -> List[bytes]:
    """Return `count` distinct, valid, lexicographically-ascending x-only pubkeys.

    Each key is secret*G for secret = 2, 3, 4, … (secret 1 == G == TEST_VP_KEY, so
    we start at 2).  All are valid curve points, mutually distinct (small secrets
    < n/2 never share an x-coordinate), and any key in `exclude` (the VP or
    depositor key) is skipped.  The firmware requires each group's keys to be
    strictly ascending by memcmp, so the caller slices a sorted list.
    """
    keys: List[bytes] = []
    seen = set(exclude)
    secret = 2
    while len(keys) < count:
        k = pubkey_gen(secret.to_bytes(32, "big"))
        if k not in seen:
            seen.add(k)
            keys.append(k)
        secret += 1
    return sorted(keys)


def test_sign_psbt_pegin_max_participants(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn validation + signing at the 32-keeper / 32-challenger maximum.

    This is the memory-critical case: HTLC Leaf 0 embeds depositor + VP + all 32
    keepers + all 32 challengers (~34 B/key), so the device must reconstruct a
    ~2.3 KB script into its VAULT_SCRIPT_MAX_LEN (2560 B) buffer AND read the
    equally-large leaf back from the PSBT.  If either buffer were undersized the
    leaf check would fail with SW_INCORRECT_DATA; SW_OK means validation passed,
    the leaf was reconstructed/compared at full size, and sign_custom_inputs
    (NAPPS-1377) signed the HTLC Leaf 0 input.

    Unlike the captured sample-vector test (which rejects at the state guard
    before any vault buffering), this drives the largest reconstruction path the
    firmware has.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    all_keys = _distinct_sorted_keys(
        VAULT_MAX_KEEPERS + VAULT_MAX_CHALLENGERS, exclude=[TEST_VP_KEY, dep_pk]
    )
    keeper_pks = all_keys[:VAULT_MAX_KEEPERS]
    challenger_pks = all_keys[VAULT_MAX_KEEPERS:]

    # Sanity: Leaf 0 sits just under the firmware buffer ceiling — i.e. this test
    # genuinely exercises the near-max buffer, not a comfortably small script.
    leaf0 = _htlc_leaf0(dep_pk, TEST_VP_KEY, keeper_pks, challenger_pks, bytes(32))
    assert 2000 < len(leaf0) <= VAULT_SCRIPT_MAX_LEN, f"Leaf 0 len = {len(leaf0)}"

    hashlock = _setup_s2_state(
        client, navigator, device, coin_type, _PREPEGIN_TXID,
        keeper_pks=keeper_pks, challenger_pks=challenger_pks,
    )

    psbt = _build_pegin_psbt(
        dep_pk, hashlock, _PREPEGIN_TXID,
        keeper_pks=keeper_pks, challenger_pks=challenger_pks,
    )
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    # Valid max-size PegIn: validation passes and sign_custom_inputs signs Leaf 0 → SW_OK.
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)
