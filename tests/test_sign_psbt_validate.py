"""
Silent-flow validation tests for SIGN_PSBT (NAPPS-1375/1376/1462).

Covers Pre-PegIn, PegIn, Payout, NoPayout, and Refund validation (no display).
Screen-capture tests live in the corresponding test_screen*.py files:
  test_screen3_refund.py  — Screen 3 (Refund)
  test_screen4_claim.py  — Screen 4 (Claim)
  test_screen5_assert.py — Screen 5 (Assert)
  test_screen6_wc.py     — Screen 6 (WC)
"""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING, List, Optional
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from ledger_bitcoin import WalletPolicy
from ledger_bitcoin.common import hash160
from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness

from test_utils.taproot import tagged_hash, taproot_tweak_pubkey, ser_script, pubkey_gen

from .vault_client import (
    SW_BAD_STATE,
    SW_BAD_CPFP_ANCHOR,
    SW_CAP_EXCEEDED,
    SW_INCORRECT_DATA,
    CLA_VAULT,
    INS_APPROVE_VAULT_INTENT,
    P1_SCALARS,
    P1_GROUP,
    P1_KEY_BATCH,
    P2_UNUSED,
    derive_context_hash,
    approve_vault_intent_with_nav,
    build_intent_tlv,
    build_group_tlv,
    sign_psbt_with_nav_and_compare,
    VAULT_APP_NAME,
    vault_hashlock,
    vault_auth_anchor,
    depositor_path,
    TEST_VP_KEY,
    TEST_VALID_KEYS,
    TEST_DEPOSITOR_XONLY_MAINNET,
    TEST_DEPOSITOR_XONLY_TESTNET,
)

HARDENED = 0x80000000

# BIP-44 purposes for the four standard single-key policies the base app accepts without
# an HMAC.  Only the two native-SegWit ones spend with an empty scriptSig, which is the
# precondition _validate_prepegin enforces before trusting its own txid reconstruction.
BIP44_LEGACY        = 44   # pkh(@0/**)
BIP49_NESTED_SEGWIT = 49   # sh(wpkh(@0/**))
BIP84_NATIVE_SEGWIT = 84   # wpkh(@0/**)
BIP86_TAPROOT       = 86   # tr(@0/**)

# Script opcodes used to build the non-Taproot scriptPubKeys under test.
OP_0            = 0x00
OP_PUSHBYTES_20 = 0x14
OP_DUP          = 0x76
OP_EQUAL        = 0x87
OP_EQUALVERIFY  = 0x88
OP_HASH160      = 0xA9
OP_CHECKSIG     = 0xAC

VAULT_NUMS_XONLY = bytes.fromhex(
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
)


def _hash256(data: bytes) -> bytes:
    """Bitcoin double-SHA256 (txid computation)."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


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
_BASE_FEE_RATE              = 1
_MAX_COUNCIL_NOPAYOUT_VSIZE = 500  # must match MAX_COUNCIL_NOPAYOUT_VSIZE in sign_psbt_validate.c
_PEGIN_MAX_FEE        = 567_891     # 0.00567891 BTC
_PEGIN_CSV_TIMELOCK   = 144
_PAYOUT_TIMELOCK      = 200
_HTLC_REFUND_TIMELOCK = 144
_HTLC_VOUT            = 0
# Must match VAULT_DUST_LIMIT in vault_constants.h (P2TR relay dust limit).
_VAULT_DUST_LIMIT     = 546
# P2A anchor output value in satoshis — must match P2A_ANCHOR_VALUE in vault_constants.h.
_PEGIN_ANCHOR_VALUE = 240

# htlc_value must be in [vault_amount + depositor_claim_value + anchor,
#                         vault_amount + depositor_claim_value + anchor + pegin_max_fee]
_HTLC_VALUE           = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_ANCHOR_VALUE + 234_567

# Single keeper and challenger for all tests (sorted ascending — key[0] < key[1])
_TEST_KEEPER_PKS     = [TEST_VALID_KEYS[0]]
_TEST_CHALLENGER_PKS = [TEST_VALID_KEYS[1]]
# Distinct vault_provider_pk per group for multi-vault tests; excludes keeper/challenger keys.
_VP_KEYS = [TEST_VP_KEY] + TEST_VALID_KEYS[2:]

# Firmware participant caps and script buffer ceiling — must match src/vault_intent.h
# (VAULT_MAX_KEEPERS / VAULT_MAX_CHALLENGERS) and src/vault_script.h
# (VAULT_SCRIPT_MAX_LEN).  At the 32/32 maximum, HTLC Leaf 0 — which embeds
# depositor + VP + every keeper + every challenger — is the largest single script
# the device reconstructs into its VAULT_SCRIPT_MAX_LEN buffer.
VAULT_MAX_KEEPERS     = 32
VAULT_MAX_CHALLENGERS = 32
VAULT_SCRIPT_MAX_LEN  = 2560

# Pre-PegIn txid committed in the intent; used by PegIn/Payout validators.
_PREPEGIN_TXID = bytes(range(32))

# Assert txid spent by NoPayout Input 0. Arbitrary on purpose: the device cannot
# reconstruct the Assert txid (Assert:0 embeds Council keys and the connectors embed fresh
# WOTS chain tips, none of them carried in the intent), so it never checks this value.
_ASSERT_TXID = bytes([0xA5]) * 32


# ---------------------------------------------------------------------------
# Python replicas of the C vault_script.c leaf builders
# ---------------------------------------------------------------------------

def _multisig_group(keys: List[bytes], is_final: bool) -> bytes:
    """N-of-N multisig fragment.  is_final=True uses OP_NUMEQUAL; False uses OP_NUMEQUALVERIFY."""
    if len(keys) == 1:
        return bytes([0x20]) + keys[0] + bytes([0xac, 0x51, 0x9c if is_final else 0x9d])
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

def _standard_single_key_wallet(client: "RaggerClient", coin_type: int,
                                purpose: int, descriptor_template: str) -> WalletPolicy:
    """Default (HMAC-less) single-key wallet policy for the test device.

    wallet_id != all-zeros → has_no_wallet_policy = false → SIGN_PSBT routes to the
    Pre-PegIn validator.  The base app only accepts such a policy without an HMAC when
    the key origin is m/purpose'/coin_type'/account', so purpose must match the template.
    """
    fingerprint = client.get_master_fingerprint()
    xpub = client.get_extended_pubkey(f"m/{purpose}'/{coin_type}'/0'", display=False)
    return WalletPolicy(
        name="",
        descriptor_template=descriptor_template,
        keys_info=[f"[{fingerprint.hex()}/{purpose}'/{coin_type}'/0']{xpub}"],
    )


def _standard_taproot_wallet(client: "RaggerClient", coin_type: int) -> WalletPolicy:
    """BIP-86 tr() wallet — SegWit v1, empty scriptSig."""
    return _standard_single_key_wallet(client, coin_type, BIP86_TAPROOT, "tr(@0/**)")


def _standard_native_segwit_wallet(client: "RaggerClient", coin_type: int) -> WalletPolicy:
    """BIP-84 wpkh() wallet — SegWit v0, empty scriptSig."""
    return _standard_single_key_wallet(client, coin_type, BIP84_NATIVE_SEGWIT, "wpkh(@0/**)")


def _standard_nested_segwit_wallet(client: "RaggerClient", coin_type: int) -> WalletPolicy:
    """BIP-49 sh(wpkh()) wallet — SegWit v0 wrapped in P2SH, so the scriptSig carries a
    23-byte redeemScript push."""
    return _standard_single_key_wallet(client, coin_type, BIP49_NESTED_SEGWIT, "sh(wpkh(@0/**))")


def _standard_legacy_wallet(client: "RaggerClient", coin_type: int) -> WalletPolicy:
    """BIP-44 pkh() wallet — legacy, so the scriptSig carries the full ~106-byte
    signature + pubkey unlocking script."""
    return _standard_single_key_wallet(client, coin_type, BIP44_LEGACY, "pkh(@0/**)")


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
    cpfp_anchor_spk: Optional[bytes] = None,
    cpfp_anchor_value: int = _VAULT_DUST_LIMIT,
) -> PSBT:
    """Pre-PegIn PSBTv0: HTLC output at htlc_vout, plus optional trailing outputs.

    The device accepts an optional OP_RETURN = "OP_RETURN <SHA256(authAnchor)>"
    (= 0x6A 0x20 || auth_anchor); pass auth_anchor=vault_auth_anchor(root) to include
    it.

    The device also accepts an optional CPFP anchor: P2TR(depositor_pk) at exactly
    VAULT_DUST_LIMIT (546 sat).  Pass cpfp_anchor_spk=_bip86_depositor_spk(dep_pk) to
    include it; cpfp_anchor_value overrides the value for negative tests.

    When input_internal_key and input_fingerprint are provided the input is a
    proper BIP-86 key-path P2TR UTXO (required for the 'all inputs internal'
    validation check in _validate_prepegin).
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
    if cpfp_anchor_spk is not None:
        # CPFP anchor: P2TR(depositor_pk) at VAULT_DUST_LIMIT; cpfp_anchor_value lets
        # negative tests exercise wrong-value rejection.
        tx.vout.append(CTxOut(cpfp_anchor_value, cpfp_anchor_spk))
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


def _bip86_depositor_spk(dep_pk: bytes) -> bytes:
    """BIP-86 P2TR scriptPubKey for the depositor key (used as CPFP anchor)."""
    _, tweaked = taproot_tweak_pubkey(dep_pk, b'')
    return bytes([0x51, 0x20]) + tweaked


# ---------------------------------------------------------------------------
# Non-Taproot (ECDSA) wallet-input helpers
#
# The Pre-PegIn validator only trusts its own txid reconstruction under a wallet policy
# whose inputs carry an empty scriptSig.  These helpers build the three non-Taproot
# standard policies' inputs so that acceptance and rejection can be tested end to end.
# ---------------------------------------------------------------------------

def _p2wpkh_spk(pubkey: bytes) -> bytes:
    """P2WPKH scriptPubKey: OP_0 <20-byte key hash>."""
    return bytes([OP_0, OP_PUSHBYTES_20]) + hash160(pubkey)


def _p2sh_spk(redeem_script: bytes) -> bytes:
    """P2SH scriptPubKey: OP_HASH160 <20-byte script hash> OP_EQUAL."""
    return bytes([OP_HASH160, OP_PUSHBYTES_20]) + hash160(redeem_script) + bytes([OP_EQUAL])


def _p2pkh_spk(pubkey: bytes) -> bytes:
    """P2PKH scriptPubKey: OP_DUP OP_HASH160 <20-byte key hash> OP_EQUALVERIFY OP_CHECKSIG."""
    return (bytes([OP_DUP, OP_HASH160, OP_PUSHBYTES_20]) + hash160(pubkey)
            + bytes([OP_EQUALVERIFY, OP_CHECKSIG]))


def _ecdsa_input_key(client: "RaggerClient", purpose: int, coin_type: int):
    """Return (fingerprint, 33-byte compressed pubkey) at m/{purpose}'/{coin_type}'/0'/0/0.

    Non-Taproot policies identify a wallet input through PSBT_IN_BIP32_DERIVATION on the
    compressed pubkey, not through the x-only key used by tr().
    """
    fingerprint = client.get_master_fingerprint()
    pubkey = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/{purpose}'/{coin_type}'/0'/0/0", display=False)
    ).pubkey
    return fingerprint, pubkey


def _funding_tx(spk: bytes, value: int) -> CTransaction:
    """Single-output transaction supplied as PSBT_IN_NON_WITNESS_UTXO.

    The device recomputes this transaction's txid and requires it to match the spending
    input's PSBT_IN_PREVIOUS_TXID, so callers must take the outpoint from `tx.hash`.
    """
    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(COutPoint(int.from_bytes(b'\xbb' * 32, 'little'), 0), b'', 0xFFFFFFFF)]
    tx.vout = [CTxOut(value, spk)]
    tx.wit = CTxWitness()
    tx.rehash()
    return tx


def _build_prepegin_psbt_ecdsa(
    htlc_spk: bytes,
    purpose: int,
    fingerprint: bytes,
    pubkey: bytes,
    coin_type: int,
    auth_anchor: bytes,
    htlc_value: int = _HTLC_VALUE,
) -> PSBT:
    """Pre-PegIn PSBTv0 whose single wallet input belongs to a non-Taproot standard policy.

    `purpose` selects the address type and must match the wallet policy passed to
    sign_psbt:
      BIP44_LEGACY        → P2PKH; legacy inputs must carry the non-witness UTXO and no
                            witness UTXO.
      BIP49_NESTED_SEGWIT → P2SH-P2WPKH; the redeemScript is published so the base app can
                            match it against the scriptPubKey.
      BIP84_NATIVE_SEGWIT → P2WPKH.
    Both SegWit v0 variants need the witness UTXO *and* the non-witness UTXO: derived apps
    reject a segwitv0 input whose previous transaction is absent.

    Outputs are the HTLC and the auth-anchor OP_RETURN, both 34 bytes, which is what the
    device's txid reconstruction expects.
    """
    redeem_script = b''
    if purpose == BIP44_LEGACY:
        input_spk = _p2pkh_spk(pubkey)
    elif purpose == BIP49_NESTED_SEGWIT:
        redeem_script = _p2wpkh_spk(pubkey)
        input_spk = _p2sh_spk(redeem_script)
    elif purpose == BIP84_NATIVE_SEGWIT:
        input_spk = _p2wpkh_spk(pubkey)
    else:
        raise ValueError(f"unsupported BIP-44 purpose for an ECDSA input: {purpose}")

    input_value = htlc_value + 3_456  # pre-pegin tx fee = 3456 sats = 0.00003456 BTC
    prev_tx = _funding_tx(input_spk, input_value)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(prev_tx.hash, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [
        CTxOut(htlc_value, htlc_spk),
        CTxOut(0, bytes([0x6A, 0x20]) + auth_anchor),
    ]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0) for _ in tx.vout]

    psbt.inputs[0].non_witness_utxo = prev_tx
    if purpose != BIP44_LEGACY:
        psbt.inputs[0].witness_utxo = CTxOut(input_value, input_spk)
    if redeem_script:
        psbt.inputs[0].redeem_script = redeem_script
    psbt.inputs[0].hd_keypaths[pubkey] = KeyOriginInfo(
        fingerprint,
        [HARDENED | purpose, HARDENED | coin_type, HARDENED | 0, 0, 0],
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
        CTxOut(_PEGIN_ANCHOR_VALUE, p2a_spk),
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

    The 'all inputs internal' check in _validate_prepegin requires the
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
    prepegin_max_fee: int = 500_000,
) -> bytes:
    if keeper_pks is None:
        keeper_pks = _TEST_KEEPER_PKS
    if challenger_pks is None:
        challenger_pks = _TEST_CHALLENGER_PKS
    return build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=_BASE_FEE_RATE,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=prepegin_txid,
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=len(keeper_pks),
        challenger_count=len(challenger_pks),
        prepegin_max_fee=prepegin_max_fee,
        vault_count=1,
    )


def _build_group_for_test() -> bytes:
    return build_group_tlv(
        htlc_vout=_HTLC_VOUT,
        vault_provider_pk=TEST_VP_KEY,
        vault_amount=_VAULT_AMOUNT,
        commission_fee=_COMMISSION_FEE,
        depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
        pegin_max_fee=_PEGIN_MAX_FEE,
    )


# ---------------------------------------------------------------------------
# 3-vault helpers (NAPPS-1444)
# ---------------------------------------------------------------------------

_3V_HTLC_VOUTS            = [0, 1, 2]
_3V_VAULT_AMOUNTS         = [9_876_543, 8_765_432, 7_654_321]
_3V_DEPOSITOR_CLAIM_VALUES = [12_345, 11_234, 10_123]
_3V_PEGIN_MAX_FEES        = [567_891, 456_780, 345_679]


def _build_groups_tlv_3vault() -> List[bytes]:
    """Three vault group TLVs at htlc_vouts [0, 1, 2], each with a distinct vault_provider_pk."""
    return [
        build_group_tlv(
            htlc_vout=_3V_HTLC_VOUTS[i],
            vault_provider_pk=_VP_KEYS[i],
            vault_amount=_3V_VAULT_AMOUNTS[i],
            commission_fee=_COMMISSION_FEE,
            depositor_claim_value=_3V_DEPOSITOR_CLAIM_VALUES[i],
            pegin_max_fee=_3V_PEGIN_MAX_FEES[i],
        )
        for i in range(3)
    ]


def _build_groups_tlv_2vault() -> List[bytes]:
    """Two vault group TLVs at htlc_vouts [0, 1], each with a distinct vault_provider_pk."""
    return [
        build_group_tlv(
            htlc_vout=i,
            vault_provider_pk=_VP_KEYS[i],
            vault_amount=_VAULT_AMOUNT,
            commission_fee=_COMMISSION_FEE,
            depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
            pegin_max_fee=_PEGIN_MAX_FEE,
        )
        for i in range(2)
    ]


def _setup_s1_state_3vault(
    client: "RaggerClient",
    navigator: "Navigator",
    device,
    coin_type: int,
) -> List[bytes]:
    """Derive root + approve 3-vault intent. Returns [hashlock_0, hashlock_1, hashlock_2].

    prepegin_txid is zeros: the intent carries no Pre-PegIn binding; all signing
    flows are accepted from VAULT_STATE_INTENT_LOADED.
    """
    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(
        client, VAULT_APP_NAME, depositor_path(coin_type), _DERIVE_CONTEXT, navigator, device
    )
    hashlocks = [vault_hashlock(_DERIVED_ROOT, v) for v in _3V_HTLC_VOUTS]
    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=_BASE_FEE_RATE,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=bytes(32),
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=len(_TEST_KEEPER_PKS),
        challenger_count=len(_TEST_CHALLENGER_PKS),
        prepegin_max_fee=500_000,
        vault_count=3,
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=_build_groups_tlv_3vault(),
    )
    return hashlocks


def _build_prepegin_psbt_multi_vault(
    group_htlc_outputs: List[tuple],
    auth_anchor: Optional[bytes] = None,
    auth_anchor_value: int = 0,
    tx_version: int = 2,
    input_internal_key: Optional[bytes] = None,
    input_fingerprint: Optional[bytes] = None,
    input_coin_type: int = 0,
) -> PSBT:
    """Pre-PegIn PSBTv0 with one HTLC output per vault group.

    group_htlc_outputs[i] = (htlc_spk, htlc_value) for vault group i at htlc_vout=i.
    The OP_RETURN is appended after all HTLC outputs when auth_anchor is given.
    """
    total_htlc = sum(v for _, v in group_htlc_outputs)
    input_value = total_htlc + 3_456

    if input_internal_key is not None and input_fingerprint is not None:
        _, input_tweaked = taproot_tweak_pubkey(input_internal_key, b'')
        input_spk = bytes([0x51, 0x20]) + input_tweaked
    else:
        input_spk = bytes([0x51, 0x20]) + bytes(32)

    tx = CTransaction()
    tx.nVersion = tx_version
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xaa' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [CTxOut(htlc_value, htlc_spk) for htlc_spk, htlc_value in group_htlc_outputs]
    if auth_anchor is not None:
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
    """Derive root + approve intent.  Returns the 32-byte hashlock h.

    After this call the device is in VAULT_STATE_INTENT_LOADED with htlc_hashlock set.
    prepegin_txid is zeros: the intent carries no Pre-PegIn binding.
    """
    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    scalars_tlv = _build_intent_tlv_for_test(coin_type, bytes(32))
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
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
    n_swipes: Optional[int] = None,
) -> bytes:
    """Derive root + approve intent with a non-zero prepegin_txid.  Returns the 32-byte hashlock h.

    After this call the device is in VAULT_STATE_INTENT_LOADED.
    prepegin_txid is embedded in the intent for tests that need a bound Pre-PegIn txid
    (e.g., PegIn signing, which reads intent->prepegin_txid for display and validation).

    keeper_pks / challenger_pks default to the single-keeper / single-challenger
    test sets; pass larger sorted sets to approve a many-participant vault.

    n_swipes: when provided, approve_vault_intent_with_nav uses deterministic navigation
    (no text search) to avoid the Flex/Apex swipe-animation race condition that can occur
    with many keys.  Compute with vault_intent_steps_for_keys(device, total_keys).
    """
    if keeper_pks is None:
        keeper_pks = _TEST_KEEPER_PKS
    if challenger_pks is None:
        challenger_pks = _TEST_CHALLENGER_PKS
    assert any(prepegin_txid), "prepegin_txid must be non-zero for txid-bound intent tests"
    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    scalars_tlv = _build_intent_tlv_for_test(coin_type, prepegin_txid, keeper_pks, challenger_pks)
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, keeper_pks, challenger_pks,
        groups=[_build_group_for_test()],
        n_swipes=n_swipes,
    )
    return hashlock


def _setup_s2_state_2vault(
    client: "RaggerClient",
    navigator: "Navigator",
    device,
    coin_type: int,
) -> bytes:
    """Derive root + approve 2-vault intent with bound prepegin_txid. Returns the hashlock for group 0.

    After this call the device is in VAULT_STATE_INTENT_LOADED.
    Uses vault_count=2 to exercise the I3 index arithmetic
    (htlc_hashlock[vault_count-1] vs htlc_hashlock[0]).
    """
    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(
        client, VAULT_APP_NAME, depositor_path(coin_type), _DERIVE_CONTEXT, navigator, device
    )
    hashlock = vault_hashlock(_DERIVED_ROOT, 0)  # group 0 htlc_vout=0
    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=_BASE_FEE_RATE,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=_PREPEGIN_TXID,
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=len(_TEST_KEEPER_PKS),
        challenger_count=len(_TEST_CHALLENGER_PKS),
        prepegin_max_fee=500_000,
        vault_count=2,
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=_build_groups_tlv_2vault(),
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


def _payout_leaf(d_pk: bytes, app_chal_key: bytes, univ_chal_key: bytes, t2: int) -> bytes:
    """Payout leaf: <D> OP_CHECKSIGVERIFY <AppChal 1-of-1> <UnivChal 1-of-1> <t2> OP_CSV.

    Uses minimal single-key multisig groups for test purposes.  The leaf is always
    > 68 bytes (110 with these parameters), which distinguishes it from the 68-byte
    Assert leaf that the firmware's payout-leaf shape check requires.
    """
    s  = bytes([0x20]) + d_pk + bytes([0xAD])                      # <D> OP_CHECKSIGVERIFY
    s += bytes([0x20]) + app_chal_key + bytes([0xAC, 0x51, 0x9D])  # AppChal 1-of-1: OP_CHECKSIG OP_1 OP_NUMEQUALVERIFY
    s += bytes([0x20]) + univ_chal_key + bytes([0xAC, 0x51, 0x9D]) # UnivChal 1-of-1: OP_CHECKSIG OP_1 OP_NUMEQUALVERIFY
    s += _encode_script_num(t2) + bytes([0xB2])          # <t2> OP_CSV
    return s


def _build_payout_finalize_psbt(
    fingerprint: bytes,
    d_key: bytes,
    coin_type: int,
    app_chal_key: bytes = None,
    univ_chal_key: bytes = None,
    t2: int = _PAYOUT_TIMELOCK,
    amount_received: int = 1_234_567,
    dust_value: int = _VAULT_DUST_LIMIT,
    vault_amount: int = 2_000_000,
    d_key_index: int = 0,
) -> PSBT:
    """Build a minimal PSBTv0 for a PayoutFinalize transaction (Screen 8).

    Input 0: Vault UTXO — pre-signed during deposit ceremony; no TAP_LEAF_SCRIPT or
             TAP_BIP32_DERIVATION.  The device does not sign this input and does not
             validate its witness_utxo value (SIGHASH_DEFAULT commits to all amounts).
    Input 1: Assert:0 P2TR script-path spend via payout leaf; the device signs this input.
             witness_utxo value is VAULT_DUST_LIMIT (546 sat).
    Output 0: amount_received → P2TR(BIP-86(D)).
    Output 1: dust_value (546 sat) → P2TR(BIP-86(D)).

    Both outputs carry the same scriptPubKey (the depositor's BIP-86 key-path address).
    """
    if app_chal_key is None:
        app_chal_key = TEST_VALID_KEYS[0]
    if univ_chal_key is None:
        univ_chal_key = TEST_VALID_KEYS[1]

    leaf = _payout_leaf(d_key, app_chal_key, univ_chal_key, t2)
    leaf_hash = _tapleaf_hash(leaf)
    parity, tweaked_key = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    input1_spk = bytes([0x51, 0x20]) + tweaked_key
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    _, bip86_out_key = taproot_tweak_pubkey(d_key, b'')
    out_spk = bytes([0x51, 0x20]) + bip86_out_key

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(), CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xAA' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFE   # Input 0: Vault UTXO (pre-signed, sequence not validated here)
    tx.vin[1].prevout = COutPoint(int.from_bytes(b'\xBB' * 32, 'little'), 0)
    tx.vin[1].nSequence = t2           # Input 1: CSV timelock satisfied
    tx.vout = [
        CTxOut(amount_received, out_spk),
        CTxOut(dust_value, out_spk),
    ]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0), PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0), PartiallySignedOutput(0)]

    # Input 0: Vault UTXO — pre-signed, no leaf, no derivation (the bitvector bit stays 0)
    psbt.inputs[0].witness_utxo = CTxOut(vault_amount, bytes([0x51, 0x20]) + bytes(32))

    # Input 1: Assert:0 payout leaf — VAULT_DUST_LIMIT value, leaf + BIP-86 derivation for D
    psbt.inputs[1].witness_utxo = CTxOut(_VAULT_DUST_LIMIT, input1_spk)
    psbt.inputs[1].tap_scripts[(leaf, 0xC0)] = {control_block}
    psbt.inputs[1].tap_bip32_paths[d_key] = (
        {leaf_hash},
        KeyOriginInfo(
            fingerprint,
            [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, d_key_index],
        ),
    )

    return psbt


# ===========================================================================
# Pre-PegIn signing (NAPPS-1375, NAPPS-1444)
# Pre-PegIn is signed silently — no user confirmation screen.
# The intent approval (Screen 2) already bound all vault parameters.
# ===========================================================================

def test_sign_psbt_prepegin(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Valid 1-vault Pre-PegIn passes validation and is signed silently."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    # Derive root + hashlock first so we can build the PSBT before approving the intent.
    # The intent must commit to the txid of this exact PSBT.
    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt(htlc_spk,
                                input_internal_key=input_key,
                                input_fingerprint=fingerprint,
                                input_coin_type=coin_type,
                                auth_anchor=vault_auth_anchor(_DERIVED_ROOT))

    # Approve intent with the txid the device will compute from this PSBT.
    scalars_tlv = _build_intent_tlv_for_test(
        coin_type, _hash256(psbt.tx.serialize_without_witness())
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
    )

    wallet = _standard_taproot_wallet(client, coin_type)

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 1, f"expected one signature, got {len(result)}"
    input_index, partial_sig = result[0]
    assert input_index == 0
    assert len(partial_sig.signature) == 64, (
        f"expected 64-byte SIGHASH_DEFAULT Schnorr sig, got {len(partial_sig.signature)}"
    )


# ---------------------------------------------------------------------------
# Wallet-policy scriptSig precondition
#
# _validate_prepegin reconstructs the Pre-PegIn txid with an empty scriptSig on every
# input.  That only matches the broadcast transaction under a native SegWit policy, so
# the validator rejects anything else before the txid gate.  Each case below commits the
# intent to the txid the device *does* compute, so acceptance or rejection is decided by
# the policy alone and never by a txid mismatch.
# ---------------------------------------------------------------------------

def _setup_prepegin_ecdsa_case(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    purpose: int,
):
    """Approve an intent bound to a Pre-PegIn PSBT spending a `purpose` wallet input.

    Returns (psbt, coin_type, pubkey) where pubkey is the input's compressed wallet key.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, pubkey = _ecdsa_input_key(client, purpose, coin_type)
    psbt = _build_prepegin_psbt_ecdsa(
        htlc_spk, purpose, fingerprint, pubkey, coin_type,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
    )

    scalars_tlv = _build_intent_tlv_for_test(
        coin_type, _hash256(psbt.tx.serialize_without_witness())
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
    )
    return psbt, coin_type, pubkey


def test_sign_psbt_prepegin_native_segwit_wallet(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Pre-PegIn under wpkh() (BIP-84) is accepted and signed.

    Native SegWit v0 inputs spend with an empty scriptSig, so the HLD's "SIGHASH_ALL
    (SegWit v0) or SIGHASH_DEFAULT (Taproot v1)" rule stays satisfiable and the device's
    txid reconstruction is exact.
    """
    psbt, coin_type, pubkey = _setup_prepegin_ecdsa_case(
        client, navigator, device, bitcoin_network, BIP84_NATIVE_SEGWIT
    )
    wallet = _standard_native_segwit_wallet(client, coin_type)

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 1, f"expected one signature, got {len(result)}"
    input_index, partial_sig = result[0]
    assert input_index == 0
    assert partial_sig.pubkey == pubkey, "signed with an unexpected key"
    # SegWit v0 is signed with ECDSA: a DER signature plus a trailing SIGHASH_ALL byte.
    sig = partial_sig.signature
    assert sig[0] == 0x30, f"expected a DER-encoded ECDSA signature, got 0x{sig[0]:02x}"
    assert len(sig) == sig[1] + 3, (
        f"DER length byte {sig[1]} inconsistent with a {len(sig)}-byte signature"
    )
    assert sig[-1] == 0x01, f"expected a SIGHASH_ALL trailer, got 0x{sig[-1]:02x}"


def test_sign_psbt_prepegin_nested_segwit_wallet_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Pre-PegIn under sh(wpkh()) (BIP-49) is refused.

    A P2SH-wrapped input spends with a 23-byte redeemScript push in its scriptSig, so the
    broadcast txid can never equal the one the device computed and the intent committed to.
    """
    psbt, coin_type = _setup_prepegin_ecdsa_case(
        client, navigator, device, bitcoin_network, BIP49_NESTED_SEGWIT
    )
    wallet = _standard_nested_segwit_wallet(client, coin_type)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_legacy_wallet_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Pre-PegIn under pkh() (BIP-44) is refused.

    A legacy input spends with a ~106-byte signature + pubkey scriptSig, so the broadcast
    txid can never equal the one the device computed and the intent committed to.
    """
    psbt, coin_type = _setup_prepegin_ecdsa_case(
        client, navigator, device, bitcoin_network, BIP44_LEGACY
    )
    wallet = _standard_legacy_wallet(client, coin_type)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_3vaults(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """3-vault Pre-PegIn passes validation and is signed silently.

    Acceptance criterion NAPPS-1444: 3-vault Pre-PegIn with correct HTLC outputs and
    OP_RETURN (positioned after all HTLCs) passes device validation and returns one
    BIP-86 Taproot Schnorr signature per wallet input.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    # Derive root first so we can build the PSBT before approving the intent.
    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(
        client, VAULT_APP_NAME, depositor_path(coin_type), _DERIVE_CONTEXT, navigator, device
    )
    hashlocks = [vault_hashlock(_DERIVED_ROOT, v) for v in _3V_HTLC_VOUTS]

    group_htlc_outputs = []
    for i, h in enumerate(hashlocks):
        _, _, _, _, htlc_spk = _htlc_output(
            dep_pk, _VP_KEYS[i], _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, h,
        )
        htlc_value = (_3V_VAULT_AMOUNTS[i] + _3V_DEPOSITOR_CLAIM_VALUES[i]
                      + _PEGIN_ANCHOR_VALUE + 10_000)
        group_htlc_outputs.append((htlc_spk, htlc_value))

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt_multi_vault(
        group_htlc_outputs,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
    )

    # Approve intent with the txid the device will compute from this PSBT.
    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=_BASE_FEE_RATE,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=_hash256(psbt.tx.serialize_without_witness()),
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=len(_TEST_KEEPER_PKS),
        challenger_count=len(_TEST_CHALLENGER_PKS),
        prepegin_max_fee=500_000,
        vault_count=3,
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=_build_groups_tlv_3vault(),
    )

    wallet = _standard_taproot_wallet(client, coin_type)

    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 1, f"expected one signature, got {len(result)}"
    input_index, partial_sig = result[0]
    assert input_index == 0
    assert len(partial_sig.signature) == 64, (
        f"expected 64-byte SIGHASH_DEFAULT Schnorr sig, got {len(partial_sig.signature)}"
    )


def test_sign_psbt_prepegin_wrong_htlc_spk_vault1(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when vault group 1's HTLC scriptPubKey is wrong."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlocks = _setup_s1_state_3vault(client, navigator, device, coin_type)

    group_htlc_outputs = []
    for i, h in enumerate(hashlocks):
        wrong_h = bytes([0xde] * 32) if i == 1 else h
        _, _, _, _, htlc_spk = _htlc_output(
            dep_pk, _VP_KEYS[i], _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
            _HTLC_REFUND_TIMELOCK, wrong_h,
        )
        htlc_value = (_3V_VAULT_AMOUNTS[i] + _3V_DEPOSITOR_CLAIM_VALUES[i]
                      + _PEGIN_ANCHOR_VALUE + 10_000)
        group_htlc_outputs.append((htlc_spk, htlc_value))

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt_multi_vault(
        group_htlc_outputs,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
    )
    wallet = _standard_taproot_wallet(client, coin_type)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_op_return_before_htlcs(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when the OP_RETURN is positioned before the last HTLC output.

    Uses a 2-vault intent where group 0 has htlc_vout=0 and group 1 has htlc_vout=2.
    The PSBT places the OP_RETURN at vout 1, which is before the last HTLC at vout 2.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(
        client, VAULT_APP_NAME, depositor_path(coin_type), _DERIVE_CONTEXT, navigator, device
    )
    # Two groups: htlc_vout 0 and 2 (gap at 1 where the OP_RETURN will sit).
    hl0 = vault_hashlock(_DERIVED_ROOT, 0)
    hl2 = vault_hashlock(_DERIVED_ROOT, 2)

    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=_BASE_FEE_RATE,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=bytes(32),
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=len(_TEST_KEEPER_PKS),
        challenger_count=len(_TEST_CHALLENGER_PKS),
        prepegin_max_fee=500_000,
        vault_count=2,
    )
    groups_tlv = [
        build_group_tlv(htlc_vout=0, vault_provider_pk=_VP_KEYS[0],
                        vault_amount=_VAULT_AMOUNT, commission_fee=_COMMISSION_FEE,
                        depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
                        pegin_max_fee=_PEGIN_MAX_FEE),
        build_group_tlv(htlc_vout=2, vault_provider_pk=_VP_KEYS[1],
                        vault_amount=_VAULT_AMOUNT, commission_fee=_COMMISSION_FEE,
                        depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
                        pegin_max_fee=_PEGIN_MAX_FEE),
    ]
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, groups=groups_tlv,
    )

    _, _, _, _, htlc_spk0 = _htlc_output(
        dep_pk, _VP_KEYS[0], _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hl0,
    )
    _, _, _, _, htlc_spk2 = _htlc_output(
        dep_pk, _VP_KEYS[1], _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hl2,
    )
    htlc_value = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_ANCHOR_VALUE + 10_000
    anchor_spk = bytes([0x6A, 0x20]) + vault_auth_anchor(_DERIVED_ROOT)

    # Build PSBT manually: [htlc_0, op_return, htlc_2] — OP_RETURN is before last HTLC.
    input_value = htlc_value * 2 + 3_456
    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    _, input_tweaked = taproot_tweak_pubkey(input_key, b'')
    input_spk = bytes([0x51, 0x20]) + input_tweaked

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xaa' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [
        CTxOut(htlc_value, htlc_spk0),   # vout 0: HTLC group 0
        CTxOut(0, anchor_spk),             # vout 1: OP_RETURN before last HTLC — INVALID
        CTxOut(htlc_value, htlc_spk2),   # vout 2: HTLC group 1
    ]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0) for _ in tx.vout]
    psbt.inputs[0].witness_utxo = CTxOut(input_value, input_spk)
    psbt.inputs[0].tap_bip32_paths[input_key] = (
        set(),
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
    )

    wallet = _standard_taproot_wallet(client, coin_type)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


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
    """Pre-PegIn fails with SW_BAD_STATE when no vault session is active.

    Input 0 must be marked internal (via tap_bip32_paths) so the dispatch router
    reaches _validate_prepegin and its state guard fires.  Without the internal key
    the router falls through to _validate_display_wc and the wrong error is returned.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    wallet = _standard_taproot_wallet(client, coin_type)
    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt(
        bytes([0x51, 0x20]) + bytes(32),
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_BAD_STATE


def test_sign_psbt_prepegin_no_hashlock(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """APPROVE_VAULT_INTENT is rejected with SW_BAD_STATE when DERIVE_CONTEXT_HASH was not called first.

    The state machine requires HASH_DERIVED before any APPROVE_VAULT_INTENT phase.  The
    firmware enforces this at P1=0x00 (scalars), so a zero htlc_hashlock intent can never
    be loaded.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    scalars_tlv = _build_intent_tlv_for_test(coin_type, bytes(32))
    # P1=0x00 on a fresh session (IDLE state) must be rejected before any TLV parsing.
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(
            cla=CLA_VAULT, ins=INS_APPROVE_VAULT_INTENT,
            p1=P1_SCALARS, p2=P2_UNUSED, data=scalars_tlv,
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
    After signing, pegin_signed is incremented; the device remains in VAULT_STATE_INTENT_LOADED.
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

    excessive_htlc = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_ANCHOR_VALUE + _PEGIN_MAX_FEE + 1
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


def test_sign_psbt_pegin_wrong_htlc_vout(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when input 0 spends the wrong htlc_vout (vout != group.htlc_vout)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    # Build PegIn PSBT with vout=1 but the intent has htlc_vout=0.
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID, htlc_vout=1)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_2vault_group_index(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn succeeds for group 0 of a 2-vault intent (regression guard for the I3 fix).

    The I3 fix ensures vault_group_index is set by scanning htlc_hashlock entries, not
    by a hardcoded index.  vault_count=2 distinguishes htlc_hashlock[0] from
    htlc_hashlock[1]; with vault_count=1 both indices alias the same slot.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state_2vault(client, navigator, device, coin_type)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


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


def test_sign_psbt_prepegin_cpfp_anchor_accepted(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Pre-PegIn with a P2TR(depositor_pk) CPFP anchor at VAULT_DUST_LIMIT is accepted."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    cpfp_spk = _bip86_depositor_spk(dep_pk)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
        cpfp_anchor_spk=cpfp_spk,
    )

    scalars_tlv = _build_intent_tlv_for_test(
        coin_type, _hash256(psbt.tx.serialize_without_witness())
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
    )

    wallet = _standard_taproot_wallet(client, coin_type)
    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 1
    input_index, partial_sig = result[0]
    assert input_index == 0
    assert len(partial_sig.signature) == 64


def test_sign_psbt_prepegin_duplicate_cpfp_anchor_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Pre-PegIn fails when two CPFP anchor outputs are present."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    cpfp_spk = _bip86_depositor_spk(dep_pk)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        cpfp_anchor_spk=cpfp_spk,
    )
    # Append a second CPFP anchor — must be rejected.
    psbt.tx.vout.append(CTxOut(_VAULT_DUST_LIMIT, cpfp_spk))
    psbt.outputs.append(PartiallySignedOutput(0))

    wallet = _standard_taproot_wallet(client, coin_type)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_cpfp_anchor_wrong_value_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Pre-PegIn fails when CPFP anchor value differs from VAULT_DUST_LIMIT."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    cpfp_spk = _bip86_depositor_spk(dep_pk)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        cpfp_anchor_spk=cpfp_spk,
        cpfp_anchor_value=_VAULT_DUST_LIMIT + 1,  # off by one — must be rejected
    )

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
    """AppChallengers = {VP, VK_1..VK_N} \\ {Claimer}, sorted ascending lexicographically.

    VP or Depositor (idx == 0 or idx == keeper_count+1): AppChallengers = sorted(keeper_pks).
    Matches C vault_script.c build_app_challengers — both cases return all VaultKeepers.
    VK_i (idx == i): AppChallengers = sorted({VP, VK_1..VK_N} \\ {VK_{i-1}}).
    """
    if claimer_idx == 0 or claimer_idx == len(keeper_pks) + 1:
        return sorted(keeper_pks)
    claimer_key = keeper_pks[claimer_idx - 1]
    return sorted(k for k in ([vp_key] + list(keeper_pks)) if k != claimer_key)


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
    buf += struct.pack('<Q', _PEGIN_ANCHOR_VALUE) + b'\x04\x51\x02\x4e\x73'  # P2A anchor
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
    vp_key: Optional[bytes] = None,
) -> PSBT:
    """Build a valid Payout PSBTv0 for the given claimer_idx.

    Input 0 spends Vault UTXO from computed_pegin_txid:0 with sequence=pegin_csv_timelock.
    Input 1 spends Assert:0 UTXO (arbitrary txid, value=VAULT_DUST_LIMIT) with sequence=payout_timelock.
    VP (idx==0):            Out0=depositor (V-fee-Fc), Out1=VP (Fc), Out2=VP CPFP anchor (DUST).
    VK (idx==1..N):         Out0=VaultKeeper_i (V-fee), Out1=VaultKeeper_i CPFP anchor (DUST).
    Depositor (idx==N+1):   Out0=depositor (V-fee), Out1=depositor CPFP anchor (DUST) — script-verified.
    """
    if vp_key is None:
        vp_key = TEST_VP_KEY
    # Reconstruct leaves to compute scriptPubKeys and txid
    vault_utxo_leaf = _vault_utxo_leaf(
        depositor_pk, vp_key, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, pegin_csv_timelock,
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
    keeper_count = len(_TEST_KEEPER_PKS)
    if claimer_idx == 0:
        claimer_key = vp_key
    elif claimer_idx == keeper_count + 1:
        claimer_key = depositor_pk          # Depositor is the claimer
    else:
        claimer_key = _TEST_KEEPER_PKS[claimer_idx - 1]
    app_challengers = _build_app_challengers(vp_key, _TEST_KEEPER_PKS, claimer_idx)
    assert0_leaf = _assert0_payout_leaf(
        claimer_key, app_challengers, _TEST_CHALLENGER_PKS, payout_timelock,
    )
    assert0_spk = _p2tr_from_single_leaf(assert0_leaf)

    if claimer_idx == 0:  # VP claimer
        out0_value = vault_amount + VAULT_DUST_LIMIT - fee - commission_fee - VAULT_DUST_LIMIT
        out1_value = commission_fee
        out2_value = VAULT_DUST_LIMIT
        out0_spk = _bip86_p2tr_spk(depositor_pk)
        out1_spk = _bip86_p2tr_spk(vp_key)
        out2_spk = _bip86_p2tr_spk(vp_key)
    elif claimer_idx == keeper_count + 1:  # Depositor claimer — Out0 and Out1 both script-verified
        out0_value = vault_amount + VAULT_DUST_LIMIT - fee - VAULT_DUST_LIMIT
        out1_value = VAULT_DUST_LIMIT
        out0_spk = _bip86_p2tr_spk(depositor_pk)
        out1_spk = _bip86_p2tr_spk(depositor_pk)
    else:  # VK claimer — Out0 and Out1 value-only in v22
        out0_value = vault_amount + VAULT_DUST_LIMIT - fee - VAULT_DUST_LIMIT
        out1_value = VAULT_DUST_LIMIT
        out0_spk = _bip86_p2tr_spk(claimer_key)
        out1_spk = _bip86_p2tr_spk(claimer_key)

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
    """Approve intent then sign PegIn (pegin_signed=1, payout_index=0). Returns the 32-byte hashlock."""
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


def test_sign_psbt_payout_multileaf_assert0(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Assert:0 with a 2-leaf Huffman taptree (payout + nopayout sibling) passes.

    The 65-byte control block contains one sibling hash. Exercises the
    _refund_verify_taproot_commitment path for payout, which must iterate sibling
    hashes to reconstruct the merkle root and verify the WITNESS_UTXO SPK — the
    single-leaf assumption that triggered this bug would reject an honest payout here.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)

    # Extract the payout leaf from the single-leaf PSBT built above.
    (assert0_leaf, _leaf_ver), _cbs = next(iter(psbt.inputs[1].tap_scripts.items()))

    # NoPayout sibling: <VP> OP_CHECKSIGVERIFY <keeper_0> OP_CHECKSIG
    # (mirrors btc-vault Assert:0 NoPayout leaf; exact content only affects the sibling
    # hash, not the payout-leaf commitment the firmware verifies).
    nopayout_leaf = (
        bytes([0x20]) + TEST_VP_KEY
        + bytes([0xAD])               # OP_CHECKSIGVERIFY
        + bytes([0x20]) + _TEST_KEEPER_PKS[0]
        + bytes([0xAC])               # OP_CHECKSIG
    )

    # 2-leaf merkle root (sorted TapBranch, as in BIP-341 and btc-vault Huffman tree).
    merkle_root = _taptree2_root(assert0_leaf, nopayout_leaf)
    assert0_parity, assert0_tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, merkle_root)

    # 65-byte control block: (0xC0 | parity) || internal_key || nopayout_leaf_hash
    nopayout_lh = _tapleaf_hash(nopayout_leaf)
    assert0_cb = bytes([0xC0 | assert0_parity]) + VAULT_NUMS_XONLY + nopayout_lh

    # Replace Input 1 with the multi-leaf Assert:0 UTXO.
    psbt.inputs[1].witness_utxo = CTxOut(VAULT_DUST_LIMIT, bytes([0x51, 0x20]) + assert0_tweaked)
    psbt.inputs[1].tap_scripts = {(assert0_leaf, 0xC0): {assert0_cb}}

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


def test_sign_psbt_payout_vk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP then VK_1 then Depositor payouts all succeed; each signs the Vault UTXO input.

    For a 1-keeper vault (N=1) the full sequence is 3 claimers (N+2):
      idx 0 = VP, idx 1 = VK_1, idx 2 = Depositor.
    payout_signed reaches N+2 after the Depositor (last) payout.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    # VP payout — advances payout_index to 1
    vp_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    result = client.sign_psbt(vp_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)

    # VK_1 payout — advances payout_index to 2
    vk_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    result = client.sign_psbt(vk_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)

    # Depositor payout — last payout, payout_signed reaches N+2
    dep_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID,
                                  claimer_idx=len(_TEST_KEEPER_PKS) + 1)
    result = client.sign_psbt(dep_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


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
    """VK payout succeeds before VP — no inter-transaction ordering requirement (HLD v22)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    # VK_1 payout presented before VP must succeed per HLD (no claimer ordering enforced).
    vk_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    result = client.sign_psbt(vk_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


# ===========================================================================
# Payout — host-provided (VK/VP registered address) output script length
#
# Out0 of a VK payout is value-only: the address is registered in the vault contract, so
# the device cannot derive it and enforces only length and not-OP_RETURN. The accepted
# range is VAULT_PAYOUT_SPK_MIN_LEN..VAULT_PAYOUT_SPK_MAX_LEN.
#
# The upper bound is the base app's MAX_OUTPUT_SCRIPTPUBKEY_LEN, not the vault contract's
# MAX_PAYOUT_ADDRESS_LENGTH (128): hash_output_n reads every output script into that buffer
# while computing the sighash, so a longer output cannot be signed at all. Registrable
# addresses in 84..128 bytes — in practice only bare multisig of 3+ compressed keys — are
# therefore out of reach until the submoduled base app widens its buffer.
# ===========================================================================

_PAYOUT_SPK_MIN_LEN = 22  # must match VAULT_PAYOUT_SPK_MIN_LEN in vault_script.h
_PAYOUT_SPK_MAX_LEN = 83  # must match MAX_OUTPUT_SCRIPTPUBKEY_LEN in the base app


@pytest.mark.parametrize("spk_len", [_PAYOUT_SPK_MIN_LEN, 34, 42, _PAYOUT_SPK_MAX_LEN])
def test_sign_psbt_payout_host_spk_length_accepted(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
    spk_len: int,
) -> None:
    """A VK payout Out0 script anywhere in 22..83 bytes is accepted.

    Covers every standard address type the device can sign for: P2WPKH (22), P2WSH/P2TR
    (34), the longest future witness program (42), and the buffer boundary (83).
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    psbt.tx.vout[0].scriptPubKey = bytes([0x51, spk_len - 2]) + bytes(spk_len - 2)
    assert len(psbt.tx.vout[0].scriptPubKey) == spk_len

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


@pytest.mark.parametrize("spk_len", [1, _PAYOUT_SPK_MIN_LEN - 1, _PAYOUT_SPK_MAX_LEN + 1, 105])
def test_sign_psbt_payout_host_spk_length_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
    spk_len: int,
) -> None:
    """A VK payout Out0 script outside 22..83 bytes is refused.

    Below 22 no standard output script exists. Above 83 the base app cannot hash the output
    into the sighash, so the signature could never be produced; 105 is the concrete case —
    a compressed 3-of-3 bare multisig, registrable in the contract but unsignable here.
    Both ends fail closed rather than being signed over.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    psbt.tx.vout[0].scriptPubKey = bytes([0x51]) + bytes(spk_len - 1)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_host_spk_op_return_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """A VK payout Out0 paying to OP_RETURN is refused — the funds would be unspendable."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    psbt.tx.vout[0].scriptPubKey = bytes([0x6A, 0x20]) + bytes(32)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
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


def test_sign_psbt_payout_vp_commission_over_fc(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP Payout fails when Out1 exceeds commission_fee."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vout[1].nValue = _COMMISSION_FEE + 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_vp_commission_sub_dust(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP Payout fails when Out1 is sub-dust (0 < out_value < VAULT_DUST_LIMIT).

    commission_fee >= VAULT_DUST_LIMIT is enforced at intent-loading time, so any
    non-zero VP commission below the dust limit would create a non-standard output.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vout[1].nValue = _VAULT_DUST_LIMIT - 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_vp_reduced_commission(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP Payout succeeds when Out1 is below Fc — VP may take less than the approved commission."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    # Reduce Out1 by 1 sat; the difference raises the effective fee (still within bound).
    psbt.tx.vout[1].nValue = _COMMISSION_FEE - 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


def test_sign_psbt_payout_vp_commission_at_fc(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP Payout succeeds when Out1 equals commission_fee (Fc), the upper bound."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    # Out1 is already set to _COMMISSION_FEE by _build_payout_psbt; assert the boundary.
    assert psbt.tx.vout[1].nValue == _COMMISSION_FEE

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


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
    """Load signet vault intent and sign PegIn to advance payout_index=0."""
    dep_pk = TEST_DEPOSITOR_XONLY_MAINNET if coin_type == 0 else TEST_DEPOSITOR_XONLY_TESTNET

    # New spec: DERIVE_CONTEXT_HASH returns the root; the per-vault hashlock is
    # SHA256(Expand(root, "hashlock" || I2OSP(htlc_vout,4))), matching what the device
    # recomputes at APPROVE_VAULT_INTENT.
    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)

    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=1,
        pegin_csv_timelock=_SIGNET_TIMELOCK,
        payout_timelock=_SIGNET_TIMELOCK,
        prepegin_txid=_PREPEGIN_TXID,
        htlc_refund_timelock=_SIGNET_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=len(_SIGNET_KEEPER_PKS),
        challenger_count=len(_SIGNET_CHALLENGER_PKS),
        prepegin_max_fee=500_000,
        vault_count=1,
    )
    group_tlv = build_group_tlv(
        htlc_vout=_HTLC_VOUT,
        vault_provider_pk=_SIGNET_VP_KEY,
        vault_amount=_SIGNET_VAULT_AMOUNT,
        commission_fee=_SIGNET_COMMISSION_FEE,
        depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
        pegin_max_fee=_PEGIN_MAX_FEE,
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _SIGNET_KEEPER_PKS, _SIGNET_CHALLENGER_PKS,
        groups=[group_tlv],
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
    htlc_value = _SIGNET_VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_ANCHOR_VALUE + 1_000
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
        CTxOut(_PEGIN_ANCHOR_VALUE, p2a_spk),
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


def _build_signet_payout_psbt(
    depositor_pk: bytes,
    claimer_idx: int,
) -> PSBT:
    """Build a Payout PSBT for the signet vault (3 keepers, 3 challengers, timelock=432).

    VP (idx=0):          Out0=depositor(1_330_072), Out1=VP commission(13_443), Out2=VP CPFP(546).
    VK (idx=1..3):       Out0=VaultKeeper(V-fee), Out1=VaultKeeper CPFP anchor(546).
    Depositor (idx=4):   Out0=depositor(V-fee), Out1=depositor CPFP anchor(546) — script-verified.
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

    signet_keeper_count = len(_SIGNET_KEEPER_PKS)
    if claimer_idx == 0:
        claimer_key = _SIGNET_VP_KEY
    elif claimer_idx == signet_keeper_count + 1:
        claimer_key = depositor_pk
    else:
        claimer_key = _SIGNET_KEEPER_PKS[claimer_idx - 1]
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
    elif claimer_idx == signet_keeper_count + 1:
        out0_value = _SIGNET_VAULT_AMOUNT - _SIGNET_FEE
        out1_value = VAULT_DUST_LIMIT
        out0_spk = _bip86_p2tr_spk(depositor_pk)
        out1_spk = _bip86_p2tr_spk(depositor_pk)
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
    Runs all N+2 = 5 claimers: VP (idx=0), VK_1..VK_3 (idx=1..3), Depositor (idx=4).
    payout_signed reaches N+2 after the Depositor (last) payout.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_signet_payout_state(client, navigator, device, coin_type)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    for ci in range(len(_SIGNET_KEEPER_PKS) + 2):  # 0=VP, 1..3=VK, 4=Depositor
        psbt = _build_signet_payout_psbt(dep_pk, claimer_idx=ci)
        result = client.sign_psbt(psbt, dummy_wallet, None)
        _assert_single_schnorr_sig(result, dep_pk)


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


# ===========================================================================
# CPFP anchor key validation (NAPPS-1445)
# ===========================================================================

def test_sign_psbt_payout_vp_wrong_cpfp_anchor_key(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP CPFP anchor is value-only in v22; wrong scriptPubKey key is accepted."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    wrong_key = TEST_VALID_KEYS[2]
    psbt.tx.vout[2] = CTxOut(VAULT_DUST_LIMIT, _bip86_p2tr_spk(wrong_key))

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    result = client.sign_psbt(psbt, dummy_wallet, None)
    assert len(result) >= 1


def test_sign_psbt_payout_vk_wrong_cpfp_anchor_key(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VK CPFP anchor is value-only in v22; wrong scriptPubKey key is accepted."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    # VP payout first to advance payout_index to 1 (VK turn).
    vp_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    client.sign_psbt(vp_psbt, dummy_wallet, None)

    # VK payout with a tampered CPFP anchor key — accepted in v22 (value-only check).
    vk_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    wrong_key = TEST_VALID_KEYS[2]
    vk_psbt.tx.vout[1] = CTxOut(VAULT_DUST_LIMIT, _bip86_p2tr_spk(wrong_key))

    result = client.sign_psbt(vk_psbt, dummy_wallet, None)
    assert len(result) >= 1


# ===========================================================================
# 3-vault batch iteration (NAPPS-1445)
# ===========================================================================

def test_sign_psbt_payout_3vault_batch(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """3-vault batch: payout_signed cap is reached only after all 3 groups' payouts are signed.

    Uses uniform groups (same vault_amount/commission_fee, htlc_vout = 0/1/2) to keep
    the PSBT builders simple.  Verifies that intermediate group completions succeed and
    that a post-cap attempt returns SW_CAP_EXCEEDED.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    # Derive root and approve a 3-vault intent with uniform group parameters.
    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(
        client, VAULT_APP_NAME, depositor_path(coin_type), _DERIVE_CONTEXT, navigator, device
    )
    hashlock_0 = vault_hashlock(_DERIVED_ROOT, 0)
    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=_BASE_FEE_RATE,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=_PREPEGIN_TXID,
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=len(_TEST_KEEPER_PKS),
        challenger_count=len(_TEST_CHALLENGER_PKS),
        prepegin_max_fee=500_000,
        vault_count=3,
    )
    uniform_groups = [
        build_group_tlv(
            htlc_vout=i,
            vault_provider_pk=_VP_KEYS[i],
            vault_amount=_VAULT_AMOUNT,
            commission_fee=_COMMISSION_FEE,
            depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
            pegin_max_fee=_PEGIN_MAX_FEE,
        )
        for i in range(3)
    ]
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=uniform_groups,
    )

    # PegIn for group 0 only (multi-vault PegIn for groups 1/2 is not yet implemented).
    pegin_psbt = _build_pegin_psbt(dep_pk, hashlock_0, _PREPEGIN_TXID, htlc_vout=0)
    client.sign_psbt(pegin_psbt, dummy_wallet, None)

    # Sign all N+2 payouts for each of the 3 groups in order.
    # claimer_idx: 0=VP, 1..keeper_count=VK_i, keeper_count+1=Depositor.
    for gi in range(3):
        for ci in range(len(_TEST_KEEPER_PKS) + 2):  # 0=VP, 1=VK_1, 2=Depositor
            psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=ci, htlc_vout=gi,
                                      vp_key=_VP_KEYS[gi])
            result = client.sign_psbt(psbt, dummy_wallet, None)
            _assert_single_schnorr_sig(result, dep_pk)

    # payout_signed cap is now reached; any further payout must be rejected.
    extra_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0, htlc_vout=0)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(extra_psbt, dummy_wallet, None)
    assert exc.value.status == SW_CAP_EXCEEDED


# ===========================================================================
# Depositor claimer payout (NAPPS-1462)
# ===========================================================================

def test_sign_psbt_payout_depositor(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Depositor claimer (idx=keeper_count+1): both Out0 and Out1 are script-verified BIP-86 P2TR(D)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # Advance past VP and all VK claimers
    for ci in range(len(_TEST_KEEPER_PKS) + 1):
        psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=ci)
        client.sign_psbt(psbt, dummy_wallet, None)

    # Depositor payout — claimer_idx = keeper_count + 1
    dep_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID,
                                  claimer_idx=len(_TEST_KEEPER_PKS) + 1)
    result = client.sign_psbt(dep_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


def test_sign_psbt_payout_depositor_wrong_cpfp_anchor_key(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Depositor payout: wrong Out1 scriptPubKey returns SW_BAD_CPFP_ANCHOR (0xB009)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # Advance past VP and all VK claimers
    for ci in range(len(_TEST_KEEPER_PKS) + 1):
        psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=ci)
        client.sign_psbt(psbt, dummy_wallet, None)

    # Depositor payout with tampered Out1 (wrong anchor key) → SW_BAD_CPFP_ANCHOR
    dep_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID,
                                  claimer_idx=len(_TEST_KEEPER_PKS) + 1)
    wrong_key = TEST_VALID_KEYS[2]
    dep_psbt.tx.vout[1] = CTxOut(VAULT_DUST_LIMIT, _bip86_p2tr_spk(wrong_key))

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(dep_psbt, dummy_wallet, None)
    assert exc.value.status == SW_BAD_CPFP_ANCHOR


# ===========================================================================
# NoPayout transaction (NAPPS-1462)
# ===========================================================================

# NoPayout amounts. Input 0 (Assert:0) carries the fee, Inputs 1-2 are DUST connectors.
# The firmware bounds the implied fee by base_fee_rate * MAX_COUNCIL_NOPAYOUT_VSIZE and
# requires Output 0 to be at least DUST, so the default output leaves a fee under the cap.
_NOPAYOUT_INPUTS_TOTAL = 3 * VAULT_DUST_LIMIT
_NOPAYOUT_MAX_FEE = _BASE_FEE_RATE * _MAX_COUNCIL_NOPAYOUT_VSIZE
_NOPAYOUT_OUT_VALUE = _NOPAYOUT_INPUTS_TOTAL - 400


def _build_nopayout_psbt(
    depositor_pk: bytes,
    challenger_pk: bytes,
    assert_txid: bytes = _ASSERT_TXID,
    out_value: int = _NOPAYOUT_OUT_VALUE,
) -> PSBT:
    """Build a NoPayout PSBT: 3 custom inputs, 1 output.

    Input 0: NoPayout leaf <D> OP_CHECKSIGVERIFY <Cj> OP_CHECKSIG (68 bytes),
             single-leaf P2TR (NUMS internal key), value=VAULT_DUST_LIMIT.
             Its prevout is Assert:0 (HLD: NoPayout Input 0 spends the depositor graph's
             Assert output 0). Only vout==0 is checked; the txid is unconstrained because
             the device cannot reconstruct the Assert txid.
    Inputs 1, 2: ChallengeAssert connectors — WITNESS_UTXO only (device ignores script).
    Output 0: P2TR(key-path-tweak(challenger_pk)) — device verifies this exact scriptPubKey,
             requires out_value >= DUST, and bounds the implied fee.

    Needs no intent geometry: the leaf and the output are functions of (depositor,
    challenger) alone, which is exactly why the device cannot tell vault groups apart here.
    """
    nopayout_leaf = bytes([0x20]) + depositor_pk + bytes([0xAD, 0x20]) + challenger_pk + bytes([0xAC])
    assert len(nopayout_leaf) == 68, f"NoPayout leaf must be exactly 68 bytes, got {len(nopayout_leaf)}"

    leaf_hash = _tapleaf_hash(nopayout_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    nopayout_spk = bytes([0x51, 0x20]) + tweaked
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    # Output must pay P2TR(key-path-tweak(challenger_pk)) — validated by firmware.
    _, ch_tweaked = taproot_tweak_pubkey(challenger_pk, b'')
    out_spk = bytes([0x51, 0x20]) + ch_tweaked
    connector_spk = bytes([0x51, 0x20]) + bytes(32)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(), CTxIn(), CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(assert_txid, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    for i, fill in enumerate([b'\xdd', b'\xee']):
        tx.vin[1 + i].prevout = COutPoint(int.from_bytes(fill * 32, 'little'), 0)
        tx.vin[1 + i].nSequence = 0xFFFFFFFF
    tx.vout = [CTxOut(out_value, out_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0), PartiallySignedInput(0), PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(VAULT_DUST_LIMIT, nopayout_spk)
    psbt.inputs[0].tap_scripts[(nopayout_leaf, 0xC0)] = {control_block}
    psbt.inputs[1].witness_utxo = CTxOut(VAULT_DUST_LIMIT, connector_spk)
    psbt.inputs[2].witness_utxo = CTxOut(VAULT_DUST_LIMIT, connector_spk)

    return psbt


def test_sign_psbt_nopayout(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout: silent (no display), Input 0 is signed without user confirmation."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # _TEST_KEEPER_PKS[0] is a valid challenger (keeper) in the loaded intent.
    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])

    # NoPayout is silent — no display, no navigator interaction required.
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


def test_sign_psbt_nopayout_assert_txid_unconstrained(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout Input 0 accepts any Assert txid — it is not the group's PegIn txid.

    Regression guard: the device used to identify the vault group by matching Input 0's
    PREVIOUS_TXID against each group's computed PegIn txid, which no real NoPayout PSBT
    can satisfy — Input 0 spends Assert:0, so its prevout is the Assert txid. That made
    every NoPayout from btc-vault fail with SW_INCORRECT_DATA.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # A txid unrelated to any PegIn the intent can compute.
    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0], assert_txid=bytes([0x7C]) * 32)

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


def test_sign_psbt_nopayout_wrong_input0_vout(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when Input 0's prevout vout is not 0 (Assert:0 is always output 0).

    The vout check is the only binding left on the Input 0 prevout, so it must hold.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.tx.vin[0].prevout = COutPoint(psbt.tx.vin[0].prevout.hash, 1)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_cap_exhausted(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout is rejected after cap = vault_count × (keeper_count + challenger_count) are signed."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # Cap = 1 × (1 keeper + 1 challenger) = 2.
    # NoPayout is silent — no navigator interaction for each signing.
    for ch_pk in (_TEST_KEEPER_PKS + _TEST_CHALLENGER_PKS):
        psbt = _build_nopayout_psbt(dep_pk, ch_pk)
        client.sign_psbt(psbt, dummy_wallet, None)

    # One more exceeds the cap → SW_CAP_EXCEEDED. nopayout_signed is the only bound on
    # NoPayout: the vault group is unidentifiable from the PSBT, so there is no per-slot mask.
    over_cap_psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(over_cap_psbt, dummy_wallet, None)
    assert exc.value.status == SW_CAP_EXCEEDED


def test_sign_psbt_nopayout_32_challengers(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout succeeds with the maximum 32 challengers in the intent.

    Signs with the last challenger (displayed as #33, 1-based) to exercise
    the full keeper + challenger key-set iteration in _validate_nopayout.

    Keys are generated as multiples of G starting at 2G (1G = TEST_VP_KEY is excluded),
    then sorted ascending to satisfy the firmware's strict-ordering requirement.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    # 1 keeper + 32 challengers; skip 1G because TEST_VP_KEY = 1G.
    all_keys = sorted(pubkey_gen(i.to_bytes(32, 'big')) for i in range(2, 35))
    keeper_pks    = all_keys[:1]
    challenger_pks = all_keys[1:]  # 32 keys

    # Deterministic step count avoids the Flex/Apex swipe-animation race that can occur
    # with navigate_until_text when there are many keys (33 here: 1 keeper + 32 challengers).
    # Nano and Stax are not affected by this race; leave them with text-based navigation.
    # Setup only, no snapshots — navigate to the finish page by title instead of pinning a
    # swipe count, which would need recalibrating every time NBGL repacks pairs per page.
    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID,
                               keeper_pks=keeper_pks, challenger_pks=challenger_pks)
    pegin_psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID,
                                   keeper_pks=keeper_pks, challenger_pks=challenger_pks)
    client.sign_psbt(pegin_psbt, dummy_wallet, None)

    # Sign with the last challenger key — the device must walk all 33 entries to find it.
    # NoPayout is silent — no display, no navigator interaction required.
    psbt = _build_nopayout_psbt(dep_pk, challenger_pks[-1])
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


# ===========================================================================
# Pre-PegIn without auth-anchor OP_RETURN (v22 optional)
# ===========================================================================

def test_sign_psbt_prepegin_no_op_return(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Valid Pre-PegIn without the auth-anchor OP_RETURN is accepted per v22.

    In v22 the OP_RETURN is optional (sign_psbt_validate.c: '(void) anchor_found').
    The intent must still commit to the correct prepegin_txid.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )
    fingerprint, input_key = _prepegin_input_key(client, coin_type)

    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        auth_anchor=None,  # no OP_RETURN — valid in v22
    )

    scalars_tlv = _build_intent_tlv_for_test(
        coin_type, _hash256(psbt.tx.serialize_without_witness())
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
    )

    wallet = _standard_taproot_wallet(client, coin_type)
    result = client.sign_psbt(psbt, wallet, None)
    assert len(result) == 1
    _, partial_sig = result[0]
    assert len(partial_sig.signature) == 64


# ===========================================================================
# Pre-PegIn — additional error paths
# ===========================================================================

def test_sign_psbt_prepegin_htlc_value_too_high(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when the HTLC output value exceeds vault_amount + depositor_claim_value + anchor + pegin_max_fee."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )

    too_high = _VAULT_AMOUNT + _DEPOSITOR_CLAIM_VALUE + _PEGIN_ANCHOR_VALUE + _PEGIN_MAX_FEE + 1
    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        htlc_value=too_high,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_wrong_anchor_hash(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when the OP_RETURN carries a wrong 32-byte payload (not SHA-256(authAnchor))."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    wallet = _standard_taproot_wallet(client, coin_type)
    # Pass bytes(32) as auth_anchor: OP_RETURN payload will be all-zeros, not SHA256(authAnchor).
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        auth_anchor=bytes(32),
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_nonzero_locktime(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when nLockTime is non-zero."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        locktime=1,
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_wrong_tx_version(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when nVersion is not 2."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    wallet = _standard_taproot_wallet(client, coin_type)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        tx_version=1,
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# Pre-PegIn — signature cap
# ===========================================================================

def test_sign_psbt_prepegin_cap_exceeded(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn signing is capped at 1 per intent; a second attempt returns SW_CAP_EXCEEDED."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )
    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
    )
    scalars_tlv = _build_intent_tlv_for_test(
        coin_type, _hash256(psbt.tx.serialize_without_witness())
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
    )
    wallet = _standard_taproot_wallet(client, coin_type)

    result = client.sign_psbt(psbt, wallet, None)
    assert len(result) == 1

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_CAP_EXCEEDED


def test_sign_psbt_prepegin_cap_nullifies_intent(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """After Pre-PegIn cap is exceeded the intent is nullified; PegIn returns SW_BAD_STATE."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )
    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
    )
    scalars_tlv = _build_intent_tlv_for_test(
        coin_type, _hash256(psbt.tx.serialize_without_witness())
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
    )
    wallet = _standard_taproot_wallet(client, coin_type)

    client.sign_psbt(psbt, wallet, None)  # first sign: OK
    with pytest.raises(ExceptionRAPDU):
        client.sign_psbt(psbt, wallet, None)  # cap exceeded: intent nullified

    # Intent nullified — any PSBT requiring state returns SW_BAD_STATE.
    pegin_psbt = _build_pegin_psbt(dep_pk, vault_hashlock(_DERIVED_ROOT, _HTLC_VOUT),
                                   _hash256(psbt.tx.serialize_without_witness()))
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(pegin_psbt, dummy_wallet, None)
    assert exc.value.status == SW_BAD_STATE


def test_sign_psbt_prepegin_wrong_txid_binding(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when intent->prepegin_txid doesn't match hash256 of the PSBT tx.

    The intent commits to a specific Pre-PegIn transaction by storing its txid.
    Signing a different transaction must be rejected with SW_INCORRECT_DATA.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, _HTLC_REFUND_TIMELOCK, hashlock,
    )
    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
    )

    # Load intent with a wrong (non-zero) prepegin_txid — doesn't match this PSBT.
    wrong_txid = bytes([0xFF] * 32)
    scalars_tlv = _build_intent_tlv_for_test(coin_type, wrong_txid)
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
    )

    wallet = _standard_taproot_wallet(client, coin_type)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# PegIn — additional error paths
# ===========================================================================

def test_sign_psbt_pegin_wrong_tx_version(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when nVersion is not 3 (TRUC/BIP-431)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.nVersion = 2

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_anchor_spk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when Output 2 (P2A anchor) scriptPubKey is not the canonical P2A script."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vout[2].scriptPubKey = bytes([0x51, 0x20]) + bytes(32)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_anchor_value(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when Output 2 (P2A anchor) value is not exactly 240 sat."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vout[2].nValue = 241

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_claim_spk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when Output 1 (Depositor Claim) scriptPubKey doesn't match the reconstructed claim output."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.vout[1].scriptPubKey = bytes([0x51, 0x20]) + bytes(32)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_nonzero_locktime(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn fails when nLockTime is non-zero."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    psbt.tx.nLockTime = 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# PegIn — signature cap
# ===========================================================================

def test_sign_psbt_pegin_cap_exceeded(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn signing is capped at vault_count (1) per intent; a second attempt returns SW_CAP_EXCEEDED."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_CAP_EXCEEDED


def test_sign_psbt_pegin_cap_nullifies_intent(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """After PegIn cap is exceeded the intent is nullified; any further signing returns SW_BAD_STATE."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)

    client.sign_psbt(psbt, dummy_wallet, None)  # first sign: OK
    with pytest.raises(ExceptionRAPDU):
        client.sign_psbt(psbt, dummy_wallet, None)  # cap exceeded: intent nullified

    # Intent nullified — NoPayout must return SW_BAD_STATE.
    nopayout_psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(nopayout_psbt, dummy_wallet, None)
    assert exc.value.status == SW_BAD_STATE


def test_sign_psbt_pegin_duplicate_group_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Replaying the same PegIn PSBT for the same group returns SW_CAP_EXCEEDED (per-group dedup).

    vault_count=2 keeps the flat pegin_signed cap at 2, so only the per-group bitmask
    prevents the replay — not the flat cap.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    hashlock = _setup_s2_state_2vault(client, navigator, device, coin_type)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)  # first: OK

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)  # replay group 0: mask fires
    assert exc.value.status == SW_CAP_EXCEEDED


def test_sign_psbt_pegin_duplicate_group_nullifies_intent(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """After a duplicate PegIn group is rejected the intent is nullified; further signing returns SW_BAD_STATE."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    hashlock = _setup_s2_state_2vault(client, navigator, device, coin_type)
    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)

    client.sign_psbt(psbt, dummy_wallet, None)  # first: OK
    with pytest.raises(ExceptionRAPDU):
        client.sign_psbt(psbt, dummy_wallet, None)  # duplicate: intent nullified

    # Intent nullified (state zeroed to IDLE) — PegIn is routed before the INTENT_LOADED
    # gate and hits the SW_BAD_STATE guard inside _validate_pegin.
    hashlock1 = vault_hashlock(_DERIVED_ROOT, 1)  # group 1 (htlc_vout=1)
    pegin1_psbt = _build_pegin_psbt(dep_pk, hashlock1, _PREPEGIN_TXID, htlc_vout=1)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(pegin1_psbt, dummy_wallet, None)
    assert exc.value.status == SW_BAD_STATE


# ===========================================================================
# Refund — additional error paths
# ===========================================================================

def test_sign_psbt_refund_wrong_sighash(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when PSBT_IN_SIGHASH_TYPE is set to SIGHASH_ALL (device expects SIGHASH_DEFAULT)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.inputs[0].sighash = 1  # SIGHASH_ALL

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_wrong_nsequence(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when nSequence does not equal csv_timelock (too high or zero)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type, csv_timelock=144)
    psbt.tx.vin[0].nSequence = 145  # csv_timelock + 1

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA

    psbt2 = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type, csv_timelock=144)
    psbt2.tx.vin[0].nSequence = 0

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt2, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_extra_output(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when the PSBT has 2 outputs instead of exactly 1."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.tx.vout.append(CTxOut(1000, bytes([0x51, 0x20]) + bytes(32)))
    psbt.outputs.append(PartiallySignedOutput(0))

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_extra_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when the PSBT has 2 inputs instead of exactly 1."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_refund_wrong_tx_version(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Refund fails when nVersion is not 2."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    out_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/1", display=False)
    ).pubkey[1:]

    psbt = _build_refund_psbt(fingerprint, leaf_key, out_key, coin_type)
    psbt.tx.nVersion = 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# Payout — additional error paths
# ===========================================================================

def test_sign_psbt_payout_vp_wrong_out0_key(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """VP Payout fails when Output 0 scriptPubKey is not BIP-86(depositor)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vout[0].scriptPubKey = _bip86_p2tr_spk(TEST_VALID_KEYS[3])

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_out0_at_dust_limit(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when Output 0 value equals VAULT_DUST_LIMIT (must be strictly greater)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.vout[0].nValue = VAULT_DUST_LIMIT  # exactly 546 — boundary: must be strictly > VAULT_DUST_LIMIT

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_zero_fee(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when fee is zero (sum of inputs equals sum of outputs)."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0, fee=0)

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_nonzero_locktime(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when nLockTime is non-zero."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.nLockTime = 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_wrong_version(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Payout fails when nVersion is not 2."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    psbt.tx.nVersion = 1

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_duplicate_claimer_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Replaying the same Payout PSBT for the same claimer returns SW_CAP_EXCEEDED.

    The per-slot bitmask (payout_claimer_mask) must reject a second signing of the
    same (group, claimer) pair even when the flat payout_signed counter is below cap.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)  # first sign: OK

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)  # same PSBT again: rejected
    assert exc.value.status == SW_CAP_EXCEEDED


def test_sign_psbt_payout_duplicate_claimer_nullifies_intent(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """After a duplicate Payout is rejected the intent is nullified; further signing returns SW_INCORRECT_DATA."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=0)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    client.sign_psbt(psbt, dummy_wallet, None)  # first sign: OK
    with pytest.raises(ExceptionRAPDU):
        client.sign_psbt(psbt, dummy_wallet, None)  # duplicate: intent nullified

    # Intent nullified (state zeroed to IDLE) — payout routing is skipped entirely;
    # the PSBT hits the standalone fallback and returns SW_INCORRECT_DATA.
    vk_psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=1)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(vk_psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# NoPayout — additional error paths
# ===========================================================================

def test_sign_psbt_nopayout_extra_input(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when the PSBT has 4 inputs instead of exactly 3."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.tx.vin.append(CTxIn())
    psbt.inputs.append(PartiallySignedInput(0))

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_too_few_inputs(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when the PSBT has 2 inputs instead of exactly 3."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.tx.vin = psbt.tx.vin[:2]
    psbt.inputs = psbt.inputs[:2]

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_extra_output(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when the PSBT has 2 outputs instead of exactly 1."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.tx.vout.append(CTxOut(1000, bytes([0x51, 0x20]) + bytes(32)))
    psbt.outputs.append(PartiallySignedOutput(0))

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_input0_value_too_high(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when Input 0 WITNESS_UTXO value exceeds the maximum allowed value.

    The firmware accepts values in [VAULT_DUST_LIMIT, VAULT_DUST_LIMIT + base_fee_rate *
    MAX_COUNCIL_NOPAYOUT_VSIZE].  A value one above the upper bound must be rejected.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.inputs[0].witness_utxo = CTxOut(
        VAULT_DUST_LIMIT + _BASE_FEE_RATE * _MAX_COUNCIL_NOPAYOUT_VSIZE + 1,
        psbt.inputs[0].witness_utxo.scriptPubKey,
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_input1_value_too_high(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when Input 1 WITNESS_UTXO value exceeds VAULT_DUST_LIMIT."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.inputs[1].witness_utxo = CTxOut(
        VAULT_DUST_LIMIT + 1, psbt.inputs[1].witness_utxo.scriptPubKey
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_input2_value_too_high(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when Input 2 WITNESS_UTXO value exceeds VAULT_DUST_LIMIT."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.inputs[2].witness_utxo = CTxOut(
        VAULT_DUST_LIMIT + 1, psbt.inputs[2].witness_utxo.scriptPubKey
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_zero_output_value(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when Output 0 has the right scriptPubKey but a zero amount.

    Pinning the scriptPubKey alone leaves the amount free: a zero-value output would
    send the challenger nothing and burn every input satoshi to miner fees, silently
    (NoPayout is signed without a user screen).
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0], out_value=0)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_sub_dust_output_value(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when Output 0 is one satoshi below the dust floor."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(
        dep_pk, _TEST_KEEPER_PKS[0], out_value=VAULT_DUST_LIMIT - 1
    )

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_fee_above_bound(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when the implied fee exceeds base_fee_rate * MAX_COUNCIL_NOPAYOUT_VSIZE.

    Output 0 still clears the dust floor here, so only the fee bound can reject it.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    over_bound_out = _NOPAYOUT_INPUTS_TOTAL - _NOPAYOUT_MAX_FEE - 1
    assert over_bound_out >= VAULT_DUST_LIMIT, "test must isolate the fee bound from the dust floor"
    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0], out_value=over_bound_out)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_fee_at_bound(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout accepts a fee exactly equal to base_fee_rate * MAX_COUNCIL_NOPAYOUT_VSIZE."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    at_bound_out = _NOPAYOUT_INPUTS_TOTAL - _NOPAYOUT_MAX_FEE
    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0], out_value=at_bound_out)

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


def test_sign_psbt_nopayout_wrong_depositor_key(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when the leaf uses a key other than the device-derived depositor key."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # Use a foreign x-only key as depositor — device reconstructs the leaf with its
    # derived depositor key and detects a mismatch.
    foreign_key = TEST_VALID_KEYS[3]
    psbt = _build_nopayout_psbt(foreign_key, _TEST_KEEPER_PKS[0])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_wrong_challenger_key(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when the leaf uses a challenger key not in the intent's keeper/challenger set."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # TEST_VALID_KEYS[4] (2G) is not in _TEST_KEEPER_PKS or _TEST_CHALLENGER_PKS.
    foreign_challenger = TEST_VALID_KEYS[4]
    psbt = _build_nopayout_psbt(dep_pk, foreign_challenger)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_wrong_output_spk(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when Output 0 scriptPubKey is not key-path P2TR of the challenger key.

    The device must verify Output 0 belongs to the challenger before signing the
    NoPayout Assert:0 leaf, preventing an attacker from redirecting funds.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    # Replace Output 0 with an attacker-controlled address (arbitrary P2TR).
    psbt.tx.vout[0].scriptPubKey = bytes([0x51, 0x20]) + bytes([0xAB] * 32)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_nonzero_locktime(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when nLockTime is non-zero."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.tx.nLockTime = 1

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_wrong_version(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when nVersion is not 2."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.tx.nVersion = 1

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_nopayout_no_state(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """NoPayout fails with SW_BAD_STATE when no vault session is active."""
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_BAD_STATE


# ===========================================================================
# Cross-cutting cap recovery — new intent resets counters
# ===========================================================================

def test_sign_psbt_cap_recovery_via_new_intent(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Exhausting the NoPayout cap nullifies the intent; re-approving resets all counters.

    Steps:
    1. Load intent and advance to payout state (pegin_signed=1).
    2. Exhaust NoPayout cap (vault_count × (K+C) = 1 × 2 = 2 signings).
    3. One more NoPayout → SW_CAP_EXCEEDED (intent nullified).
    4. Re-derive and re-approve a fresh intent.
    5. Sign one NoPayout → SW_OK (cap counters reset).
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    # Step 1 + 2: load intent, sign PegIn, exhaust NoPayout cap.
    # NoPayout is silent — no navigator interaction for each signing.
    _setup_payout_state(client, navigator, device, coin_type)
    for ch_pk in (_TEST_KEEPER_PKS + _TEST_CHALLENGER_PKS):
        psbt = _build_nopayout_psbt(dep_pk, ch_pk)
        client.sign_psbt(psbt, dummy_wallet, None)

    # Step 3: exceed cap → intent nullified (no screen shown before SW_CAP_EXCEEDED).
    over_cap_psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(over_cap_psbt, dummy_wallet, None)
    assert exc.value.status == SW_CAP_EXCEEDED

    # Step 4: re-approve a fresh intent (also advances through PegIn to reach payout state).
    _setup_payout_state(client, navigator, device, coin_type)

    # Step 5: NoPayout succeeds — cap counters have been reset.
    # NoPayout is silent — no navigator interaction required.
    recovery_psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    result = client.sign_psbt(recovery_psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


# ===========================================================================
# N-09 — Slot formula boundary: no overflow at V=10 / N=32
# ===========================================================================

def test_sign_psbt_payout_slot_formula_max_no_overflow(
    client: "RaggerClient",
    navigator: "Navigator",
    bitcoin_network: str,
    device: "Device",
) -> None:
    """Payout bitmask slot gi*(keeper_count+2)+claimer_idx does not overflow at maximum.

    Uses vault_count=VAULT_MAX_VAULTS=10 with keeper_count=1 so the APDU tick budget is
    not exceeded.  vault_compute_pegin_txid is called 20 times (10 peek + 10 validate) but
    with a 1-keeper ~180-byte leaf each call is fast.  Using keeper_count=32 instead would
    inflate each call to ~1200 bytes and time out on Speculos.

    Tested configuration (gi=9, claimer_idx=2=K+1 depositor, K=1):
      slot = 9*(1+2)+(1+1) = 9*3+2 = 29,  mask_size = 10*(1+2) = 30,  29 < 30.

    The theoretical maximum (VAULT_MAX_VAULTS=10, VAULT_MAX_KEEPERS=32) is verified via
    pure Python arithmetic — the bit-setting logic is identical regardless of keeper count.

    SW_OK confirms bit 29 is set without memory corruption — an overflow in the index
    or bit computation would either crash or return an unexpected status code.
    """
    _V = 10   # vault_count — must equal VAULT_MAX_VAULTS
    _N = 1    # keeper_count — minimised for Speculos performance (see docstring)
    _C = 1    # challenger_count — minimised to keep keys manageable

    # Verify the slot formula for the tested configuration (gi=9, K=1, depositor).
    max_slot = (_V - 1) * (_N + 2) + (_N + 1)
    mask_size = _V * (_N + 2)
    assert max_slot == 29, f"expected max_slot=29, got {max_slot}"
    assert mask_size == 30, f"expected mask_size=30, got {mask_size}"
    assert max_slot < mask_size, f"slot formula overflows mask: {max_slot} >= {mask_size}"

    # Verify the theoretical maximum (V=10, K=32) overflows neither uint16_t nor the mask.
    _N_MAX = 32
    assert (_V - 1) * (_N_MAX + 2) + (_N_MAX + 1) == 339
    assert _V * (_N_MAX + 2) == 340
    assert (_V - 1) * (_N_MAX + 2) + (_N_MAX + 1) < _V * (_N_MAX + 2)

    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    all_keys = _distinct_sorted_keys(_N + _C, exclude=[TEST_VP_KEY, dep_pk])
    keeper_pks = all_keys[:_N]
    challenger_pks = all_keys[_N:]

    # Derive root and build intent with vault_count=10, groups at htlc_vout 0..9.
    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(
        client, VAULT_APP_NAME, depositor_path(coin_type), _DERIVE_CONTEXT, navigator, device
    )
    hashlock_0 = vault_hashlock(_DERIVED_ROOT, 0)

    # Each group needs a distinct vault_provider_pk; exclude role keys to avoid ROLE_COLLISION.
    slot_vp_keys = [TEST_VP_KEY] + _distinct_sorted_keys(
        _V - 1, exclude=[TEST_VP_KEY, dep_pk] + keeper_pks + challenger_pks,
    )

    scalars_tlv = build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=_BASE_FEE_RATE,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=_PREPEGIN_TXID,
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=depositor_path(coin_type),
        keeper_count=_N,
        challenger_count=_C,
        prepegin_max_fee=500_000,
        vault_count=_V,
    )
    groups_tlv = [
        build_group_tlv(
            htlc_vout=gi,
            vault_provider_pk=slot_vp_keys[gi],
            vault_amount=_VAULT_AMOUNT,
            commission_fee=_COMMISSION_FEE,
            depositor_claim_value=_DEPOSITOR_CLAIM_VALUE,
            pegin_max_fee=_PEGIN_MAX_FEE,
        )
        for gi in range(_V)
    ]
    # Intent approval here is setup, not the assertion, and no snapshots are captured, so
    # navigate to the finish page by title rather than pinning a swipe count.  A fixed count has
    # to be recalibrated whenever NBGL repacks pairs per page — which it did when
    # SKIPPABLE_OPERATION was removed from the intent review, freeing header space.
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, keeper_pks, challenger_pks,
        groups=groups_tlv,
    )

    # Sign PegIn for group 0 (htlc_vout=0) to advance pegin_signed to 1.
    pegin_psbt = _build_pegin_psbt(
        dep_pk, hashlock_0, _PREPEGIN_TXID,
        htlc_vout=0,
        keeper_pks=keeper_pks,
        challenger_pks=challenger_pks,
    )
    client.sign_psbt(pegin_psbt, dummy_wallet, None)

    # Build depositor payout for group 9 (gi=9, htlc_vout=9) — slot = 29.
    vault_utxo_leaf = _vault_utxo_leaf(
        dep_pk, slot_vp_keys[9], keeper_pks, challenger_pks, _PEGIN_CSV_TIMELOCK,
    )
    claim_leaf = _depositor_claim_leaf(dep_pk)
    vault_utxo_spk = _p2tr_from_single_leaf(vault_utxo_leaf)
    claim_spk = _p2tr_from_single_leaf(claim_leaf)

    # pegin_txid for group 9 uses htlc_vout=9 (distinguishes groups in the pegin tx).
    pegin_txid_9 = _compute_pegin_txid(
        _PREPEGIN_TXID, 9,
        _VAULT_AMOUNT, vault_utxo_spk,
        _DEPOSITOR_CLAIM_VALUE, claim_spk,
    )

    # For depositor claimer (idx = N+1 = 2), app_challengers = sorted(keeper_pks).
    app_challengers_dep = _build_app_challengers(slot_vp_keys[9], keeper_pks, claimer_idx=_N + 1)
    assert0_leaf = _assert0_payout_leaf(
        dep_pk, app_challengers_dep, challenger_pks, _PAYOUT_TIMELOCK,
    )
    assert0_spk = _p2tr_from_single_leaf(assert0_leaf)

    vault_leaf_hash = _tapleaf_hash(vault_utxo_leaf)
    vault_parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, vault_leaf_hash)
    vault_cb = bytes([0xC0 | vault_parity]) + VAULT_NUMS_XONLY

    assert0_hash = _tapleaf_hash(assert0_leaf)
    assert0_parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, assert0_hash)
    assert0_cb = bytes([0xC0 | assert0_parity]) + VAULT_NUMS_XONLY

    # Depositor payout: Out0 = depositor, Out1 = CPFP anchor (both BIP-86 P2TR(D)).
    out0_value = _VAULT_AMOUNT - _PAYOUT_FEE
    out1_value = VAULT_DUST_LIMIT
    out_spk = _bip86_p2tr_spk(dep_pk)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn(), CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(pegin_txid_9, 'little'), 0)
    tx.vin[0].nSequence = _PEGIN_CSV_TIMELOCK
    tx.vin[1].prevout = COutPoint(int.from_bytes(b'\xdd' * 32, 'little'), 0)
    tx.vin[1].nSequence = _PAYOUT_TIMELOCK
    tx.vout = [CTxOut(out0_value, out_spk), CTxOut(out1_value, out_spk)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0), PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0), PartiallySignedOutput(0)]
    psbt.inputs[0].witness_utxo = CTxOut(_VAULT_AMOUNT, vault_utxo_spk)
    psbt.inputs[0].tap_scripts[(vault_utxo_leaf, 0xC0)] = {vault_cb}
    psbt.inputs[1].witness_utxo = CTxOut(VAULT_DUST_LIMIT, assert0_spk)
    psbt.inputs[1].tap_scripts[(assert0_leaf, 0xC0)] = {assert0_cb}

    # Slot 29 is within the 30-bit payout_claimer_mask — must return SW_OK.
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


# ===========================================================================
# N-09 — Discriminated rejection tests for security-critical paths
#
# Each test is named after the specific condition being rejected so that a
# failing test immediately identifies which path is no longer guarded.
# ===========================================================================

def test_sign_psbt_pegin_wrong_depositor_claim_spk(
    client: "RaggerClient",
    navigator: "Navigator",
    bitcoin_network: str,
    device: "Device",
) -> None:
    """PegIn fails when output 1 (depositor claim) uses a foreign depositor key.

    The firmware reconstructs the expected depositor claim scriptPubKey from the
    device-derived depositor key and compares it to output 1's scriptPubKey.
    Substituting a foreign key in the claim P2TR output must be rejected to prevent
    an attacker from redirecting the depositor's claim UTXO to a controlled address.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    # Replace output 1 (depositor claim) with a claim output using a foreign key.
    foreign_key = TEST_VALID_KEYS[3]  # not the device depositor key
    wrong_claim_spk = _p2tr_from_single_leaf(_depositor_claim_leaf(foreign_key))
    psbt.tx.vout[1].scriptPubKey = wrong_claim_spk

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_htlc_spk_wrong_vp_key(
    client: "RaggerClient",
    navigator: "Navigator",
    bitcoin_network: str,
    device: "Device",
) -> None:
    """Pre-PegIn fails when the HTLC output scriptPubKey uses a wrong vault-provider key.

    The device stores the approved VP key from the group intent and uses it to
    reconstruct the expected HTLC taptree.  If the HTLC was built with a different
    VP key the device's reconstruction won't match the PSBT output SPK, rejecting
    a substitution attack where the attacker replaces VP with a key they control.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s1_state(client, navigator, device, coin_type)

    # Build HTLC with a different VP key — the device expects TEST_VP_KEY.
    wrong_vp_key = TEST_VALID_KEYS[2]  # 5G — different from TEST_VP_KEY (1G)
    _, _, _, _, wrong_htlc_spk = _htlc_output(
        dep_pk, wrong_vp_key,
        _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )

    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    psbt = _build_prepegin_psbt(
        wrong_htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
    )
    wallet = _standard_taproot_wallet(client, coin_type)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_pegin_wrong_p2a_script_bytes(
    client: "RaggerClient",
    navigator: "Navigator",
    bitcoin_network: str,
    device: "Device",
) -> None:
    """PegIn fails when output 2 (P2A anchor) does not carry the expected 4-byte P2A script.

    The P2A anchor script is fixed: OP_1 OP_PUSHBYTES_2 0x4e73 (0x51024e73).
    If the script is replaced by anything else the firmware must reject the PegIn to
    prevent an attacker from redirecting the anchor to a spendable output they control.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    # Replace output 2 script with a different (non-P2A) script.
    wrong_anchor_spk = bytes([0x51, 0x20]) + bytes(32)   # P2TR with NUMS key — not P2A
    psbt.tx.vout[2].scriptPubKey = wrong_anchor_spk

    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_depositor_wrong_out0_spk(
    client: "RaggerClient",
    navigator: "Navigator",
    bitcoin_network: str,
    device: "Device",
) -> None:
    """Depositor payout fails when output 0 scriptPubKey is not BIP-86 P2TR(depositor).

    For the depositor claimer (idx=keeper_count+1), both Out0 and Out1 are
    script-verified as BIP-86 P2TR(depositor).  Replacing Out0 with a foreign key
    must be rejected to prevent an attacker from redirecting the recovered vault funds.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # Sign VP and VK payouts to advance state to depositor's turn.
    for ci in range(len(_TEST_KEEPER_PKS) + 1):
        psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=ci)
        client.sign_psbt(psbt, dummy_wallet, None)

    # Depositor payout with Out0 replaced by a foreign key's BIP-86 P2TR.
    dep_psbt = _build_payout_psbt(
        dep_pk, _PREPEGIN_TXID, claimer_idx=len(_TEST_KEEPER_PKS) + 1,
    )
    dep_psbt.tx.vout[0].scriptPubKey = _bip86_p2tr_spk(TEST_VALID_KEYS[3])

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(dep_psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_payout_depositor_out1_wrong_value(
    client: "RaggerClient",
    navigator: "Navigator",
    bitcoin_network: str,
    device: "Device",
) -> None:
    """Depositor payout fails when output 1 (CPFP anchor) does not equal VAULT_DUST_LIMIT.

    For the depositor claimer, output 1 must be exactly VAULT_DUST_LIMIT satoshis
    (the P2A-equivalent anchor dust).  An inflated value would overpay the anchor,
    and the excess must not silently increase the effective fee.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # Advance past VP and VK payouts so the depositor slot is next.
    for ci in range(len(_TEST_KEEPER_PKS) + 1):
        psbt = _build_payout_psbt(dep_pk, _PREPEGIN_TXID, claimer_idx=ci)
        client.sign_psbt(psbt, dummy_wallet, None)

    dep_psbt = _build_payout_psbt(
        dep_pk, _PREPEGIN_TXID, claimer_idx=len(_TEST_KEEPER_PKS) + 1,
    )
    # Out1 is the CPFP anchor; inflate it by 1 sat.
    dep_psbt.tx.vout[1].nValue = VAULT_DUST_LIMIT + 1

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(dep_psbt, dummy_wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA
