"""
Silent-flow validation tests for SIGN_PSBT.

Covers Pre-PegIn, PegIn, Payout, NoPayout, Refund, and Reclaim validation (no display).
Screen-capture tests live in the corresponding test_screen*.py files:
  test_screen3_refund.py  — Screen 3 (Refund)
  test_screen4_claim.py  — Screen 4 (Claim)
  test_screen5_assert.py — Screen 5 (Assert)
  test_screen6_wc.py     — Screen 6 (WC)
  test_screen9_reclaim.py — Screen 9 (Reclaim), incl. cross-flow and session-state cases
"""

from __future__ import annotations

import hashlib
import struct
from typing import TYPE_CHECKING, Callable, List, Optional, Sequence
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

import ledger_bitcoin.client as ledger_bitcoin_client
from ledger_bitcoin import WalletPolicy
from ledger_bitcoin.client_command import ClientCommandInterpreter
from ledger_bitcoin.common import hash160
from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness

from test_utils.taproot import tagged_hash, taproot_tweak_pubkey, ser_script, pubkey_gen
# Independent BIP-341 sighash and BIP-340 verifier, used to check returned signatures
# against the PSBT rather than trusting the device's own output.
from test_utils.taproot_sighash import TaprootSignatureHash
from test_utils.bip0340 import schnorr_verify

SIGHASH_DEFAULT = 0

from .vault_client import (
    SW_BAD_STATE,
    SW_BAD_CPFP_ANCHOR,
    SW_CAP_EXCEEDED,
    SW_DENY,
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

# Pre-PegIn fee cap committed in the intent (prepegin_max_fee), and the fee
# _build_prepegin_psbt funds its input for (3_456 sat = 0.00003456 BTC).
_PREPEGIN_MAX_FEE     = 500_000
_PREPEGIN_DEFAULT_FEE = 3_456
_PREPEGIN_DEPOSITOR_CHANGE = 250_000  # change returned to P2TR(depositor_pk)
_OP_RETURN_PUSH32 = bytes([0x6A, 0x20])  # OP_RETURN OP_PUSHBYTES_32: auth-anchor script prefix

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
                                purpose: int, descriptor_template: str,
                                account: int = 0) -> WalletPolicy:
    """Default (HMAC-less) single-key wallet policy for the test device.

    wallet_id != all-zeros → has_no_wallet_policy = false → SIGN_PSBT routes to the
    Pre-PegIn validator.  The base app only accepts such a policy without an HMAC when
    the key origin is m/purpose'/coin_type'/account', so purpose must match the template.
    """
    fingerprint = client.get_master_fingerprint()
    xpub = client.get_extended_pubkey(f"m/{purpose}'/{coin_type}'/{account}'", display=False)
    return WalletPolicy(
        name="",
        descriptor_template=descriptor_template,
        keys_info=[f"[{fingerprint.hex()}/{purpose}'/{coin_type}'/{account}']{xpub}"],
    )


def _standard_taproot_wallet(client: "RaggerClient", coin_type: int, account: int = 0) -> WalletPolicy:
    """BIP-86 tr() wallet of the given account — SegWit v1, empty scriptSig."""
    return _standard_single_key_wallet(client, coin_type, BIP86_TAPROOT, "tr(@0/**)", account)


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
    input_account: int = 0,
) -> PSBT:
    """Pre-PegIn PSBTv0: HTLC output at htlc_vout, plus an optional OP_RETURN.

    The device accepts an optional OP_RETURN = "OP_RETURN <SHA256(authAnchor)>"
    (= 0x6A 0x20 || auth_anchor); pass auth_anchor=vault_auth_anchor(root) to include
    it.  Depositor outputs (CPFP anchor, change) are added by _prepegin_bound_to_intent.

    When input_internal_key and input_fingerprint are provided the input is a
    proper BIP-86 key-path P2TR UTXO (required for the 'all inputs internal'
    validation check in _validate_prepegin).
    """
    input_value = htlc_value + _PREPEGIN_DEFAULT_FEE

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
        tx.vout.append(CTxOut(auth_anchor_value, _OP_RETURN_PUSH32 + auth_anchor))
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
                [HARDENED | 86, HARDENED | input_coin_type, HARDENED | input_account, 0, 0],
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
    extra_outputs: Sequence[CTxOut] = (),
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
    device's txid reconstruction expects, then `extra_outputs`, which the input funds.
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

    input_value = htlc_value + _PREPEGIN_DEFAULT_FEE + sum(out.nValue for out in extra_outputs)
    prev_tx = _funding_tx(input_spk, input_value)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(prev_tx.hash, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [
        CTxOut(htlc_value, htlc_spk),
        CTxOut(0, _OP_RETURN_PUSH32 + auth_anchor),
        *extra_outputs,
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

def _prepegin_input_key(client: "RaggerClient", coin_type: int, account: int = 0):
    """Return (fingerprint, internal_key) for a BIP-86 P2TR input at m/86'/{coin_type}'/{account}'/0/0.

    The 'all inputs internal' check in _validate_prepegin requires the
    input witness_utxo to have a BIP-86 tweaked key derived from this device's
    wallet.  Pass the returned values as input_fingerprint/input_internal_key to
    _build_prepegin_psbt.
    """
    fingerprint = client.get_master_fingerprint()
    internal_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/{account}'/0/0", display=False)
    ).pubkey[1:]
    return fingerprint, internal_key


# ---------------------------------------------------------------------------
# Session setup helpers (both sessions require navigating the vault intent screen)
# ---------------------------------------------------------------------------

def _depositor_pk(bitcoin_network: str) -> bytes:
    return TEST_DEPOSITOR_XONLY_MAINNET if bitcoin_network == "main" else TEST_DEPOSITOR_XONLY_TESTNET


def _assert_schnorr_sig_verifies(psbt: PSBT, result, expected_xonly: bytes,
                                 expected_input: int = 0) -> None:
    """Independently verify a returned signature against the sighash it must commit to.

    The count/index/pubkey/length checks in
    _assert_single_schnorr_sig are shape checks, not verification — a regression that
    returned arbitrary 64-byte data, or signed a *different* digest than the PSBT the
    user reviewed, would satisfy every one of them.  This recomputes the BIP-341
    script-path sighash from the original PSBT and checks the BIP-340 signature under the
    expected key, using the base app's independent implementations rather than anything
    the device produced.

    The leaf script and version are taken from the PSBT's own PSBT_IN_TAP_LEAF_SCRIPT, so
    this works for any custom-input flow without the caller restating them.
    """
    input_index, partial_sig = result[0]
    leaf_script, leaf_ver = next(iter(psbt.inputs[input_index].tap_scripts))
    sighash = TaprootSignatureHash(
        psbt.tx,
        [inp.witness_utxo for inp in psbt.inputs],
        SIGHASH_DEFAULT,
        input_index=input_index,
        scriptpath=True,
        script=leaf_script,
        leaf_ver=leaf_ver,
    )
    assert schnorr_verify(sighash, expected_xonly, partial_sig.signature[:64]), (
        "returned signature does not verify against the sighash of the reviewed PSBT")


def _assert_single_schnorr_sig(result, expected_xonly: bytes, expected_input: int = 0,
                               psbt: Optional[PSBT] = None) -> None:
    """Assert a custom-input sign yielded exactly one usable signature.

    A successful vault custom-input sign (PegIn / Payout / Refund) returns a single
    BIP-340 Schnorr signature — 64 bytes, since the device signs SIGHASH_DEFAULT — for
    `expected_input`, produced by `expected_xonly`.  Checking the yielded value (not just
    the SW_OK) guards against a regression that returns success without a valid signature.

    Pass `psbt` to additionally verify the signature cryptographically against the sighash
    that PSBT implies.  Prefer doing so: without it these are shape checks only.
    """
    assert len(result) == 1, f"expected exactly one signature, got {len(result)}: {result}"
    input_index, partial_sig = result[0]
    assert input_index == expected_input, f"signed unexpected input {input_index}"
    assert partial_sig.pubkey[-32:] == expected_xonly, "signed with an unexpected key"
    assert len(partial_sig.signature) == 64, (
        f"expected 64-byte SIGHASH_DEFAULT Schnorr sig, got {len(partial_sig.signature)}")
    if psbt is not None:
        _assert_schnorr_sig_verifies(psbt, result, expected_xonly, expected_input)


def _assert_refused_unsigned(expected_sw: int, send: Callable[[], object]) -> None:
    """Assert `send()` fails with `expected_sw` and the device yielded nothing first.

    A status word alone does not prove nothing was signed: the device returns each
    signature as a YIELD during the exchange, before the final status word, so a flow that
    signed and then failed would still end in an error.  client.sign_psbt drops the yields
    when it raises, so this records them from the command interpreter it creates.
    """
    interpreters: List[ClientCommandInterpreter] = []

    class _RecordingInterpreter(ClientCommandInterpreter):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            interpreters.append(self)

    ledger_bitcoin_client.ClientCommandInterpreter = _RecordingInterpreter
    try:
        with pytest.raises(ExceptionRAPDU) as exc:
            send()
    finally:
        ledger_bitcoin_client.ClientCommandInterpreter = ClientCommandInterpreter

    assert exc.value.status == expected_sw
    assert interpreters, "SIGN_PSBT was never sent"
    yielded = [value for interp in interpreters for value in interp.yielded]
    assert not yielded, f"device yielded {len(yielded)} value(s) before refusing: {yielded}"


def _depositor_path_at(coin_type: int, depositor_index: int, depositor_account: int = 0) -> List[int]:
    """Depositor path m/86'/coin_type'/depositor_account'/0/depositor_index.

    Account 0, index 0 is the address the dApp shows.
    """
    return [HARDENED | 86, HARDENED | coin_type, HARDENED | depositor_account, 0, depositor_index]


def _build_intent_tlv_for_test(
    coin_type: int,
    prepegin_txid: bytes,
    keeper_pks: Optional[List[bytes]] = None,
    challenger_pks: Optional[List[bytes]] = None,
    prepegin_max_fee: int = _PREPEGIN_MAX_FEE,
    base_fee_rate: int = _BASE_FEE_RATE,
    depositor_index: int = 0,
    depositor_account: int = 0,
) -> bytes:
    if keeper_pks is None:
        keeper_pks = _TEST_KEEPER_PKS
    if challenger_pks is None:
        challenger_pks = _TEST_CHALLENGER_PKS
    return build_intent_tlv(
        coin_type=coin_type,
        base_fee_rate=base_fee_rate,
        pegin_csv_timelock=_PEGIN_CSV_TIMELOCK,
        payout_timelock=_PAYOUT_TIMELOCK,
        prepegin_txid=prepegin_txid,
        htlc_refund_timelock=_HTLC_REFUND_TIMELOCK,
        depositor_path=_depositor_path_at(coin_type, depositor_index, depositor_account),
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
# 3-vault helpers
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
        prepegin_max_fee=_PREPEGIN_MAX_FEE,
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
    depositor_spk: Optional[bytes] = None,
    depositor_values: Sequence[int] = (),
) -> PSBT:
    """Pre-PegIn PSBTv0 with one HTLC output per vault group.

    group_htlc_outputs[i] = (htlc_spk, htlc_value) for vault group i at htlc_vout=i.
    The OP_RETURN is appended after all HTLC outputs when auth_anchor is given, then one
    depositor_spk output per entry of depositor_values; the input is funded for them, so
    the fee stays at _PREPEGIN_DEFAULT_FEE.
    """
    total_htlc = sum(v for _, v in group_htlc_outputs)
    input_value = total_htlc + sum(depositor_values) + _PREPEGIN_DEFAULT_FEE

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
        tx.vout.append(CTxOut(auth_anchor_value, _OP_RETURN_PUSH32 + auth_anchor))
    tx.vout += [CTxOut(value, depositor_spk) for value in depositor_values]
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


def _derive_root_and_hashlock(client: "RaggerClient", navigator: "Navigator", device, coin_type: int,
                              depositor_index: int = 0, depositor_account: int = 0) -> bytes:
    """Run DERIVE_CONTEXT_HASH, stash the root, and return the per-vault hashlock h."""
    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(client, VAULT_APP_NAME,
                                        _depositor_path_at(coin_type, depositor_index,
                                                           depositor_account),
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
    base_fee_rate: int = _BASE_FEE_RATE,
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
    scalars_tlv = _build_intent_tlv_for_test(coin_type, prepegin_txid, keeper_pks, challenger_pks,
                                             base_fee_rate=base_fee_rate)
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
        prepegin_max_fee=_PREPEGIN_MAX_FEE,
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
# Pre-PegIn signing
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
    depositor_values: Sequence[int] = (),
):
    """Approve an intent bound to a Pre-PegIn PSBT spending a `purpose` wallet input.

    Each entry of depositor_values pays P2TR(depositor_pk) after the auth-anchor.

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
    depositor_spk = _bip86_depositor_spk(dep_pk)
    psbt = _build_prepegin_psbt_ecdsa(
        htlc_spk, purpose, fingerprint, pubkey, coin_type,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
        extra_outputs=[CTxOut(value, depositor_spk) for value in depositor_values],
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
    psbt, coin_type, _ = _setup_prepegin_ecdsa_case(
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
    psbt, coin_type, _ = _setup_prepegin_ecdsa_case(
        client, navigator, device, bitcoin_network, BIP44_LEGACY
    )
    wallet = _standard_legacy_wallet(client, coin_type)

    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


@pytest.mark.parametrize("depositor_values", [
    pytest.param([], id="no_depositor_outputs"),
    pytest.param([_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE], id="anchor_then_change"),
])
def test_sign_psbt_prepegin_3vaults(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    depositor_values: List[int],
) -> None:
    """3-vault Pre-PegIn passes validation and is signed silently.

    Acceptance criterion: 3-vault Pre-PegIn with correct HTLC outputs and
    OP_RETURN (positioned after all HTLCs) passes device validation and returns one
    BIP-86 Taproot Schnorr signature per wallet input.  The depositor anchor and change
    follow the OP_RETURN, after the last of the three HTLC outputs.
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
        depositor_spk=_bip86_depositor_spk(dep_pk),
        depositor_values=depositor_values,
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
        prepegin_max_fee=_PREPEGIN_MAX_FEE,
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


@pytest.mark.parametrize("misplaced_output", ["op_return", "cpfp_anchor"])
def test_sign_psbt_prepegin_non_htlc_output_before_htlcs(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
    misplaced_output: str,
) -> None:
    """Pre-PegIn fails when a non-HTLC output is positioned before the last HTLC output.

    Uses a 2-vault intent where group 0 has htlc_vout=0 and group 1 has htlc_vout=2.
    The PSBT places the OP_RETURN or the depositor's CPFP anchor at vout 1, which is before
    the last HTLC at vout 2.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    global _DERIVED_ROOT
    _DERIVED_ROOT = derive_context_hash(
        client, VAULT_APP_NAME, depositor_path(coin_type), _DERIVE_CONTEXT, navigator, device
    )
    # Two groups: htlc_vout 0 and 2 (gap at 1 where the misplaced output will sit).
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
        prepegin_max_fee=_PREPEGIN_MAX_FEE,
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
    misplaced = {
        "op_return": CTxOut(0, _OP_RETURN_PUSH32 + vault_auth_anchor(_DERIVED_ROOT)),
        "cpfp_anchor": CTxOut(_VAULT_DUST_LIMIT, _bip86_depositor_spk(dep_pk)),
    }[misplaced_output]

    # Build PSBT manually: [htlc_0, misplaced, htlc_2] — the misplaced output is before the
    # last HTLC.
    input_value = htlc_value * 2 + misplaced.nValue + _PREPEGIN_DEFAULT_FEE
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
        misplaced,                         # vout 1: before the last HTLC — INVALID
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
# Screen 3 — Refund transaction review negative tests
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
# Reclaim transaction validation (Screen 9)
#
# Reclaim shares its leaf shape byte-for-byte with Claim (<D> OP_CHECKSIG, 34 bytes);
# the dispatcher tells them apart by output count alone (2 outputs -> Claim, 1 -> Reclaim).
# Every case below is refused by _validate_display_reclaim before Screen 9 is shown, so
# none needs navigation; each asserts the status word and that nothing was signed.  The
# happy path, the user rejection, the cross-flow collisions and the session-state cases
# live in test_screen9_reclaim.py.
# ===========================================================================

_RECLAIM_SEQUENCE = 0xFFFFFFFD
# PegIn txid in PSBT_IN_PREVIOUS_TXID byte order.  Not a palindrome, so Screen 9 goldens
# pin the byte order the txid is displayed in.
_RECLAIM_PEGIN_TXID = hashlib.sha256(b"reclaim pegin txid").digest()
_DEPOSITOR_CLAIM_VOUT = 1  # PegIn Output 1 holds the depositor claim reserve
_RECLAIM_D_INDEX = 1  # D sits at m/86'/coin'/0'/0/<this>


def _own_xonly_key(client: "RaggerClient", coin_type: int, account: int, change: int,
                   index: int) -> bytes:
    """X-only key this device derives at m/86'/coin_type'/account'/change/index."""
    path = f"m/86'/{coin_type}'/{account}'/{change}/{index}"
    return ExtendedKey.deserialize(client.get_extended_pubkey(path, display=False)).pubkey[1:]


def _build_reclaim_psbt(
    fingerprint: bytes,
    leaf_key: bytes,
    coin_type: int,
    input_value: int = 1_200_000,
    reclaimed_value: int = 1_199_000,
    nsequence: int = _RECLAIM_SEQUENCE,
    leaf_key_index: int = _RECLAIM_D_INDEX,
    pegin_txid: bytes = _RECLAIM_PEGIN_TXID,
    out_key: Optional[bytes] = None,
    out_origin: Optional[KeyOriginInfo] = None,
) -> PSBT:
    """Build a Reclaim PSBTv0 (Screen 9).

    Input 0: PegIn Output 1 (depositor claim reserve) -- leaf <D> OP_CHECKSIG (34 bytes),
             byte-identical to Claim; single-leaf P2TR with NUMS internal key.  D is
             proven via the input's own TAP_BIP32_DERIVATION.
    Output 0: BIP-86 P2TR of `out_key`, which is D unless overridden -- the only output the
              device accepts.  It carries no TAP_BIP32_DERIVATION, since the device reads
              none for it; `out_origin` attaches one anyway.
    """
    reclaim_leaf = _depositor_claim_leaf(leaf_key)  # <D> OP_CHECKSIG, 34 bytes
    leaf_hash = _tapleaf_hash(reclaim_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    in_spk = bytes([0x51, 0x20]) + tweaked
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    _, bip86_out_key = taproot_tweak_pubkey(leaf_key if out_key is None else out_key, b'')
    out_script = bytes([0x51, 0x20]) + bip86_out_key

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(pegin_txid, 'little'), _DEPOSITOR_CLAIM_VOUT)
    tx.vin[0].nSequence = nsequence
    tx.vout = [CTxOut(reclaimed_value, out_script)]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(input_value, in_spk)
    psbt.inputs[0].tap_scripts[(reclaim_leaf, 0xC0)] = {control_block}
    psbt.inputs[0].tap_bip32_paths[leaf_key] = (
        {leaf_hash},
        KeyOriginInfo(
            fingerprint,
            [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, leaf_key_index],
        ),
    )

    if out_origin is not None:
        psbt.outputs[0].tap_bip32_paths[bip86_out_key] = (set(), out_origin)

    return psbt


def _reclaim_keys(client: "RaggerClient", bitcoin_network: str):
    """Return (fingerprint, leaf_key, coin_type) for the standard Reclaim: D at
    m/86'/coin'/0'/0/_RECLAIM_D_INDEX."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = _own_xonly_key(client, coin_type, 0, 0, _RECLAIM_D_INDEX)
    return fingerprint, leaf_key, coin_type


def _standard_reclaim_psbt(client: "RaggerClient", bitcoin_network: str, **overrides) -> PSBT:
    """_build_reclaim_psbt over the standard keys; `overrides` go to the builder."""
    fingerprint, leaf_key, coin_type = _reclaim_keys(client, bitcoin_network)
    return _build_reclaim_psbt(fingerprint, leaf_key, coin_type, **overrides)


def _add_foreign_p2tr_input(psbt: PSBT, value: int, tag: int) -> None:
    """Append a well-formed external P2TR input.

    It carries a WITNESS_UTXO because the base app refuses an input with neither UTXO
    field during input preprocessing, so a test built on one would never reach the vault
    validator it targets.
    """
    txin = CTxIn()
    txin.prevout = COutPoint(int.from_bytes(bytes([tag]) * 32, 'little'), 0)
    txin.nSequence = 0xFFFFFFFF
    psbt.tx.vin.append(txin)
    psbt.inputs.append(PartiallySignedInput(0))
    psbt.inputs[-1].witness_utxo = CTxOut(value, bytes([0x51, 0x20]) + bytes([tag]) * 32)


def _add_p2tr_output(psbt: PSBT, value: int, spk: bytes) -> None:
    psbt.tx.vout.append(CTxOut(value, spk))
    psbt.outputs.append(PartiallySignedOutput(0))


def _replace_reclaim_tap_script(psbt: PSBT, control_block: bytes,
                                witness_spk: Optional[bytes] = None) -> None:
    """Swap Input 0's control block, and optionally the spent scriptPubKey."""
    (leaf, leaf_ver), _ = next(iter(psbt.inputs[0].tap_scripts.items()))
    psbt.inputs[0].tap_scripts = {(leaf, leaf_ver): {control_block}}
    if witness_spk is not None:
        psbt.inputs[0].witness_utxo = CTxOut(psbt.inputs[0].witness_utxo.nValue, witness_spk)


def _assert_reclaim_refused(client: "RaggerClient", psbt: PSBT,
                            expected_sw: int = SW_INCORRECT_DATA) -> None:
    """Send `psbt` with no wallet policy; assert it is refused and nothing was signed."""
    wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    _assert_refused_unsigned(expected_sw, lambda: client.sign_psbt(psbt, wallet, None))


# ---------------------------------------------------------------------------
# Dispatcher: the leaf must be exactly <D> OP_CHECKSIG
# ---------------------------------------------------------------------------

def test_sign_psbt_reclaim_dispatch_wrong_leaf_shape(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """A single-output PSBT whose Input 0 leaf is not exactly <D> OP_CHECKSIG (e.g. the
    terminal opcode is OP_CHECKSIGVERIFY instead) matches no dispatch pattern."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    (orig_leaf, leaf_ver), control_blocks = next(iter(psbt.inputs[0].tap_scripts.items()))
    wrong_leaf = orig_leaf[:33] + bytes([0xAD])  # OP_CHECKSIG (0xAC) -> OP_CHECKSIGVERIFY
    psbt.inputs[0].tap_scripts = {(wrong_leaf, leaf_ver): control_blocks}
    _assert_reclaim_refused(client, psbt)


# ---------------------------------------------------------------------------
# Validator: rejection matrix.  Each PSBT differs from a signable Reclaim in one rule.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("version", [1, 0])
def test_sign_psbt_reclaim_wrong_version(
    client: "RaggerClient",
    bitcoin_network: str,
    version: int,
) -> None:
    """Reclaim fails when nVersion < 2.

    Version 1 is refused by Reclaim's own version rule.  Version 0 is the Proof-of-Possession
    discriminator, so it is routed to the PoP validator and refused on its shape rules; the
    test asserts that a version-0 Reclaim-shaped PSBT is never signed.
    """
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    psbt.tx.nVersion = version
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_nonzero_locktime(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when nLockTime != 0."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    psbt.tx.nLockTime = 1
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_extra_input(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Outside INTENT_LOADED a 2-input Reclaim-shaped PSBT reaches Reclaim's own
    input-count gate (the INTENT_LOADED case, caught by Payout's gate, is in
    test_screen9_reclaim.py)."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    _add_foreign_p2tr_input(psbt, 10_000, tag=0x42)
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_wrong_sighash(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when PSBT_IN_SIGHASH_TYPE is set to SIGHASH_ALL (1); only DEFAULT
    is accepted.  SIGHASH_ALL is the only other value that gets this far: the base app
    refuses every other type with SW_NOT_SUPPORTED before any vault validator runs."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    psbt.inputs[0].sighash = 1  # SIGHASH_ALL
    _assert_reclaim_refused(client, psbt)


@pytest.mark.parametrize("nsequence", [0, 1, 144, 0x0040_0090, 0xFFFF_FFFB,
                                       0xFFFF_FFFE, 0xFFFF_FFFF])
def test_sign_psbt_reclaim_wrong_nsequence(
    client: "RaggerClient",
    bitcoin_network: str,
    nsequence: int,
) -> None:
    """Reclaim requires Input 0 nSequence == 0xFFFFFFFD exactly and rejects everything
    else, including the SEQUENCE_FINAL that Claim requires for the very same leaf shape."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network, nsequence=nsequence)
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_sequence_absent(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when PSBT_IN_SEQUENCE is absent.

    An absent field decodes as 0xFFFFFFFF, which is not replaceable, so defaulting it would
    sign a final transaction under a screen for an RBF one.  PSBTv0 always carries the
    sequence in its unsigned tx, so this is sent as PSBTv2 with the field removed.
    """
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    psbt.convert_to_v2()
    psbt.inputs[0].sequence = None
    _assert_reclaim_refused(client, psbt)


@pytest.mark.parametrize("below_dust_by", [0, 1])
def test_sign_psbt_reclaim_input_value_at_or_below_dust(
    client: "RaggerClient",
    bitcoin_network: str,
    below_dust_by: int,
) -> None:
    """Reclaim fails when Input 0's WITNESS_UTXO value is not strictly above dust."""
    input_value = VAULT_DUST_LIMIT - below_dust_by
    psbt = _standard_reclaim_psbt(client, bitcoin_network,
                                  input_value=input_value, reclaimed_value=input_value - 1)
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_tampered_control_block(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when the control block internal key is not VAULT_NUMS_XONLY
    (taproot commitment mismatch)."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    _replace_reclaim_tap_script(psbt, bytes([0xC0]) + bytes([0x01] * 32))
    _assert_reclaim_refused(client, psbt)


@pytest.mark.parametrize("tamper", ["flipped_parity", "spk_commits_other_leaf"])
def test_sign_psbt_reclaim_wrong_taproot_commitment(
    client: "RaggerClient",
    bitcoin_network: str,
    tamper: str,
) -> None:
    """Reclaim fails when a 33-byte NUMS control block does not commit the leaf to the
    spent scriptPubKey: a wrong output-key parity bit, or a scriptPubKey built for a
    different leaf."""
    fingerprint, leaf_key, coin_type = _reclaim_keys(client, bitcoin_network)
    psbt = _build_reclaim_psbt(fingerprint, leaf_key, coin_type)
    leaf_hash = _tapleaf_hash(_depositor_claim_leaf(leaf_key))
    parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    if tamper == "flipped_parity":
        _replace_reclaim_tap_script(psbt, bytes([0xC0 | (parity ^ 1)]) + VAULT_NUMS_XONLY)
    else:
        other_spk = _p2tr_from_single_leaf(_depositor_claim_leaf(TEST_VALID_KEYS[0]))
        _replace_reclaim_tap_script(psbt, bytes([0xC0 | parity]) + VAULT_NUMS_XONLY,
                                    witness_spk=other_spk)
    _assert_reclaim_refused(client, psbt)


@pytest.mark.parametrize("shape", ["with_sibling", "trailing_bytes"])
def test_sign_psbt_reclaim_control_block_not_33_bytes(
    client: "RaggerClient",
    bitcoin_network: str,
    shape: str,
) -> None:
    """Reclaim fails unless the control block is exactly 33 bytes (depth 0).

    PegIn Output 1 is a single-leaf tree, so both cases carry a commitment check could
    otherwise pass: "with_sibling" is a valid depth-1 proof for a scriptPubKey that really
    is a two-leaf tree, and "trailing_bytes" appends 7 bytes that are not a whole sibling
    hash, which a proof walk that stops at the last full 32 bytes never reads.  Sent as
    PSBTv2 because the client's PSBTv0 round-trip refuses a 40-byte control block itself.
    """
    fingerprint, leaf_key, coin_type = _reclaim_keys(client, bitcoin_network)
    psbt = _build_reclaim_psbt(fingerprint, leaf_key, coin_type)
    reclaim_leaf = _depositor_claim_leaf(leaf_key)
    if shape == "with_sibling":
        sibling_leaf = _depositor_claim_leaf(TEST_VALID_KEYS[0])
        root = _taptree2_root(reclaim_leaf, sibling_leaf)
        parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, root)
        _replace_reclaim_tap_script(
            psbt,
            bytes([0xC0 | parity]) + VAULT_NUMS_XONLY + _tapleaf_hash(sibling_leaf),
            witness_spk=bytes([0x51, 0x20]) + tweaked,
        )
    else:
        parity, _ = taproot_tweak_pubkey(VAULT_NUMS_XONLY, _tapleaf_hash(reclaim_leaf))
        _replace_reclaim_tap_script(psbt, bytes([0xC0 | parity]) + VAULT_NUMS_XONLY + bytes(7))
    psbt.convert_to_v2()
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_wrong_fingerprint(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when Input 0's TAP_BIP32_DERIVATION fingerprint belongs to a
    foreign device."""
    _, leaf_key, coin_type = _reclaim_keys(client, bitcoin_network)
    psbt = _build_reclaim_psbt(b'\xff\xff\xff\xff', leaf_key, coin_type)
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_foreign_key(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when the leaf's D key is not derived from this device's seed."""
    fingerprint, _, coin_type = _reclaim_keys(client, bitcoin_network)
    foreign_key = TEST_VALID_KEYS[0]  # valid EC point, not derived from this device
    psbt = _build_reclaim_psbt(fingerprint, foreign_key, coin_type)
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_input_no_derivation(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when Input 0 carries no TAP_BIP32_DERIVATION: without it the device
    cannot prove D is its own key."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    psbt.inputs[0].tap_bip32_paths = {}
    _assert_reclaim_refused(client, psbt)


@pytest.mark.parametrize("account, change, index, with_derivation", [
    (0, 0, 0, True),      # another receive address of D's own account
    (0, 0, 0, False),     # the same, with no derivation entry at all
    (0, 1, 0, True),      # the account's change branch
    (99, 1, 9999, True),  # a path no wallet scans
])
def test_sign_psbt_reclaim_output_not_depositor_address(
    client: "RaggerClient",
    bitcoin_network: str,
    account: int,
    change: int,
    index: int,
    with_derivation: bool,
) -> None:
    """Reclaim fails when Output 0 pays any BIP-86 address of this device other than
    P2TR(D), whatever derivation entry comes with it.

    The host picks that path and the device never shows it, so funds sent elsewhere would
    be safe on the seed but sit where no wallet looks.  Output 0 is therefore pinned to D
    itself rather than to a device-derived key at a host-supplied path.
    """
    fingerprint, leaf_key, coin_type = _reclaim_keys(client, bitcoin_network)
    other_key = _own_xonly_key(client, coin_type, account, change, index)
    assert other_key != leaf_key
    origin = KeyOriginInfo(
        fingerprint,
        [HARDENED | 86, HARDENED | coin_type, HARDENED | account, change, index],
    ) if with_derivation else None
    psbt = _build_reclaim_psbt(fingerprint, leaf_key, coin_type,
                               out_key=other_key, out_origin=origin)
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_output_script_tree(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when Output 0 is not BIP-86: its key is D, but tweaked with a script
    tree rather than the empty one, so the output is also spendable by whoever controls
    the tree's leaf."""
    fingerprint, leaf_key, coin_type = _reclaim_keys(client, bitcoin_network)
    psbt = _build_reclaim_psbt(fingerprint, leaf_key, coin_type)
    script_tree_root = _tapleaf_hash(_depositor_claim_leaf(TEST_VALID_KEYS[0]))
    _, tree_out_key = taproot_tweak_pubkey(leaf_key, script_tree_root)
    psbt.tx.vout[0].scriptPubKey = bytes([0x51, 0x20]) + tree_out_key
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_output_foreign_key(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when Output 0 pays a BIP-86 key this device did not derive, even with
    a derivation entry claiming this device's fingerprint and a valid BIP-86 path."""
    fingerprint, leaf_key, coin_type = _reclaim_keys(client, bitcoin_network)
    origin = KeyOriginInfo(
        fingerprint,
        [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, _RECLAIM_D_INDEX],
    )
    psbt = _build_reclaim_psbt(fingerprint, leaf_key, coin_type,
                               out_key=TEST_VALID_KEYS[0], out_origin=origin)
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_zero_fee_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when the output value equals the input value (zero fee)."""
    input_value = 1_000_000
    psbt = _standard_reclaim_psbt(client, bitcoin_network,
                                  input_value=input_value, reclaimed_value=input_value)
    _assert_reclaim_refused(client, psbt)


def test_sign_psbt_reclaim_output_exceeds_input_rejected(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """Reclaim fails when the output value exceeds the input value (fee would underflow).

    End to end this is refused by the base app's outputs-exceed-inputs check before
    _validate_display_reclaim runs; reclaim_fee_ok's own underflow rejection is pinned by
    the unit tests in unit-tests/test_sign_psbt_validate.c."""
    input_value = 1_000_000
    psbt = _standard_reclaim_psbt(client, bitcoin_network,
                                  input_value=input_value, reclaimed_value=input_value + 1)
    _assert_reclaim_refused(client, psbt)


# ===========================================================================
# PegIn transaction validation
# ===========================================================================

def test_sign_psbt_pegin(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """PegIn validation passes silently and sign_custom_inputs signs the HTLC Leaf 0 input.

    sign_custom_inputs is fully implemented, so the SIGN_PSBT command returns
    SW_OK with the depositor's Schnorr signature over the HTLC Leaf 0 sighash.
    After signing, pegin_signed is incremented; the device remains in VAULT_STATE_INTENT_LOADED.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)

    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)

    psbt = _build_pegin_psbt(dep_pk, hashlock, _PREPEGIN_TXID)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk, psbt=psbt)  # HTLC Leaf 0 signed by the depositor key


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
# Pre-PegIn — additional negative tests
# ===========================================================================

def _prepegin_bound_to_intent(
    client: "RaggerClient",
    navigator: Navigator,
    device,
    bitcoin_network: str,
    depositor_values: Sequence[int] = (),
    foreign_outputs: Sequence[CTxOut] = (),
    internal_change_value: Optional[int] = None,
    extra_fee: int = 0,
    depositor_index: int = 0,
    depositor_account: int = 0,
    signing_account: int = 0,
):
    """Build a Pre-PegIn, then approve the intent committed to its txid.  Returns (psbt, wallet).

    Outputs: HTLC, auth-anchor OP_RETURN, then one P2TR(depositor_pk) output per entry of
    depositor_values (in order), then the wallet's own change-branch output
    (m/86'/coin'/0'/1/0, marked internal through its derivation) when internal_change_value
    is given, then foreign_outputs.  The input is funded for the extra outputs, so the fee
    stays at the builder's default (_PREPEGIN_DEFAULT_FEE) unless extra_fee raises it.

    Binding the txid is what lets a rejection be attributed to output validation: an intent
    committed to any other txid rejects the PSBT whatever its outputs are.  extra_fee only
    grows the input's value, which the txid does not cover, so the binding stays valid.

    The depositor is m/86'/coin'/depositor_account'/0/depositor_index; account 0 index 0 is the
    address the dApp shows.  The inputs are signed from signing_account.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    if depositor_index == 0 and depositor_account == 0:
        dep_pk = _depositor_pk(bitcoin_network)
    else:
        dep_path = f"m/86'/{coin_type}'/{depositor_account}'/0/{depositor_index}"
        dep_pk = ExtendedKey.deserialize(
            client.get_extended_pubkey(dep_path, display=False)
        ).pubkey[1:]

    hashlock = _derive_root_and_hashlock(client, navigator, device, coin_type,
                                         depositor_index, depositor_account)
    _, _, _, _, htlc_spk = _htlc_output(
        dep_pk, TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, hashlock,
    )
    fingerprint, input_key = _prepegin_input_key(client, coin_type, signing_account)
    psbt = _build_prepegin_psbt(
        htlc_spk,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        auth_anchor=vault_auth_anchor(_DERIVED_ROOT),
        input_account=signing_account,
    )

    depositor_spk = _bip86_depositor_spk(dep_pk)
    extra = [CTxOut(value, depositor_spk) for value in depositor_values]
    change_out = None
    if internal_change_value is not None:
        change_key = ExtendedKey.deserialize(
            client.get_extended_pubkey(f"m/86'/{coin_type}'/{signing_account}'/1/0", display=False)
        ).pubkey[1:]
        _, change_tweaked = taproot_tweak_pubkey(change_key, b'')
        change_out = PartiallySignedOutput(0)
        # Keyed by the tweaked output key; the path records the internal key's position.
        change_out.tap_bip32_paths[change_tweaked] = (
            set(),
            KeyOriginInfo(
                fingerprint,
                [HARDENED | 86, HARDENED | coin_type, HARDENED | signing_account, 1, 0],
            ),
        )
        extra.append(CTxOut(internal_change_value, bytes([0x51, 0x20]) + change_tweaked))
    extra += list(foreign_outputs)
    for out in extra:
        psbt.tx.vout.append(out)
        psbt.outputs.append(
            change_out if change_out is not None and out.scriptPubKey[2:] == change_tweaked
            else PartiallySignedOutput(0)
        )
    funding = psbt.inputs[0].witness_utxo
    psbt.inputs[0].witness_utxo = CTxOut(
        funding.nValue + sum(out.nValue for out in extra) + extra_fee, funding.scriptPubKey,
    )

    scalars_tlv = _build_intent_tlv_for_test(
        coin_type, _hash256(psbt.tx.serialize_without_witness()),
        depositor_index=depositor_index, depositor_account=depositor_account,
    )
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        groups=[_build_group_for_test()],
    )
    return psbt, _standard_taproot_wallet(client, coin_type, signing_account)


def test_sign_psbt_prepegin_external_output(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """Pre-PegIn fails when a non-HTLC output is external (not owned by this device)."""
    # No TAP_BIP32_DERIVATION and not the depositor's script — btcext marks it external.
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network,
        foreign_outputs=[CTxOut(1000, bytes([0x51, 0x20]) + bytes(32))],
    )
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
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network,
        depositor_values=[_VAULT_DUST_LIMIT],
    )
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
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network,
        depositor_values=[_VAULT_DUST_LIMIT, _VAULT_DUST_LIMIT],
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_cpfp_anchor_wrong_value_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Pre-PegIn fails when a depositor output is below VAULT_DUST_LIMIT.

    Above the limit, a depositor output is change and accepted (see
    test_sign_psbt_prepegin_depositor_change_accepted); below it, it is neither.
    """
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network,
        depositor_values=[_VAULT_DUST_LIMIT - 1],  # off by one — must be rejected
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


@pytest.mark.parametrize("depositor_values", [
    pytest.param([_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE], id="anchor_then_change"),
    pytest.param([_VAULT_DUST_LIMIT, _VAULT_DUST_LIMIT + 1], id="change_one_above_dust"),
])
def test_sign_psbt_prepegin_depositor_change_accepted(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    depositor_values: List[int],
) -> None:
    """Pre-PegIn accepts change to P2TR(depositor_pk) above VAULT_DUST_LIMIT, next to the anchor.

    This is the receive address the dApp shows, so change sent there stays visible to the
    user; the device derived depositor_pk itself, so no value leaves the depositor.
    """
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network, depositor_values=depositor_values,
    )
    result = client.sign_psbt(psbt, wallet, None)

    assert len(result) == 1
    input_index, partial_sig = result[0]
    assert input_index == 0
    assert len(partial_sig.signature) == 64


@pytest.mark.parametrize("depositor_values", [
    pytest.param([_PREPEGIN_DEPOSITOR_CHANGE, _VAULT_DUST_LIMIT], id="change_before_anchor"),
    pytest.param([_PREPEGIN_DEPOSITOR_CHANGE], id="change_without_anchor"),
    pytest.param([_VAULT_DUST_LIMIT + 1], id="change_one_above_dust_without_anchor"),
    pytest.param(
        [_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE, _VAULT_DUST_LIMIT],
        id="second_anchor_after_change",
    ),
])
def test_sign_psbt_prepegin_depositor_change_layout_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    depositor_values: List[int],
) -> None:
    """Pre-PegIn fails when depositor change is not preceded by exactly one CPFP anchor.

    The anchor and the change share one scriptPubKey, so the layout is what tells them
    apart: [anchor, change].  Change first, change alone, or a second anchor after the
    change is rejected.
    """
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network, depositor_values=depositor_values,
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


@pytest.mark.parametrize("depositor_values", [
    pytest.param([], id="without_anchor"),
    pytest.param([_VAULT_DUST_LIMIT], id="with_anchor"),
])
def test_sign_psbt_prepegin_change_branch_output_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    depositor_values: List[int],
) -> None:
    """Pre-PegIn fails when an output pays the wallet's change branch (m/86'/coin'/0'/1/0).

    Change goes to the depositor's own address; an output on the wallet policy's change
    branch matches no accepted output kind.
    """
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network,
        depositor_values=depositor_values,
        internal_change_value=_PREPEGIN_DEPOSITOR_CHANGE,
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


def test_sign_psbt_prepegin_two_depositor_changes_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Pre-PegIn fails when two depositor outputs above VAULT_DUST_LIMIT are present."""
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network,
        depositor_values=[_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE, _PREPEGIN_DEPOSITOR_CHANGE],
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA


@pytest.mark.parametrize("fee_over_cap, accepted", [
    pytest.param(0, True, id="fee_at_cap_accepted"),
    pytest.param(1, False, id="fee_one_above_cap_rejected"),
])
def test_sign_psbt_prepegin_depositor_change_fee_cap(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    fee_over_cap: int,
    accepted: bool,
) -> None:
    """Pre-PegIn with anchor and depositor change keeps the prepegin_max_fee cap.

    A fee equal to the cap is signed, one satoshi above it is refused.  The change is funded
    by the input, so it never counts as fee.  The two cases differ only by one satoshi of
    input value, which the txid does not cover, so the rejection can only come from the
    fee check.
    """
    # The builder funds the input for _PREPEGIN_DEFAULT_FEE; top it up to the cap.
    extra_fee = _PREPEGIN_MAX_FEE - _PREPEGIN_DEFAULT_FEE + fee_over_cap
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network,
        depositor_values=[_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE],
        extra_fee=extra_fee,
    )
    # Guard the premise: the PSBT sits exactly on the boundary under test.
    fee = psbt.inputs[0].witness_utxo.nValue - sum(out.nValue for out in psbt.tx.vout)
    assert fee == _PREPEGIN_MAX_FEE + fee_over_cap

    if accepted:
        result = client.sign_psbt(psbt, wallet, None)

        assert len(result) == 1
        input_index, partial_sig = result[0]
        assert input_index == 0
        assert len(partial_sig.signature) == 64
    else:
        with pytest.raises(ExceptionRAPDU) as exc:
            client.sign_psbt(psbt, wallet, None)
        assert exc.value.status == SW_INCORRECT_DATA


@pytest.mark.parametrize(
    "depositor_index, depositor_account, signing_account, depositor_values, accepted", [
        pytest.param(1, 0, 0, [_VAULT_DUST_LIMIT], True, id="other_index_anchor_only_accepted"),
        pytest.param(1, 0, 0, [_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE], False,
                     id="other_index_change_rejected"),
        pytest.param(1, 1, 0, [_VAULT_DUST_LIMIT], True, id="other_account_anchor_only_accepted"),
        pytest.param(0, 1, 0, [_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE], False,
                     id="other_account_change_rejected"),
        pytest.param(0, 1, 1, [_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE], True,
                     id="signing_account_1_change_accepted"),
        pytest.param(0, 0, 1, [_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE], False,
                     id="signing_account_1_depositor_account_0_change_rejected"),
    ])
def test_sign_psbt_prepegin_change_needs_signing_accounts_first_receive_address(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    depositor_index: int,
    depositor_account: int,
    signing_account: int,
    depositor_values: List[int],
    accepted: bool,
) -> None:
    """Pre-PegIn change is accepted only at m/86'/coin'/account'/0/0 of the signing account.

    The depositor path is the host's choice and is not shown on the device, so change to any
    other address of the depositor would land where a wallet does not look: another address
    index of the signing account, or the first address of an account the inputs are not
    signed from.  The signing account is taken from the wallet policy, so both a zero and a
    nonzero account are exercised.  The anchor is not affected by the path.
    """
    psbt, wallet = _prepegin_bound_to_intent(
        client, navigator, device, bitcoin_network,
        depositor_values=depositor_values,
        depositor_index=depositor_index, depositor_account=depositor_account,
        signing_account=signing_account,
    )
    if accepted:
        result = client.sign_psbt(psbt, wallet, None)

        assert len(result) == 1
        input_index, partial_sig = result[0]
        assert input_index == 0
        assert len(partial_sig.signature) == 64
    else:
        with pytest.raises(ExceptionRAPDU) as exc:
            client.sign_psbt(psbt, wallet, None)
        assert exc.value.status == SW_INCORRECT_DATA


@pytest.mark.parametrize("depositor_values, accepted", [
    pytest.param([_VAULT_DUST_LIMIT], True, id="anchor_only_accepted"),
    pytest.param([_VAULT_DUST_LIMIT, _PREPEGIN_DEPOSITOR_CHANGE], False, id="change_rejected"),
])
def test_sign_psbt_prepegin_change_needs_bip86_signing_wallet(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    depositor_values: List[int],
    accepted: bool,
) -> None:
    """Pre-PegIn change is refused when the inputs are signed from a non-BIP-86 wallet.

    The account matches the depositor's; the anchor alone is signed, so the change is the
    only reason for the refusal.
    """
    psbt, coin_type, pubkey = _setup_prepegin_ecdsa_case(
        client, navigator, device, bitcoin_network, BIP84_NATIVE_SEGWIT,
        depositor_values=depositor_values,
    )
    wallet = _standard_native_segwit_wallet(client, coin_type)

    if accepted:
        result = client.sign_psbt(psbt, wallet, None)

        assert len(result) == 1
        input_index, partial_sig = result[0]
        assert input_index == 0
        assert partial_sig.pubkey == pubkey
    else:
        with pytest.raises(ExceptionRAPDU) as exc:
            client.sign_psbt(psbt, wallet, None)
        assert exc.value.status == SW_INCORRECT_DATA


# ===========================================================================
# Refund — additional negative tests
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
# PegIn — additional negative tests
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
# Payout transaction validation
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
    base_fee_rate: int = _BASE_FEE_RATE,
) -> bytes:
    """Approve intent then sign PegIn (pegin_signed=1, payout_index=0). Returns the 32-byte hashlock."""
    dep_pk = TEST_DEPOSITOR_XONLY_MAINNET if coin_type == 0 else TEST_DEPOSITOR_XONLY_TESTNET
    hashlock = _setup_s2_state(client, navigator, device, coin_type, prepegin_txid,
                               base_fee_rate=base_fee_rate)
    pegin_psbt = _build_pegin_psbt(dep_pk, hashlock, prepegin_txid)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    # PegIn signing is fully wired; SW_OK advances state to PAYOUT_EXPECTED.
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
    _assert_single_schnorr_sig(result, dep_pk, psbt=psbt)  # Vault UTXO signed by the depositor key


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
    psbt.tx.vout[0].scriptPubKey = _OP_RETURN_PUSH32 + bytes(32)

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
        prepegin_max_fee=_PREPEGIN_MAX_FEE,
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
# Maximum-participant memory stress (VAULT_SCRIPT_MAX_LEN ceiling)
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
    signed the HTLC Leaf 0 input.

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
# CPFP anchor key validation
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
# 3-vault batch iteration
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
        prepegin_max_fee=_PREPEGIN_MAX_FEE,
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
# Depositor claimer payout
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
# NoPayout transaction
# ===========================================================================

# NoPayout amounts, funded from the protocol formula rather than pinned to DUST.
#
# The previous fixture hardcoded all three inputs to VAULT_DUST_LIMIT — the maximum the
# old connector cap allowed and a value the protocol never produces — so the whole suite
# passed while no real NoPayout could be signed above 1 sat/vB. Values below follow
# btc-vault's builders (see tmp/hld-discrepancies-2026-09-01.md):
#
#   Assert:0            = DUST      + rate * council_nopayout_vsize
#   ChallengeAssert:0   = P2TR_DUST + rate * WronglyChallenged_vsize
#
# These live only in the test: the firmware deliberately mirrors none of them, bounding
# the fee instead (D1). They are here so the fixture funds like production does.
_P2TR_DUST = 330                    # rust-bitcoin P2TR_DUST_THRESHOLD; not DUST (546)
_WC_VSIZE = 179                     # WronglyChallenged, fixed (WC taptree is pinned)
_COUNCIL_NOPAYOUT_VSIZE = 210       # 3-of-5 council, 2 challengers
_NOPAYOUT_VSIZE = 337               # NoPayout itself at N=M=1
_MAX_NOPAYOUT_VSIZE = 450           # must match MAX_NOPAYOUT_VSIZE in sign_psbt_validate.c


def _nopayout_input0_value(base_fee_rate: int = _BASE_FEE_RATE) -> int:
    """Assert:0 funding: covers the CouncilNoPayout that may spend it."""
    return VAULT_DUST_LIMIT + base_fee_rate * _COUNCIL_NOPAYOUT_VSIZE


def _nopayout_connector_value(base_fee_rate: int = _BASE_FEE_RATE) -> int:
    """ChallengeAssert:0 funding: covers the WronglyChallenged that may spend it."""
    return _P2TR_DUST + base_fee_rate * _WC_VSIZE


def _nopayout_inputs_total(base_fee_rate: int = _BASE_FEE_RATE) -> int:
    return _nopayout_input0_value(base_fee_rate) + 2 * _nopayout_connector_value(base_fee_rate)


def _nopayout_out_value(base_fee_rate: int = _BASE_FEE_RATE) -> int:
    """Output 0 leaving a realistic NoPayout fee (rate * its own vsize)."""
    return _nopayout_inputs_total(base_fee_rate) - base_fee_rate * _NOPAYOUT_VSIZE


_NOPAYOUT_INPUTS_TOTAL = _nopayout_inputs_total()
_NOPAYOUT_MAX_FEE = _BASE_FEE_RATE * _MAX_NOPAYOUT_VSIZE
_NOPAYOUT_OUT_VALUE = _nopayout_out_value()


def _build_nopayout_psbt(
    depositor_pk: bytes,
    challenger_pk: bytes,
    assert_txid: bytes = _ASSERT_TXID,
    out_value: Optional[int] = None,
    base_fee_rate: int = _BASE_FEE_RATE,
) -> PSBT:
    """Build a NoPayout PSBT: 3 custom inputs, 1 output.

    Input 0: NoPayout leaf <D> OP_CHECKSIGVERIFY <Cj> OP_CHECKSIG (68 bytes),
             single-leaf P2TR (NUMS internal key), funded per the protocol formula
             (DUST + rate * council_nopayout_vsize).
             Its prevout is Assert:0 (HLD: NoPayout Input 0 spends the depositor graph's
             Assert output 0). Only vout==0 is checked; the txid is unconstrained because
             the device cannot reconstruct the Assert txid.
    Inputs 1, 2: ChallengeAssert connectors — WITNESS_UTXO only (device ignores script),
             funded at P2TR_DUST + rate * WC_vsize, which exceeds DUST above 1 sat/vB.
    base_fee_rate: must match the rate in the loaded intent; scales all three input values
             and the default output, so the implied fee stays at rate * NoPayout vsize.
    Output 0: P2TR(key-path-tweak(challenger_pk)) — device verifies this exact scriptPubKey,
             requires out_value >= DUST, and bounds the implied fee.

    Needs no intent geometry: the leaf and the output are functions of (depositor,
    challenger) alone, which is exactly why the device cannot tell vault groups apart here.
    """
    if out_value is None:
        out_value = _nopayout_out_value(base_fee_rate)

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

    psbt.inputs[0].witness_utxo = CTxOut(_nopayout_input0_value(base_fee_rate), nopayout_spk)
    psbt.inputs[0].tap_scripts[(nopayout_leaf, 0xC0)] = {control_block}
    connector_value = _nopayout_connector_value(base_fee_rate)
    psbt.inputs[1].witness_utxo = CTxOut(connector_value, connector_spk)
    psbt.inputs[2].witness_utxo = CTxOut(connector_value, connector_spk)

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
    _assert_single_schnorr_sig(result, dep_pk, psbt=psbt)


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


@pytest.mark.parametrize("input_index", [1, 2])
def test_sign_psbt_nopayout_connector_above_dust_accepted(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
    input_index: int,
) -> None:
    """A ChallengeAssert connector above VAULT_DUST_LIMIT is accepted (D1).

    These inputs used to be capped at DUST, which is what rejected every real NoPayout.
    There is deliberately no replacement bound: the extra value is passed through to
    Output 0 here, so the fee is unchanged and nothing should object. What still protects
    the depositor is Output 0's pinned scriptPubKey, the fee bound, and SIGHASH_DEFAULT
    committing every prevout amount — see the burned-to-fee test below for the fee half.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # Well clear of the old cap, and passed straight through to Output 0.
    delta = 1000
    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0],
                                out_value=_NOPAYOUT_OUT_VALUE + delta)
    raised = _nopayout_connector_value() + delta
    assert raised > VAULT_DUST_LIMIT, "test must exceed the removed cap to be meaningful"
    psbt.inputs[input_index].witness_utxo = CTxOut(
        raised, psbt.inputs[input_index].witness_utxo.scriptPubKey
    )

    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk)


@pytest.mark.parametrize("input_index", [1, 2])
def test_sign_psbt_nopayout_inflated_connector_burned_to_fee_rejected(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
    input_index: int,
) -> None:
    """Inflating a connector without paying it out is caught by the fee bound (D1).

    The adversarial case the removed per-input cap was aimed at: extra input value that
    does not reach Output 0 becomes miner fee. Removing the cap does not open that up,
    because the fee bound is computed over all three inputs.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type)

    # Output 0 left at its default, so the whole delta lands in the fee.
    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0])
    psbt.inputs[input_index].witness_utxo = CTxOut(
        _nopayout_connector_value() + _NOPAYOUT_MAX_FEE + 1,
        psbt.inputs[input_index].witness_utxo.scriptPubKey,
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


@pytest.mark.parametrize("base_fee_rate", [1, 2, 10, 50])
def test_sign_psbt_nopayout_real_funding(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
    base_fee_rate: int,
) -> None:
    """NoPayout signs when its inputs are funded the way btc-vault actually funds them.

    Regression for D1: the ChallengeAssert connectors were capped at VAULT_DUST_LIMIT, but
    the protocol funds them at P2TR_DUST(330) + rate * WC_vsize(179) — 509 sat at 1 sat/vB
    and 688 at 2 — so every real NoPayout above 1 sat/vB was rejected. Rate 1 passed only
    by 37 sat of accident. The old fixture pinned all three inputs to DUST and so could
    never have caught it; this one funds from the protocol formula and sweeps the rate.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    dep_pk = _depositor_pk(bitcoin_network)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])

    _setup_payout_state(client, navigator, device, coin_type, base_fee_rate=base_fee_rate)

    psbt = _build_nopayout_psbt(dep_pk, _TEST_KEEPER_PKS[0], base_fee_rate=base_fee_rate)
    result = client.sign_psbt(psbt, dummy_wallet, None)
    _assert_single_schnorr_sig(result, dep_pk, psbt=psbt)


def test_sign_psbt_nopayout_fee_above_bound(
    client: "RaggerClient",
    navigator: Navigator,
    bitcoin_network: str,
    device,
) -> None:
    """NoPayout fails when the implied fee exceeds base_fee_rate * MAX_NOPAYOUT_VSIZE.

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
    """NoPayout accepts a fee exactly equal to base_fee_rate * MAX_NOPAYOUT_VSIZE."""
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
        prepegin_max_fee=_PREPEGIN_MAX_FEE,
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
    # navigate to the finish page by title rather than pinning a swipe count.  A fixed count
    # has to be recalibrated whenever NBGL repacks pairs per page, which the phase-2 Skip
    # header changes; navigating by title is immune to that.
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
