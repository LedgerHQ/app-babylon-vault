"""
Ragger integration tests for DERIVE_CONTEXT_HASH (INS 0x81), realigned to
derive-context-hash v2.x.

Single APDU: app_name_len | app_name | path_len | path | context.
The device derives the connected pubkey at `path` and returns the 32-byte root:

    info = SHA256(app_name) || SHA256(canonicalNetworkName) || connectedPubkey[33] || context
    root = HKDF-SHA256(ikm = privkey@m/73681862', salt = "derive-context-hash", info, 32)

Expected roots are computed at runtime from the Speculos seed (conftest mnemonic) using
only `bip_utils` + stdlib, so the tests are self-validating (no precomputed constants).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import List, TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest
from bip_utils import Bip32KeyIndex, Bip32Slip10Secp256k1

from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from .vault_client import (
    derive_context_hash,
    CLA_VAULT,
    INS_DERIVE_CONTEXT_HASH,
    P1_INITIAL,
    P2_UNUSED,
)

HARDENED = 0x80000000
APP_NAME = b"babylon-btc-vault"
_HKDF_PATH = [HARDENED | 73681862]

# Same mnemonic Speculos is seeded with (conftest.py). The BIP-39 seed is derived with
# stdlib PBKDF2 (BIP-39: PBKDF2-HMAC-SHA512, salt "mnemonic", 2048 iters) — no extra dep.
_MNEMONIC = ("glory promote mansion idle axis finger extra february uncover one trip "
             "resource lawn turtle enact monster seven myth punch hobby comfort wild "
             "raise skin")
_SEED = hashlib.pbkdf2_hmac("sha512", _MNEMONIC.encode("utf-8"), b"mnemonic", 2048)
_BIP32_ROOT = Bip32Slip10Secp256k1.FromSeed(_SEED)


def _bip32_derive(path: List[int]) -> Bip32Slip10Secp256k1:
    node = _BIP32_ROOT
    for idx in path:
        node = node.ChildKey(Bip32KeyIndex(idx))
    return node


def _network_name(bitcoin_network: str) -> bytes:
    return b"bitcoin-mainnet" if bitcoin_network == "main" else b"bitcoin-signet"


def _connected_path(ct: int) -> List[int]:
    """connectedPubkey path used by these tests (depositor BIP-86 receive leaf)."""
    return [HARDENED | 86, HARDENED | ct, HARDENED | 0, 0, 0]


def _expected_root(app_name: bytes, path: List[int], context: bytes, bitcoin_network: str) -> bytes:
    ikm = _bip32_derive(_HKDF_PATH).PrivateKey().Raw().ToBytes()
    pubkey = _bip32_derive(path).PublicKey().RawCompressed().ToBytes()  # 33-byte compressed
    prk = hmac.new(b"derive-context-hash", ikm, hashlib.sha256).digest()
    info = (hashlib.sha256(app_name).digest()
            + hashlib.sha256(_network_name(bitcoin_network)).digest()
            + pubkey
            + context)
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_root_matches_reference(client: "RaggerClient", navigator: Navigator,
                                device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    path, ctx = _connected_path(ct), b"\xde\xad\xbe\xef"
    root = derive_context_hash(client, app_name=APP_NAME, path=path, context=ctx,
                               navigator=navigator, device=device)
    assert len(root) == 32
    assert root == _expected_root(APP_NAME, path, ctx, bitcoin_network)


def test_deterministic(client: "RaggerClient", navigator: Navigator,
                       device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    path = _connected_path(ct)
    a = derive_context_hash(client, APP_NAME, path, b"\x01\x02", navigator, device)
    b = derive_context_hash(client, APP_NAME, path, b"\x01\x02", navigator, device)
    assert a == b


def test_different_app_name_diverges(client: "RaggerClient", navigator: Navigator,
                                     device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    path, ctx = _connected_path(ct), b"\xaa\xbb"
    base = derive_context_hash(client, APP_NAME, path, ctx, navigator, device)
    other = derive_context_hash(client, b"other-app", path, ctx, navigator, device)
    assert other != base
    assert other == _expected_root(b"other-app", path, ctx, bitcoin_network)


def test_different_context_diverges(client: "RaggerClient", navigator: Navigator,
                                    device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    path = _connected_path(ct)
    a = derive_context_hash(client, APP_NAME, path, b"\x11\x11", navigator, device)
    b = derive_context_hash(client, APP_NAME, path, b"\x22\x22", navigator, device)
    assert a != b


def test_different_path_diverges(client: "RaggerClient", navigator: Navigator,
                                 device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    ctx = b"\xab\xcd"
    a = derive_context_hash(client, APP_NAME, _connected_path(ct), ctx, navigator, device)
    other_path = [HARDENED | 86, HARDENED | ct, HARDENED | 0, 0, 1]  # different receive leaf
    b = derive_context_hash(client, APP_NAME, other_path, ctx, navigator, device)
    assert a != b
    assert b == _expected_root(APP_NAME, other_path, ctx, bitcoin_network)


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

def test_invalid_p1_raises(client: "RaggerClient"):
    """Unknown P1 must return SW_WRONG_P1P2 (0x6A86) — no continuation chunks exist."""
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=0x42, p2=P2_UNUSED, data=b"")
    assert exc.value.status == 0x6A86


def test_app_name_too_long_raises(client: "RaggerClient"):
    """app_name_len > 64 → SW_INCORRECT_DATA (0x6A80)."""
    payload = bytes([65]) + b"A" * 65
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == 0x6A80


def test_empty_context_raises(client: "RaggerClient", bitcoin_network: str):
    """app_name + path but no context → SW_INCORRECT_DATA (0x6A80)."""
    ct = 0 if bitcoin_network == "main" else 1
    path = _connected_path(ct)
    payload = (bytes([len(APP_NAME)]) + APP_NAME
               + bytes([len(path)]) + b"".join(p.to_bytes(4, "big") for p in path))
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == 0x6A80


# NOTE: VAULT_CONTEXT_MAX_LEN (1024 bytes) cannot be tested at the integration level
# because standard APDU Lc is a single byte (max 255).  The limit is covered by the
# unit test in unit-tests/test_derive_context_hash.c via the handler's C validation
# and serves as spec-aligned defensive code for any future extended-APDU transport.

def test_zero_path_len_raises(client: "RaggerClient"):
    """path_len == 0 → SW_INCORRECT_DATA (0x6A80)."""
    payload = bytes([len(APP_NAME)]) + APP_NAME + bytes([0]) + b"\xde\xad\xbe\xef"
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == 0x6A80


# ---------------------------------------------------------------------------
# Session interaction
# ---------------------------------------------------------------------------

def test_invalidates_loaded_intent(client: "RaggerClient", navigator: Navigator,
                                    device: Device, bitcoin_network: str):
    """DERIVE_CONTEXT_HASH after an intent is loaded must reset the session and still work."""
    from .vault_client import (
        approve_vault_intent_with_nav, build_intent_tlv, TEST_VP_KEY, TEST_VALID_KEYS,
    )

    ct = 0 if bitcoin_network == "main" else 1
    scalars = build_intent_tlv(
        coin_type=ct, vault_provider_pk=TEST_VP_KEY,
        vault_amount=100_000, commission_fee=1_000,
        depositor_claim_value=10_000, base_fee_rate=10, pegin_max_fee=50_000,
        pegin_csv_timelock=100, payout_timelock=200,
        prepegin_txid=bytes(range(32)), htlc_vout=0, htlc_refund_timelock=144,
        depositor_path=[HARDENED | 86, HARDENED | ct, HARDENED | 0, 0, 0],
        keeper_count=1, challenger_count=1,
    )
    # Must derive first — state machine requires HASH_DERIVED before APPROVE_VAULT_INTENT.
    derive_context_hash(client, APP_NAME, _connected_path(ct), b"\xde\xad\xbe\xef",
                        navigator, device)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[TEST_VALID_KEYS[0]],
                                  challenger_pks=[TEST_VALID_KEYS[1]])

    path, ctx = _connected_path(ct), b"\xde\xad\xbe\xef"
    root = derive_context_hash(client, app_name=APP_NAME, path=path, context=ctx,
                               navigator=navigator, device=device)
    assert len(root) == 32
    assert root == _expected_root(APP_NAME, path, ctx, bitcoin_network)
