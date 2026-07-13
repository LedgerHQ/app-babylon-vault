"""
Ragger integration tests for DERIVE_CONTEXT_HASH (INS 0x81), rev 2.1.

Multi-chunk streaming:
  P1=0x00: app_name_len | app_name | path_len | path | context_total_len(2B BE)
           | first_context_chunk
  P1=0x01: continuation context bytes (repeated until total received)

P2=0x00: Screen 1 (app_name), returns 32-byte root.
P2=0x01: silent, returns SW_OK with no data.

The device derives the connected pubkey at `path` and returns the 32-byte root:

    info = SHA256(app_name) || SHA256(canonicalNetworkName) || connectedPubkey[33] || context
    root = HKDF-SHA256(ikm = privkey@m/73681862', salt = "derive-context-hash", info, 32)

Expected roots are computed at runtime from the Speculos seed (conftest mnemonic) using
only `bip_utils` + stdlib, so the tests are self-validating (no precomputed constants).
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
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
    depositor_path,
    CLA_VAULT,
    INS_DERIVE_CONTEXT_HASH,
    P1_INITIAL,
    P1_CONTINUE,
    P2_UNUSED,
    P2_SHOW,
    P2_SILENT,
    SW_BAD_STATE,
    SW_DENY,
    SW_INCORRECT_DATA,
    SW_WRONG_DATA_LENGTH,
    SW_WRONG_P1P2,
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
    path, ctx = depositor_path(ct), b"\xde\xad\xbe\xef"
    root = derive_context_hash(client, app_name=APP_NAME, path=path, context=ctx,
                               navigator=navigator, device=device)
    assert len(root) == 32
    assert root == _expected_root(APP_NAME, path, ctx, bitcoin_network)


def test_deterministic(client: "RaggerClient", navigator: Navigator,
                       device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    a = derive_context_hash(client, APP_NAME, path, b"\x01\x02", navigator, device)
    b = derive_context_hash(client, APP_NAME, path, b"\x01\x02", navigator, device)
    assert a == b


def test_different_app_name_diverges(client: "RaggerClient", navigator: Navigator,
                                     device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    path, ctx = depositor_path(ct), b"\xaa\xbb"
    base = derive_context_hash(client, APP_NAME, path, ctx, navigator, device)
    other = derive_context_hash(client, b"other-app", path, ctx, navigator, device)
    assert other != base
    assert other == _expected_root(b"other-app", path, ctx, bitcoin_network)


def test_different_context_diverges(client: "RaggerClient", navigator: Navigator,
                                    device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    a = derive_context_hash(client, APP_NAME, path, b"\x11\x11", navigator, device)
    b = derive_context_hash(client, APP_NAME, path, b"\x22\x22", navigator, device)
    assert a != b


def test_different_path_diverges(client: "RaggerClient", navigator: Navigator,
                                 device: Device, bitcoin_network: str):
    ct = 0 if bitcoin_network == "main" else 1
    ctx = b"\xab\xcd"
    a = derive_context_hash(client, APP_NAME, depositor_path(ct), ctx, navigator, device)
    other_path = [HARDENED | 86, HARDENED | ct, HARDENED | 0, 0, 1]  # different receive leaf
    b = derive_context_hash(client, APP_NAME, other_path, ctx, navigator, device)
    assert a != b
    assert b == _expected_root(APP_NAME, other_path, ctx, bitcoin_network)


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

def test_invalid_p1_raises(client: "RaggerClient"):
    """P1 values other than 0x00 and 0x01 must return SW_WRONG_P1P2 (0x6A86)."""
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
    """context_total_len == 0 → SW_INCORRECT_DATA (0x6A80)."""
    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    # New wire format: include 2-byte context_total_len = 0x0000, no context bytes.
    payload = (bytes([len(APP_NAME)]) + APP_NAME
               + bytes([len(path)]) + b"".join(p.to_bytes(4, "big") for p in path)
               + b"\x00\x00")
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == 0x6A80


def test_zero_path_len_raises(client: "RaggerClient"):
    """path_len == 0 → SW_INCORRECT_DATA (0x6A80)."""
    payload = bytes([len(APP_NAME)]) + APP_NAME + bytes([0]) + b"\xde\xad\xbe\xef"
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == 0x6A80


def test_continuation_without_initial_raises(client: "RaggerClient"):
    """P1=0x01 without a prior P1=0x00 → SW_BAD_STATE (0xB007)."""
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_CONTINUE, p2=P2_UNUSED, data=b"\x01\x02\x03")
    assert exc.value.status == SW_BAD_STATE


# ---------------------------------------------------------------------------
# Multi-chunk streaming
# ---------------------------------------------------------------------------

def test_multi_chunk_context_matches_reference(client: "RaggerClient", navigator: Navigator,
                                               device: Device, bitcoin_network: str):
    """Large context split across P1=0x00 + P1=0x01 yields same root as single-chunk."""
    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    # 300-byte context forces at least two APDUs (header ~30 B, first chunk ~225 B, rest ~75 B).
    context = bytes(range(256)) + b"\xca\xfe" * 22  # 300 bytes
    root = derive_context_hash(client, APP_NAME, path, context, navigator, device)
    assert len(root) == 32
    assert root == _expected_root(APP_NAME, path, context, bitcoin_network)


def test_multi_chunk_deterministic(client: "RaggerClient", navigator: Navigator,
                                   device: Device, bitcoin_network: str):
    """Multi-chunk root is deterministic across calls."""
    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    context = bytes(range(256)) + b"\xab" * 44  # 300 bytes
    a = derive_context_hash(client, APP_NAME, path, context, navigator, device)
    b = derive_context_hash(client, APP_NAME, path, context, navigator, device)
    assert a == b


# ---------------------------------------------------------------------------
# P2=0x01 silent mode
# ---------------------------------------------------------------------------

def test_p2_silent_returns_no_data(client: "RaggerClient", navigator: Navigator,
                                   device: Device, bitcoin_network: str):
    """P2=0x01 completes without a screen and returns no root data."""
    ct = 0 if bitcoin_network == "main" else 1
    path, ctx = depositor_path(ct), b"\xde\xad\xbe\xef"
    result = derive_context_hash(client, APP_NAME, path, ctx,
                                 navigator, device, p2=P2_SILENT)
    assert result == b""


def test_p2_silent_advances_state(client: "RaggerClient", navigator: Navigator,
                                  device: Device, bitcoin_network: str):
    """P2=0x01 still advances the session to HASH_DERIVED (can be followed by P2=0x00)."""
    ct = 0 if bitcoin_network == "main" else 1
    path, ctx = depositor_path(ct), b"\x01\x02\x03\x04"
    # Silent re-derivation — no root back.
    derive_context_hash(client, APP_NAME, path, ctx, navigator, device, p2=P2_SILENT)
    # P2=0x00 re-derive must succeed and return the same root as a direct P2=0x00 call.
    root_show = derive_context_hash(client, APP_NAME, path, ctx, navigator, device, p2=P2_SHOW)
    assert root_show == _expected_root(APP_NAME, path, ctx, bitcoin_network)


def test_p2_silent_multi_chunk(client: "RaggerClient", navigator: Navigator,
                                device: Device, bitcoin_network: str):
    """P2=0x01 with a large context spans multiple APDUs without triggering a screen."""
    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    context = b"\xff" * 300  # forces P1=0x01 chunks
    result = derive_context_hash(client, APP_NAME, path, context,
                                 navigator, device, p2=P2_SILENT)
    assert result == b""


# ---------------------------------------------------------------------------
# Session interaction
# ---------------------------------------------------------------------------

def test_invalidates_loaded_intent(client: "RaggerClient", navigator: Navigator,
                                    device: Device, bitcoin_network: str):
    """DERIVE_CONTEXT_HASH after an intent is loaded must reset the session and still work."""
    from .vault_client import (
        approve_vault_intent_with_nav, build_intent_tlv, build_group_tlv,
        TEST_VP_KEY, TEST_VALID_KEYS,
    )

    ct = 0 if bitcoin_network == "main" else 1
    scalars = build_intent_tlv(
        coin_type=ct, base_fee_rate=10,
        pegin_csv_timelock=100, payout_timelock=200,
        prepegin_txid=bytes(range(32)), htlc_refund_timelock=144,
        depositor_path=depositor_path(ct),
        keeper_count=1, challenger_count=1, vault_count=1,
    )
    group = build_group_tlv(
        htlc_vout=0, vault_provider_pk=TEST_VP_KEY,
        vault_amount=100_000, commission_fee=1_000,
        depositor_claim_value=10_000, pegin_max_fee=50_000,
    )
    # Must derive first — state machine requires HASH_DERIVED before APPROVE_VAULT_INTENT.
    derive_context_hash(client, APP_NAME, depositor_path(ct), b"\xde\xad\xbe\xef",
                        navigator, device)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[TEST_VALID_KEYS[0]],
                                  challenger_pks=[TEST_VALID_KEYS[1]],
                                  groups=[group])

    path, ctx = depositor_path(ct), b"\xde\xad\xbe\xef"
    root = derive_context_hash(client, app_name=APP_NAME, path=path, context=ctx,
                               navigator=navigator, device=device)
    assert len(root) == 32
    assert root == _expected_root(APP_NAME, path, ctx, bitcoin_network)


# ---------------------------------------------------------------------------
# More error paths
# ---------------------------------------------------------------------------

def test_invalid_p2_raises(client: "RaggerClient"):
    """P2 values other than 0x00 and 0x01 on P1=0x00 must return SW_WRONG_P1P2."""
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=0x02, data=b"")
    assert exc.value.status == SW_WRONG_P1P2


def test_empty_app_name_raises(client: "RaggerClient"):
    """app_name_len == 0 → SW_INCORRECT_DATA."""
    payload = bytes([0])  # app_name_len = 0
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == SW_INCORRECT_DATA


def test_invalid_app_name_charset_raises(client: "RaggerClient"):
    """app_name with characters outside [a-z0-9-] → SW_INCORRECT_DATA."""
    name = b"BABYLON"  # uppercase letters are not in the allowed charset
    payload = bytes([len(name)]) + name
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == SW_INCORRECT_DATA


def test_path_too_deep_raises(client: "RaggerClient"):
    """path_len > VAULT_MAX_PATH_DEPTH (10) → SW_INCORRECT_DATA."""
    # Include a valid app_name so the path_len byte is reached.
    payload = bytes([len(APP_NAME)]) + APP_NAME + bytes([11])  # path_len = 11
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == SW_INCORRECT_DATA


def test_context_too_large_raises(client: "RaggerClient"):
    """context_total_len > VAULT_CONTEXT_MAX_LEN (1024) → SW_INCORRECT_DATA."""
    _path = [HARDENED | 86, HARDENED | 0, HARDENED | 0, 0, 0]
    path_bytes = bytes([len(_path)]) + b"".join(p.to_bytes(4, "big") for p in _path)
    payload = bytes([len(APP_NAME)]) + APP_NAME + path_bytes + (1025).to_bytes(2, "big")
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_INITIAL, p2=P2_UNUSED, data=payload)
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# Streaming edge cases
# ---------------------------------------------------------------------------

def _enter_streaming(client: "RaggerClient", bitcoin_network: str,
                     context_total: int = 100, first_chunk_len: int = 50) -> None:
    """Send a valid P1=0x00 that puts the device into streaming mode.

    Declares context_total bytes but only sends first_chunk_len in the initial
    APDU, so the device waits for continuation chunks.
    """
    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    path_bytes = bytes([len(path)]) + b"".join(p.to_bytes(4, "big") for p in path)
    header = bytes([len(APP_NAME)]) + APP_NAME + path_bytes + context_total.to_bytes(2, "big")
    client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                     p1=P1_INITIAL, p2=P2_UNUSED,
                                     data=header + b"\xaa" * first_chunk_len)


def test_continuation_overflow_raises(client: "RaggerClient", bitcoin_network: str):
    """P1=0x01 carrying more bytes than remaining → SW_INCORRECT_DATA."""
    _enter_streaming(client, bitcoin_network, context_total=100, first_chunk_len=50)
    # 51 bytes > 50 remaining
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_CONTINUE, p2=P2_UNUSED, data=b"\xbb" * 51)
    assert exc.value.status == SW_INCORRECT_DATA


def test_empty_continuation_raises(client: "RaggerClient", bitcoin_network: str):
    """P1=0x01 with lc == 0 → SW_WRONG_DATA_LENGTH."""
    _enter_streaming(client, bitcoin_network, context_total=100, first_chunk_len=50)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
                                         p1=P1_CONTINUE, p2=P2_UNUSED, data=b"")
    assert exc.value.status == SW_WRONG_DATA_LENGTH


def test_reset_during_streaming(client: "RaggerClient", navigator: Navigator,
                                device: Device, bitcoin_network: str):
    """A new P1=0x00 while streaming cancels in-flight state and starts fresh."""
    _enter_streaming(client, bitcoin_network)
    ct = 0 if bitcoin_network == "main" else 1
    path, ctx = depositor_path(ct), b"\xde\xad\xbe\xef"
    # P2_SILENT reset — no screen, should succeed cleanly.
    result = derive_context_hash(client, APP_NAME, path, ctx, navigator, device, p2=P2_SILENT)
    assert result == b""
    # A subsequent P2_SHOW call must return the correct root for the fresh derivation.
    root = derive_context_hash(client, APP_NAME, path, ctx, navigator, device)
    assert root == _expected_root(APP_NAME, path, ctx, bitcoin_network)


def test_max_context_matches_reference(client: "RaggerClient", navigator: Navigator,
                                       device: Device, bitcoin_network: str):
    """Exactly 1024 bytes of context (VAULT_CONTEXT_MAX_LEN) must yield the correct root."""
    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    context = bytes(range(256)) * 4  # 1024 bytes
    root = derive_context_hash(client, APP_NAME, path, context, navigator, device)
    assert len(root) == 32
    assert root == _expected_root(APP_NAME, path, context, bitcoin_network)


# ---------------------------------------------------------------------------
# Screen tests — snapshot and rejection
# ---------------------------------------------------------------------------

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


def test_screen_snapshot(client: "RaggerClient", navigator: Navigator,
                         device: Device, bitcoin_network: str):
    """Screen 1 snapshot: 1024-byte context (maximum, multi-chunk), P2=0x00.

    Uses navigate_until_text_and_compare with screen_change_before_first_instruction=False
    so the review screen (already rendered when the last APDU is processed) is captured
    immediately without waiting for a change that may have already happened.
    On first run use --golden_run:

        pytest tests/test_derive_context_hash.py::test_screen_snapshot --golden_run -k flex
    """
    from .instructions import derive_context_hash_nav
    from .vault_client import _dch_exchange, _encode_bip32_path

    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    context = bytes(range(256)) * 4  # 1024 bytes — exercises multi-chunk streaming

    # Build and stream the APDU sequence manually so we control the async boundary.
    path_bytes = _encode_bip32_path(path)
    header = bytes([len(APP_NAME)]) + APP_NAME + path_bytes + len(context).to_bytes(2, "big")
    first_chunk_max = 255 - len(header)
    first_chunk = context[:first_chunk_max]
    remaining = context[first_chunk_max:]
    cont_chunks = [remaining[i:i + 255] for i in range(0, len(remaining), 255)]

    # All but the last chunk are non-blocking.
    _dch_exchange(client, P1_INITIAL, P2_SHOW, header + first_chunk)
    for chunk in cont_chunks[:-1]:
        _dch_exchange(client, P1_CONTINUE, P2_SHOW, chunk)

    # Last chunk triggers Screen 1.
    nav_instr, confirm_instrs, search_text = derive_context_hash_nav(device)
    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_DERIVE_CONTEXT_HASH,
        p1=P1_CONTINUE,
        p2=P2_SHOW,
        data=cont_chunks[-1],
    ):
        navigator.navigate_until_text_and_compare(
            navigate_instruction=nav_instr,
            validation_instructions=confirm_instrs,
            text=search_text,
            path=ROOT_SCREENSHOT_PATH,
            test_case_name="derive_context_hash/approve_" + bitcoin_network,
            screen_change_before_first_instruction=False,
        )

    root = bytes(client.last_async_response()[1])
    assert len(root) == 32
    assert root == _expected_root(APP_NAME, path, context, bitcoin_network)


def test_user_rejects_screen(client: "RaggerClient", navigator: Navigator,
                              device: Device, bitcoin_network: str):
    """User rejects Screen 1 → SW_DENY (0x6985)."""
    from .instructions import derive_context_hash_reject_nav

    ct = 0 if bitcoin_network == "main" else 1
    path = depositor_path(ct)
    ctx = b"\xde\xad\xbe\xef"

    path_bytes = bytes([len(path)]) + b"".join(p.to_bytes(4, "big") for p in path)
    payload = (bytes([len(APP_NAME)]) + APP_NAME
               + path_bytes
               + len(ctx).to_bytes(2, "big")
               + ctx)

    nav_instr, confirm_instrs, search_text = derive_context_hash_reject_nav(device)

    with pytest.raises(ExceptionRAPDU) as exc:
        with client.transport_client.exchange_async(
            cla=CLA_VAULT,
            ins=INS_DERIVE_CONTEXT_HASH,
            p1=P1_INITIAL,
            p2=P2_SHOW,
            data=payload,
        ):
            navigator.navigate_until_text(
                navigate_instruction=nav_instr,
                validation_instructions=confirm_instrs,
                text=search_text,
                screen_change_before_first_instruction=False,
            )
    assert exc.value.status == SW_DENY
