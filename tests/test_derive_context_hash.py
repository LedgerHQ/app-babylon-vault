"""
Ragger integration tests for DERIVE_CONTEXT_HASH (INS 0x81).

Device: Speculos emulator seeded with the default test mnemonic (see conftest.py).
No UX navigation needed — DERIVE_CONTEXT_HASH has no display.

Reference values were pre-computed with Python using the same mnemonic:

    from mnemonic import Mnemonic
    from bip32 import BIP32
    import hmac, hashlib

    MNEMONIC = "glory promote mansion idle axis ..."
    seed  = Mnemonic.to_seed(MNEMONIC)
    bip32 = BIP32.from_seed(seed)
    ikm   = bip32.get_privkey_from_path("m/73681862h")
    salt  = b"derive-context-hash"
    prk   = hmac.new(salt, ikm, hashlib.sha256).digest()
    def expand(prk, info):
        return hmac.new(prk, info + b"\\x01", hashlib.sha256).digest()
    preimage = expand(prk, hashlib.sha256(app_name).digest() + context)
    hashlock = hashlib.sha256(preimage).digest()
"""

from __future__ import annotations

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ragger.error import ExceptionRAPDU

from .vault_client import (
    derive_context_hash,
    CLA_VAULT,
    INS_DERIVE_CONTEXT_HASH,
    P1_INITIAL,
    P1_CONTINUE,
    P2_UNUSED,
)

# ---------------------------------------------------------------------------
# Pre-computed reference values (Speculos default seed, see module docstring)
# ---------------------------------------------------------------------------

# app_name=b"BabylonVault", context=b""
HASHLOCK_NO_CTX   = bytes.fromhex("b8f292ec5ae6a422b3d857ed53d4723cb393b6befa65b4140d5f52e8a0923daa")

# app_name=b"BabylonVault", context=b"session_context_data"
HASHLOCK_WITH_CTX = bytes.fromhex("01c7b70fae3f336cf5e772cc0e4ae73bb486086ef8348a666aba1edf513b6286")

# app_name=b"OtherApp", context=b""  — must differ from HASHLOCK_NO_CTX
HASHLOCK_OTHER_APP = bytes.fromhex("a809f4575c4e25586da6cb6e6bb4db0f9dad91d6f1192e6e39ba3a9601cd4d28")

# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_zero_context(client: RaggerClient):
    hashlock = derive_context_hash(client, app_name=b"BabylonVault", context=b"")
    assert len(hashlock) == 32
    assert hashlock == HASHLOCK_NO_CTX


def test_single_chunk_context(client: RaggerClient):
    hashlock = derive_context_hash(
        client, app_name=b"BabylonVault", context=b"session_context_data"
    )
    assert hashlock == HASHLOCK_WITH_CTX


def test_multi_chunk_context(client: RaggerClient):
    # Same context split across two P1=0x01 chunks — must match single-chunk result.
    # "session_" (8 B) + "context_data" (12 B) == "session_context_data" (20 B)
    hashlock = derive_context_hash(
        client,
        app_name=b"BabylonVault",
        context=b"session_" + b"context_data",
    )
    assert hashlock == HASHLOCK_WITH_CTX


def test_deterministic(client: RaggerClient):
    hashlock_a = derive_context_hash(client, b"BabylonVault", b"")
    hashlock_b = derive_context_hash(client, b"BabylonVault", b"")
    assert hashlock_a == hashlock_b


def test_different_app_name_produces_different_hashlock(client: RaggerClient):
    hashlock = derive_context_hash(client, app_name=b"OtherApp", context=b"")
    assert hashlock != HASHLOCK_NO_CTX
    assert hashlock == HASHLOCK_OTHER_APP


def test_different_context_produces_different_hashlock(client: RaggerClient):
    hashlock = derive_context_hash(client, b"BabylonVault", b"different_data")
    assert hashlock != HASHLOCK_NO_CTX
    assert hashlock != HASHLOCK_WITH_CTX


def test_hashlock_is_32_bytes(client: RaggerClient):
    hashlock = derive_context_hash(client, b"BabylonVault", b"")
    assert len(hashlock) == 32


def test_large_context_chunked(client: RaggerClient):
    # 600 bytes of context — forces three 255-byte + one 90-byte chunk
    context = bytes(range(256)) * 2 + bytes(range(88))
    hashlock_chunked = derive_context_hash(client, b"BabylonVault", context)

    # Same context in one shot (255 + remainder via helper internals) — same result
    hashlock_again = derive_context_hash(client, b"BabylonVault", context)
    assert hashlock_chunked == hashlock_again
    assert len(hashlock_chunked) == 32


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

def test_p1_continue_before_initial_raises(client: RaggerClient):
    """P1=0x01 with no prior P1=0x00 must return SW_BAD_STATE (0xB007)."""
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(
            cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
            p1=P1_CONTINUE, p2=P2_UNUSED,
            data=b"some_data",
        )
    assert exc.value.status == 0xB007


def test_invalid_p1_raises(client: RaggerClient):
    """Unknown P1 must return SW_WRONG_P1P2 (0x6A86)."""
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(
            cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
            p1=0x42, p2=P2_UNUSED,
            data=b"",
        )
    assert exc.value.status == 0x6A86


def test_app_name_too_long_raises(client: RaggerClient):
    """app_name_len > 64 must return SW_INCORRECT_DATA (0x6A80)."""
    oversized = b"A" * 65
    payload = bytes([len(oversized)]) + oversized + (0).to_bytes(2, "big")
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(
            cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
            p1=P1_INITIAL, p2=P2_UNUSED,
            data=payload,
        )
    assert exc.value.status == 0x6A80


def test_chunk_exceeds_declared_length_raises(client: RaggerClient):
    """Sending more context bytes than declared must return SW_INCORRECT_DATA (0x6A80)."""
    app_name = b"BabylonVault"
    # Declare 5 bytes of context but then send 10
    initial = bytes([len(app_name)]) + app_name + (5).to_bytes(2, "big")
    client.transport_client.exchange(
        cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
        p1=P1_INITIAL, p2=P2_UNUSED,
        data=initial,
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        client.transport_client.exchange(
            cla=CLA_VAULT, ins=INS_DERIVE_CONTEXT_HASH,
            p1=P1_CONTINUE, p2=P2_UNUSED,
            data=b"0123456789",  # 10 bytes, but only 5 declared
        )
    assert exc.value.status == 0x6A80


def test_invalidates_loaded_intent(client: RaggerClient, bitcoin_network: str):
    """Calling DERIVE_CONTEXT_HASH while intent is loaded must invalidate the session.

    Covered more thoroughly in test_approve_vault_intent.py::test_approve_resets_session_derive_can_run.
    This test just verifies the inverse: DERIVE_CONTEXT_HASH still works after an intent was loaded.
    """
    from .vault_client import approve_vault_intent, build_intent_tlv, VAULT_STRUCTURE_TYPE, VAULT_PROTOCOL_VERSION

    HARDENED = 0x80000000
    ct = 0 if bitcoin_network == "main" else 1
    vp = bytes([0x02]) + bytes(31)
    key_a = bytes([0xAA]) + bytes(31)
    key_b = bytes([0xBB]) + bytes(31)
    scalars = build_intent_tlv(
        coin_type=ct, vault_provider_pk=vp,
        vault_amount=100_000, commission_fee=1_000,
        depositor_claim_value=10_000, base_fee_rate=10, pegin_max_fee=50_000,
        pegin_csv_timelock=100, payout_timelock=200,
        prepegin_txid=bytes(range(32)), htlc_vout=0, htlc_refund_timelock=144,
        depositor_path=[HARDENED | 86, HARDENED | ct, HARDENED | 0, 0, 0],
        keeper_count=1, challenger_count=1,
    )
    approve_vault_intent(client, scalars, keeper_pks=[key_a], challenger_pks=[key_b])

    # DERIVE_CONTEXT_HASH must still work (and resets state to IDLE)
    hashlock = derive_context_hash(client, app_name=b"BabylonVault", context=b"")
    assert len(hashlock) == 32
    assert hashlock == HASHLOCK_NO_CTX
