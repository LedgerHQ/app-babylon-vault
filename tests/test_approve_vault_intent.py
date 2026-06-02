"""
Ragger integration tests for APPROVE_VAULT_INTENT (INS 0x80).

Device: Speculos emulator seeded with the default test mnemonic (see conftest.py).
No UX navigation needed — NAPPS-1373 adds the display screen; until then the
device auto-transitions to INTENT_LOADED on a valid two-phase exchange.

Test keys are synthetic 32-byte values chosen so they:
  - are lexicographically sorted within each group
  - are globally distinct
  - do not equal VP_KEY or the depositor x-only pubkey for the test seed
"""

from __future__ import annotations

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest
from ragger.error import ExceptionRAPDU

from .vault_client import (
    approve_vault_intent,
    build_intent_tlv,
    derive_context_hash,
    CLA_VAULT,
    INS_APPROVE_VAULT_INTENT,
    P1_SCALARS,
    P1_KEY_BATCH,
    P2_UNUSED,
    SW_INCORRECT_DATA,
    SW_WRONG_DATA_LENGTH,
    SW_WRONG_P1P2,
    SW_BAD_STATE,
    VAULT_STRUCTURE_TYPE,
    VAULT_PROTOCOL_VERSION,
    TAG_STRUCTURE_TYPE,
    TAG_COIN_TYPE,
    TAG_PEGIN_CSV_TIMELOCK,
    TAG_KEEPER_COUNT,
)

# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------

HARDENED = 0x80000000

# Vault provider key — 32 synthetic bytes, clearly not a real curve point
VP_KEY = bytes([0x02]) + bytes(31)

# Pre-PegIn txid placeholder
TXID = bytes(range(32))

# Synthetic x-only keys — sorted ascending, globally distinct, != VP_KEY
KEY_A = bytes([0xAA]) + bytes(31)
KEY_B = bytes([0xBB]) + bytes(31)
KEY_C = bytes([0xCC]) + bytes(31)
KEY_D = bytes([0xDD]) + bytes(31)


def _coin_type(network: str) -> int:
    return 0 if network == "main" else 1


def _depositor_path(coin_type: int) -> list:
    """BIP-86 path m/86'/coin_type'/0'/0/0."""
    return [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]


def _make_scalars(network: str, **overrides) -> bytes:
    """Build a valid TLV scalar payload, with optional field overrides."""
    ct = _coin_type(network)
    defaults = dict(
        coin_type=ct,
        vault_provider_pk=VP_KEY,
        vault_amount=100_000,
        commission_fee=1_000,
        depositor_claim_value=10_000,
        base_fee_rate=10,
        pegin_max_fee=50_000,
        pegin_csv_timelock=100,
        payout_timelock=200,
        prepegin_txid=TXID,
        htlc_vout=0,
        htlc_refund_timelock=144,
        depositor_path=_depositor_path(ct),
        keeper_count=1,
        challenger_count=1,
    )
    defaults.update(overrides)
    return build_intent_tlv(**defaults)


def _raw_exchange(client, p1: int, data: bytes):
    """Send one APPROVE_VAULT_INTENT APDU; returns response or raises ExceptionRAPDU."""
    return client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=p1,
        p2=P2_UNUSED,
        data=data,
    )


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_minimal_1_keeper_1_challenger(client: RaggerClient, bitcoin_network: str):
    """Load a minimal intent (1 keeper, 1 challenger) end-to-end → SW_OK."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    approve_vault_intent(client, scalars, keeper_pks=[KEY_A], challenger_pks=[KEY_B])


def test_keys_split_across_batches(client: RaggerClient, bitcoin_network: str):
    """8 keepers + 8 challengers forces three P1=0x01 batches (7+7+2 keys)."""
    keepers     = [bytes([0x10 + i]) + bytes(31) for i in range(8)]
    challengers = [bytes([0x20 + i]) + bytes(31) for i in range(8)]
    scalars = _make_scalars(bitcoin_network, keeper_count=8, challenger_count=8)
    approve_vault_intent(client, scalars, keeper_pks=keepers, challenger_pks=challengers)


def test_reload_intent_invalidates_previous(client: RaggerClient, bitcoin_network: str):
    """Loading a second intent while one is active must succeed (session reset)."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    # First load
    approve_vault_intent(client, scalars, keeper_pks=[KEY_A], challenger_pks=[KEY_B])
    # Second load — handler must invalidate the first session and accept this one
    approve_vault_intent(client, scalars, keeper_pks=[KEY_A], challenger_pks=[KEY_B])


def test_approve_resets_session_derive_can_run(client: RaggerClient, bitcoin_network: str):
    """After a successful approve, DERIVE_CONTEXT_HASH must reset state back to IDLE.

    Replaces the skipped test in test_derive_context_hash.py.
    """
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    approve_vault_intent(client, scalars, keeper_pks=[KEY_A], challenger_pks=[KEY_B])

    # DERIVE_CONTEXT_HASH invalidates any loaded intent per spec.
    hashlock = derive_context_hash(client, app_name=b"BabylonVault", context=b"")
    assert len(hashlock) == 32

    # State is now IDLE — P1=0x01 without prior P1=0x00 must fail.
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, KEY_A)
    assert exc.value.status == SW_BAD_STATE


# ---------------------------------------------------------------------------
# P1=0x00 scalar errors
# ---------------------------------------------------------------------------

def test_p1_key_batch_before_scalars(client: RaggerClient):
    """P1=0x01 with no prior P1=0x00 must return SW_BAD_STATE."""
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, KEY_A)
    assert exc.value.status == SW_BAD_STATE


def test_invalid_p1(client: RaggerClient):
    """Unknown P1 must return SW_WRONG_P1P2."""
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, 0x42, b"data")
    assert exc.value.status == SW_WRONG_P1P2


def test_wrong_structure_type(client: RaggerClient, bitcoin_network: str):
    """Wrong structure_type constant must return SW_INCORRECT_DATA."""
    ct = _coin_type(bitcoin_network)
    bad_tlv = build_intent_tlv(
        coin_type=ct,
        vault_provider_pk=VP_KEY,
        vault_amount=100_000, commission_fee=1_000,
        depositor_claim_value=10_000, base_fee_rate=10, pegin_max_fee=50_000,
        pegin_csv_timelock=100, payout_timelock=200,
        prepegin_txid=TXID, htlc_vout=0, htlc_refund_timelock=144,
        depositor_path=_depositor_path(ct),
        keeper_count=1, challenger_count=1,
    ).replace(
        bytes([TAG_STRUCTURE_TYPE, 1, VAULT_STRUCTURE_TYPE]),
        bytes([TAG_STRUCTURE_TYPE, 1, VAULT_STRUCTURE_TYPE + 1]),
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, bad_tlv)
    assert exc.value.status == SW_INCORRECT_DATA


def test_wrong_coin_type(client: RaggerClient, bitcoin_network: str):
    """coin_type field not matching the active network must return SW_INCORRECT_DATA."""
    wrong_ct = 99
    scalars = _make_scalars(
        bitcoin_network,
        coin_type=wrong_ct,
        depositor_path=_depositor_path(wrong_ct),
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pegin_csv_below_min(client: RaggerClient, bitcoin_network: str):
    """pegin_csv_timelock = 71 (below minimum 72) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, pegin_csv_timelock=71)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_keeper_count_zero(client: RaggerClient, bitcoin_network: str):
    """keeper_count = 0 must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=0)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_duplicate_tlv_tag(client: RaggerClient, bitcoin_network: str):
    """TLV payload with a duplicate tag must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network)
    # Append an extra TAG_VERSION
    bad_tlv = scalars + bytes([0x02, 1, VAULT_PROTOCOL_VERSION])
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, bad_tlv)
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# P1=0x01 key batch errors
# ---------------------------------------------------------------------------

def test_keys_out_of_order(client: RaggerClient, bitcoin_network: str):
    """Keepers sent in descending lex order must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=2, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    with pytest.raises(ExceptionRAPDU) as exc:
        # KEY_B > KEY_A — send in wrong order (B then A)
        _raw_exchange(client, P1_KEY_BATCH, KEY_B + KEY_A + KEY_C)
    assert exc.value.status == SW_INCORRECT_DATA


def test_extra_keys_beyond_count(client: RaggerClient, bitcoin_network: str):
    """Sending more keys than keeper_count + challenger_count must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    with pytest.raises(ExceptionRAPDU) as exc:
        # 3 keys declared total = 2, send 3
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + KEY_B + KEY_C)
    assert exc.value.status == SW_INCORRECT_DATA


def test_key_batch_not_multiple_of_32(client: RaggerClient, bitcoin_network: str):
    """P1=0x01 payload not a multiple of 32 bytes must return SW_WRONG_DATA_LENGTH."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, b"\xAA" * 31)   # 31 bytes — not multiple of 32
    assert exc.value.status == SW_WRONG_DATA_LENGTH


def test_key_equals_vault_provider_pk(client: RaggerClient, bitcoin_network: str):
    """A keeper key equal to vault_provider_pk must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, VP_KEY + KEY_B)
    assert exc.value.status == SW_INCORRECT_DATA


def test_duplicate_key_across_groups(client: RaggerClient, bitcoin_network: str):
    """A challenger key identical to a keeper key must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    with pytest.raises(ExceptionRAPDU) as exc:
        # Keeper = KEY_A, Challenger = KEY_A (duplicate)
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + KEY_A)
    assert exc.value.status == SW_INCORRECT_DATA
