"""
Ragger integration tests for RELEASE_CONTEXT_SECRET (INS 0x82).

Device: Speculos emulator seeded with the default test mnemonic (see conftest.py).

Tests that require Session 2 to be fully complete (happy path, double-call) are
deferred to NAPPS-1378 — they depend on SIGN_PSBT flows that are not yet implemented.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest
from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from .vault_client import (
    CLA_VAULT,
    INS_RELEASE_CONTEXT_SECRET,
    SW_WRONG_P1P2,
    SW_WRONG_DATA_LENGTH,
    SW_BAD_STATE,
    approve_vault_intent_with_nav,
    build_intent_tlv,
    TEST_VALID_KEYS,
)

HARDENED = 0x80000000

from .vault_client import TEST_VP_KEY

_KEY_A = TEST_VALID_KEYS[0]
_KEY_B = TEST_VALID_KEYS[1]


def _make_scalars(bitcoin_network: str) -> bytes:
    ct = 0 if bitcoin_network == "main" else 1
    return build_intent_tlv(
        coin_type=ct,
        vault_provider_pk=TEST_VP_KEY,
        vault_amount=100_000,
        commission_fee=1_000,
        depositor_claim_value=10_000,
        base_fee_rate=10,
        pegin_max_fee=50_000,
        pegin_csv_timelock=100,
        payout_timelock=200,
        prepegin_txid=bytes(range(32)),
        htlc_vout=0,
        htlc_refund_timelock=144,
        depositor_path=[HARDENED | 86, HARDENED | ct, HARDENED | 0, 0, 0],
        keeper_count=1,
        challenger_count=1,
    )


def _release_exchange(client: RaggerClient, p1: int = 0x00, p2: int = 0x00, data: bytes = b""):
    return client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_RELEASE_CONTEXT_SECRET,
        p1=p1,
        p2=p2,
        data=data,
    )


# ---------------------------------------------------------------------------
# APDU format guards (P1 / P2 / lc)
# ---------------------------------------------------------------------------

def test_wrong_p1_rejected(client: RaggerClient):
    """Non-zero P1 must return SW_WRONG_P1P2 (0x6A86) regardless of session state."""
    with pytest.raises(ExceptionRAPDU) as exc:
        _release_exchange(client, p1=0x01)
    assert exc.value.status == SW_WRONG_P1P2


def test_wrong_p2_rejected(client: RaggerClient):
    """Non-zero P2 must return SW_WRONG_P1P2 (0x6A86) regardless of session state."""
    with pytest.raises(ExceptionRAPDU) as exc:
        _release_exchange(client, p2=0x01)
    assert exc.value.status == SW_WRONG_P1P2


def test_payload_rejected(client: RaggerClient):
    """Non-empty data field must return SW_WRONG_DATA_LENGTH (0x6A87).

    RELEASE_CONTEXT_SECRET takes no payload; any lc > 0 is malformed.
    """
    with pytest.raises(ExceptionRAPDU) as exc:
        _release_exchange(client, data=b"\x00")
    assert exc.value.status == SW_WRONG_DATA_LENGTH


# ---------------------------------------------------------------------------
# State guard
# ---------------------------------------------------------------------------

def test_from_idle_rejected(client: RaggerClient):
    """Calling RELEASE_CONTEXT_SECRET with no session must return SW_BAD_STATE (0xB007).

    The device starts in VAULT_STATE_IDLE; the secret is only available after
    SESSION2_COMPLETE, which requires a full Session 2 signing sequence.
    """
    with pytest.raises(ExceptionRAPDU) as exc:
        _release_exchange(client)
    assert exc.value.status == SW_BAD_STATE


def test_from_intent_loaded_rejected(client: RaggerClient, navigator: Navigator,
                                     device: Device, bitcoin_network: str):
    """Calling RELEASE_CONTEXT_SECRET after APPROVE_VAULT_INTENT must return SW_BAD_STATE.

    State is INTENT_LOADED after a successful approval, not SESSION2_COMPLETE.
    The secret is only released at the end of a full Session 2 signing sequence.
    """
    scalars = _make_scalars(bitcoin_network)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[_KEY_A], challenger_pks=[_KEY_B])

    with pytest.raises(ExceptionRAPDU) as exc:
        _release_exchange(client)
    assert exc.value.status == SW_BAD_STATE
