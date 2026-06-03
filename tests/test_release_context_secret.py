"""
Ragger integration tests for RELEASE_CONTEXT_SECRET (INS 0x82).

Device: Speculos emulator seeded with the default test mnemonic (see conftest.py).
No UX navigation needed for these tests — they all exercise guard conditions that
are checked before any state or crypto work.

Tests that require Session 2 to be fully complete (happy path, double-call) are
deferred to NAPPS-1378 — they depend on SIGN_PSBT flows that are not yet implemented.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest
from ragger.error import ExceptionRAPDU

from .vault_client import (
    CLA_VAULT,
    INS_RELEASE_CONTEXT_SECRET,
    SW_WRONG_P1P2,
    SW_WRONG_DATA_LENGTH,
    SW_BAD_STATE,
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
