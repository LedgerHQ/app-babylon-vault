"""
Snapshot tests for the APPROVE_VAULT_INTENT display screen.

These tests capture every page of the vault intent review flow as golden images.
On first run use --golden_run to generate the reference snapshots:

    pytest tests/test_vault_intent_screen.py --golden_run -k flex

Subsequent runs compare against those goldens automatically.

Two flows are covered:
  - Approval  (all content pages → confirm)
  - Rejection (first content page → reject)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ledgered.devices import DeviceType
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from .vault_client import (
    CLA_VAULT,
    INS_APPROVE_VAULT_INTENT,
    P1_SCALARS,
    P1_KEY_BATCH,
    P2_UNUSED,
    TEST_VP_KEY,
    TEST_VALID_KEYS,
    build_intent_tlv,
)
from .instructions import (
    vault_intent_approve_instructions,
    vault_intent_reject_instructions,
    VAULT_INTENT_1K1C_SWIPES,
)

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

HARDENED = 0x80000000

# Minimal 1-keeper + 1-challenger intent — enough to exercise all display fields.
_KEY_A = TEST_VALID_KEYS[0]
_KEY_B = TEST_VALID_KEYS[1]


def _scalars(bitcoin_network: str) -> bytes:
    ct = 0 if bitcoin_network == "main" else 1
    return build_intent_tlv(
        coin_type=ct,
        vault_provider_pk=TEST_VP_KEY,
        vault_amount=100_000,
        commission_fee=1_000,
        depositor_claim_value=10_000,
        base_fee_rate=10,
        pegin_max_fee=50_000,
        pegin_csv_timelock=144,
        payout_timelock=200,
        htlc_refund_timelock=144,
        prepegin_txid=bytes(range(32)),
        htlc_vout=0,
        depositor_path=[HARDENED | 86, HARDENED | ct, HARDENED | 0, 0, 0],
        keeper_count=1,
        challenger_count=1,
    )


def _send_scalars(client: "RaggerClient", bitcoin_network: str) -> None:
    client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_SCALARS,
        p2=P2_UNUSED,
        data=_scalars(bitcoin_network),
    )


# ---------------------------------------------------------------------------
# Approval flow
# ---------------------------------------------------------------------------

def test_approve_intent_screen(client: "RaggerClient", navigator: Navigator,
                                firmware: DeviceType, bitcoin_network: str,
                                test_name: str):
    """Navigate all vault intent review pages and approve.

    Captures every page as a snapshot — run with --golden_run to create goldens.
    """
    _send_scalars(client, bitcoin_network)

    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_KEY_BATCH,
        p2=P2_UNUSED,
        data=_KEY_A + _KEY_B,
    ):
        navigator.navigate_and_compare(
            path=ROOT_SCREENSHOT_PATH,
            test_case_name=test_name + "_" + bitcoin_network,
            instructions=vault_intent_approve_instructions(firmware, VAULT_INTENT_1K1C_SWIPES),
            screen_change_before_first_instruction=False,
        )


# ---------------------------------------------------------------------------
# Rejection flow
# ---------------------------------------------------------------------------

def test_reject_intent_screen(client: "RaggerClient", navigator: Navigator,
                               firmware: DeviceType, bitcoin_network: str,
                               test_name: str):
    """Navigate to the reject button and reject the vault intent → SW_DENY.

    Captures every page up to and including the rejection status screen.
    """
    _send_scalars(client, bitcoin_network)

    with pytest.raises(ExceptionRAPDU) as exc:
        with client.transport_client.exchange_async(
            cla=CLA_VAULT,
            ins=INS_APPROVE_VAULT_INTENT,
            p1=P1_KEY_BATCH,
            p2=P2_UNUSED,
            data=_KEY_A + _KEY_B,
        ):
            navigator.navigate_and_compare(
                path=ROOT_SCREENSHOT_PATH,
                test_case_name=test_name + "_" + bitcoin_network,
                instructions=vault_intent_reject_instructions(firmware, VAULT_INTENT_1K1C_SWIPES),
                screen_change_before_first_instruction=False,
            )
    assert exc.value.status == 0x6985  # SW_DENY
