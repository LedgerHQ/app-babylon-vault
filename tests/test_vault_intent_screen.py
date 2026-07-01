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

from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from .vault_client import (
    CLA_VAULT,
    INS_APPROVE_VAULT_INTENT,
    P1_SCALARS,
    P1_KEY_BATCH,
    P2_UNUSED,
    SW_DENY,
    TEST_VP_KEY,
    TEST_VALID_KEYS,
    build_intent_tlv,
    approve_vault_intent_with_nav,
)
from .instructions import (
    vault_intent_reject_instructions,
    vault_intent_skip_instructions,
    vault_intent_1k1c_steps,
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
        vault_amount=8_765_432,      # 0.08765432 BTC — all 8 decimal places
        commission_fee=43_219,       # 0.00043219 BTC
        depositor_claim_value=21_987, # 0.00021987 BTC
        base_fee_rate=7,
        pegin_max_fee=456_789,       # 0.00456789 BTC
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
                                device: Device, bitcoin_network: str):
    """Navigate all vault intent review pages and approve.

    Captures every page as a snapshot — run with --golden_run to create goldens.
    """
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv=_scalars(bitcoin_network),
        keeper_pks=[_KEY_A],
        challenger_pks=[_KEY_B],
        path=ROOT_SCREENSHOT_PATH,
        test_case_name="vault_intent/approve_" + bitcoin_network,
        n_swipes=vault_intent_1k1c_steps(device),
    )


# ---------------------------------------------------------------------------
# Rejection flow
# ---------------------------------------------------------------------------

def test_reject_intent_screen(client: "RaggerClient", navigator: Navigator,
                               device: Device, bitcoin_network: str):
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
                test_case_name="vault_intent/reject_" + bitcoin_network,
                instructions=vault_intent_reject_instructions(device, vault_intent_1k1c_steps(device)),
                screen_change_before_first_instruction=True,
            )
    assert exc.value.status == SW_DENY


# ---------------------------------------------------------------------------
# Skip flow (streaming review): keeper/challenger keys are skippable
# ---------------------------------------------------------------------------

# 4 keepers + 3 challengers = 7 keys (224 B) — fits a single P1=0x01 key batch and
# gives a multi-page keys segment to skip.  TEST_VALID_KEYS is sorted ascending, so
# each slice is in the strict per-group ascending order the firmware requires.
_SKIP_KEEPERS = TEST_VALID_KEYS[0:4]
_SKIP_CHALLENGERS = TEST_VALID_KEYS[4:7]


def _scalars_4k3c(bitcoin_network: str) -> bytes:
    ct = 0 if bitcoin_network == "main" else 1
    return build_intent_tlv(
        coin_type=ct,
        vault_provider_pk=TEST_VP_KEY,
        vault_amount=8_765_432,
        commission_fee=43_219,
        depositor_claim_value=21_987,
        base_fee_rate=7,
        pegin_max_fee=456_789,
        pegin_csv_timelock=144,
        payout_timelock=200,
        htlc_refund_timelock=144,
        prepegin_txid=bytes(range(32)),
        htlc_vout=0,
        depositor_path=[HARDENED | 86, HARDENED | ct, HARDENED | 0, 0, 0],
        keeper_count=len(_SKIP_KEEPERS),
        challenger_count=len(_SKIP_CHALLENGERS),
    )


def test_skip_intent_screen(client: "RaggerClient", navigator: Navigator,
                            device: Device, bitcoin_network: str):
    """Skip flow: view only the first screen of each segment, then skip to approval.

    The streaming review makes the keeper/challenger key list skippable.  This
    navigates intro → first params page → Skip (advances to keys) → Skip (jumps to
    approval) → approve, capturing the short skip path as goldens (far fewer screens
    than the full review).  Approval returns SW_OK, so no exception is expected.

    Skip is touch-only: on nano the SDK interleaves a skip page after every screen,
    so the firmware does not enable it there and this flow does not apply.
    """
    if device.is_nano:
        pytest.skip("skip affordance is touch-only; nano uses the full review")

    client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_SCALARS,
        p2=P2_UNUSED,
        data=_scalars_4k3c(bitcoin_network),
    )

    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_KEY_BATCH,
        p2=P2_UNUSED,
        data=b"".join(_SKIP_KEEPERS + _SKIP_CHALLENGERS),
    ):
        navigator.navigate_and_compare(
            path=ROOT_SCREENSHOT_PATH,
            test_case_name="vault_intent/skip_" + bitcoin_network,
            instructions=vault_intent_skip_instructions(device),
            screen_change_before_first_instruction=True,
        )
