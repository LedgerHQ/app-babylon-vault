"""
Snapshot tests for the APPROVE_VAULT_INTENT display screen.

These tests capture every page of the vault intent review flow as golden images.
On first run use --golden_run to generate the reference snapshots:

    pytest tests/test_screen2_vault_intent.py --golden_run -k flex

Subsequent runs compare against those goldens automatically.

Flows covered:
  - Approval  (all content pages → confirm)
  - Rejection (first content page → reject)
  - Skip      (params in full, then Skip from phase 2 → approval)
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID, Navigator

from .vault_client import (
    CLA_VAULT,
    INS_APPROVE_VAULT_INTENT,
    P1_SCALARS,
    P1_GROUP,
    P1_KEY_BATCH,
    P2_UNUSED,
    SW_DENY,
    TAG_KEEPER_PK,
    TAG_CHALLENGER_PK,
    TEST_VP_KEY,
    TEST_VALID_KEYS,
    build_intent_tlv,
    build_group_tlv,
    approve_vault_intent_with_nav,
    capture_status_screen,
    depositor_path,
    derive_for_intent,
    _ktlv,
)
from .instructions import (
    vault_intent_approve_instructions,
    vault_intent_params_pages,
    vault_intent_reject_instructions,
    vault_intent_skip_instructions,
    vault_intent_steps,
    vault_intent_steps_for_keys,
)

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()

# Minimal 1-keeper + 1-challenger intent — enough to exercise all display fields.
_KEY_A = TEST_VALID_KEYS[0]
_KEY_B = TEST_VALID_KEYS[1]


def _scalars(bitcoin_network: str) -> bytes:
    ct = 0 if bitcoin_network == "main" else 1
    return build_intent_tlv(
        coin_type=ct,
        base_fee_rate=7,
        pegin_csv_timelock=144,
        payout_timelock=200,
        htlc_refund_timelock=144,
        prepegin_txid=bytes(range(32)),
        depositor_path=depositor_path(ct),
        keeper_count=1,
        challenger_count=1,
        prepegin_max_fee=500_000,
        vault_count=1,
    )


def _group() -> bytes:
    return build_group_tlv(
        htlc_vout=0,
        vault_provider_pk=TEST_VP_KEY,
        vault_amount=8_765_432,       # 0.08765432 BTC — all 8 decimal places
        commission_fee=43_219,        # 0.00043219 BTC
        depositor_claim_value=21_987, # 0.00021987 BTC
        pegin_max_fee=456_789,        # 0.00456789 BTC
    )


def _send_scalars_and_group(client: "RaggerClient", bitcoin_network: str) -> None:
    client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_SCALARS,
        p2=P2_UNUSED,
        data=_scalars(bitcoin_network),
    )
    client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_GROUP,
        p2=P2_UNUSED,
        data=_group(),
    )


# ---------------------------------------------------------------------------
# Approval flow
# ---------------------------------------------------------------------------

def test_approve_intent_screen(client: "RaggerClient", navigator: Navigator,
                                device: Device, bitcoin_network: str):
    """Navigate all vault intent review pages and approve.

    Captures every page as a snapshot — run with --golden_run to create goldens.
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    approve_vault_intent_with_nav(
        client, navigator, device,
        scalars_tlv=_scalars(bitcoin_network),
        keeper_pks=[_KEY_A],
        challenger_pks=[_KEY_B],
        groups=[_group()],
        path=ROOT_SCREENSHOT_PATH,
        test_case_name="screen2_vault_intent/approve_" + bitcoin_network,
        n_swipes=vault_intent_steps(device, 1, 1),
    )


# ---------------------------------------------------------------------------
# Rejection flow
# ---------------------------------------------------------------------------

def test_reject_intent_screen(client: "RaggerClient", navigator: Navigator,
                               device: Device, bitcoin_network: str):
    """Navigate to the reject button and reject the vault intent → SW_DENY.

    Captures every page up to and including the rejection status screen.
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    _send_scalars_and_group(client, bitcoin_network)

    with pytest.raises(ExceptionRAPDU) as exc:
        with client.transport_client.exchange_async(
            cla=CLA_VAULT,
            ins=INS_APPROVE_VAULT_INTENT,
            p1=P1_KEY_BATCH,
            p2=P2_UNUSED,
            data=_ktlv(TAG_KEEPER_PK, _KEY_A) + _ktlv(TAG_CHALLENGER_PK, _KEY_B),
        ):
            with capture_status_screen(navigator):
                navigator.navigate_and_compare(
                    path=ROOT_SCREENSHOT_PATH,
                    test_case_name="screen2_vault_intent/reject_" + bitcoin_network,
                    instructions=vault_intent_reject_instructions(device, vault_intent_steps(device, 1, 1)),
                    screen_change_before_first_instruction=True,
                )
    assert exc.value.status == SW_DENY


# ---------------------------------------------------------------------------
# Asymmetric keeper/challenger counts (full review — nothing is skippable)
# ---------------------------------------------------------------------------

# 4 keepers + 3 challengers = 7 keys (245 B) — fits a single P1=0x02 key batch and gives
# a multi-page keys segment.  The odd total is deliberate: it is the only case that
# exercises the round-up when keys are packed 2 per page on touch.  TEST_VALID_KEYS is
# sorted ascending, so each slice is in the strict per-group ascending order the
# firmware requires.
_ASYM_KEEPERS = TEST_VALID_KEYS[0:4]
_ASYM_CHALLENGERS = TEST_VALID_KEYS[4:7]


def _scalars_4k3c(bitcoin_network: str) -> bytes:
    ct = 0 if bitcoin_network == "main" else 1
    return build_intent_tlv(
        coin_type=ct,
        base_fee_rate=7,
        pegin_csv_timelock=144,
        payout_timelock=200,
        htlc_refund_timelock=144,
        prepegin_txid=bytes(range(32)),
        depositor_path=depositor_path(ct),
        keeper_count=len(_ASYM_KEEPERS),
        challenger_count=len(_ASYM_CHALLENGERS),
        prepegin_max_fee=500_000,
        vault_count=1,
    )


def test_intent_screen_asymmetric_keys_full_review(client: "RaggerClient", navigator: Navigator,
                                                   device: Device, bitcoin_network: str):
    """Paging phase 2 through in full still shows every field, Skip notwithstanding.

    Phase 2 is skippable, but nothing forces the user to skip it: this walks every page
    of both phases and approves, which is the counterpart to test_skip_intent_screen's
    short path.  It also pins the page packing that SKIPPABLE_OPERATION's header changes
    — see _vault_intent_key_pages.

    The asymmetric 4-keeper / 3-challenger fixture is the only intent test with unequal
    counts, so it is the only one that must call vault_intent_steps_for_keys directly.
    vault_intent_steps is a thin wrapper over that same function for the symmetric case,
    so both share one calibrated step count — an odd key total also makes this the only
    test that exercises the round-up in the keys-per-page division.  Approval returns
    SW_OK, so no exception is expected.
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_SCALARS,
        p2=P2_UNUSED,
        data=_scalars_4k3c(bitcoin_network),
    )
    client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_GROUP,
        p2=P2_UNUSED,
        data=_group(),
    )

    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_KEY_BATCH,
        p2=P2_UNUSED,
        data=(b"".join(_ktlv(TAG_KEEPER_PK, k) for k in _ASYM_KEEPERS) +
              b"".join(_ktlv(TAG_CHALLENGER_PK, k) for k in _ASYM_CHALLENGERS)),
    ):
        navigator.navigate_and_compare(
            path=ROOT_SCREENSHOT_PATH,
            test_case_name="screen2_vault_intent/asymmetric_keys_" + bitcoin_network,
            instructions=vault_intent_approve_instructions(
                device,
                vault_intent_steps_for_keys(
                    device, len(_ASYM_KEEPERS) + len(_ASYM_CHALLENGERS)
                ),
            ),
            screen_change_before_first_instruction=True,
        )


# ---------------------------------------------------------------------------
# Skip affordance (phase 2 skippable, phase 1 mandatory)
# ---------------------------------------------------------------------------

def _skip_offered(client: "RaggerClient") -> bool:
    """True when the current screen shows the NBGL "Skip" header button."""
    content = client.transport_client.get_current_screen_content()
    return any(event.get("text") == "Skip" for event in content.get("events", []))


def test_skip_intent_screen(client: "RaggerClient", navigator: Navigator,
                            device: Device, bitcoin_network: str):
    """Skip from the first vault group jumps to approval, bypassing groups and keys.

    Phase 2 carries SKIPPABLE_OPERATION, so the per-vault groups and the whole
    keeper/challenger key list can be bypassed.  The 4-keeper / 3-challenger fixture
    makes that visible: the skipped path is a handful of pages where the full review is
    more than twice as long.

    Skip lands on the approve/reject page, not on a signature — the captured goldens end
    with an explicit approval, which is the property that keeps "did not read the
    details" distinct from "did not approve".  Approval returns SW_OK, so no exception
    is expected.

    Skip is touch-only: on nano the review is a single mandatory streaming review.
    """
    if device.is_nano:
        pytest.skip("skip affordance is touch-only; nano uses the full review")

    derive_for_intent(client, navigator, device, bitcoin_network)
    client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_SCALARS,
        p2=P2_UNUSED,
        data=_scalars_4k3c(bitcoin_network),
    )
    client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_GROUP,
        p2=P2_UNUSED,
        data=_group(),
    )

    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_KEY_BATCH,
        p2=P2_UNUSED,
        data=(b"".join(_ktlv(TAG_KEEPER_PK, k) for k in _ASYM_KEEPERS) +
              b"".join(_ktlv(TAG_CHALLENGER_PK, k) for k in _ASYM_CHALLENGERS)),
    ):
        navigator.navigate_and_compare(
            path=ROOT_SCREENSHOT_PATH,
            test_case_name="screen2_vault_intent/skip_" + bitcoin_network,
            instructions=vault_intent_skip_instructions(device),
            screen_change_before_first_instruction=True,
        )


def test_phase1_params_not_skippable(client: "RaggerClient", navigator: Navigator,
                                     device: Device, bitcoin_network: str):
    """The scalar params segment offers no Skip; the vault groups that follow do.

    Phase 1 and phase 2 are separate streaming reviews precisely so SKIPPABLE_OPERATION
    can arm one without the other.  This reads the header off the live screens rather
    than inferring the boundary from a page count, so it fails if the flag ever widens
    to cover the params segment.
    """
    if device.is_nano:
        pytest.skip("skip affordance is touch-only; nano runs one mandatory review")

    derive_for_intent(client, navigator, device, bitcoin_network)
    _send_scalars_and_group(client, bitcoin_network)

    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_KEY_BATCH,
        p2=P2_UNUSED,
        data=_ktlv(TAG_KEEPER_PK, _KEY_A) + _ktlv(TAG_CHALLENGER_PK, _KEY_B),
    ):
        # Only the first navigate() waits for the review to appear; afterwards the screen
        # is already settled, so waiting again before swiping would time out.
        def swipe(first: bool = False) -> None:
            navigator.navigate([NavInsID.SWIPE_CENTER_TO_LEFT],
                               screen_change_before_first_instruction=first)

        # Phase 1 intro → first params page.
        swipe(first=True)

        # Every params page must be free of the Skip header.  Swiping past the last one
        # confirms phase 1 and starts phase 2, landing on its intro.
        for page in range(vault_intent_params_pages(device)):
            assert not _skip_offered(client), \
                f"phase 1 params page {page} must not offer Skip"
            swipe()

        # Phase 2 intro → first vault group, where Skip is armed.
        swipe()
        assert _skip_offered(client), "phase 2 vault groups must offer Skip"

        # Complete the flow so the pending APDU gets its response.
        navigator.navigate(
            [
                NavInsID.RIGHT_HEADER_TAP,
                NavInsID.USE_CASE_CHOICE_CONFIRM,
                NavInsID.USE_CASE_REVIEW_CONFIRM,
                NavInsID.USE_CASE_STATUS_DISMISS,
            ],
            screen_change_before_first_instruction=False,
        )
