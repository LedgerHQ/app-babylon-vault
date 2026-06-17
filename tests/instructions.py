from ragger.navigator import NavInsID
from ledgered.devices import Device
from ragger.firmware import Firmware
from ragger_bitcoin.ragger_instructions import Instructions
from typing import List, Tuple

# Steps to page through all content fields of a 1-keeper + 1-challenger intent
# before reaching the final confirm/reject trigger.
#
# Stax fits 2 keys on one page (wider display), so 1K+1C = 5 pages total.
# Flex and Apex fit only 1 key per page (less vertical space), so 1K+1C = 6 pages.
#
# Update these constants (and regenerate golden snapshots) if the display layout changes.
VAULT_INTENT_1K1C_SWIPES_STAX = 4   # Stax: 5 pages (intro + 3 content + hold-to-sign)
VAULT_INTENT_1K1C_SWIPES      = 5   # Flex, Apex: 6 pages (intro + 4 content + hold-to-sign)
VAULT_INTENT_1K1C_CLICKS      = 15  # Nano devices


def vault_intent_1k1c_steps(device: Device) -> int:
    """Return the step count for standard 1K+1C intent data on the given device."""
    if device.is_nano:
        return VAULT_INTENT_1K1C_CLICKS
    if device.name == "stax":
        return VAULT_INTENT_1K1C_SWIPES_STAX
    return VAULT_INTENT_1K1C_SWIPES


def vault_intent_approve_instructions(device: Device, n_steps: int) -> List[NavInsID]:
    """Return the complete navigation instruction list for approving a vault intent.

    n_steps: RIGHT_CLICKs (Nano) or SWIPEs (touch) to reach the confirm trigger.
    Pass vault_intent_1k1c_steps(device) for standard 1-keeper + 1-challenger data.
    """
    if device.is_nano:
        return [NavInsID.RIGHT_CLICK] * n_steps + [NavInsID.BOTH_CLICK]
    return (
        [NavInsID.SWIPE_CENTER_TO_LEFT] * n_steps
        + [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]
    )


def vault_intent_reject_instructions(device: Device, n_steps: int) -> List[NavInsID]:
    """Return the complete navigation instruction list for rejecting a vault intent.

    Nano: needs n_steps + 1 RIGHT_CLICKs — the extra click moves past "Approve intent?"
    to the "Reject operation" screen, then BOTH_CLICK confirms rejection.

    Touch: USE_CASE_REVIEW_REJECT taps the footer Reject button; USE_CASE_CHOICE_CONFIRM
    taps "Yes, reject" in the confirmation dialog. The rejection callback fires at
    CHOICE_CONFIRM, so no USE_CASE_STATUS_DISMISS is needed.
    """
    if device.is_nano:
        return [NavInsID.RIGHT_CLICK] * (n_steps + 1) + [NavInsID.BOTH_CLICK]
    return (
        [NavInsID.SWIPE_CENTER_TO_LEFT] * n_steps
        + [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM]
    )


def vault_intent_approve_nav(device: Device) -> Tuple[NavInsID, List[NavInsID], str]:
    """Return (navigate_instruction, validation_instructions, search_text) to approve.

    Touch: SWIPE_CENTER_TO_LEFT until "Hold to sign", USE_CASE_REVIEW_CONFIRM (3 s hold),
           then USE_CASE_STATUS_DISMISS for the "Operation signed" status screen.
    Nano:  RIGHT_CLICK until our custom finishTitle "Approve intent?" appears, BOTH_CLICK.
           No status dismiss needed — Nano NBGL auto-dismisses the status.
    """
    if device.is_nano:
        # Nano NBGL shows our custom finishTitle on the confirmation screen.
        # VAULT_INTENT_FINISH_TITLE (no SCREEN_SIZE_WALLET) = "Approve intent?"
        return (NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                r"^Approve intent\?$")
    return (NavInsID.SWIPE_CENTER_TO_LEFT,
            [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS],
            "^Hold to sign$")


def vault_intent_reject_nav(device: Device) -> Tuple[NavInsID, List[NavInsID], str]:
    """Return (navigate_instruction, validation_instructions, search_text) to reject.

    On touch: navigate to "Hold to sign", tap Reject, confirm, dismiss rejection status.
    On Nano:  navigate until "Reject operation", both-click to confirm.
    """
    if device.is_nano:
        return (NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                r"^Reject operation$")
    return (NavInsID.SWIPE_CENTER_TO_LEFT,
            [NavInsID.USE_CASE_REVIEW_REJECT,
             NavInsID.USE_CASE_CHOICE_CONFIRM,
             NavInsID.USE_CASE_STATUS_DISMISS],
            "^Hold to sign$")


def sign_psbt_refund_instructions(firmware: Firmware) -> Instructions:
    """Reject-path Instructions for Screen 3 (Refund transaction review).

    The Flex NBGL layout has 3 pages: intro ("Review refund transaction"),
    a single content page showing both "Reclaimed amount" and "Transaction fee",
    and the finish page ("Sign refund transaction?").  Navigates through each
    and rejects to capture all golden snapshots.  Expects SW_DENY on return.
    """
    instructions = Instructions(firmware)
    if firmware.name.startswith("nano"):
        instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    else:
        instructions.new_request(
            "Review refund",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_TAP,
        )
        # Both "Reclaimed amount" and "Transaction fee" appear on the same content page.
        instructions.same_request(
            "Reclaimed amount",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_TAP,
        )
        instructions.same_request(
            "Sign refund",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_REJECT,
        )
        instructions.same_request(
            "Reject",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_CHOICE_CONFIRM,
        )
    return instructions


def sign_psbt_prepegin_instructions(firmware: Firmware) -> Instructions:
    """Reject-path Instructions for Screen 2 (Pre-PegIn transaction review).

    Navigates through all review pages ("Review Pre-PegIn", "Vault amount",
    "Transaction fee", "HTLC address", "Sign Pre-PegIn") and rejects at the
    sign page. Expects SW_DENY on return.
    """
    instructions = Instructions(firmware)
    if firmware.name.startswith("nano"):
        instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    else:
        instructions.new_request(
            "Review Pre-PegIn",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_TAP,
        )
        instructions.same_request(
            "Vault amount",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_TAP,
        )
        instructions.same_request(
            "Transaction fee",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_TAP,
        )
        instructions.same_request(
            "HTLC address",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_TAP,
        )
        instructions.same_request(
            "Sign Pre-PegIn",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_REVIEW_REJECT,
        )
        instructions.same_request(
            "Reject",
            NavInsID.USE_CASE_REVIEW_TAP,
            NavInsID.USE_CASE_CHOICE_CONFIRM,
        )
    return instructions
