from ragger.navigator import NavInsID
from ledgered.devices import Device
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

# Steps for 32-keeper + 32-challenger intent (64 keys total).
# These are used by test_max_32_keepers_32_challengers to switch from text-based
# navigation (navigate_until_text_and_compare) to deterministic navigate_and_compare.
# Text-based nav is racy on touch devices: the flex/stax swipe animation can fire
# one extra tick between wait_for_screen_change() and compare_screen_with_text(),
# causing the loop to break one swipe too early and skip the last content screenshot.
#
# Derived from the golden snapshot counts: n_swipes = snapshots - 3 (touch),
#                                          n_clicks = snapshots - 2 (nano).
# Update these constants and regenerate snapshots if the display layout changes.
VAULT_INTENT_4K4C_SWIPES_STAX = 7    # Stax:        10 snapshots
VAULT_INTENT_4K4C_SWIPES     = 8    # Flex, Apex:  11 snapshots
VAULT_INTENT_4K4C_CLICKS     = 27   # NanoSP/NanoX: 29 snapshots

VAULT_INTENT_32K32C_SWIPES_STAX = 35   # Stax:        38 snapshots
VAULT_INTENT_32K32C_SWIPES     = 36   # Flex, Apex:  39 snapshots
VAULT_INTENT_32K32C_CLICKS     = 139  # NanoSP/NanoX: 141 snapshots


def vault_intent_1k1c_steps(device: Device) -> int:
    """Return the step count for standard 1K+1C intent data on the given device."""
    if device.is_nano:
        return VAULT_INTENT_1K1C_CLICKS
    if device.name == "stax":
        return VAULT_INTENT_1K1C_SWIPES_STAX
    return VAULT_INTENT_1K1C_SWIPES


def vault_intent_4k4c_steps(device: Device) -> int:
    """Return the deterministic step count for 4K+4C intent data on the given device.

    Use instead of n_swipes=None to avoid the navigate_until_text_and_compare race
    that duplicates the first screenshot and skips the last content screenshot.
    """
    if device.is_nano:
        return VAULT_INTENT_4K4C_CLICKS
    if device.name == "stax":
        return VAULT_INTENT_4K4C_SWIPES_STAX
    return VAULT_INTENT_4K4C_SWIPES


def vault_intent_32k32c_steps(device: Device) -> int:
    """Return the deterministic step count for 32K+32C intent data on the given device.

    Use this instead of n_swipes=None (text-based navigation) to avoid the race
    in navigate_until_text_and_compare where an animation tick between
    wait_for_screen_change() and compare_screen_with_text() causes the last
    content screenshot to be skipped.
    """
    if device.is_nano:
        return VAULT_INTENT_32K32C_CLICKS
    if device.name == "stax":
        return VAULT_INTENT_32K32C_SWIPES_STAX
    return VAULT_INTENT_32K32C_SWIPES


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


def sign_psbt_refund_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 3 (Refund) — Nano devices only.

    Touch devices should use sign_psbt_refund_nav() with sign_psbt_with_nav_and_compare()
    instead, which stores all screenshots in a single folder as numbered PNGs.
    """
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_refund_nav(device: Device) -> List[NavInsID]:
    """Flat navigation for Screen 3 (Refund) on touch devices.

    Use with sign_psbt_with_nav_and_compare().  Stores all review pages as:
      00000.png — intro ("Review refund transaction")
      00001.png — content ("Reclaimed amount" + "Transaction fee" + "Reclaim address")
      00002.png — finish ("Sign refund transaction?")
      00003.png — reject confirmation dialog
      00004.png — rejection status
    """
    assert not device.is_nano, "Nano uses sign_psbt_refund_instructions, not flat nav"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,     # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,     # content → finish
        NavInsID.USE_CASE_REVIEW_REJECT,  # finish → reject dialog
        NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm rejection
    ]


def sign_psbt_prepegin_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 2 (Pre-PegIn) — Nano devices only.

    Touch devices should use sign_psbt_prepegin_nav() with sign_psbt_with_nav_and_compare().
    """
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_prepegin_nav(device: Device) -> List[NavInsID]:
    """Flat navigation for Screen 2 (Pre-PegIn) on touch devices.

    Use with sign_psbt_with_nav_and_compare().  Stores all review pages as:
      00000.png — intro ("Review Pre-PegIn transaction")
      00001.png — content ("Vault amount" + "Transaction fee" + "HTLC address")
      00002.png — finish ("Sign Pre-PegIn transaction?")
      00003.png — reject confirmation dialog
      00004.png — rejection status
    """
    assert not device.is_nano, "Nano uses sign_psbt_prepegin_instructions, not flat nav"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,     # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,     # content → finish
        NavInsID.USE_CASE_REVIEW_REJECT,  # finish → reject dialog
        NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm rejection
    ]
