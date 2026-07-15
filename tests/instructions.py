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
# +1 page on touch vs. the old single review: the streaming review splits params
# and keys into separate segments, forcing a page break so the first keeper starts
# on a fresh page.
VAULT_INTENT_1K1C_SWIPES_STAX = 5   # Stax: 6 pages (intro + params + keys + hold-to-sign)
VAULT_INTENT_1K1C_SWIPES      = 6   # Flex, Apex: 7 pages
VAULT_INTENT_1K1C_CLICKS      = 16  # Nano devices

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
# NOTE: unlike 1K1C, the params/keys segment break does NOT add a touch page here:
# with more keys the keeper list already started on a fresh page in the old layout,
# so these keep their pre-streaming swipe counts (bumping them over-swipes → timeout).
VAULT_INTENT_4K4C_SWIPES_STAX = 8    # Stax:        10 snapshots
VAULT_INTENT_4K4C_SWIPES     = 12    # Flex, Apex:  15 snapshots
VAULT_INTENT_4K4C_CLICKS     = 28   # NanoSP/NanoX: 29 snapshots

VAULT_INTENT_32K32C_SWIPES_STAX = 36   # Stax:        39 snapshots
VAULT_INTENT_32K32C_SWIPES     = 68   # Flex, Apex:  71 snapshots
VAULT_INTENT_32K32C_CLICKS     = 140  # NanoSP/NanoX: 142 snapshots

# Steps for 10-vault + 1-keeper + 1-challenger intent (1 group display × 10).
# Stax and Apex_p golden counts differ from Flex after the vault-group display rework.
# Flex and Apex_p also diverge from each other: Apex_p renders vault groups one page wider.
# Derived from golden snapshot counts: n_swipes = snapshots - 3 (touch),
#                                      n_clicks = snapshots - 2 (nano).
# Use these in test_10_vault_groups_accepted to avoid the navigate_until_text_and_compare
# race that duplicates a frame when the swipe animation fires between screen capture calls.
VAULT_INTENT_10V_1K1C_SWIPES_STAX = 19   # Stax:        22 snapshots
VAULT_INTENT_10V_1K1C_SWIPES_FLEX = 24   # Flex:        27 snapshots
VAULT_INTENT_10V_1K1C_SWIPES_APEX = 22   # Apex_p:      25 snapshots
VAULT_INTENT_10V_1K1C_CLICKS      = 79   # NanoSP/NanoX: 81 snapshots

# Steps for 10-vault + 32-keeper + 32-challenger intent (64 keys + 10 groups).
# Apex_p diverges from Flex by one page — vault groups render one screen wider there.
# Derived from golden snapshot counts: n_swipes = snapshots - 3 (touch),
#                                      n_clicks = snapshots - 2 (nano).
VAULT_INTENT_10V_32K32C_SWIPES_STAX = 54   # Stax:        57 snapshots
VAULT_INTENT_10V_32K32C_SWIPES_APEX = 86   # Apex_p:      90 snapshots
VAULT_INTENT_10V_32K32C_CLICKS      = 203  # NanoSP/NanoX: 205 snapshots


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


def vault_intent_10v_1k1c_steps(device: Device) -> int:
    """Return the deterministic step count for 10-vault + 1K + 1C intent data.

    Flex and Apex_p diverge by one page; use separate constants to avoid over-swiping
    (over-swipe → Speculos timeout) or under-swiping (misses the last content screen).
    """
    if device.is_nano:
        return VAULT_INTENT_10V_1K1C_CLICKS
    if device.name == "stax":
        return VAULT_INTENT_10V_1K1C_SWIPES_STAX
    if device.name == "apex_p":
        return VAULT_INTENT_10V_1K1C_SWIPES_APEX
    return VAULT_INTENT_10V_1K1C_SWIPES_FLEX


def vault_intent_10v_32k32c_steps(device: Device) -> int:
    """Return the deterministic step count for 10-vault + 32K + 32C intent data."""
    if device.is_nano:
        return VAULT_INTENT_10V_32K32C_CLICKS
    if device.name == "stax":
        return VAULT_INTENT_10V_32K32C_SWIPES_STAX
    return VAULT_INTENT_10V_32K32C_SWIPES_APEX


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


def vault_intent_skip_instructions(device: Device) -> List[NavInsID]:
    """Navigation that views only the first screen of each segment, then SKIPS.

    Exercises the skippable keeper/challenger flow added with the streaming review:
    skip on the params segment advances to the keys segment, and skip on the keys
    segment jumps straight to the approval page.  Because skip is taken from the
    first page of each segment, this sequence is independent of how many param/key
    pages the layout produces.

    Skip is a touch-only affordance: on nano the SDK interleaves a skip page after
    every screen, so the firmware does not enable SKIPPABLE_OPERATION there.

    Touch: RIGHT_HEADER_TAP taps the top-right "Skip" button; USE_CASE_CHOICE_CONFIRM
           taps "Yes, skip" in the confirmation modal.

    NOTE: skip is a UX affordance whose exact page sequence is layout-dependent.
    Verify/adjust this list against the first --golden_run, as with the
    VAULT_INTENT_* step constants above.
    """
    assert not device.is_nano, "skip is touch-only; nano has no skip affordance"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,         # intro → first params page
        NavInsID.RIGHT_HEADER_TAP,            # tap "Skip" on params
        NavInsID.USE_CASE_CHOICE_CONFIRM,     # "Yes, skip" → keys segment
        NavInsID.RIGHT_HEADER_TAP,            # tap "Skip" on keys
        NavInsID.USE_CASE_CHOICE_CONFIRM,     # "Yes, skip" → approval page
        NavInsID.USE_CASE_REVIEW_CONFIRM,     # hold to sign
        NavInsID.USE_CASE_STATUS_DISMISS,     # dismiss "Operation signed"
    ]


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


# Step counts for the DERIVE_CONTEXT_HASH approval screen.
# The review has 1 content page ("App name") — minimal navigation before the hold.
# Verify these against the first --golden_run if the counts produce wrong snapshots.
DCH_APPROVE_SWIPES_STAX = 2   # Stax: intro(1/3) → App name(2/3) → Allow derivation?(3/3)
DCH_APPROVE_SWIPES      = 2   # Flex, Apex: same 3-page layout
DCH_APPROVE_CLICKS      = 2   # NanoSP, NanoX: header → App name → Allow derivation?


def derive_context_hash_approve_steps(device: Device) -> int:
    """Return the step count for the DERIVE_CONTEXT_HASH approval screen."""
    if device.is_nano:
        return DCH_APPROVE_CLICKS
    if device.name == "stax":
        return DCH_APPROVE_SWIPES_STAX
    return DCH_APPROVE_SWIPES


def derive_context_hash_approve_instructions(device: Device, n_steps: int) -> List[NavInsID]:
    """Return the full navigation instruction list for approving DERIVE_CONTEXT_HASH.

    n_steps: RIGHT_CLICKs (Nano) or SWIPEs (touch) before the confirm trigger.
    Pass derive_context_hash_approve_steps(device) for the standard 1-field screen.
    """
    if device.is_nano:
        return [NavInsID.RIGHT_CLICK] * n_steps + [NavInsID.BOTH_CLICK]
    return (
        [NavInsID.SWIPE_CENTER_TO_LEFT] * n_steps
        + [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]
    )


def derive_context_hash_nav(device: Device) -> Tuple[NavInsID, List[NavInsID], str]:
    """Return (navigate_instruction, validation_instructions, search_text) to approve
    a DERIVE_CONTEXT_HASH request.

    Touch: SWIPE until "Allow derivation?", USE_CASE_REVIEW_CONFIRM (3 s hold),
           then USE_CASE_STATUS_DISMISS for the "Operation signed" status screen.
    Nano:  RIGHT_CLICK until "Allow derivation?", BOTH_CLICK to confirm.
    """
    if device.is_nano:
        return (NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                r"^Allow derivation\?$")
    return (NavInsID.SWIPE_CENTER_TO_LEFT,
            [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS],
            "^Allow derivation\\?$")


def derive_context_hash_reject_nav(device: Device) -> Tuple[NavInsID, List[NavInsID], str]:
    """Return (navigate_instruction, validation_instructions, search_text) to reject
    a DERIVE_CONTEXT_HASH request.

    Touch: SWIPE until "Allow derivation?", USE_CASE_REVIEW_REJECT, then
           USE_CASE_CHOICE_CONFIRM to confirm the rejection modal.
    Nano:  RIGHT_CLICK until "Reject operation?", BOTH_CLICK to confirm.
    """
    if device.is_nano:
        return (NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                r"^Reject operation$")
    return (NavInsID.SWIPE_CENTER_TO_LEFT,
            [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM],
            "^Allow derivation\\?$")


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
