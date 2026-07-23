from ragger.navigator import NavInsID
from ledgered.devices import Device
from ragger_bitcoin.ragger_instructions import Instructions
from typing import List, Tuple


def vault_intent_steps(device: Device, vault_count: int, challenger_count: int) -> int:
    """Compute navigation step count from the screen layout formulas.

    vault_count: total number of vaults (>= 1). The first vault is rendered inline
                 on the params screen; each additional vault adds dedicated screens.
    challenger_count: number of challenger/keeper pairs.

    Stax  (touch):  screens = 1+1 + 2*(vault_count-1) + challenger_count,   total + 2
    Flex/Apex (touch): screens = 1+1 + 2*(vault_count-1) + 2*challenger_count, total + 2
    Nano:           screens = 1+4 + 7*(vault_count-1) + 4*challenger_count,  total + 7

    n_swipes = total_screens (touch); n_clicks = total_screens (nano).
    Relationship to golden snapshot counts: n_swipes = snapshots - 3, n_clicks = snapshots - 2.
    """
    extra = vault_count - 1
    if device.is_nano:
        return 1 + 4 + 7 * extra + 4 * challenger_count + 7
    if device.name == "stax":
        return 1 + 1 + 2 * extra + challenger_count + 2
    return 1 + 1 + 2 * extra + 2 * challenger_count + 2


def vault_intent_approve_instructions(device: Device, n_steps: int) -> List[NavInsID]:
    """Return the complete navigation instruction list for approving a vault intent.

    n_steps: RIGHT_CLICKs (Nano) or SWIPEs (touch) to reach the confirm trigger.
    Pass vault_intent_steps(device, 1, 1) for standard 1-keeper + 1-challenger data.
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
    step formulas in vault_intent_steps above.
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
      00001.png — content ("Pre-PegIn txid" + "Reclaimed amount" + "Refund timelock"
                           + "Transaction fee" + "Reclaim address") — may span multiple pages
      ...    — finish ("Sign refund transaction?")
      ...    — reject confirmation dialog
      ...    — rejection status
    """
    assert not device.is_nano, "Nano uses sign_psbt_refund_instructions, not flat nav"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,     # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,     # content → finish
        NavInsID.USE_CASE_REVIEW_REJECT,  # finish → reject dialog
        NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm rejection
    ]


def sign_psbt_claim_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 4 (Claim) — Nano devices only.

    Touch devices should use sign_psbt_claim_nav() instead.
    """
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_claim_nav(device: Device) -> List[NavInsID]:
    """Flat reject-path navigation for Screen 4 (Claim) on touch devices.

    Fields: "Amount spent", "Connector amount", "Transaction fee", "PegIn txid" — 4 fields.
    Verify step count against first --golden_run if snapshots are wrong.
    """
    assert not device.is_nano, "Nano uses sign_psbt_claim_instructions, not flat nav"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,     # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,     # content → finish
        NavInsID.USE_CASE_REVIEW_REJECT,  # finish → reject dialog
        NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm rejection
    ]


def sign_psbt_claim_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 4 (Claim) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
        NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
        NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
    ]


def sign_psbt_assert_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 5 (Assert) — Nano devices only.

    Touch devices should use sign_psbt_assert_nav() instead.
    """
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_assert_nav(device: Device) -> List[NavInsID]:
    """Flat reject-path navigation for Screen 5 (Assert) on touch devices.

    Fields: "Claim txid" (32-byte hex), "Amount", "Output count", "Transaction fee" — 4 fields.
    The long txid field may span an extra page on some devices; verify with --golden_run.
    """
    assert not device.is_nano, "Nano uses sign_psbt_assert_instructions, not flat nav"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,     # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,     # content → finish
        NavInsID.USE_CASE_REVIEW_REJECT,  # finish → reject dialog
        NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm rejection
    ]


def sign_psbt_assert_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 5 (Assert) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
        NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
        NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
    ]


def sign_psbt_wc_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 6 (Wrongly Challenged) — Nano devices only.

    Touch devices should use sign_psbt_wc_nav() instead.
    """
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_wc_nav(device: Device) -> List[NavInsID]:
    """Flat reject-path navigation for Screen 6 (WC) on touch devices.

    Fields: "Reclaimed amount", ["Wallet inputs"], "Transaction fee", "Reclaim address" — 3–4 fields.
    Verify step count against first --golden_run if snapshots are wrong.
    """
    assert not device.is_nano, "Nano uses sign_psbt_wc_instructions, not flat nav"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,     # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,     # content → finish
        NavInsID.USE_CASE_REVIEW_REJECT,  # finish → reject dialog
        NavInsID.USE_CASE_CHOICE_CONFIRM, # confirm rejection
    ]


def sign_psbt_wc_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 6 (WC) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
        NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
        NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
    ]
