from ragger.navigator import NavInsID
from ledgered.devices import Device
from ragger_bitcoin.ragger_instructions import Instructions
from typing import List, Tuple


def _vault_intent_key_pages(device: Device, total_keys: int) -> int:
    """Steps the keeper + challenger list contributes to the intent review.

    Derived from the calibrated counts in vault_intent_steps_for_keys, not predicted:
    `challenger_count` pairs there means 2*challenger_count keys and contributes
    `challenger_count` steps on touch, i.e. **2 keys per page**.  (Flex fit only 1 key
    per page while the review carried SKIPPABLE_OPERATION; removing the Skip affordance
    freed the header space for a second.)  Nano shows one key per screen, 2 clicks each.
    """
    if device.is_nano:
        return 2 * total_keys
    return (total_keys + 1) // 2


def vault_intent_steps_for_keys(device: Device, total_keys: int, vault_count: int = 1) -> int:
    """Navigation steps to reach the intent-approval trigger.

    total_keys: keepers + challengers combined; handles asymmetric counts, unlike passing
                a single "pairs" figure.
    vault_count: number of vault groups (>= 1).

    On touch the review runs in two phases, neither skippable:
      Phase 1: intro + params pages + confirm
      Phase 2: intro + vault-group pages + key pages

    Per-device fixed part (everything except the key pages), for vault_count == 1:
      Stax:       5     Flex/Apex:  6     Nano:  14
    Each extra vault group adds 2 steps on touch and 7 on nano.

    n_swipes = total_screens (touch); n_clicks = total_screens (nano).
    Relationship to golden snapshot counts: n_swipes = snapshots - 3, n_clicks = snapshots - 2 —
    so after a --golden_run the observed counts confirm (or correct) these figures.
    """
    extra = vault_count - 1
    key_pages = _vault_intent_key_pages(device, total_keys)
    if device.is_nano:
        return 14 + 7 * extra + key_pages
    if device.name == "stax":
        return 5 + 2 * extra + key_pages
    return 6 + 2 * extra + key_pages


def vault_intent_steps(device: Device, vault_count: int, challenger_count: int) -> int:
    """Navigation steps for an intent with `challenger_count` keeper/challenger *pairs*.

    Convenience wrapper over vault_intent_steps_for_keys for the common symmetric case
    (equal keeper and challenger counts); prefer the latter directly when they differ.
    Exactly equivalent to the previous hand-expanded formulas:
      Stax  5 + 2*(vault_count-1) + challenger_count
      Flex  6 + 2*(vault_count-1) + challenger_count
      Nano 14 + 7*(vault_count-1) + 4*challenger_count
    """
    return vault_intent_steps_for_keys(device, 2 * challenger_count, vault_count)


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


# There is deliberately no skip-navigation helper: the intent review carries no
# SKIPPABLE_OPERATION in either phase, so no Skip button exists to tap.  Every field in
# this review is a displayed-and-approved field in the HLD's intent TLV table, and the
# approval is the only anchor for the silent signing that follows it, so none of it may
# be bypassed.  A previous `vault_intent_skip_instructions` drove that affordance; if
# Skip is ever reintroduced for a subset of segments, add it back alongside a test that
# pins which fields remain mandatory.


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


def vault_intent_reject_nav(device: Device) -> Tuple[NavInsID, List[NavInsID], str]:
    """Return (navigate_instruction, validation_instructions, search_text) to reject
    a vault intent, without pinning a page count.

    The count-based vault_intent_reject_instructions has to be recalibrated whenever NBGL
    repacks pairs per page; this walks to the final page by text instead.

    Touch: SWIPE until "Hold to sign", USE_CASE_REVIEW_REJECT, then USE_CASE_CHOICE_CONFIRM.
    Nano:  RIGHT_CLICK until "Reject operation", BOTH_CLICK to confirm.
    """
    if device.is_nano:
        return (NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                r"^Reject operation$")
    return (NavInsID.SWIPE_CENTER_TO_LEFT,
            [NavInsID.USE_CASE_REVIEW_REJECT, NavInsID.USE_CASE_CHOICE_CONFIRM],
            "^Hold to sign$")


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


def sign_psbt_refund_approve_instructions(device: Device) -> Instructions:
    """Approve-path Instructions for Screen 3 (Refund) — Nano devices only.

    Touch devices should use sign_psbt_refund_approve_nav() instead.
    """
    instructions = Instructions(device)
    instructions.new_request("Sign", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_refund_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 3 (Refund) on touch devices."""
    assert not device.is_nano, "Nano uses sign_psbt_refund_approve_instructions, not flat nav"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
        NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
        NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
        NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
    ]


def sign_psbt_claim_approve_instructions(device: Device) -> Instructions:
    """Approve-path Instructions for Screen 4 (Claim) — Nano devices only.

    Touch devices should use sign_psbt_claim_approve_nav() instead.
    """
    instructions = Instructions(device)
    instructions.new_request("Sign", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_claim_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 4 (Claim) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    if device.name == "stax":
        return [
            NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
            NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
            NavInsID.USE_CASE_REVIEW_TAP,      # content → finish

            NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
            NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
        ]
    else:
        return [
            NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
            NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
            NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
            NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
            NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
        ]


def sign_psbt_assert_approve_instructions(device: Device) -> Instructions:
    """Approve-path Instructions for Screen 5 (Assert) — Nano devices only.

    Touch devices should use sign_psbt_assert_approve_nav() instead.
    """
    instructions = Instructions(device)
    instructions.new_request("Sign", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_assert_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 5 (Assert) on touch devices.

    Screen 5 shows three pairs (claim txid, amount carried, fee) on a single content page
    on every touch device, so the page sequence is intro → content → hold-to-sign: two
    taps, then the hold.  Flex/Apex previously carried a third tap, left over from before
    the W7 fix removed the "Output count" field and with it one content page; the extra
    tap had nothing to advance to and timed out waiting for a screen change.
    """
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,      # content → hold to sign
        NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
        NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
    ]


def sign_psbt_wc_approve_instructions(device: Device) -> Instructions:
    """Approve-path Instructions for Screen 6 (WC) — Nano devices only.

    Touch devices should use sign_psbt_wc_approve_nav() instead.
    """
    instructions = Instructions(device)
    instructions.new_request("Sign", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_wc_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 6 (WC) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
        NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
        NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
    ]


def sign_psbt_claim_reject_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 4 (Claim) — Nano devices only."""
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_claim_reject_nav(device: Device) -> List[NavInsID]:
    """Flat reject-path navigation for Screen 4 (Claim) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,
        NavInsID.USE_CASE_REVIEW_REJECT,
        NavInsID.USE_CASE_CHOICE_CONFIRM,
    ]


def sign_psbt_assert_reject_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 5 (Assert) — Nano devices only."""
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_assert_reject_nav(device: Device) -> List[NavInsID]:
    """Flat reject-path navigation for Screen 5 (Assert) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,
        NavInsID.USE_CASE_REVIEW_REJECT,
        NavInsID.USE_CASE_CHOICE_CONFIRM,
    ]


def sign_psbt_wc_reject_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 6 (WC) — Nano devices only."""
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_wc_reject_nav(device: Device) -> List[NavInsID]:
    """Flat reject-path navigation for Screen 6 (WC) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,
        NavInsID.USE_CASE_REVIEW_REJECT,
        NavInsID.USE_CASE_CHOICE_CONFIRM,
    ]


def sign_psbt_pop_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 7 (PoP) — all devices."""
    if device.is_nano:
        return [NavInsID.RIGHT_CLICK] * 6 + [NavInsID.BOTH_CLICK]
    elif  device.name == "stax":
        return [
            NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
            NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
            NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
            NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
            NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
        ]
    else:
        return [
            NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
            NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
            NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
            NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
            NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
        ]


def sign_psbt_pop_reject_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 7 (PoP) — Nano devices only."""
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_pop_reject_nav(device: Device) -> List[NavInsID]:
    """Flat reject-path navigation for Screen 7 (PoP) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,
        NavInsID.USE_CASE_REVIEW_REJECT,
        NavInsID.USE_CASE_CHOICE_CONFIRM,
    ]


def sign_psbt_payout_finalize_approve_instructions(device: Device) -> Instructions:
    """Approve-path Instructions for Screen 8 (PayoutFinalize) — Nano devices only.

    Touch devices should use sign_psbt_payout_finalize_approve_nav() instead.
    """
    instructions = Instructions(device)
    instructions.new_request("Sign", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_payout_finalize_approve_nav(device: Device) -> List[NavInsID]:
    """Flat approve-path navigation for Screen 8 (PayoutFinalize) — touch devices.

    Screen 8 shows 3 fields: "Amount received", "Destination", and "CPFP address".
    All touch devices fit across 3 pages (intro + 2 content pages).
    """
    assert not device.is_nano, "Nano uses sign_psbt_payout_finalize_approve_instructions"
    taps = [
        NavInsID.USE_CASE_REVIEW_TAP,  # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,  # content page 1
        NavInsID.USE_CASE_REVIEW_TAP,  # content page 2
    ]
    return taps + [
        NavInsID.USE_CASE_REVIEW_CONFIRM,  # hold to sign
        NavInsID.USE_CASE_STATUS_DISMISS,  # dismiss status
    ]


def sign_psbt_payout_finalize_reject_instructions(device: Device) -> Instructions:
    """Reject-path Instructions for Screen 8 (PayoutFinalize) — Nano devices only."""
    instructions = Instructions(device)
    instructions.new_request("Reject", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_payout_finalize_reject_nav(device: Device) -> List[NavInsID]:
    """Flat reject-path navigation for Screen 8 (PayoutFinalize) — touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,
        NavInsID.USE_CASE_REVIEW_REJECT,
        NavInsID.USE_CASE_CHOICE_CONFIRM,
    ]


