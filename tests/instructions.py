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


def vault_intent_steps_for_keys(device: Device, total_keys: int) -> int:
    """n_swipes for a single vault with total_keys key entries (keepers + challengers combined).

    Unlike vault_intent_steps, this handles asymmetric keeper/challenger counts correctly
    by taking the total key count instead of assuming they are equal.

    Stax (touch):     2 keys per content page  → ceil(total_keys / 2) pages
    Flex/Apex (touch): 1 key per content page  → total_keys pages
    Nano:              2 clicks per key
    """
    if device.is_nano:
        return 1 + 4 + 2 * total_keys + 7
    if device.name == "stax":
        return 1 + 1 + (total_keys + 1) // 2 + 2
    return 1 + 1 + total_keys + 2


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
    """Flat approve-path navigation for Screen 5 (Assert) on touch devices."""
    assert not device.is_nano, "Nano uses Instructions-based navigation"
    if device.name == "stax":
        return [
            NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
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
        return [NavInsID.RIGHT_CLICK] * 4 + [NavInsID.BOTH_CLICK]
    return [
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

    Screen 8 shows 2 fields: "Amount received" and "Your address".
    Both Stax and Flex/Apex render in 2 pages (intro + content), matching the
    WC (Screen 6) layout pattern.
    """
    assert not device.is_nano, "Nano uses sign_psbt_payout_finalize_approve_instructions"
    return [
        NavInsID.USE_CASE_REVIEW_TAP,      # intro → content
        NavInsID.USE_CASE_REVIEW_TAP,      # content → finish
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


def sign_psbt_nopayout_approve_instructions(device: Device) -> Instructions:
    """Approve-path Instructions for NoPayout — Nano devices only.

    Touch devices should use sign_psbt_nopayout_approve_nav() instead.

    The 64-char hex challenger key spans ~6 Nano screens, so the navigator
    RIGHT_CLICKs through them before finding "Sign".  That is expected; the
    resulting snapshot skips are not failures.
    """
    instructions = Instructions(device)
    instructions.new_request("Sign", NavInsID.RIGHT_CLICK, NavInsID.BOTH_CLICK)
    return instructions


def sign_psbt_nopayout_approve_nav(device: Device, total_keys: int) -> List[NavInsID]:
    """Flat approve-path navigation for NoPayout — touch devices.

    NoPayout uses a streaming review showing all keepers and challengers.
    Layout: intro page + key content pages (no params segment).
    Stax:      ceil(total_keys / 2) key pages per content screen
    Flex/Apex: 1 key per content screen
    """
    assert not device.is_nano, "Nano uses sign_psbt_nopayout_approve_instructions"
    if device.name == "stax":
        n_swipes = 1 + (total_keys + 1) // 2
    else:
        n_swipes = 1 + total_keys
    return (
        [NavInsID.SWIPE_CENTER_TO_LEFT] * n_swipes
        + [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS]
    )
