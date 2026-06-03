from ragger.navigator import NavInsID
from ledgered.devices import Devices, DeviceType
from typing import Tuple, List


def vault_intent_approve_nav(firmware: DeviceType) -> Tuple[NavInsID, List[NavInsID], str]:
    """Return (navigate_instruction, validation_instructions, search_text) to approve.

    Touch: SWIPE_CENTER_TO_LEFT until "Hold to sign", USE_CASE_REVIEW_CONFIRM (3 s hold),
           then USE_CASE_STATUS_DISMISS for the "Operation signed" status screen.
    Nano:  RIGHT_CLICK until our custom finishTitle "Approve intent?" appears, BOTH_CLICK.
           No status dismiss needed — Nano NBGL auto-dismisses the status.
    """
    if Devices.get_by_type(firmware).is_nano:
        # Nano NBGL shows our custom finishTitle on the confirmation screen.
        # VAULT_INTENT_FINISH_TITLE (no SCREEN_SIZE_WALLET) = "Approve intent?"
        return (NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                r"Approve intent")
    return (NavInsID.SWIPE_CENTER_TO_LEFT,
            [NavInsID.USE_CASE_REVIEW_CONFIRM, NavInsID.USE_CASE_STATUS_DISMISS],
            "^Hold to sign$")


def vault_intent_reject_nav(firmware: DeviceType) -> Tuple[NavInsID, List[NavInsID], str]:
    """Return (navigate_instruction, validation_instructions, search_text) to reject.

    On touch: navigate to "Hold to sign", tap Reject, confirm, dismiss rejection status.
    On Nano:  navigate until "Reject operation", both-click to confirm.
    """
    if Devices.get_by_type(firmware).is_nano:
        return (NavInsID.RIGHT_CLICK,
                [NavInsID.BOTH_CLICK],
                r"^Reject operation$")
    return (NavInsID.SWIPE_CENTER_TO_LEFT,
            [NavInsID.USE_CASE_REVIEW_REJECT,
             NavInsID.USE_CASE_CHOICE_CONFIRM,
             NavInsID.USE_CASE_STATUS_DISMISS],
            "^Hold to sign$")
