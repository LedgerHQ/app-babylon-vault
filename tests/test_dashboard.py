from ledgered.devices import Device
from ragger.navigator import NavInsID, Navigator
from pathlib import Path

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


def test_dashboard(navigator: Navigator, device: Device, test_name: str, bitcoin_network: str):
    # Tests that the text shown in the dashboard screens are the expected ones

    if device.is_nano:
        instructions = [
            NavInsID.RIGHT_CLICK,
            NavInsID.RIGHT_CLICK,
        ]
    else:
        instructions = [
            NavInsID.USE_CASE_HOME_INFO,
            NavInsID.USE_CASE_SETTINGS_SINGLE_PAGE_EXIT
        ]

    navigator.navigate_and_compare(ROOT_SCREENSHOT_PATH, test_name + "_" + bitcoin_network, instructions,
                                   screen_change_before_first_instruction=False)
