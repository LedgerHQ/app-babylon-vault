from ledger_bitcoin import Chain
from ragger.backend import RaisePolicy
from ragger.backend.interface import BackendInterface
from ragger.conftest import configuration
import os
from pathlib import Path
from typing import Literal, Union
import pytest

# disable reordering of imports for autopep8
# fmt: off

TESTS_ROOT_DIR = Path(__file__).parent
REPO_ROOT_DIR = Path(__file__).parent.parent

# update pythonpath to include the ragger_bitcoin package
import sys
sys.path.append(str(REPO_ROOT_DIR / "bitcoin_app_base" ))

print(str(REPO_ROOT_DIR / "bitcoin_app_base" ))

from ragger_bitcoin import createRaggerClient, RaggerClient

# fmt: on

# Seed Speculos with the standard test mnemonic so that BIP-32 derivations
# (including m/73681862' used by DERIVE_CONTEXT_HASH) are reproducible.
MNEMONIC = (
    "glory promote mansion idle axis finger extra february uncover one trip "
    "resource lawn turtle enact monster seven myth punch hobby comfort wild "
    "raise skin"
)
configuration.OPTIONAL.CUSTOM_SEED = MNEMONIC


###########################
### CONFIGURATION START ###
###########################

# You can configure optional parameters by overriding the value of ragger.configuration.OPTIONAL_CONFIGURATION
# Please refer to ragger/conftest/configuration.py for their descriptions and accepted values

#########################
### CONFIGURATION END ###
#########################

# Pull all features from the base ragger conftest using the overridden configuration
pytest_plugins = ("ragger.conftest.base_conftest", )

def pytest_addoption(parser):
    parser.addoption("--network", default="test")


def _detect_network_from_binary() -> str:
    """Infer mainnet/testnet from the most recently built app binary.

    The mainnet binary embeds APPNAME='Babylon Vault'; the testnet binary
    embeds APPNAME='Babylon Vault Testnet'.  Searching for b'Testnet' in
    the raw ELF is sufficient — it lives in the ledger.app_name section.
    Falls back to 'test' if no binary is found or the file is unreadable.
    """
    for elf in REPO_ROOT_DIR.glob("build/*/bin/app.elf"):
        try:
            if b"Testnet" not in elf.read_bytes():
                return "main"
        except OSError:
            pass
        break  # all device variants are built from the same COIN — one check is enough
    return "test"


@pytest.fixture
def bitcoin_network(pytestconfig) -> Union[Literal['main'], Literal['test']]:
    network = pytestconfig.getoption("--network")
    # The VS Code plugin never passes --network, so the default "test" is always
    # used even when testing the mainnet binary.  Auto-detect from the binary
    # when the default hasn't been overridden explicitly.
    if network == "test":
        network = _detect_network_from_binary()
    if network not in ["main", "test"]:
        raise ValueError(f'Invalid value for BITCOIN_NETWORK: {network}')
    return network


@pytest.fixture
def client(bitcoin_network: str, backend: BackendInterface) -> RaggerClient:
    if bitcoin_network == "main":
        chain = Chain.MAIN
    elif bitcoin_network == "test":
        chain = Chain.TEST
    else:
        raise ValueError(
            f'Invalid value for BITCOIN_NETWORK: {bitcoin_network}')

    backend.raise_policy = RaisePolicy.RAISE_CUSTOM
    backend.whitelisted_status = [0x9000, 0xE000]
    return createRaggerClient(backend, chain=chain, debug=True, screenshot_dir=TESTS_ROOT_DIR)
