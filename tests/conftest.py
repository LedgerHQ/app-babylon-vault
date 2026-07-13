from ledger_bitcoin import Chain
from ragger.backend import RaisePolicy
from ragger.backend.interface import BackendInterface
from ragger.conftest import configuration
import os
from pathlib import Path
from typing import Literal, List, Optional, Union
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


def _iter_leaf_snapshot_dirs(base: Path):
    """Yield leaf snapshot dirs up to 2 levels deep under base.

    Handles the nested structure  base/<feature>/<flow_net>/
    as well as legacy flat  base/<test_case_name>/  entries.
    """
    if not base.exists():
        return
    for entry in base.iterdir():
        if not entry.is_dir():
            continue
        children = [c for c in entry.iterdir() if c.is_dir()]
        if children:
            yield from children
        else:
            yield entry


@pytest.fixture(autouse=True)
def check_no_extra_snapshots(request, device):
    """After each test, verify no stale golden snapshots remain.

    Walks snapshots-tmp/<device>/ up to 2 levels deep so it handles both
    the nested  feature/flow_net/  layout and legacy flat  test_case/  dirs.

    Normal run: fail if snapshots/ has more PNGs than snapshots-tmp/.
    --golden_run: delete the extra files so goldens stay in sync automatically.
    """
    yield

    golden_run = request.config.getoption("--golden_run", default=False)
    tmp_base = TESTS_ROOT_DIR / "snapshots-tmp" / device.name
    golden_base = TESTS_ROOT_DIR / "snapshots" / device.name

    for tmp_dir in _iter_leaf_snapshot_dirs(tmp_base):
        rel = tmp_dir.relative_to(tmp_base)
        golden_dir = golden_base / rel
        if not golden_dir.exists():
            continue

        expected_count = len(list(tmp_dir.glob("*.png")))
        if expected_count == 0:
            continue  # test produced no snapshots (skipped/early error) — leave goldens alone

        extra = sorted(p for p in golden_dir.glob("*.png") if int(p.stem) >= expected_count)
        if not extra:
            continue

        if golden_run:
            for png in extra:
                png.unlink()
        else:
            rel_display = golden_dir.relative_to(TESTS_ROOT_DIR)
            pytest.fail(
                f"Stale golden snapshots in '{rel_display}': {[p.name for p in extra]}. "
                f"Test produced {expected_count} screen(s) but {expected_count + len(extra)} golden(s) exist. "
                f"Run with --golden_run to regenerate."
            )


def pytest_assertrepr_compare(op: str, left: object, right: object) -> Optional[List[str]]:
    """Show APDU status word comparisons in hex instead of decimal."""
    if op == "==" and isinstance(left, int) and isinstance(right, int) and repr(right).startswith("0x"):
        return [f"{hex(left)} {op} {hex(right)}"]


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
