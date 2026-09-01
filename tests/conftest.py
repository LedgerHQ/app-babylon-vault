from ledger_bitcoin import Chain
from ragger.backend import RaisePolicy
from ragger.backend.interface import BackendInterface
from ragger.conftest import configuration
import os
import shutil
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

def pytest_sessionstart(session):
    # snapshots-tmp is the Ragger framework's ephemeral comparison directory,
    # distinct from the golden snapshots/ tree.  Clearing it here prevents
    # stale per-test subdirs from a previous session causing spurious deletions
    # of golden snapshots that were updated between runs.
    tmp_root = TESTS_ROOT_DIR / "snapshots-tmp"
    if tmp_root.exists():
        shutil.rmtree(tmp_root)


def pytest_addoption(parser):
    # "auto" is a distinct value, not an alias for "test".  Overloading "test" as the
    # auto sentinel made an omitted option and an explicit --network test
    # indistinguishable, so either could be silently switched to "main" by detection —
    # and no CLI value could force testnet (Cerberus V-032).
    parser.addoption("--network", default="auto", choices=("auto", "main", "test"))


def _detect_network_from_binary() -> Optional[str]:
    """Infer mainnet/testnet from the built app binaries.

    The mainnet binary embeds APPNAME='Babylon Vault'; the testnet binary embeds
    APPNAME='Babylon Vault Testnet'.  Searching for b'Testnet' in the raw ELF is
    sufficient — it lives in the ledger.app_name section.

    Every device variant is built from the same COIN, so they must agree.  Returns None
    when there is no binary to inspect or the variants disagree: a stale build directory
    left over from the other network is exactly how a run silently tests the wrong
    artifact, so ambiguity must not resolve to a guess.
    """
    detected = set()
    for elf in sorted(REPO_ROOT_DIR.glob("build/*/bin/app.elf")):
        try:
            detected.add("test" if b"Testnet" in elf.read_bytes() else "main")
        except OSError:
            continue
    if len(detected) != 1:
        return None  # nothing readable, or variants disagree
    return detected.pop()


@pytest.fixture
def bitcoin_network(pytestconfig) -> Union[Literal['main'], Literal['test']]:
    requested = pytestconfig.getoption("--network")
    detected = _detect_network_from_binary()

    if requested == "auto":
        if detected is None:
            raise pytest.UsageError(
                "Cannot detect the app network: no readable build/*/bin/app.elf, or the "
                "device variants disagree (a stale build dir from the other network?). "
                "Pass --network main or --network test explicitly."
            )
        return detected

    # Explicit request: fail closed on a mismatch rather than adapting to the artifact.
    if detected is not None and detected != requested:
        raise pytest.UsageError(
            f"--network {requested} was requested, but the built binary is {detected}. "
            f"Rebuild for {requested}, or remove the stale build directory."
        )
    return requested


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

    Only directories this test actually wrote are checked.  snapshots-tmp accumulates for
    the whole session, so scanning all of it made every subsequent test fail on the first
    bad directory — one flaky capture produced hundreds of teardown errors naming a
    directory the failing test never touched, burying the real signal.
    """
    tmp_base = TESTS_ROOT_DIR / "snapshots-tmp" / device.name
    golden_base = TESTS_ROOT_DIR / "snapshots" / device.name

    before = {d: len(list(d.glob("*.png"))) for d in _iter_leaf_snapshot_dirs(tmp_base)}

    yield

    golden_run = request.config.getoption("--golden_run", default=False)

    for tmp_dir in _iter_leaf_snapshot_dirs(tmp_base):
        # Untouched by this test: present beforehand with the same number of PNGs.  A test
        # that rewrites a pre-existing directory with an identical count is therefore not
        # re-checked — accepted, because whichever test first produced that count already
        # reported it, and the alternative is the session-wide cascade described above.
        if before.get(tmp_dir) == len(list(tmp_dir.glob("*.png"))):
            continue
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
