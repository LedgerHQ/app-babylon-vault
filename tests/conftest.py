from ledger_bitcoin import Chain
from ragger.backend import RaisePolicy
from ragger.backend.interface import BackendInterface
from ragger.conftest import configuration
import atexit
import os
import re
import shutil
import threading
import time
import uuid
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

# Upper bound on Speculos instances started by `-n auto`.  An explicit `-n N` is not capped.
DEFAULT_MAX_SPECULOS_WORKERS = 16

# Seconds an exchange may stay unanswered before a parallel run treats it as a UI wait.
DEFAULT_PARALLEL_APDU_TIMEOUT = 3.0

# Runs of this suite that share the repository directory (one container per target) record
# themselves here, so each can split the cores between the runs that are alive right now.
PARALLEL_RUNS_DIR = TESTS_ROOT_DIR / ".parallel-runs"
_RUN_HEARTBEAT_SECONDS = 5.0
_RUN_STALE_AFTER_SECONDS = 15.0
# Time to let simultaneously launched runs register before counting them.
_RUN_REGISTRATION_GRACE_SECONDS = 3.0

_run_file: Optional[Path] = None
_workers_note: str = ""


def _xdist_worker_index() -> Optional[int]:
    """Index of this pytest-xdist worker (gw3 -> 3), or None outside a worker."""
    match = re.fullmatch(r"gw(\d+)", os.environ.get("PYTEST_XDIST_WORKER", ""))
    return int(match.group(1)) if match else None


@pytest.hookimpl(tryfirst=True)
def pytest_sessionstart(session):
    # snapshots-tmp is the Ragger framework's ephemeral comparison directory,
    # distinct from the golden snapshots/ tree.  Clearing it here prevents
    # stale per-test subdirs from a previous session causing spurious deletions
    # of golden snapshots that were updated between runs.
    # Only the controller clears it, and before xdist starts the workers: a worker doing
    # so would delete the captures of the others.
    if _xdist_worker_index() is not None:
        return
    tmp_root = TESTS_ROOT_DIR / "snapshots-tmp"
    if tmp_root.exists():
        shutil.rmtree(tmp_root)


def _snapshot_the_screen_before_the_reply() -> None:
    """Make the last snapshot of a review that ends in an error status word deterministic.

    The app draws its status screen ("Transaction rejected") and only then sends the status
    word.  After the final tap, Ragger's wait_for_screen_change() samples the screen, finds
    it unchanged (the sample predates the draw), then checks for an early reply.  If the
    reply has landed in between, it raises ExceptionRAPDU on the spot and the snapshot of
    the status screen is never taken; if it has not, the snapshot is taken.  The same flow
    therefore leaves 3 or 4 PNGs depending on timing, which fails the run either as a
    stale golden (surplus golden) or a missing one, and every --golden_run bakes in
    whichever count that run happened to get.

    A reply being available does not mean no screen change is coming: the draw precedes the
    reply in the same stream.  So when the reply is in, look at the screen once more, and if
    it has moved, let the wait return and the caller capture it.  The error still surfaces,
    as before, when the exchange ends.  If the screen has not moved the app really did
    refuse without a screen, and Ragger's own early raise applies unchanged.
    """
    # Local import: ragger is only guaranteed importable once pytest has loaded its plugins.
    from io import BytesIO
    from ragger.backend.speculos import SpeculosBackend, has_data_available, screenshot_equal

    ragger_check = getattr(SpeculosBackend, "_check_async_error", None)
    if ragger_check is None:
        return  # a Ragger without the early-reply check has no such race

    def check_async_error(self) -> None:
        pending = self._pending_async_response
        if (pending is not None and self._last_async_response is None
                and has_data_available(pending, timeout=0)
                and not screenshot_equal(BytesIO(self._client.get_screenshot()),
                                         self._last_screenshot)):
            return
        ragger_check(self)

    SpeculosBackend._check_async_error = check_async_error


def pytest_configure(config):
    """Install the Speculos backend patches this suite relies on.

    Everywhere: see _snapshot_the_screen_before_the_reply.

    Under xdist, give Speculos exchanges a longer window before they count as 'waiting'.

    bitcoin_app_base's ragger_navigate sets apdu_timeout to 1.0 s and reads "no answer within
    that window" as "the device is waiting for the user", spending one navigation step.  With
    many emulators sharing the cores, an exchange that is only busy (verifying, signing) can
    exceed it; the step index then drifts and the instruction lookup fails with IndexError.
    Raising the floor costs that many seconds per genuine UI prompt, so it is applied only to
    parallel runs.  SPECULOS_APDU_TIMEOUT overrides it (seconds).
    """
    _snapshot_the_screen_before_the_reply()
    if _xdist_worker_index() is None:
        return
    floor = float(os.environ.get("SPECULOS_APDU_TIMEOUT", DEFAULT_PARALLEL_APDU_TIMEOUT))
    from ragger.backend.speculos import SpeculosBackend

    setter = SpeculosBackend.apdu_timeout.fset

    def floored_apdu_timeout(self, value: float) -> None:
        setter(self, max(value, floor))

    SpeculosBackend.apdu_timeout = SpeculosBackend.apdu_timeout.setter(floored_apdu_timeout)


def _unregister_run() -> None:
    global _run_file
    run_file, _run_file = _run_file, None
    if run_file is not None:
        run_file.unlink(missing_ok=True)


def _register_run(device: str) -> int:
    """Record this run in the shared directory and return how many runs are alive, itself
    included.  A run is alive while its file is touched; a crashed run goes stale."""
    global _run_file
    PARALLEL_RUNS_DIR.mkdir(exist_ok=True)
    run_file = PARALLEL_RUNS_DIR / f"{device}-{uuid.uuid4().hex}.run"
    run_file.touch()
    _run_file = run_file

    def heartbeat():
        while _run_file is run_file:
            time.sleep(_RUN_HEARTBEAT_SECONDS)
            try:
                run_file.touch()
            except OSError:
                return

    threading.Thread(target=heartbeat, daemon=True).start()
    atexit.register(_unregister_run)

    time.sleep(_RUN_REGISTRATION_GRACE_SECONDS)
    alive = 0
    for other in PARALLEL_RUNS_DIR.glob("*.run"):
        try:
            if time.time() - other.stat().st_mtime < _RUN_STALE_AFTER_SECONDS:
                alive += 1
        except FileNotFoundError:
            continue
    return max(1, alive)


@pytest.hookimpl(optionalhook=True)
def pytest_xdist_auto_num_workers(config):
    """Worker count for `-n auto`: the usable cores (`nproc`) divided by the runs alive now.

    One container per target means up to five runs share the cores; a lone run gets them all.
    SPECULOS_PARALLEL_TARGETS fixes the divisor instead of counting, SPECULOS_MAX_WORKERS
    caps the result.  Runs that do not share this directory cannot see each other, so each
    would take every core: set SPECULOS_PARALLEL_TARGETS there.
    """
    global _workers_note
    cap = int(os.environ.get("SPECULOS_MAX_WORKERS", DEFAULT_MAX_SPECULOS_WORKERS))
    # The affinity mask is what `nproc` reports and follows a container's --cpuset-cpus;
    # os.cpu_count() would count the host's cores.
    cores = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count()
    cores = cores or 1
    if "SPECULOS_PARALLEL_TARGETS" in os.environ:
        runs, source = max(1, int(os.environ["SPECULOS_PARALLEL_TARGETS"])), "fixed"
    else:
        runs, source = _register_run(str(config.getoption("device", default="run"))), "counted"
    workers = max(1, min(cap, cores // runs))
    _workers_note = f"speculos workers: {workers} ({cores} cores / {runs} {source} run(s), cap {cap})"
    return workers


def pytest_report_header(config):
    return _workers_note or None


def pytest_addoption(parser):
    # "auto" is a distinct value, not an alias for "test".  Overloading "test" as the
    # auto sentinel made an omitted option and an explicit --network test
    # indistinguishable, so either could be silently switched to "main" by detection —
    # and no CLI value could force testnet (Cerberus V-032).
    parser.addoption("--network", default="auto", choices=("auto", "main", "test"))
    # Under pytest-xdist each worker gets its own Speculos ports: API port
    # base + index * stride, APDU port one above.  Ragger would otherwise pick the first
    # free port, and workers starting together can all see the same one as free.
    parser.addoption("--speculos-base-port", type=int,
                     default=int(os.environ.get("SPECULOS_BASE_PORT", "5000")))
    parser.addoption("--speculos-port-stride", type=int,
                     default=int(os.environ.get("SPECULOS_PORT_STRIDE", "10")))


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


@pytest.fixture(scope=configuration.OPTIONAL.BACKEND_SCOPE)
def additional_speculos_arguments(request) -> List[str]:
    """Distinct Speculos ports per xdist worker; Ragger's own choice outside xdist."""
    index = _xdist_worker_index()
    if index is None:
        return []
    stride = request.config.getoption("--speculos-port-stride")
    if stride < 2:
        raise pytest.UsageError("--speculos-port-stride must be at least 2 (API + APDU port)")
    api_port = request.config.getoption("--speculos-base-port") + index * stride
    return ["--api-port", str(api_port), "--apdu-port", str(api_port + 1)]


def _stale_goldens(tmp_dir: Path, tmp_base: Path, golden_base: Path):
    """Return (golden_dir, produced, extra) when goldens outnumber the screens produced.

    None when the directory has no golden, produced nothing (skipped/early error: leave
    the goldens alone) or has no surplus golden.
    """
    golden_dir = golden_base / tmp_dir.relative_to(tmp_base)
    if not golden_dir.exists():
        return None
    produced = len(list(tmp_dir.glob("*.png")))
    if produced == 0:
        return None
    extra = sorted(p for p in golden_dir.glob("*.png") if int(p.stem) >= produced)
    return (golden_dir, produced, extra) if extra else None


def _stale_golden_message(golden_dir: Path, produced: int, extra) -> str:
    rel_display = golden_dir.relative_to(TESTS_ROOT_DIR)
    return (
        f"Stale golden snapshots in '{rel_display}': {[p.name for p in extra]}. "
        f"Test produced {produced} screen(s) but {produced + len(extra)} golden(s) exist. "
        f"Run with --golden_run to regenerate."
    )


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

    Under pytest-xdist this check does not run per test: workers write into the same
    snapshots-tmp, so a directory another worker is still filling would look stale.
    pytest_sessionfinish performs it once, after every worker has finished.
    """
    if _xdist_worker_index() is not None:
        yield
        return

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
        stale = _stale_goldens(tmp_dir, tmp_base, golden_base)
        if stale is None:
            continue
        golden_dir, produced, extra = stale

        if golden_run:
            for png in extra:
                png.unlink()
        else:
            pytest.fail(_stale_golden_message(golden_dir, produced, extra))


def pytest_sessionfinish(session, exitstatus):
    """The stale-golden check for a parallel run, once all workers are done."""
    _unregister_run()
    if _xdist_worker_index() is not None or not getattr(session.config.option, "numprocesses", None):
        return
    golden_run = session.config.getoption("--golden_run", default=False)
    tmp_root = TESTS_ROOT_DIR / "snapshots-tmp"
    golden_root = TESTS_ROOT_DIR / "snapshots"
    problems = []
    for device_tmp in sorted(p for p in tmp_root.glob("*") if p.is_dir()):
        for tmp_dir in _iter_leaf_snapshot_dirs(device_tmp):
            stale = _stale_goldens(tmp_dir, device_tmp, golden_root / device_tmp.name)
            if stale is None:
                continue
            golden_dir, produced, extra = stale
            if golden_run:
                for png in extra:
                    png.unlink()
            else:
                problems.append(_stale_golden_message(golden_dir, produced, extra))
    if problems:
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        for problem in problems:
            reporter.write_line(problem, red=True)
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


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
