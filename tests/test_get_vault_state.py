"""
Ragger integration tests for GET_VAULT_STATE (INS 0x82).

The command is read-only and silent. Every query here is a plain synchronous exchange, so
a review screen would block the exchange instead of passing unnoticed, and the tests that
reach a steady state also compare the screen with the home-screen golden.

Expected fingerprints are computed host-side (vault_client.fingerprint) from what the test
sent or received, which is the computation a host performs to decide whether to resume.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Tuple
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest
from ledgered.devices import Device
from ragger.backend.interface import BackendInterface
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from .instructions import derive_context_hash_reject_nav, vault_intent_reject_nav
from .test_approve_vault_intent import _make_group, _make_scalars
from .test_sign_psbt_validate import (
    _DERIVE_CONTEXT,
    _HTLC_REFUND_TIMELOCK,
    _HTLC_VOUT,
    _TEST_CHALLENGER_PKS,
    _TEST_KEEPER_PKS,
    _build_group_for_test,
    _build_intent_tlv_for_test,
    _build_prepegin_psbt,
    _depositor_pk,
    _hash256,
    _htlc_output,
    _prepegin_input_key,
    _standard_taproot_wallet,
)
from .vault_client import (
    CLA_VAULT,
    FINGERPRINT_LEN,
    INS_APPROVE_VAULT_INTENT,
    INS_DERIVE_CONTEXT_HASH,
    P1_CONTINUE,
    P1_GROUP,
    P1_INITIAL,
    P1_KEY_BATCH,
    P1_SCALARS,
    P2_SHOW,
    P2_SILENT,
    P2_UNUSED,
    SW_BAD_STATE,
    SW_CAP_EXCEEDED,
    SW_DENY,
    SW_INCORRECT_DATA,
    SW_WRONG_DATA_LENGTH,
    SW_WRONG_P1P2,
    TAG_CHALLENGER_PK,
    TAG_KEEPER_PK,
    TEST_NONCANONICAL_XONLY_KEY,
    TEST_VALID_KEYS,
    TEST_VP_KEY,
    VAULT_APP_NAME,
    _approve_exchange,
    _dch_exchange,
    _encode_bip32_path,
    _ktlv,
    approve_vault_intent_with_nav,
    context_fingerprint,
    depositor_path,
    derive_context_hash,
    derive_for_intent,
    get_vault_state,
    get_vault_state_raw,
    intent_fingerprint,
    vault_auth_anchor,
    vault_hashlock,
)

SNAPSHOTS_DIR = Path(__file__).parent.resolve() / "snapshots"

# derive_for_intent's default vaultContext.
_DEFAULT_CONTEXT = b"\xde\xad\xbe\xef"

# The 1-keeper / 1-challenger intent's fingerprint (_make_scalars, one _make_group, keys
# TEST_VALID_KEYS[0..1]).  The mainnet value is also pinned in unit-tests/test_vault_context.c.
_PINNED_1K1C_INTENT_FP = {
    "main": bytes.fromhex("44a99b57"),
    "test": bytes.fromhex("e51e391a"),
}

_NOTHING_HELD = bytes([0, 0])


def _coin_type(bitcoin_network: str) -> int:
    return 0 if bitcoin_network == "main" else 1


def _state_bytes(intent_fp: Optional[bytes], context_fp: Optional[bytes]) -> bytes:
    """Wire encoding of a GET_VAULT_STATE answer, built independently of the parser."""
    out = b""
    for fp in (intent_fp, context_fp):
        out += bytes([0]) if fp is None else bytes([FINGERPRINT_LEN]) + fp
    return out


def _assert_home_screen(backend: BackendInterface, device: Device, bitcoin_network: str) -> None:
    """The device shows the app home screen: frame 0 of the dashboard golden."""
    golden = SNAPSHOTS_DIR / device.name / "dashboard" / bitcoin_network / "00000.png"
    assert backend.compare_screen_with_snapshot(golden), "screen is not the app home screen"


def _intent_1k1c(bitcoin_network: str, **scalar_overrides) -> Tuple[bytes, List[bytes], List[bytes], List[bytes]]:
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1, **scalar_overrides)
    return scalars, [_make_group()], [TEST_VALID_KEYS[0]], [TEST_VALID_KEYS[1]]


def _derive_silent(client: "RaggerClient", bitcoin_network: str) -> None:
    derive_context_hash(client, VAULT_APP_NAME, depositor_path(_coin_type(bitcoin_network)),
                        _DEFAULT_CONTEXT, None, None, p2=P2_SILENT)


# ---------------------------------------------------------------------------
# One answer per session state
# ---------------------------------------------------------------------------

def test_idle_reports_nothing(client: "RaggerClient", backend: BackendInterface,
                              device: Device, bitcoin_network: str):
    """Fresh session → 00 00, and the query leaves the home screen untouched."""
    assert get_vault_state_raw(client) == _NOTHING_HELD
    _assert_home_screen(backend, device, bitcoin_network)


def test_derive_reports_context_fingerprint(client: "RaggerClient", navigator: Navigator,
                                            device: Device, bitcoin_network: str):
    """After DERIVE_CONTEXT_HASH → 00 04 SHA-256(root)[-4:]."""
    root = derive_for_intent(client, navigator, device, bitcoin_network)
    assert get_vault_state_raw(client) == _state_bytes(None, context_fingerprint(root))


def test_silent_derive_reports_context_fingerprint(client: "RaggerClient", navigator: Navigator,
                                                   device: Device, bitcoin_network: str):
    """P2=0x01 returns no root and needs no approval, yet its fingerprint is readable at once.

    This is the case the security note in docs/apdu.md covers: the fingerprint is reported
    before any Screen 1 approval, and it matches the root a later approval releases.
    """
    _derive_silent(client, bitcoin_network)
    _, silent_fp = get_vault_state(client)
    assert silent_fp is not None

    root = derive_for_intent(client, navigator, device, bitcoin_network)
    assert silent_fp == context_fingerprint(root)
    assert get_vault_state(client) == (None, silent_fp)


def test_approved_intent_reports_both_fingerprints(client: "RaggerClient", navigator: Navigator,
                                                   backend: BackendInterface, device: Device,
                                                   bitcoin_network: str):
    """After APPROVE_VAULT_INTENT → 04 intent_fp 04 context_fp.

    The device zeroes the root once the intent's commitments are derived, so a correct
    context fingerprint here proves it was captured at derivation time.
    """
    root = derive_for_intent(client, navigator, device, bitcoin_network)
    scalars, groups, keepers, challengers = _intent_1k1c(bitcoin_network)
    approve_vault_intent_with_nav(client, navigator, device, scalars, keepers, challengers,
                                  groups=groups)
    backend.wait_for_home_screen()

    intent_fp = intent_fingerprint(scalars, groups, keepers, challengers)
    assert intent_fp == _PINNED_1K1C_INTENT_FP[bitcoin_network]
    assert get_vault_state_raw(client) == _state_bytes(intent_fp, context_fingerprint(root))
    _assert_home_screen(backend, device, bitcoin_network)


def test_intent_in_flight_is_not_reported(client: "RaggerClient", navigator: Navigator,
                                          device: Device, bitcoin_network: str):
    """Between P1=0x00 and approval only the context fingerprint is reported."""
    root = derive_for_intent(client, navigator, device, bitcoin_network)
    scalars, groups, _, _ = _intent_1k1c(bitcoin_network)
    _approve_exchange(client, P1_SCALARS, scalars)
    assert get_vault_state(client) == (None, context_fingerprint(root))
    _approve_exchange(client, P1_GROUP, groups[0])
    assert get_vault_state(client) == (None, context_fingerprint(root))


# ---------------------------------------------------------------------------
# Intent fingerprint definition
# ---------------------------------------------------------------------------

def test_intent_fingerprint_independent_of_batching(client: "RaggerClient", navigator: Navigator,
                                                    device: Device, bitcoin_network: str):
    """The same intent sent with different P1=0x01 / P1=0x02 splits → the same fingerprint."""
    keepers, challengers = TEST_VALID_KEYS[0:3], TEST_VALID_KEYS[3:5]
    scalars = _make_scalars(bitcoin_network, keeper_count=len(keepers),
                            challenger_count=len(challengers), vault_count=2)
    groups = [_make_group(htlc_vout=0), _make_group(htlc_vout=1)]
    expected = intent_fingerprint(scalars, groups, keepers, challengers)

    batchings = [
        dict(groups=groups, keys_per_batch=1),              # one group, one key per APDU
        dict(groups=[b"".join(groups)], keys_per_batch=7),  # everything in one APDU per phase
        dict(groups=groups, keys_per_batch=2),              # keys split across the two roles
    ]
    for batching in batchings:
        _derive_silent(client, bitcoin_network)
        approve_vault_intent_with_nav(client, navigator, device, scalars, keepers, challengers,
                                      **batching)
        intent_fp, _ = get_vault_state(client)
        assert intent_fp == expected, f"fingerprint depends on batching {batching}"


def test_one_changed_byte_changes_intent_fingerprint(client: "RaggerClient", navigator: Navigator,
                                                     device: Device, bitcoin_network: str):
    """Two intents differing in a single CData byte (base_fee_rate 10 → 11) differ in fingerprint."""
    fps = []
    scalars_sent = []
    for base_fee_rate in (10, 11):
        scalars, groups, keepers, challengers = _intent_1k1c(bitcoin_network,
                                                             base_fee_rate=base_fee_rate)
        _derive_silent(client, bitcoin_network)
        approve_vault_intent_with_nav(client, navigator, device, scalars, keepers, challengers,
                                      groups=groups)
        intent_fp, _ = get_vault_state(client)
        assert intent_fp == intent_fingerprint(scalars, groups, keepers, challengers)
        fps.append(intent_fp)
        scalars_sent.append(scalars)

    assert sum(a != b for a, b in zip(*scalars_sent)) == 1
    assert fps[0] != fps[1]


# ---------------------------------------------------------------------------
# Read-only: no state change, no signature slot consumed
# ---------------------------------------------------------------------------

def _prepegin_psbt(client: "RaggerClient", root: bytes, bitcoin_network: str, locktime: int = 0):
    """A Pre-PegIn PSBT the device can sign for the root; locktime varies its txid."""
    coin_type = _coin_type(bitcoin_network)
    _, _, _, _, htlc_spk = _htlc_output(
        _depositor_pk(bitcoin_network), TEST_VP_KEY, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS,
        _HTLC_REFUND_TIMELOCK, vault_hashlock(root, _HTLC_VOUT),
    )
    fingerprint, input_key = _prepegin_input_key(client, coin_type)
    return _build_prepegin_psbt(
        htlc_spk,
        locktime=locktime,
        input_internal_key=input_key,
        input_fingerprint=fingerprint,
        input_coin_type=coin_type,
        auth_anchor=vault_auth_anchor(root),
    )


def _approve_prepegin_intent(client: "RaggerClient", navigator: Navigator, device: Device,
                             bitcoin_network: str):
    """Derive and approve an intent bound to a signable Pre-PegIn; return (psbt, wallet, root)."""
    coin_type = _coin_type(bitcoin_network)
    root = derive_context_hash(client, VAULT_APP_NAME, depositor_path(coin_type),
                               _DERIVE_CONTEXT, navigator, device)
    psbt = _prepegin_psbt(client, root, bitcoin_network)
    scalars = _build_intent_tlv_for_test(coin_type, _hash256(psbt.tx.serialize_without_witness()))
    groups = [_build_group_for_test()]
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS, groups=groups)

    expected = _state_bytes(
        intent_fingerprint(scalars, groups, _TEST_KEEPER_PKS, _TEST_CHALLENGER_PKS),
        context_fingerprint(root),
    )
    assert get_vault_state_raw(client) == expected
    return psbt, _standard_taproot_wallet(client, coin_type), root


def test_repeated_queries_consume_no_signature(client: "RaggerClient", navigator: Navigator,
                                               device: Device, bitcoin_network: str):
    """Queries return identical bytes and move no counter.

    The Pre-PegIn cap is 1: if any query had consumed a slot, the signature after them
    would be refused.  A successful signature leaves the session, and so the answer, as is.
    """
    psbt, wallet, _ = _approve_prepegin_intent(client, navigator, device, bitcoin_network)
    first = get_vault_state_raw(client)
    for _ in range(5):
        assert get_vault_state_raw(client) == first

    assert len(client.sign_psbt(psbt, wallet, None)) == 1
    assert get_vault_state_raw(client) == first


def test_rejected_psbt_keeps_session(client: "RaggerClient", navigator: Navigator,
                                     device: Device, bitcoin_network: str):
    """A SIGN_PSBT that fails validation is refused without touching the session.

    The rejected Pre-PegIn differs from the approved one only in locktime, so its txid does
    not match the intent.  The approved one still signs afterwards, which shows the rejection
    spent neither the session nor the single Pre-PegIn slot.
    """
    psbt, wallet, root = _approve_prepegin_intent(client, navigator, device, bitcoin_network)
    loaded = get_vault_state_raw(client)

    unbound = _prepegin_psbt(client, root, bitcoin_network, locktime=1)
    assert unbound.tx.serialize_without_witness() != psbt.tx.serialize_without_witness()
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(unbound, wallet, None)
    assert exc.value.status == SW_INCORRECT_DATA
    assert get_vault_state_raw(client) == loaded

    assert len(client.sign_psbt(psbt, wallet, None)) == 1
    assert get_vault_state_raw(client) == loaded


# ---------------------------------------------------------------------------
# Invalidation → 00 00
# ---------------------------------------------------------------------------

def test_cap_exceeded_clears_state(client: "RaggerClient", navigator: Navigator,
                                   device: Device, bitcoin_network: str):
    """A SIGN_PSBT that exceeds a signature cap nullifies the session → 00 00."""
    psbt, wallet, _ = _approve_prepegin_intent(client, navigator, device, bitcoin_network)
    client.sign_psbt(psbt, wallet, None)
    with pytest.raises(ExceptionRAPDU) as exc:
        client.sign_psbt(psbt, wallet, None)
    assert exc.value.status == SW_CAP_EXCEEDED
    assert get_vault_state_raw(client) == _NOTHING_HELD


def test_rejected_intent_apdu_clears_state(client: "RaggerClient", navigator: Navigator,
                                           device: Device, bitcoin_network: str):
    """An APPROVE_VAULT_INTENT error invalidates the session, context root included → 00 00."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars, groups, _, challengers = _intent_1k1c(bitcoin_network)
    _approve_exchange(client, P1_SCALARS, scalars)
    _approve_exchange(client, P1_GROUP, groups[0])
    with pytest.raises(ExceptionRAPDU) as exc:
        _approve_exchange(client, P1_KEY_BATCH,
                          _ktlv(TAG_KEEPER_PK, TEST_NONCANONICAL_XONLY_KEY) +
                          _ktlv(TAG_CHALLENGER_PK, challengers[0]))
    assert exc.value.status == SW_INCORRECT_DATA
    assert get_vault_state_raw(client) == _NOTHING_HELD


def test_user_rejection_clears_state(client: "RaggerClient", navigator: Navigator,
                                     device: Device, bitcoin_network: str):
    """Rejecting the intent review invalidates the session → 00 00."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars, groups, keepers, challengers = _intent_1k1c(bitcoin_network)
    _approve_exchange(client, P1_SCALARS, scalars)
    _approve_exchange(client, P1_GROUP, groups[0])
    nav_instr, reject_instrs, search_text = vault_intent_reject_nav(device)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.transport_client.exchange_async(
            cla=CLA_VAULT,
            ins=INS_APPROVE_VAULT_INTENT,
            p1=P1_KEY_BATCH,
            p2=P2_UNUSED,
            data=_ktlv(TAG_KEEPER_PK, keepers[0]) + _ktlv(TAG_CHALLENGER_PK, challengers[0]),
        ):
            navigator.navigate_until_text(
                navigate_instruction=nav_instr,
                validation_instructions=reject_instrs,
                text=search_text,
                screen_change_before_first_instruction=False,
            )
    assert exc.value.status == SW_DENY
    assert get_vault_state_raw(client) == _NOTHING_HELD


def test_new_derivation_clears_loaded_intent(client: "RaggerClient", navigator: Navigator,
                                             device: Device, bitcoin_network: str):
    """Opening a DERIVE_CONTEXT_HASH stream drops the loaded intent → 00 00 until it completes."""
    root = derive_for_intent(client, navigator, device, bitcoin_network)
    scalars, groups, keepers, challengers = _intent_1k1c(bitcoin_network)
    approve_vault_intent_with_nav(client, navigator, device, scalars, keepers, challengers,
                                  groups=groups)
    assert get_vault_state(client)[0] is not None

    header = (bytes([len(VAULT_APP_NAME)]) + VAULT_APP_NAME
              + _encode_bip32_path(depositor_path(_coin_type(bitcoin_network)))
              + len(_DEFAULT_CONTEXT).to_bytes(2, "big"))
    split = len(_DEFAULT_CONTEXT) // 2
    _dch_exchange(client, P1_INITIAL, P2_SILENT, header + _DEFAULT_CONTEXT[:split])
    assert get_vault_state_raw(client) == _NOTHING_HELD

    _dch_exchange(client, P1_CONTINUE, P2_SILENT, _DEFAULT_CONTEXT[split:])
    assert get_vault_state(client) == (None, context_fingerprint(root))


def test_rejected_derivation_clears_loaded_intent(client: "RaggerClient", navigator: Navigator,
                                                  device: Device, bitcoin_network: str):
    """Declining a new Screen 1 while an intent is loaded leaves no session → 00 00."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars, groups, keepers, challengers = _intent_1k1c(bitcoin_network)
    approve_vault_intent_with_nav(client, navigator, device, scalars, keepers, challengers,
                                  groups=groups)
    assert get_vault_state(client)[0] is not None

    payload = (bytes([len(VAULT_APP_NAME)]) + VAULT_APP_NAME
               + _encode_bip32_path(depositor_path(_coin_type(bitcoin_network)))
               + len(_DEFAULT_CONTEXT).to_bytes(2, "big") + _DEFAULT_CONTEXT)
    nav_instr, reject_instrs, search_text = derive_context_hash_reject_nav(device)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.transport_client.exchange_async(
            cla=CLA_VAULT,
            ins=INS_DERIVE_CONTEXT_HASH,
            p1=P1_INITIAL,
            p2=P2_SHOW,
            data=payload,
        ):
            navigator.navigate_until_text(
                navigate_instruction=nav_instr,
                validation_instructions=reject_instrs,
                text=search_text,
                screen_change_before_first_instruction=False,
            )
    assert exc.value.status == SW_DENY
    assert get_vault_state_raw(client) == _NOTHING_HELD


def test_invalid_scalars_clear_derived_root(client: "RaggerClient", navigator: Navigator,
                                            device: Device, bitcoin_network: str):
    """A P1=0x00 that fails validation drops the derived root too → 00 00."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=0)
    with pytest.raises(ExceptionRAPDU) as exc:
        _approve_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA
    assert get_vault_state_raw(client) == _NOTHING_HELD


def test_bad_p1_mid_load_keeps_session(client: "RaggerClient", navigator: Navigator,
                                       device: Device, bitcoin_network: str):
    """SW_WRONG_P1P2 in the middle of an intent load invalidates nothing; the load continues."""
    root = derive_for_intent(client, navigator, device, bitcoin_network)
    scalars, groups, _, _ = _intent_1k1c(bitcoin_network)
    _approve_exchange(client, P1_SCALARS, scalars)

    with pytest.raises(ExceptionRAPDU) as exc:
        _approve_exchange(client, P1_KEY_BATCH + 1, groups[0])
    assert exc.value.status == SW_WRONG_P1P2
    assert get_vault_state(client) == (None, context_fingerprint(root))
    _approve_exchange(client, P1_GROUP, groups[0])


def test_out_of_sequence_intent_apdu_keeps_session(client: "RaggerClient", navigator: Navigator,
                                                   device: Device, bitcoin_network: str):
    """P1=0x00 while an intent is loaded is refused with SW_BAD_STATE and invalidates nothing.

    This pins current behaviour as docs/apdu.md records it.  HLD v23 lists "APPROVE_VAULT_INTENT
    is called while an intent is loaded" among the invalidation triggers; the device does not
    implement that, and this test is the one to update if it ever does.
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars, groups, keepers, challengers = _intent_1k1c(bitcoin_network)
    approve_vault_intent_with_nav(client, navigator, device, scalars, keepers, challengers,
                                  groups=groups)
    loaded = get_vault_state_raw(client)

    with pytest.raises(ExceptionRAPDU) as exc:
        _approve_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_BAD_STATE
    assert get_vault_state_raw(client) == loaded


# ---------------------------------------------------------------------------
# Malformed calls
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("p1, p2, data, expected_sw", [
    (0x01, 0x00, b"", SW_WRONG_P1P2),
    (0x00, 0x01, b"", SW_WRONG_P1P2),
    (0xFF, 0xFF, b"", SW_WRONG_P1P2),
    (0x01, 0x00, b"\x00", SW_WRONG_P1P2),   # P1/P2 are checked before the length
    (0x00, 0x00, b"\x00", SW_WRONG_DATA_LENGTH),
    (0x00, 0x00, bytes(255), SW_WRONG_DATA_LENGTH),
])
def test_malformed_call_rejected_state_kept(client: "RaggerClient", navigator: Navigator,
                                            device: Device, bitcoin_network: str,
                                            p1: int, p2: int, data: bytes, expected_sw: int):
    """A malformed call gets a status word and changes nothing; the next query is unchanged."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    before = get_vault_state_raw(client)
    assert before != _NOTHING_HELD

    with pytest.raises(ExceptionRAPDU) as exc:
        get_vault_state_raw(client, p1, p2, data)
    assert exc.value.status == expected_sw
    assert get_vault_state_raw(client) == before
