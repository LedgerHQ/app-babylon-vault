"""Screen 9 — Reclaim: goldens, signing, cross-flow collisions and session states.

Reclaim is a standalone SIGN_PSBT flow: the depositor sweeps the claim reserve (PegIn
Output 1) back to their own address, P2TR(D).  Screen 9 is a consent screen — the
device proves where the funds go, not that the vault is redeemed — so its intro states
the risk before the amount, fee, address and PegIn txid are shown.

The validator's rejection matrix lives in test_sign_psbt_validate.py; this file covers
what needs the screen, a loaded session, or another pattern's validator.

Snapshots are stored under:
    tests/snapshots/<device>/screen9_reclaim/<test_case>_<network>/

Run with --golden_run to regenerate reference snapshots:

    pytest tests/test_screen9_reclaim.py --golden_run -k flex
"""

from __future__ import annotations

import re
from decimal import Decimal
from typing import TYPE_CHECKING, Dict, List, Optional

if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest

from ledgered.devices import Device
from ragger.navigator import Navigator

from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT

from test_utils import segwit_addr

from .vault_client import (
    SW_BAD_STATE,
    SW_DENY,
    SW_INCORRECT_DATA,
    capture_status_screen,
    get_vault_state_raw,
    record_screen_text,
    sign_psbt_with_nav_and_compare,
)
from .instructions import (
    sign_psbt_reclaim_approve_instructions,
    sign_psbt_reclaim_approve_nav,
    sign_psbt_reclaim_reject_instructions,
    sign_psbt_reclaim_reject_nav,
    sign_psbt_wc_reject_instructions,
    sign_psbt_wc_reject_nav,
)
from .test_get_vault_state import _NOTHING_HELD, _approve_prepegin_intent, _derive_silent
from .test_screen6_wc import _build_wc_psbt
from .test_sign_psbt_validate import (
    HARDENED,
    VAULT_DUST_LIMIT,
    _PREPEGIN_TXID,
    _RECLAIM_D_INDEX,
    _NoWalletPolicy,
    _add_foreign_p2tr_input,
    _add_p2tr_output,
    _assert_reclaim_refused,
    _assert_refused_unsigned,
    _assert_single_schnorr_sig,
    _bip86_p2tr_spk,
    _build_pegin_psbt,
    _build_reclaim_psbt,
    _depositor_pk,
    _reclaim_keys,
    _setup_s2_state,
    _standard_reclaim_psbt,
)


def _sign_reclaim_with_nav(client: "RaggerClient", navigator: Navigator, device: Device,
                           psbt: PSBT, testname: str, approve: bool):
    """Send `psbt`, approve or reject Screen 9, and compare every page against goldens."""
    wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    if device.is_nano:
        instructions = (sign_psbt_reclaim_approve_instructions(device) if approve
                        else sign_psbt_reclaim_reject_instructions(device))
        with capture_status_screen(navigator):
            return client.sign_psbt(psbt, wallet, None, navigator,
                                    testname=testname, instructions=instructions)
    nav = sign_psbt_reclaim_approve_nav(device) if approve else sign_psbt_reclaim_reject_nav(device)
    return sign_psbt_with_nav_and_compare(client, psbt, wallet, None, navigator,
                                          testname=testname, nav_instructions=nav)


# Nano labels a value split over several pages "Label (1/2)", "Label (2/2)".
_PAGE_COUNTER = re.compile(r"\(\d+/\d+\)$")


def _expected_review_values(psbt: PSBT, bitcoin_network: str) -> Dict[str, str]:
    """Screen 9 values computed from the PSBT alone, as the user would read them."""
    main = bitcoin_network == "main"
    ticker = "BTC" if main else "sBTC"
    output = psbt.tx.vout[0]
    fee = psbt.inputs[0].witness_utxo.nValue - output.nValue
    txid = psbt.tx.vin[0].prevout.hash.to_bytes(32, "little")[::-1]
    return {
        "amount reclaimed": f"{Decimal(output.nValue).scaleb(-8).normalize():f} {ticker}",
        "fee": f"{Decimal(fee).scaleb(-8).normalize():f} {ticker}",
        "reclaim address": segwit_addr.encode("bc" if main else "tb", 1, output.scriptPubKey[2:]),
        "pegin txid": txid.hex(),
    }


def _assert_review_shows(pages: List[List[str]], expected: Dict[str, str]) -> None:
    """Every expected value appears on the recorded screens.

    Whitespace and case are ignored: NBGL wraps values at arbitrary columns, and the txid
    is uppercase on the device.  Page counters are dropped so a value Nano splits over
    pages reads as one string.
    """
    shown = "".join("".join(text.split())
                    for page in pages for text in page
                    if not _PAGE_COUNTER.search(text)).lower()
    for field, value in expected.items():
        assert "".join(value.split()).lower() in shown, f"{field!r}: {value!r} not on screen"


def _approve_and_verify_reclaim(client: "RaggerClient", navigator: Navigator, device: Device,
                                bitcoin_network: str, psbt: Optional[PSBT] = None) -> None:
    """Sign the standard Reclaim (or `psbt`) through Screen 9, verify the signature under D
    and that the screens show the PSBT's values.

    Every caller compares against the same goldens, so a Reclaim signed from any session
    state, or with any PSBT that differs only off-screen, must also have shown exactly the
    same screens.
    """
    _, leaf_key, _ = _reclaim_keys(client, bitcoin_network)
    if psbt is None:
        psbt = _standard_reclaim_psbt(client, bitcoin_network)
    with record_screen_text(navigator) as pages:
        result = _sign_reclaim_with_nav(client, navigator, device, psbt,
                                        "screen9_reclaim/screen_" + bitcoin_network,
                                        approve=True)
    _assert_single_schnorr_sig(result, leaf_key, psbt=psbt)
    _assert_review_shows(pages, _expected_review_values(psbt, bitcoin_network))


# ===========================================================================
# Happy path and user rejection
# ===========================================================================

def test_sign_psbt_reclaim_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Show Screen 9 (Reclaim), approve it, and verify the signature and the displayed values.

    The goldens pin every review page.  The recorded screen text is checked against values
    computed from the PSBT, so a golden cannot hide a wrong value: amount reclaimed
    (Output 0), fee (input minus output), the reclaim address (bech32m of Output 0) and
    the PegIn txid (Input 0 prevout, in the byte order block explorers show).  The returned
    signature must verify against the depositor key D over the reviewed PSBT's sighash.
    """
    _approve_and_verify_reclaim(client, navigator, device, bitcoin_network)


def test_reject_reclaim_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """User rejects Screen 9 (Reclaim) → SW_DENY and nothing is signed."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    _assert_refused_unsigned(
        SW_DENY,
        lambda: _sign_reclaim_with_nav(client, navigator, device, psbt,
                                       "screen9_reclaim/reject_" + bitcoin_network,
                                       approve=False),
    )


@pytest.mark.parametrize("derivation", ["foreign_fingerprint", "non_bip86_path"])
def test_reclaim_output_derivation_is_not_read(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    derivation: str,
) -> None:
    """Reclaim signs through the same Screen 9 whatever TAP_BIP32_DERIVATION Output 0 carries.

    Output 0 is pinned to P2TR(D) and D is proven by Input 0's own entry, so the device
    reads no derivation for the output: a foreign fingerprint or a non-BIP-86 path on it
    changes neither the screens nor the signature.  The plain approval above is the case
    with no entry at all.
    """
    fingerprint, leaf_key, coin_type = _reclaim_keys(client, bitcoin_network)
    if derivation == "foreign_fingerprint":
        origin = KeyOriginInfo(
            b'\xff\xff\xff\xff',
            [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, _RECLAIM_D_INDEX],
        )
    else:
        origin = KeyOriginInfo(
            fingerprint,
            [HARDENED | 44, HARDENED | coin_type, HARDENED | 0, 0, _RECLAIM_D_INDEX],
        )
    psbt = _build_reclaim_psbt(fingerprint, leaf_key, coin_type, out_origin=origin)
    _approve_and_verify_reclaim(client, navigator, device, bitcoin_network, psbt)


# ===========================================================================
# Session-state independence
#
# Reclaim is standalone: it must sign identically from every state and leave the session
# exactly as it found it.  GET_VAULT_STATE pins the context and intent fingerprints before
# and after; in INTENT_LOADED the single-use Pre-PegIn signature then still goes through,
# which it would not if Reclaim had consumed its cap slot or invalidated the intent.
# ===========================================================================

@pytest.mark.parametrize("state", ["idle", "hash_derived", "intent_loaded"])
def test_reclaim_leaves_session_state_unchanged(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    state: str,
) -> None:
    """Reclaim signs through the same Screen 9 in IDLE, HASH_DERIVED and INTENT_LOADED,
    moves no signature counter and invalidates nothing.

    Signature counters exist only for an approved intent and reset on each approval, so
    IDLE and HASH_DERIVED hold none that Reclaim could move.  GET_VAULT_STATE does not
    return counters, so INTENT_LOADED shows it through the Pre-PegIn signature after
    the Reclaim, which a moved `pre_pegin_signed` (cap 1) would refuse."""
    prepegin = None
    if state == "hash_derived":
        _derive_silent(client, bitcoin_network)
    elif state == "intent_loaded":
        prepegin = _approve_prepegin_intent(client, navigator, device, bitcoin_network)
    before = get_vault_state_raw(client)
    assert (before == _NOTHING_HELD) == (state == "idle")

    _approve_and_verify_reclaim(client, navigator, device, bitcoin_network)
    assert get_vault_state_raw(client) == before

    if prepegin is not None:
        prepegin_psbt, wallet, _ = prepegin
        assert len(client.sign_psbt(prepegin_psbt, wallet, None)) == 1
        assert get_vault_state_raw(client) == before


def test_reclaim_leaves_pegin_slot_unspent(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """A PegIn still signs after a Reclaim: `pegin_signed` (cap 1) did not move.

    The intent here binds a PegIn-signable txid, which the Pre-PegIn intent of the
    session-state test does not, so the two tests cover different counters.
    """
    coin_type = 0 if bitcoin_network == "main" else 1
    depositor_pk = _depositor_pk(bitcoin_network)
    hashlock = _setup_s2_state(client, navigator, device, coin_type, _PREPEGIN_TXID)
    before = get_vault_state_raw(client)

    _approve_and_verify_reclaim(client, navigator, device, bitcoin_network)
    assert get_vault_state_raw(client) == before

    pegin_psbt = _build_pegin_psbt(depositor_pk, hashlock, _PREPEGIN_TXID)
    result = client.sign_psbt(pegin_psbt, _NoWalletPolicy("", "tr(@0/**)", []), None)
    _assert_single_schnorr_sig(result, depositor_pk, psbt=pegin_psbt)


# ===========================================================================
# Cross-flow collisions
#
# Reclaim's neighbours on input and output count share its 34-byte leaf.  Each is routed
# to the pattern that owns that shape and refused there, never signed as a Reclaim.  Where
# the owning validator answers SW_BAD_STATE outside INTENT_LOADED, that status word is
# what shows it, and not Reclaim's validator, made the call.
# ===========================================================================

# Output 0 value that leaves room for added outputs: the base app refuses a PSBT whose
# outputs exceed its inputs, so one that did would never reach the validator under test.
_ROOM_FOR_OUTPUTS = 1_000_000

def test_reclaim_two_inputs_rejected_by_payout_gate(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """2 inputs, 1 output in INTENT_LOADED goes to _validate_payout, which refuses it:
    Input 0's prevout is no PegIn of the loaded intent.  The session survives."""
    _approve_prepegin_intent(client, navigator, device, bitcoin_network)
    loaded = get_vault_state_raw(client)

    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    _add_foreign_p2tr_input(psbt, 10_000, tag=0x42)
    _assert_reclaim_refused(client, psbt)
    assert get_vault_state_raw(client) == loaded


@pytest.mark.parametrize("state, expected_sw", [
    ("idle", SW_BAD_STATE),               # NoPayout needs a loaded intent
    ("intent_loaded", SW_INCORRECT_DATA), # NoPayout wants a 68-byte Assert:0 leaf
])
def test_reclaim_three_inputs_rejected_by_nopayout_gate(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
    state: str,
    expected_sw: int,
) -> None:
    """3 inputs, 1 output goes to _validate_nopayout in every state, never to Reclaim."""
    if state == "intent_loaded":
        _approve_prepegin_intent(client, navigator, device, bitcoin_network)
    before = get_vault_state_raw(client)

    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    _add_foreign_p2tr_input(psbt, 10_000, tag=0x42)
    _add_foreign_p2tr_input(psbt, 10_000, tag=0x43)
    _assert_reclaim_refused(client, psbt, expected_sw)
    assert get_vault_state_raw(client) == before


def test_reclaim_two_outputs_rejected_by_claim(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """1 input, 2 outputs goes to _validate_display_claim and is refused on Claim's own
    rules, not accepted as a Reclaim.

    Output 1 is the dust CPFP anchor to P2TR(D) that Claim expects, so the PSBT is
    Claim-shaped except for Reclaim's RBF sequence, which Claim's SEQUENCE_FINAL rule
    refuses.
    """
    _, leaf_key, _ = _reclaim_keys(client, bitcoin_network)
    psbt = _standard_reclaim_psbt(client, bitcoin_network)
    _add_p2tr_output(psbt, VAULT_DUST_LIMIT, _bip86_p2tr_spk(leaf_key))
    _assert_reclaim_refused(client, psbt)


def test_reclaim_three_outputs_rejected_by_pegin_gate(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """1 input, 3 outputs is PegIn's shape; it is routed to _validate_pegin before the
    leaf dispatcher, which refuses it outside INTENT_LOADED."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network, reclaimed_value=_ROOM_FOR_OUTPUTS)
    _add_p2tr_output(psbt, 1_000, bytes([0x51, 0x20]) + bytes([0x61] * 32))
    _add_p2tr_output(psbt, 1_000, bytes([0x51, 0x20]) + bytes([0x62] * 32))
    _assert_reclaim_refused(client, psbt, SW_BAD_STATE)


def test_reclaim_four_outputs_rejected_by_dispatcher(
    client: "RaggerClient",
    bitcoin_network: str,
) -> None:
    """1 input, 4 outputs owns no shape gate: the leaf dispatcher sees <D> OP_CHECKSIG
    with an output count that is neither Claim's 2 nor Reclaim's 1 and refuses it."""
    psbt = _standard_reclaim_psbt(client, bitcoin_network, reclaimed_value=_ROOM_FOR_OUTPUTS)
    for tag in (0x61, 0x62, 0x63):
        _add_p2tr_output(psbt, 1_000, bytes([0x51, 0x20]) + bytes([tag] * 32))
    _assert_reclaim_refused(client, psbt)


def test_wc_leaf_with_one_output_routes_to_wc(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """A 73-byte WronglyChallenged leaf with 1 output shares Reclaim's input and output
    counts, but routes to _validate_display_wc: the device shows Screen 6 — compared
    against the Screen 6 reject goldens — not Screen 9.  Rejecting it signs nothing."""
    coin_type = 0 if bitcoin_network == "main" else 1
    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]
    psbt = _build_wc_psbt(fingerprint, leaf_key, coin_type)
    assert len(psbt.tx.vin) == 1 and len(psbt.tx.vout) == 1
    wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen6_wc/reject_" + bitcoin_network

    def send():
        if device.is_nano:
            with capture_status_screen(navigator):
                return client.sign_psbt(psbt, wallet, None, navigator, testname=tname,
                                        instructions=sign_psbt_wc_reject_instructions(device))
        return sign_psbt_with_nav_and_compare(client, psbt, wallet, None, navigator,
                                              testname=tname,
                                              nav_instructions=sign_psbt_wc_reject_nav(device))

    _assert_refused_unsigned(SW_DENY, send)
