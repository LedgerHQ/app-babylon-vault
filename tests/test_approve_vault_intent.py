"""
Ragger integration tests for APPROVE_VAULT_INTENT (INS 0x80).

Device: Speculos emulator seeded with the default test mnemonic (see conftest.py).
Happy-path tests navigate the approval screen and perform golden snapshot comparison.
Error-path tests fail before the display is shown and need no navigation.

Test keys are synthetic 32-byte values chosen so they:
  - are lexicographically sorted within each group
  - are globally distinct
  - do not equal VP_KEY or the depositor x-only pubkey for the test seed
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

import pytest
from ledgered.devices import Device
from ragger.error import ExceptionRAPDU
from ragger.navigator import Navigator

from .instructions import vault_intent_steps, vault_intent_reject_instructions
from .vault_client import (
    approve_vault_intent_with_nav,
    build_intent_tlv,
    build_group_tlv,
    derive_for_intent,
    depositor_path,
    CLA_VAULT,
    INS_APPROVE_VAULT_INTENT,
    P1_SCALARS,
    P1_GROUP,
    P1_KEY_BATCH,
    P2_UNUSED,
    SW_OK,
    SW_DENY,
    SW_INCORRECT_DATA,
    SW_WRONG_P1P2,
    SW_BAD_STATE,
    VAULT_STRUCTURE_TYPE,
    VAULT_PROTOCOL_VERSION,
    TAG_STRUCTURE_TYPE,
    TAG_COIN_TYPE,
    TAG_PEGIN_CSV_TIMELOCK,
    TAG_KEEPER_COUNT,
    TAG_KEEPER_PK,
    TAG_CHALLENGER_PK,
    TEST_VP_KEY,
    TEST_VALID_KEYS,
    TEST_INVALID_XONLY_KEY,
    TEST_DEPOSITOR_XONLY_MAINNET,
    TEST_DEPOSITOR_XONLY_TESTNET,
    _ktlv,
)

HARDENED = 0x80000000


SCREENSHOT_PATH = Path(__file__).parent.resolve()

# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------

VP_KEY = TEST_VP_KEY

# Pre-PegIn txid placeholder
TXID = bytes(range(32))

# Valid secp256k1 x-only keys for use in happy-path and error tests.
# Taken from TEST_VALID_KEYS (sorted ascending, all verified curve points).
KEY_A = TEST_VALID_KEYS[0]
KEY_B = TEST_VALID_KEYS[1]
KEY_C = TEST_VALID_KEYS[2]


def _coin_type(network: str) -> int:
    return 0 if network == "main" else 1


def _make_scalars(network: str, **overrides) -> bytes:
    """Build a valid P1=0x00 TLV scalar payload (v21 2-byte tags, 13 scalar fields)."""
    ct = _coin_type(network)
    defaults = dict(
        coin_type=ct,
        base_fee_rate=10,
        pegin_csv_timelock=100,
        payout_timelock=200,
        prepegin_txid=TXID,
        htlc_refund_timelock=144,
        depositor_path=depositor_path(ct),
        keeper_count=1,
        challenger_count=1,
        prepegin_max_fee=500_000,
        vault_count=1,
    )
    defaults.update(overrides)
    return build_intent_tlv(**defaults)


def _make_group(**overrides) -> bytes:
    """Build a valid P1=0x01 group TLV with optional field overrides."""
    defaults = dict(
        htlc_vout=0,
        vault_provider_pk=VP_KEY,
        vault_amount=100_000,
        commission_fee=1_000,
        depositor_claim_value=10_000,
        pegin_max_fee=50_000,
    )
    defaults.update(overrides)
    return build_group_tlv(**defaults)


def _raw_exchange(client, p1: int, data: bytes):
    """Send one APPROVE_VAULT_INTENT APDU; returns response or raises ExceptionRAPDU."""
    return client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=p1,
        p2=P2_UNUSED,
        data=data,
    )


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------

def test_minimal_1_keeper_1_challenger(client: RaggerClient, navigator: Navigator,
                                       device: Device, bitcoin_network: str):
    """Load a minimal intent (1 keeper, 1 challenger) end-to-end → SW_OK."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=[_make_group()],
                                  path=SCREENSHOT_PATH,
                                  test_case_name="screen2_vault_intent/1k1c_" + bitcoin_network,
                                  n_swipes=vault_intent_steps(device, 1, 1))



# 64 distinct valid secp256k1 x-only keys for the max-capacity test.
# Generated deterministically as SHA256("vault-max-test-" || i.to_bytes(4)) mod n,
# then sorted across all 64 and split: first 32 → keepers, last 32 → challengers.
# Both groups satisfy the firmware's strict-ascending lex-order constraint.
_MAX_KEEPERS = [
    bytes.fromhex("059FD0E1F9598D5539BE3688AB5D800C48191DC0560E0EE0E4CFEF40DF5E05F8"),
    bytes.fromhex("0A1615FD12BE8A9F065B7B0D76DDD79EFAED6ECE2733AA2F52519DD8D0499E08"),
    bytes.fromhex("0AFCD6753ADD83748F26FD42974FF1C2C90A8694A11A38EDE5420DB6D67F881C"),
    bytes.fromhex("0DFBD58C8A40BDBA35C3418E8B771577BE095B12FF1641C56C7DCB8AC95E1B2D"),
    bytes.fromhex("1137B7EFFCC8A846E16F1DAA1765C38AABAB1161969D3320B9994047D621ECD8"),
    bytes.fromhex("133FB4CEA2D84B605FD1B018A75808348D02DAFF9269FCD90E5A0E406E017314"),
    bytes.fromhex("1349C0FB855BE10CE20F90F36293B545AB4695E481B9CF9B167882E494E05C74"),
    bytes.fromhex("1795C824D499BC8714DE84F96E4280CB5CA9B2B9332126D00FBD8E0892D4F207"),
    bytes.fromhex("188E2493AAB749581D1593AE63BB33F88BF991409ED9C58C56389018F4B986CB"),
    bytes.fromhex("1A742A0B73445616F1265F0E1B4B56EB2F0ED20251F044C3EF84DA26BAFB3038"),
    bytes.fromhex("1F2B781DEBC68FCDF06E57E8E48EF1720E206683D187BC526817590746D90BB4"),
    bytes.fromhex("2159B403647F8549DB9A7762A50A97C03F8827B451035B2349A34AD72376F571"),
    bytes.fromhex("21BDCEF58E1583C7F69CA64058B3F7F82E2D4AA8B17E15F6B810486639846C67"),
    bytes.fromhex("2447714B6A00278F5E5C62F08DA3F2ECF9621A071508C60B6886CEB7E5D88C47"),
    bytes.fromhex("25F4C6E33E252A49E168E9FEE26D7DFD30A8D1A11DFC88EB273D7C1573E7222A"),
    bytes.fromhex("2A9FA7B9DCBF8932905D342BC0616850592016024BEC15EAB674CAB114040BEF"),
    bytes.fromhex("2E0858119873E282BF50A21FFD37DB5AC0D12A50A350318ACAE4EF77366A0F05"),
    bytes.fromhex("3C36CDAEED2EC52691639AD7AC86A7A25F5F242BF52BF6B20802E9EFB2F8592D"),
    bytes.fromhex("3C9C0E1B9E4040F54D5DEF2E0EB6DED2D936BB648F50149473E892494436D5D8"),
    bytes.fromhex("42B4D64BF3EAE776F05BC6990007F5DDDC0A582DFFACBE78F4DC8B08693178E0"),
    bytes.fromhex("4384C23499486938679838EAC29FE180E3E9B26683610F771DBE92102C2DE660"),
    bytes.fromhex("441073820096F4A48815A17F909A6DC1C41AB1FFD9C83B1A85ED960F9C45ED6E"),
    bytes.fromhex("477286E39A7E68F7BE0A830A09137BE497954DC732EADBE65FD57486BD5D31F9"),
    bytes.fromhex("4862E535101A93C90C1A5A2DB7508ED4D730ED50DDE350C47E7269EFC3ACED5D"),
    bytes.fromhex("4E2011581490E4FCFF994671172657FE300ED1280E85AE933B8A677BDB694A7D"),
    bytes.fromhex("5209CA39F4EB74C95F2F5DA3B503A6E44CCE43795D2DD2C5BDCFB66A761B04CB"),
    bytes.fromhex("5553CC539D0384BD67276D2C4570D6575C276AED7F913FE130A0577B6E555584"),
    bytes.fromhex("5562C3546160D3714591930FE5AF3E149AA911F71AA1D4DAED64334C260CCA7B"),
    bytes.fromhex("56F9BF3A4DC85E6C96CEB06FF4BDA8C41E755AF9C541D8A22E52E5871D3D0672"),
    bytes.fromhex("5DD52C8299E71BA83B559C909DF43C48537B2AA86235F51B1ADE7DF7D7767A23"),
    bytes.fromhex("62AE2A02FF82C12153A195AD07E780893EE3A83B6D0F92ED8DFA62D641CAC791"),
    bytes.fromhex("6AFE1756FCC3D21D7A35DD4233CD83ED0CAED2648A667FB8D9EBE504D17D36B8"),
]
_MAX_CHALLENGERS = [
    bytes.fromhex("6E0C66F2425D2E52C96BA61461A1DCF7B96A718D6EA58AFEBCAF157811DA3103"),
    bytes.fromhex("708AD140ABD772D4A723FC3C06FAAC24E4D5CBDC73BE3F547FDE37058571CBEB"),
    bytes.fromhex("712AD75DD4BFB6971A83EC958A1AC9E9C0E92E8D05E0744831BA69734149B06C"),
    bytes.fromhex("7662E6906F890D5DAD00C9CA945C902030142CB05F7044179F4CA2BF0B56EDF0"),
    bytes.fromhex("797D0F6A35584D925AAD54B75A5A420DA3BA65F2F3291099F8F6641ADC4D71AB"),
    bytes.fromhex("8349273DF768E8652C3429975E8C0F4E140D6CD6C8F18EDD7C25669E9B33E960"),
    bytes.fromhex("8791F03B6FC7F5C6B8F668269DF54C4441F94E0451FF5E29A0BE23ED6CC298DC"),
    bytes.fromhex("8859C984AE1FC4BDA0D4844D87FF8F277FE022BC56091B8EFB925E85A2955172"),
    bytes.fromhex("88FFFC66913ECFB54590D099DD528D95A18A8FA018CA05AFDF94BB585909DB11"),
    bytes.fromhex("890ADFD24DA074252DCDA300182F73E82DB6253E9C49BC79CBDFC73D31453120"),
    bytes.fromhex("903C5528E4E0DA8EB1B2A01FEBB079A0695B4597A6CF99066AF3E0889B98CD61"),
    bytes.fromhex("971BCBA3698270E45C4EFF62DAFE5AA7B1318662C16FC7EC9DF78DDE94F4EBD5"),
    bytes.fromhex("991D0D1F252017AE2AD6F5DC27EF4C686919A2FAF557BA26D0A421A79B0085F5"),
    bytes.fromhex("9B1DB5ECA5CA589B6446116659AEB94755C492B890DD144BEC4C0F29AD9285C4"),
    bytes.fromhex("9B6D3C7207E57E1F451E881B694D8A12B1C8A736E83FBB97A76C9FB8E37FA329"),
    bytes.fromhex("9B77C2B9F743A8819E271C8FB79E83239BECB1F6FA892DF2B4A20A3BB87EC295"),
    bytes.fromhex("A590BFEC07DA7A363A87C20B0933C3EC7FC7ABDE14A9265FEB640836F41CB275"),
    bytes.fromhex("A7D2B3AA2F34054AA5856B899E448ABF1A320000C4C1E115B9AA36F956EE9D0B"),
    bytes.fromhex("A83848C16A33C24192ABA7199D1F8BB4A14FC4E56EA7B6141837D5E01BB04E9B"),
    bytes.fromhex("AB482624FED8D46A4B5016E789AC66E4855E573D57634BE856C25E27C1D08EED"),
    bytes.fromhex("AF458B39361F009DE420F7827067E34C6F797BB14CAE6305CB90E98312B98DBC"),
    bytes.fromhex("B784F3180962A8603635029328D2D461E9E84961DC03F532EE0FFEBA461D5AAD"),
    bytes.fromhex("B8F76C9393D81C42E6D7D1C806228F1271DD04561264D8AA76152062924B4104"),
    bytes.fromhex("BC33684ADE4E7FDE5945E742CE0DAC6B3AF3613AB1E2D5783D9B4D88B478D495"),
    bytes.fromhex("C1FFABF11C11FF994D072F5E1F739DAF1E047AFB4152E241C44FF17AB920D3AE"),
    bytes.fromhex("C3F0D74F26B04B2823C5D49F7D602B5074C1316E7803E6F10B03228A27147661"),
    bytes.fromhex("CC58938284E57459308F69D44293A3BB55011E8CCC192FD154F825F6B54D2062"),
    bytes.fromhex("CE39D6B0E2B74BD537E40F675DF9ECB5E0F3BC384DDB9654B20B70BDCDF92A49"),
    bytes.fromhex("CF21F0E08DD78AB7CFCF4D692F83DF1B0AD4089458565464E1ADA406C8722C7C"),
    bytes.fromhex("D49860504ECF5B5A582201B55CAC1C3C242EAFA43725524CB717EC1683109111"),
    bytes.fromhex("D552DE8E643ADE216DF460600CF342E0CB3D5A6988FEDD2D1332957E1F4499D0"),
    bytes.fromhex("D856987DA34A9EB399138DDF33222E19C773F3426CF2ED37A84EF62C14F69D23"),
]


def test_max_32_keepers_32_challengers(client: RaggerClient, navigator: Navigator,
                                        device: Device, bitcoin_network: str):
    """32 keepers + 32 challengers — firmware maximum (VAULT_MAX_KEEPERS/CHALLENGERS = 32).

    Sends 64 keys in 10 P1=0x01 batches (9 × 7 keys + 1 × 1 key).
    Uses a deterministic step count (not text-based navigation) to avoid a race in
    navigate_until_text_and_compare where the swipe animation can fire one extra tick
    between wait_for_screen_change() and compare_screen_with_text(), causing the last
    content screenshot (last challenger) to be skipped on flex/apex_p.
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=32, challenger_count=32)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=_MAX_KEEPERS,
                                  challenger_pks=_MAX_CHALLENGERS,
                                  groups=[_make_group()],
                                  path=SCREENSHOT_PATH,
                                  test_case_name="screen2_vault_intent/max_32k32c_" + bitcoin_network,
                                  n_swipes=vault_intent_steps(device, 1, 32))


def test_reload_intent_invalidates_previous(client: RaggerClient, navigator: Navigator,
                                            device: Device, bitcoin_network: str):
    """Loading a second intent while one is active must succeed (session reset)."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    grp = [_make_group()]
    # First load — approve the screen
    derive_for_intent(client, navigator, device, bitcoin_network)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=grp,
                                  path=SCREENSHOT_PATH,
                                  test_case_name="screen2_vault_intent/reload_1_" + bitcoin_network,
                                  n_swipes=vault_intent_steps(device, 1, 1))
    # Second load — derive first to reach HASH_DERIVED, then handler invalidates the
    # first session and shows the screen again
    derive_for_intent(client, navigator, device, bitcoin_network)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=grp,
                                  path=SCREENSHOT_PATH,
                                  test_case_name="screen2_vault_intent/reload_2_" + bitcoin_network,
                                  n_swipes=vault_intent_steps(device, 1, 1))


def test_session2_preimage_survives_approve_vault_intent(client: RaggerClient, navigator: Navigator,
                                                          device: Device, bitcoin_network: str):
    """Session 2 setup: DERIVE_CONTEXT_HASH (single APDU) followed by APPROVE_VAULT_INTENT
    must complete without error and leave the session in INTENT_LOADED.

    This exercises the HASH_DERIVED → (invalidate+restore) → INTENT_LOADED path in
    approve_vault_intent.c::handle_scalar_payload, where the derived root is preserved
    across the reset.  The device never returns the root again (the host already holds it
    from DERIVE_CONTEXT_HASH), so we verify externally only that the full sequence is
    accepted and the resulting state is INTENT_LOADED.
    """
    # Step 1 — DERIVE_CONTEXT_HASH (single APDU) stores the root and reaches HASH_DERIVED.
    root = derive_for_intent(client, navigator, device, bitcoin_network)
    assert len(root) == 32

    # Step 2 — APPROVE_VAULT_INTENT must accept the HASH_DERIVED state and succeed.
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=[_make_group()],
                                  path=SCREENSHOT_PATH,
                                  test_case_name="screen2_vault_intent/session2_survive_" + bitcoin_network,
                                  n_swipes=vault_intent_steps(device, 1, 1))

    # Step 3 — state is INTENT_LOADED; P1=0x01 without a preceding P1=0x00 must fail
    # with SW_BAD_STATE (scalars_loaded == false).
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, KEY_A)
    assert exc.value.status == SW_BAD_STATE


def test_approve_resets_session_derive_can_run(client: RaggerClient, navigator: Navigator,
                                                device: Device, bitcoin_network: str):
    """After a successful approve, DERIVE_CONTEXT_HASH must reset state back to IDLE.

    Replaces the skipped test in test_derive_context_hash.py.
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=[_make_group()],
                                  path=SCREENSHOT_PATH,
                                  test_case_name="screen2_vault_intent/reset_session_" + bitcoin_network,
                                  n_swipes=vault_intent_steps(device, 1, 1))

    # DERIVE_CONTEXT_HASH invalidates any loaded intent per spec.
    root = derive_for_intent(client, navigator, device, bitcoin_network)
    assert len(root) == 32

    # State is now IDLE — P1=0x01 without prior P1=0x00 must fail.
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, KEY_A)
    assert exc.value.status == SW_BAD_STATE


# ---------------------------------------------------------------------------
# P1=0x00 scalar errors
# ---------------------------------------------------------------------------

def test_p1_key_batch_before_scalars(client: RaggerClient):
    """P1=0x01 with no prior P1=0x00 must return SW_BAD_STATE."""
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, KEY_A)
    assert exc.value.status == SW_BAD_STATE


def test_invalid_p1(client: RaggerClient):
    """Unknown P1 must return SW_WRONG_P1P2."""
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, 0x42, b"data")
    assert exc.value.status == SW_WRONG_P1P2


def test_wrong_structure_type(client: RaggerClient, bitcoin_network: str):
    """Wrong structure_type constant must return SW_INCORRECT_DATA."""
    bad_tlv = _make_scalars(bitcoin_network).replace(
        bytes([TAG_STRUCTURE_TYPE, 1, VAULT_STRUCTURE_TYPE]),
        bytes([TAG_STRUCTURE_TYPE, 1, VAULT_STRUCTURE_TYPE + 1]),
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, bad_tlv)
    assert exc.value.status == SW_INCORRECT_DATA


def test_wrong_coin_type(client: RaggerClient, bitcoin_network: str):
    """coin_type field not matching the active network must return SW_INCORRECT_DATA."""
    wrong_ct = 99
    scalars = _make_scalars(
        bitcoin_network,
        coin_type=wrong_ct,
        depositor_path=depositor_path(wrong_ct),
    )
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pegin_csv_below_min(client: RaggerClient, bitcoin_network: str):
    """pegin_csv_timelock = 71 (below minimum 72) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, pegin_csv_timelock=71)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_htlc_refund_timelock_at_max(client: RaggerClient, bitcoin_network: str):
    """htlc_refund_timelock = 4320 (maximum per v22) must be accepted."""
    scalars = _make_scalars(bitcoin_network, htlc_refund_timelock=4320)
    _raw_exchange(client, P1_SCALARS, scalars)  # must not raise


def test_htlc_refund_timelock_over_max(client: RaggerClient, bitcoin_network: str):
    """htlc_refund_timelock = 4321 (above v22 maximum 4320) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, htlc_refund_timelock=4321)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_keeper_count_zero(client: RaggerClient, bitcoin_network: str):
    """keeper_count = 0 must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=0)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_duplicate_tlv_tag(client: RaggerClient, bitcoin_network: str):
    """TLV payload with a duplicate tag must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network)
    # Append a second TAG_VERSION (0x0002) at the end — 2-byte tag, 1-byte length, value.
    # The parser sees the first TAG_VERSION during normal field collection, then hits the
    # duplicate on the appended entry and rejects it.
    bad_tlv = scalars + bytes([0x00, 0x02, 1, VAULT_PROTOCOL_VERSION])
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, bad_tlv)
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# P1=0x01 key batch errors
# ---------------------------------------------------------------------------

def test_keys_out_of_order(client: RaggerClient, navigator: Navigator,
                           device: Device, bitcoin_network: str):
    """Keepers sent in descending lex order must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=2, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        # KEY_B > KEY_A — send in wrong order (B then A); KEY_C is challenger
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, KEY_B) +
                      _ktlv(TAG_KEEPER_PK, KEY_A) +
                      _ktlv(TAG_CHALLENGER_PK, KEY_C))
    assert exc.value.status == SW_INCORRECT_DATA


def test_wrong_phase_tag_challenger_before_keepers(client: RaggerClient, navigator: Navigator,
                                                   device: Device, bitcoin_network: str):
    """TAG_CHALLENGER_PK sent while keepers are still expected must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, _ktlv(TAG_CHALLENGER_PK, KEY_A))
    assert exc.value.status == SW_INCORRECT_DATA


def test_extra_keys_beyond_count(client: RaggerClient, navigator: Navigator,
                                 device: Device, bitcoin_network: str):
    """Sending more keys than keeper_count + challenger_count must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        # declared total = 2, send 3
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, KEY_A) +
                      _ktlv(TAG_CHALLENGER_PK, KEY_B) +
                      _ktlv(TAG_CHALLENGER_PK, KEY_C))
    assert exc.value.status == SW_INCORRECT_DATA


def test_key_batch_wrong_key_length(client: RaggerClient, navigator: Navigator,
                                    device: Device, bitcoin_network: str):
    """P1=0x02 TLV entry with length != 32 must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        # TAG_KEEPER_PK with length=31 (wrong, must be 32)
        _raw_exchange(client, P1_KEY_BATCH, bytes([0x01, 0x07, 0x1F]) + b"\xAA" * 31)
    assert exc.value.status == SW_INCORRECT_DATA


def test_key_batch_empty_payload(client: RaggerClient, navigator: Navigator,
                                 device: Device, bitcoin_network: str):
    """Empty key batch (lc=0) must return SW_OK — firmware treats it as a partial delivery."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    response = _raw_exchange(client, P1_KEY_BATCH, b"")
    assert response.status == SW_OK


def test_key_equals_vault_provider_pk(client: RaggerClient, navigator: Navigator,
                                      device: Device, bitcoin_network: str):
    """A keeper key equal to vault_provider_pk must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    # _make_group() sets vault_provider_pk=VP_KEY by default.
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, VP_KEY) +
                      _ktlv(TAG_CHALLENGER_PK, KEY_B))
    assert exc.value.status == SW_INCORRECT_DATA


def test_invalid_ec_point_vault_provider_pk_rejected(client: RaggerClient, bitcoin_network: str):
    """vault_provider_pk whose x-coordinate is not on secp256k1 must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    with pytest.raises(ExceptionRAPDU) as exc:
        # TEST_INVALID_XONLY_KEY = 0xFF * 32 which is >= secp256k1 prime p.
        _raw_exchange(client, P1_GROUP, _make_group(vault_provider_pk=TEST_INVALID_XONLY_KEY))
    assert exc.value.status == SW_INCORRECT_DATA


def test_duplicate_key_across_groups(client: RaggerClient, navigator: Navigator,
                                     device: Device, bitcoin_network: str):
    """A challenger key identical to a keeper key must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        # Keeper = KEY_A, Challenger = KEY_A (duplicate)
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, KEY_A) +
                      _ktlv(TAG_CHALLENGER_PK, KEY_A))
    assert exc.value.status == SW_INCORRECT_DATA


def test_invalid_ec_point_keeper_rejected(client: RaggerClient, navigator: Navigator,
                                          device: Device, bitcoin_network: str):
    """A keeper key whose x-coordinate is not on secp256k1 must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        # TEST_INVALID_XONLY_KEY is >= secp256k1 prime p — no valid curve point.
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, TEST_INVALID_XONLY_KEY) +
                      _ktlv(TAG_CHALLENGER_PK, KEY_B))
    assert exc.value.status == SW_INCORRECT_DATA


def test_invalid_ec_point_challenger_rejected(client: RaggerClient, navigator: Navigator,
                                              device: Device, bitcoin_network: str):
    """A challenger key whose x-coordinate is not on secp256k1 must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        # TEST_INVALID_XONLY_KEY is >= secp256k1 prime p — no valid curve point.
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, KEY_A) +
                      _ktlv(TAG_CHALLENGER_PK, TEST_INVALID_XONLY_KEY))
    assert exc.value.status == SW_INCORRECT_DATA


def test_depositor_key_collision_as_keeper(client: RaggerClient, navigator: Navigator,
                                           device: Device, bitcoin_network: str):
    """Keeper key equal to the device's depositor x-only key must return SW_INCORRECT_DATA.

    The firmware derives the depositor pubkey via crypto_get_compressed_pubkey_at_path
    after all keys are received, then calls vault_check_depositor_uniqueness which scans
    vault_provider_pk, keeper_pks[], and challenger_pks[].  This test exercises the
    keeper_pks[] branch.

    The depositor x-only values are pre-computed from the test mnemonic (conftest.py)
    at m/86'/coin_type'/0'/0/0 using BIP-32 key derivation.
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    depositor_key = (TEST_DEPOSITOR_XONLY_MAINNET if bitcoin_network == "main"
                     else TEST_DEPOSITOR_XONLY_TESTNET)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    # depositor_key as keeper (idx=0, first in group → no lex-order check).
    # KEY_A as challenger: distinct from depositor_key and from VP_KEY.
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, depositor_key) +
                      _ktlv(TAG_CHALLENGER_PK, KEY_A))
    assert exc.value.status == SW_INCORRECT_DATA


def test_depositor_key_collision_as_challenger(client: RaggerClient, navigator: Navigator,
                                               device: Device, bitcoin_network: str):
    """Challenger key equal to the device's depositor x-only key must return SW_INCORRECT_DATA.

    Same as test_depositor_key_collision_as_keeper but exercises the challenger_pks[]
    branch of vault_check_depositor_uniqueness.
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    depositor_key = (TEST_DEPOSITOR_XONLY_MAINNET if bitcoin_network == "main"
                     else TEST_DEPOSITOR_XONLY_TESTNET)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    # KEY_A as keeper, depositor_key as challenger (idx=1, first in challenger group
    # → no lex-order check; KEY_A != depositor_key so no duplicate rejection).
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, KEY_A) +
                      _ktlv(TAG_CHALLENGER_PK, depositor_key))
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# Session state isolation
# ---------------------------------------------------------------------------

def test_derive_initial_clears_scalars_loaded(client: RaggerClient, navigator: Navigator,
                                               device: Device, bitcoin_network: str):
    """DERIVE_CONTEXT_HASH P1=0x00 must clear G_approve_intent_state even when state is IDLE.

    Before the fix, handle_initial_chunk only called vault_context_invalidate() when
    state != IDLE, so G_approve_intent_state.scalars_loaded survived a mid-approve
    injection of DERIVE_CONTEXT_HASH P1=0x00.  A subsequent APPROVE_VAULT_INTENT P1=0x01
    would then pass its scalars_loaded gate with stale state.

    After the fix, handle_initial_chunk unconditionally zeroes G_approve_intent_state,
    so the key-batch must be rejected with SW_BAD_STATE.
    """
    # Send APPROVE_VAULT_INTENT P1=0x00 — sets scalars_loaded=true, state stays IDLE.
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)

    # Inject DERIVE_CONTEXT_HASH P1=0x00 — must clear G_approve_intent_state.
    derive_for_intent(client, navigator, device, bitcoin_network)

    # APPROVE_VAULT_INTENT P1=0x02 must now fail because scalars_loaded == false.
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + KEY_B)
    assert exc.value.status == SW_BAD_STATE


# ---------------------------------------------------------------------------
# TLV field range validation
# ---------------------------------------------------------------------------

def test_base_fee_rate_overflow_rejected(client: RaggerClient, bitcoin_network: str):
    """base_fee_rate > UINT32_MAX must return SW_INCORRECT_DATA.

    The field is encoded as a uint64 on the wire; the firmware rejects values that
    exceed UINT32_MAX so the display cast to (unsigned) is always safe.
    """
    scalars = _make_scalars(bitcoin_network, base_fee_rate=0x100000000)  # 2^32
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# P1=0x01 vault-group phase — NAPPS-1442 acceptance criteria
# ---------------------------------------------------------------------------

def test_10_vault_groups_accepted(client: RaggerClient, navigator: Navigator,
                                   device: Device, bitcoin_network: str):
    """10-vault intent: all 10 P1=0x01 groups accepted in ascending htlc_vout order.

    Uses deterministic step counts (not text-based navigation) to avoid the
    navigate_until_text_and_compare race that duplicates a frame when the swipe
    animation fires between wait_for_screen_change() and compare_screen_with_text().
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    groups = [_make_group(htlc_vout=i, vault_amount=100_000 * (i + 1)) for i in range(10)]
    scalars = _make_scalars(bitcoin_network, vault_count=10, keeper_count=1, challenger_count=1)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=groups,
                                  path=SCREENSHOT_PATH,
                                  test_case_name="screen2_vault_intent/10vault_1k1c_" + bitcoin_network,
                                  n_swipes=vault_intent_steps(device, 10, 1))


def test_10_vaults_32_keepers_32_challengers(client: RaggerClient, navigator: Navigator,
                                              device: Device, bitcoin_network: str):
    """10-vault intent with the firmware-maximum 32 keepers + 32 challengers.

    Combines the multi-vault streaming path (P1=0x01 × 10) with the largest possible
    key set (64 keys in 10 P1=0x02 batches).
    """
    derive_for_intent(client, navigator, device, bitcoin_network)
    groups = [_make_group(htlc_vout=i, vault_amount=100_000 * (i + 1)) for i in range(10)]
    scalars = _make_scalars(bitcoin_network, vault_count=10,
                            keeper_count=32, challenger_count=32)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=_MAX_KEEPERS,
                                  challenger_pks=_MAX_CHALLENGERS,
                                  groups=groups,
                                  path=SCREENSHOT_PATH,
                                  test_case_name="screen2_vault_intent/10vault_32k32c_" + bitcoin_network,
                                  n_swipes=vault_intent_steps(device, 10, 32))


def test_htlc_vout_equal_rejected(client: RaggerClient, bitcoin_network: str):
    """Two groups with equal htlc_vout must return SW_INCORRECT_DATA (not strictly ascending)."""
    scalars = _make_scalars(bitcoin_network, vault_count=2, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=3))
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=3))  # equal
    assert exc.value.status == SW_INCORRECT_DATA


def test_missing_group_phase_rejected(client: RaggerClient, bitcoin_network: str):
    """P1=0x02 sent with no prior P1=0x01 groups must return SW_BAD_STATE."""
    scalars = _make_scalars(bitcoin_network, vault_count=1, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    # Skip P1=0x01 entirely — vault_group_index=0, vault_count=1 → mismatch
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + KEY_B)
    assert exc.value.status == SW_BAD_STATE


def test_extra_group_beyond_vault_count(client: RaggerClient, bitcoin_network: str):
    """Sending vault_count+1 P1=0x02 APDUs must return SW_INCORRECT_DATA on the extra one."""
    scalars = _make_scalars(bitcoin_network, vault_count=1, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=0))   # group 0 — accepted
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=1))  # beyond vault_count
    assert exc.value.status == SW_INCORRECT_DATA


def test_depositor_path_mismatch_rejected(client: RaggerClient, navigator: Navigator,
                                          device: Device, bitcoin_network: str):
    """Intent depositor_path differing from DERIVE_CONTEXT_HASH path must return SW_INCORRECT_DATA.

    DERIVE_CONTEXT_HASH is run with the standard path m/86'/coin_type'/0'/0/0.
    The intent TLV claims m/86'/coin_type'/0'/0/1 (change index 1 instead of 0).
    The F2 check in handle_key_batch fires when all keys arrive and rejects.
    """
    ct = _coin_type(bitcoin_network)
    # DCH stores m/86'/ct'/0'/0/0 in the session context.
    derive_for_intent(client, navigator, device, bitcoin_network)
    # Intent claims m/86'/ct'/0'/0/1 — passes TLV validation (index 1 is not hardened).
    mismatch_path = depositor_path(ct)[:-1] + [1]
    scalars = _make_scalars(bitcoin_network, depositor_path=mismatch_path,
                            keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH,
                      _ktlv(TAG_KEEPER_PK, KEY_A) +
                      _ktlv(TAG_CHALLENGER_PK, KEY_B))
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# User rejection
# ---------------------------------------------------------------------------

def test_user_rejects_intent_approval(client: RaggerClient, navigator: Navigator,
                                      device: Device, bitcoin_network: str):
    """User navigates to reject on the approval screen → SW_DENY (0x6985)."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    payload = _ktlv(TAG_KEEPER_PK, KEY_A) + _ktlv(TAG_CHALLENGER_PK, KEY_B)
    n_steps = vault_intent_steps(device, 1, 1)
    with pytest.raises(ExceptionRAPDU) as exc:
        with client.transport_client.exchange_async(
            cla=CLA_VAULT,
            ins=INS_APPROVE_VAULT_INTENT,
            p1=P1_KEY_BATCH,
            p2=P2_UNUSED,
            data=payload,
        ):
            navigator.navigate(
                vault_intent_reject_instructions(device, n_steps),
                screen_change_before_first_instruction=True,
            )
    assert exc.value.status == SW_DENY


# ---------------------------------------------------------------------------
# State machine — scalars before HASH_DERIVED
# ---------------------------------------------------------------------------

def test_scalars_without_context_hash_accepted(client: RaggerClient,
                                                bitcoin_network: str):
    """P1=0x00 scalar payload on a fresh session (no DERIVE_CONTEXT_HASH) → SW_OK.

    handle_scalar_payload does NOT gate on HASH_DERIVED state — it accepts TLV
    unconditionally and only preserves the root if DCH was called first.  The
    HASH_DERIVED guard lives in handle_key_batch; skipping DCH is caught there.
    """
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)  # must not raise


# ---------------------------------------------------------------------------
# Scalar range validation — payout and pegin_csv timelocks
# ---------------------------------------------------------------------------

def test_payout_timelock_at_min_rejected(client: RaggerClient, bitcoin_network: str):
    """payout_timelock = 90 (≤ VAULT_PAYOUT_TIMELOCK_MIN) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, payout_timelock=90)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_payout_timelock_above_max_rejected(client: RaggerClient, bitcoin_network: str):
    """payout_timelock = 4032 (≥ VAULT_PAYOUT_TIMELOCK_MAX) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, payout_timelock=4032)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pegin_csv_above_max_rejected(client: RaggerClient, bitcoin_network: str):
    """pegin_csv_timelock = 1009 (above maximum 1008) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, pegin_csv_timelock=1009)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_pegin_csv_at_max_accepted(client: RaggerClient, navigator: Navigator,
                                   device: Device, bitcoin_network: str):
    """pegin_csv_timelock = 1008 (maximum allowed) must complete the full approve flow."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, pegin_csv_timelock=1008,
                            keeper_count=1, challenger_count=1)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=[_make_group()])


def test_htlc_refund_timelock_below_min_rejected(client: RaggerClient, bitcoin_network: str):
    """htlc_refund_timelock = 71 (below minimum 72) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, htlc_refund_timelock=71)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_htlc_refund_timelock_at_min_accepted(client: RaggerClient, navigator: Navigator,
                                              device: Device, bitcoin_network: str):
    """htlc_refund_timelock = 72 (minimum allowed) must complete the full approve flow."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, htlc_refund_timelock=72,
                            keeper_count=1, challenger_count=1)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=[_make_group()])


# ---------------------------------------------------------------------------
# Scalar range validation — counts
# ---------------------------------------------------------------------------

def test_vault_count_zero_rejected(client: RaggerClient, bitcoin_network: str):
    """vault_count = 0 must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, vault_count=0)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_vault_count_above_max_rejected(client: RaggerClient, bitcoin_network: str):
    """vault_count = 11 (above VAULT_MAX_VAULTS = 10) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, vault_count=11)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_challenger_count_zero_rejected(client: RaggerClient, bitcoin_network: str):
    """challenger_count = 0 must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, challenger_count=0)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_keeper_count_above_max_rejected(client: RaggerClient, bitcoin_network: str):
    """keeper_count = 33 (above VAULT_MAX_KEEPERS = 32) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=33)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_challenger_count_above_max_rejected(client: RaggerClient, bitcoin_network: str):
    """challenger_count = 33 (above VAULT_MAX_CHALLENGERS = 32) must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, challenger_count=33)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# Scalar TLV structure — unknown and missing tags
# ---------------------------------------------------------------------------

def test_unknown_tag_in_scalars_rejected(client: RaggerClient, bitcoin_network: str):
    """TLV payload with an unknown tag appended must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network)
    bad_tlv = scalars + bytes([0x02, 0xFF, 1, 0x00])  # tag 0x02FF — unknown
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, bad_tlv)
    assert exc.value.status == SW_INCORRECT_DATA


def test_missing_required_scalar_field_rejected(client: RaggerClient, bitcoin_network: str):
    """TLV payload missing TAG_COIN_TYPE must return SW_INCORRECT_DATA."""
    ct = _coin_type(bitcoin_network)
    # Remove the 7-byte TAG_COIN_TYPE entry: 2B tag + 1B len + 4B u32
    coin_type_entry = bytes([TAG_COIN_TYPE >> 8, TAG_COIN_TYPE & 0xFF, 4]) + ct.to_bytes(4, "big")
    scalars = _make_scalars(bitcoin_network)
    bad_tlv = scalars.replace(coin_type_entry, b"")
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, bad_tlv)
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# Scalar TLV — depositor path validation
# ---------------------------------------------------------------------------

def test_depositor_path_wrong_purpose_rejected(client: RaggerClient, bitcoin_network: str):
    """depositor_path with purpose=44' instead of 86' must return SW_INCORRECT_DATA."""
    ct = _coin_type(bitcoin_network)
    wrong_path = [HARDENED | 44, HARDENED | ct, HARDENED | 0, 0, 0]
    scalars = _make_scalars(bitcoin_network, depositor_path=wrong_path)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_depositor_path_coin_type_mismatch_rejected(client: RaggerClient, bitcoin_network: str):
    """coin_type=0 in TAG_COIN_TYPE but depositor_path using coin_type=1 must return SW_INCORRECT_DATA."""
    wrong_path = [HARDENED | 86, HARDENED | 1, HARDENED | 0, 0, 0]
    scalars = _make_scalars(bitcoin_network, coin_type=0, depositor_path=wrong_path)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


# ---------------------------------------------------------------------------
# P1=0x01 vault-group phase — multi-group and ordering
# ---------------------------------------------------------------------------

def test_multi_group_per_p1_01_apdu_accepted(client: RaggerClient, navigator: Navigator,
                                              device: Device, bitcoin_network: str):
    """Two group TLVs concatenated into a single P1=0x01 APDU must be accepted."""
    from .instructions import vault_intent_approve_nav
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, vault_count=2, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    grp0 = _make_group(htlc_vout=0)
    grp1 = _make_group(htlc_vout=1, vault_amount=200_000)
    _raw_exchange(client, P1_GROUP, grp0 + grp1)   # both groups in one APDU
    payload = _ktlv(TAG_KEEPER_PK, KEY_A) + _ktlv(TAG_CHALLENGER_PK, KEY_B)
    nav_instr, confirm_instrs, search_text = vault_intent_approve_nav(device)
    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_KEY_BATCH,
        p2=P2_UNUSED,
        data=payload,
    ):
        navigator.navigate_until_text(
            navigate_instruction=nav_instr,
            validation_instructions=confirm_instrs,
            text=search_text,
            screen_change_before_first_instruction=False,
        )
    _sw, _ = client.last_async_response()
    assert _sw == SW_OK


def test_htlc_vout_descending_rejected(client: RaggerClient, navigator: Navigator,
                                        device: Device, bitcoin_network: str):
    """Group 1 with htlc_vout < group 0 (descending order) must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, vault_count=2, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=5))
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=3))  # 3 < 5 — descending
    assert exc.value.status == SW_INCORRECT_DATA


def test_vault_amount_below_min_rejected(client: RaggerClient, navigator: Navigator,
                                          device: Device, bitcoin_network: str):
    """vault_amount = commission_fee + 2*DUST - 1 (strictly below minimum) must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    DUST = 546
    commission_fee = 1_000
    below_min = commission_fee + 2 * DUST - 1   # 2091 — just below threshold
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_GROUP,
                      _make_group(vault_amount=below_min, commission_fee=commission_fee))
    assert exc.value.status == SW_INCORRECT_DATA
