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

from .instructions import (vault_intent_1k1c_steps, vault_intent_4k4c_steps,
                            vault_intent_32k32c_steps, vault_intent_10v_1k1c_steps,
                            vault_intent_10v_32k32c_steps)
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
    SW_INCORRECT_DATA,
    SW_WRONG_DATA_LENGTH,
    SW_WRONG_P1P2,
    SW_BAD_STATE,
    VAULT_STRUCTURE_TYPE,
    VAULT_PROTOCOL_VERSION,
    TAG_STRUCTURE_TYPE,
    TAG_COIN_TYPE,
    TAG_PEGIN_CSV_TIMELOCK,
    TAG_KEEPER_COUNT,
    TEST_VP_KEY,
    TEST_VALID_KEYS,
    TEST_INVALID_XONLY_KEY,
    TEST_DEPOSITOR_XONLY_MAINNET,
    TEST_DEPOSITOR_XONLY_TESTNET,
)


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
KEY_D = TEST_VALID_KEYS[3]


def _coin_type(network: str) -> int:
    return 0 if network == "main" else 1


def _make_scalars(network: str, **overrides) -> bytes:
    """Build a valid P1=0x00 TLV scalar payload (v19: 13 scalar tags, no per-vault fields)."""
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
        vault_count=1,
    )
    defaults.update(overrides)
    return build_intent_tlv(**defaults)


def _make_group(**overrides) -> bytes:
    """Build a valid P1=0x02 group TLV with optional field overrides."""
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
                                  test_case_name="vault_intent/1k1c_" + bitcoin_network,
                                  n_swipes=vault_intent_1k1c_steps(device))


def test_keys_split_across_batches(client: RaggerClient, navigator: Navigator,
                                    device: Device, bitcoin_network: str):
    """4 keepers + 4 challengers forces two P1=0x01 batches (7+1 keys)."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    keepers     = TEST_VALID_KEYS[0:4]
    challengers = TEST_VALID_KEYS[4:8]
    scalars = _make_scalars(bitcoin_network, keeper_count=4, challenger_count=4)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=keepers, challenger_pks=challengers,
                                  groups=[_make_group()],
                                  path=SCREENSHOT_PATH,
                                  test_case_name="vault_intent/4k4c_" + bitcoin_network,
                                  n_swipes=vault_intent_4k4c_steps(device))


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
                                  test_case_name="vault_intent/max_32k32c_" + bitcoin_network,
                                  n_swipes=vault_intent_32k32c_steps(device))


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
                                  test_case_name="vault_intent/reload_1_" + bitcoin_network,
                                  n_swipes=vault_intent_1k1c_steps(device))
    # Second load — derive first to reach HASH_DERIVED, then handler invalidates the
    # first session and shows the screen again
    derive_for_intent(client, navigator, device, bitcoin_network)
    approve_vault_intent_with_nav(client, navigator, device, scalars,
                                  keeper_pks=[KEY_A], challenger_pks=[KEY_B],
                                  groups=grp,
                                  path=SCREENSHOT_PATH,
                                  test_case_name="vault_intent/reload_2_" + bitcoin_network,
                                  n_swipes=vault_intent_1k1c_steps(device))


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
                                  test_case_name="vault_intent/session2_survive_" + bitcoin_network,
                                  n_swipes=vault_intent_1k1c_steps(device))

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
                                  test_case_name="vault_intent/reset_session_" + bitcoin_network,
                                  n_swipes=vault_intent_1k1c_steps(device))

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


def test_keeper_count_zero(client: RaggerClient, bitcoin_network: str):
    """keeper_count = 0 must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, keeper_count=0)
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_SCALARS, scalars)
    assert exc.value.status == SW_INCORRECT_DATA


def test_duplicate_tlv_tag(client: RaggerClient, bitcoin_network: str):
    """TLV payload with a duplicate tag must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network)
    # Append a second TAG_VERSION at the end.  The parser sees the first occurrence
    # during normal field collection, then hits the duplicate on the appended entry
    # and rejects it.  Appending (rather than inserting mid-stream) is intentional:
    # it ensures the first TAG_VERSION is always processed before the duplicate,
    # regardless of canonical field ordering.
    bad_tlv = scalars + bytes([0x02, 1, VAULT_PROTOCOL_VERSION])
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
        # KEY_B > KEY_A — send in wrong order (B then A)
        _raw_exchange(client, P1_KEY_BATCH, KEY_B + KEY_A + KEY_C)
    assert exc.value.status == SW_INCORRECT_DATA


def test_extra_keys_beyond_count(client: RaggerClient, navigator: Navigator,
                                 device: Device, bitcoin_network: str):
    """Sending more keys than keeper_count + challenger_count must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        # 3 keys declared total = 2, send 3
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + KEY_B + KEY_C)
    assert exc.value.status == SW_INCORRECT_DATA


def test_key_batch_not_multiple_of_32(client: RaggerClient, bitcoin_network: str):
    """P1=0x01 payload not a multiple of 32 bytes must return SW_WRONG_DATA_LENGTH."""
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, b"\xAA" * 31)   # 31 bytes — not multiple of 32
    assert exc.value.status == SW_WRONG_DATA_LENGTH


def test_key_equals_vault_provider_pk(client: RaggerClient, navigator: Navigator,
                                      device: Device, bitcoin_network: str):
    """A keeper key equal to vault_provider_pk must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    # _make_group() sets vault_provider_pk=VP_KEY by default.
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, VP_KEY + KEY_B)
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
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + KEY_A)
    assert exc.value.status == SW_INCORRECT_DATA


def test_invalid_ec_point_keeper_rejected(client: RaggerClient, navigator: Navigator,
                                          device: Device, bitcoin_network: str):
    """A keeper key whose x-coordinate is not on secp256k1 must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        # TEST_INVALID_XONLY_KEY = 0xFF * 32 which is >= secp256k1 prime p.
        _raw_exchange(client, P1_KEY_BATCH, TEST_INVALID_XONLY_KEY + KEY_B)
    assert exc.value.status == SW_INCORRECT_DATA


def test_invalid_ec_point_challenger_rejected(client: RaggerClient, navigator: Navigator,
                                              device: Device, bitcoin_network: str):
    """A challenger key whose x-coordinate is not on secp256k1 must return SW_INCORRECT_DATA."""
    derive_for_intent(client, navigator, device, bitcoin_network)
    scalars = _make_scalars(bitcoin_network, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group())
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + TEST_INVALID_XONLY_KEY)
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
        _raw_exchange(client, P1_KEY_BATCH, depositor_key + KEY_A)
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
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + depositor_key)
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

    # APPROVE_VAULT_INTENT P1=0x01 must now fail because scalars_loaded == false.
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
# P1=0x02 vault-group phase — NAPPS-1442 acceptance criteria
# ---------------------------------------------------------------------------

def test_10_vault_groups_accepted(client: RaggerClient, navigator: Navigator,
                                   device: Device, bitcoin_network: str):
    """10-vault intent: all 10 P1=0x02 groups accepted in ascending htlc_vout order.

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
                                  test_case_name="vault_intent/10vault_1k1c_" + bitcoin_network,
                                  n_swipes=vault_intent_10v_1k1c_steps(device))


def test_10_vaults_32_keepers_32_challengers(client: RaggerClient, navigator: Navigator,
                                              device: Device, bitcoin_network: str):
    """10-vault intent with the firmware-maximum 32 keepers + 32 challengers.

    Combines the multi-vault streaming path (P1=0x02 × 10) with the largest possible
    key set (64 keys in 10 P1=0x01 batches).  Step counts derived from existing goldens:
    new_screens = 32k32c_screens + (10vault_1k1c_screens - 1k1c_screens).
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
                                  test_case_name="vault_intent/10vault_32k32c_" + bitcoin_network,
                                  n_swipes=vault_intent_10v_32k32c_steps(device))


def test_htlc_vout_out_of_order(client: RaggerClient, bitcoin_network: str):
    """Second group with htlc_vout <= first group must return SW_INCORRECT_DATA."""
    scalars = _make_scalars(bitcoin_network, vault_count=2, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=5))
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=3))  # 3 <= 5
    assert exc.value.status == SW_INCORRECT_DATA


def test_htlc_vout_equal_rejected(client: RaggerClient, bitcoin_network: str):
    """Two groups with equal htlc_vout must return SW_INCORRECT_DATA (not strictly ascending)."""
    scalars = _make_scalars(bitcoin_network, vault_count=2, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=3))
    with pytest.raises(ExceptionRAPDU) as exc:
        _raw_exchange(client, P1_GROUP, _make_group(htlc_vout=3))  # equal
    assert exc.value.status == SW_INCORRECT_DATA


def test_missing_group_phase_rejected(client: RaggerClient, bitcoin_network: str):
    """P1=0x01 sent with no prior P1=0x02 groups must return SW_BAD_STATE."""
    scalars = _make_scalars(bitcoin_network, vault_count=1, keeper_count=1, challenger_count=1)
    _raw_exchange(client, P1_SCALARS, scalars)
    # Skip P1=0x02 entirely — vault_group_index=0, vault_count=1 → mismatch
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
        _raw_exchange(client, P1_KEY_BATCH, KEY_A + KEY_B)
    assert exc.value.status == SW_INCORRECT_DATA
