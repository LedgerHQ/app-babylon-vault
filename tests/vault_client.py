"""
Raw APDU helpers for Babylon Vault custom commands.

These functions bypass the ledger_bitcoin high-level client and send APDUs
directly via the ragger transport, which is necessary for vault-specific
INS codes that the bitcoin library doesn't know about.

Usage:
    from vault_client import derive_context_hash, VAULT_APP_NAME

    root = derive_context_hash(client, VAULT_APP_NAME, path=[...], context=b"...")
"""

from __future__ import annotations

import hashlib
import hmac
import types
from pathlib import Path
from typing import TYPE_CHECKING, List, Optional, Union
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient
    from ragger.navigator import Navigator
    from ragger.navigator import NavInsID
    from ledgered.devices import Device

CLA_VAULT                    = 0xE1
INS_DERIVE_CONTEXT_HASH      = 0x81
INS_APPROVE_VAULT_INTENT     = 0x80

P1_INITIAL   = 0x00
P1_CONTINUE  = 0x01
P1_SCALARS   = 0x00
P1_GROUP     = 0x02  # per-vault group phase (NAPPS-1442)
P1_KEY_BATCH = 0x01
P2_UNUSED    = 0x00

# Max bytes per APDU data field
_CHUNK_SIZE     = 255
_KEYS_PER_BATCH = 7   # 7 × 32 = 224 bytes ≤ 255

class _HexInt(int):
    """int subclass that prints as hex — makes pytest assertion diffs readable."""
    def __repr__(self) -> str:
        return hex(self)

# APDU status words
SW_OK                = _HexInt(0x9000)
SW_DENY              = _HexInt(0x6985)
SW_INCORRECT_DATA    = _HexInt(0x6A80)
SW_WRONG_DATA_LENGTH = _HexInt(0x6A87)
SW_WRONG_P1P2        = _HexInt(0x6A86)
SW_BAD_STATE         = _HexInt(0xB007)

# P1=0x00 scalar tag byte assignments — must match src/vault_intent_tags.h
# Tags 0x04–0x07, 0x09, 0x0D were per-vault scalars in v18; rejected by firmware whitelist since v19.
TAG_STRUCTURE_TYPE            = 0x01
TAG_VERSION                   = 0x02
TAG_COIN_TYPE                 = 0x03
TAG_BASE_FEE_RATE             = 0x08
TAG_PEGIN_CSV_TIMELOCK        = 0x0A
TAG_PAYOUT_TIMELOCK           = 0x0B
TAG_PREPEGIN_TXID             = 0x0C
TAG_HTLC_REFUND_TIMELOCK      = 0x0E
TAG_DEPOSITOR_DERIVATION_PATH = 0x0F
TAG_KEEPER_COUNT              = 0x10
TAG_CHALLENGER_COUNT          = 0x11
TAG_PEGIN_ANCHOR_VALUE        = 0x12
TAG_VAULT_COUNT               = 0x13

# P1=0x02 per-vault group tag byte assignments — must match src/vault_intent_tags.h
TAG_GRP_HTLC_VOUT             = 0x01
TAG_GRP_VAULT_PROVIDER_PK     = 0x02
TAG_GRP_VAULT_AMOUNT          = 0x03
TAG_GRP_COMMISSION_FEE        = 0x04
TAG_GRP_DEPOSITOR_CLAIM_VALUE = 0x05
TAG_GRP_PEGIN_MAX_FEE         = 0x06

HARDENED = 0x80000000

# Protocol constants — must match src/vault_constants.h
VAULT_STRUCTURE_TYPE     = 0x01
VAULT_PROTOCOL_VERSION   = 0x01

# Canonical test vault-provider key: x-coordinate of secp256k1 generator G.
# Must be a valid curve point because the firmware calls crypto_tr_lift_x on it.
TEST_VP_KEY = bytes.fromhex('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')

# Valid secp256k1 x-only public keys for use in tests, sorted ascending.
# Mix of small multiples of G (2G..8G) and BIP-340 test-vector pubkeys — all
# are verified valid curve points and do not equal TEST_VP_KEY (1G).
TEST_VALID_KEYS = [
    bytes.fromhex('25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517'),  # BIP-340 vector
    bytes.fromhex('2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01'),  # 8G
    bytes.fromhex('2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4'),  # 5G
    bytes.fromhex('5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC'),  # 7G
    bytes.fromhex('C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5'),  # 2G
    bytes.fromhex('DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'),   # BIP-340 vector
    bytes.fromhex('E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13'),  # 4G
    bytes.fromhex('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'),   # BIP-340 vector
]

# Guaranteed-invalid x-coordinate: x = p-2 gives (p-2)³+7 ≡ (-2)³+7 ≡ -1 (mod p).
# -1 is never a quadratic residue when p ≡ 3 (mod 4), which secp256k1's prime satisfies,
# so no point with this x exists. crypto_tr_lift_x must reject it.
TEST_INVALID_XONLY_KEY = bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D')

# Pre-computed x-only depositor pubkeys for the test mnemonic (see conftest.py) at
# BIP-86 path m/86'/coin_type'/0'/0/0.  The firmware derives this key at the end of
# P1=0x01 batch processing via crypto_get_compressed_pubkey_at_path and checks that
# it doesn't collide with any role key (vault_check_depositor_uniqueness in
# approve_vault_intent_core.h).
# Derivation: PBKDF2(mnemonic) → BIP-32 master key → path → x-only (strip parity byte).
TEST_DEPOSITOR_XONLY_MAINNET = bytes.fromhex('FBB1F6159D2D75F87CD29137D3D58C3C52D6EB5E1F43D7433EF85840F3D97367')
TEST_DEPOSITOR_XONLY_TESTNET = bytes.fromhex('DC8D2F9EFF0C4F4DBDE070A48E330EFC908B62A766568D91E658F284B324B878')


def _exchange(client: RaggerClient, p1: int, data: bytes) -> bytes:
    """Send one DERIVE_CONTEXT_HASH APDU and return the response data.

    Raises ExceptionRAPDU on any non-whitelisted SW (handled by caller).
    """
    response = client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_DERIVE_CONTEXT_HASH,
        p1=p1,
        p2=P2_UNUSED,
        data=data,
    )
    return bytes(response.data)


def _encode_bip32_path(path: List[int]) -> bytes:
    """Encode a BIP-32 path as path_len(1B) | level×u32-BE (Ledger wire convention)."""
    assert len(path) <= 10, "path too deep"
    return bytes([len(path)]) + b"".join(p.to_bytes(4, "big") for p in path)


def derive_context_hash(client: RaggerClient,
                        app_name: bytes,
                        path: List[int],
                        context: bytes,
                        navigator: "Navigator",
                        device: "Device") -> bytes:
    """Send the single DERIVE_CONTEXT_HASH APDU, navigate the approval screen, and return
    the 32-byte root.

    Wire (P1=0x00): app_name_len(1B) | app_name | path_len(1B) | path(4·n B BE) | context.
    The handler shows an NBGL approval screen; the caller must supply navigator + device so
    this function can drive the confirmation before the device sends its response.

    Args:
        client:    RaggerClient fixture from conftest.
        app_name:  UTF-8 app name, 1..64 bytes (host sends b"babylon-btc-vault").
        path:      connectedPubkey BIP-32 path (u32 levels, hardened bit set as usual).
        context:   vaultContext bytes; must be non-empty.
        navigator: Ragger Navigator fixture.
        device:    Ledgered Device fixture (selects Nano vs touch navigation).

    Returns:
        32-byte root.
    """
    from .instructions import derive_context_hash_nav

    assert 1 <= len(app_name) <= 64, "app_name must be 1..64 bytes"
    assert len(context) > 0, "context must be non-empty"

    payload = bytes([len(app_name)]) + app_name + _encode_bip32_path(path) + context
    nav_instr, confirm_instrs, search_text = derive_context_hash_nav(device)

    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_DERIVE_CONTEXT_HASH,
        p1=P1_INITIAL,
        p2=P2_UNUSED,
        data=payload,
    ):
        navigator.navigate_until_text(
            navigate_instruction=nav_instr,
            validation_instructions=confirm_instrs,
            text=search_text,
            screen_change_before_first_instruction=False,
        )

    _sw, response_data = client.last_async_response()
    assert len(response_data) == 32
    return bytes(response_data)


# ---------------------------------------------------------------------------
# Host-side expansion of the root into on-chain commitments (mirror of
# src/handler/derive_vault_secrets_core.h). Lets tests compute the same
# hashlock / auth-anchor the device binds, from the device-returned root.
# ---------------------------------------------------------------------------

# Fixed app name the host sends (derive-vault-secrets §2.1).
VAULT_APP_NAME = b"babylon-btc-vault"
_VS_DOMAIN_TAG = b"babylonbtcvault"


def _vault_expand_commitment(root: bytes, label: bytes, ctx: bytes) -> bytes:
    """SHA256(HKDF-Expand-SHA256(root, info(label, ctx), 32)) — Expand-only, single block."""
    info = _VS_DOMAIN_TAG + bytes([len(label)]) + label + len(ctx).to_bytes(2, "big") + ctx
    secret = hmac.new(root, info + b"\x01", hashlib.sha256).digest()
    return hashlib.sha256(secret).digest()


def vault_hashlock(root: bytes, htlc_vout: int) -> bytes:
    """On-chain HTLC hashlock h = SHA256(Expand(root, "hashlock" || I2OSP(htlc_vout, 4)))."""
    return _vault_expand_commitment(root, b"hashlock", htlc_vout.to_bytes(4, "big"))


def vault_auth_anchor(root: bytes) -> bytes:
    """Pre-PegIn auth-anchor commitment SHA256(Expand(root, "auth-anchor"))."""
    return _vault_expand_commitment(root, b"auth-anchor", b"")


def depositor_path(coin_type: int) -> "List[int]":
    """Standard BIP-86 depositor path m/86'/coin_type'/0'/0/0."""
    return [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]


def derive_for_intent(client: "RaggerClient",
                      navigator: "Navigator",
                      device: "Device",
                      bitcoin_network: str,
                      context: bytes = b"\xde\xad\xbe\xef") -> bytes:
    """Run DERIVE_CONTEXT_HASH with the default depositor path and context.

    Convenience wrapper for test suites that need to reach HASH_DERIVED before
    APPROVE_VAULT_INTENT.  Returns the 32-byte root.
    """
    ct = 0 if bitcoin_network == "main" else 1
    return derive_context_hash(client, VAULT_APP_NAME, depositor_path(ct), context, navigator, device)


# ---------------------------------------------------------------------------
# APPROVE_VAULT_INTENT helpers
# ---------------------------------------------------------------------------

def _tlv_u8(tag: int, val: int) -> bytes:
    return bytes([tag, 1, val])

def _tlv_u32be(tag: int, val: int) -> bytes:
    return bytes([tag, 4]) + val.to_bytes(4, "big")

def _tlv_u64be(tag: int, val: int) -> bytes:
    return bytes([tag, 8]) + val.to_bytes(8, "big")

def _tlv_bytes(tag: int, val: bytes) -> bytes:
    assert len(val) <= 255
    return bytes([tag, len(val)]) + val

def _tlv_path(tag: int, path: List[int]) -> bytes:
    data = b"".join(p.to_bytes(4, "big") for p in path)
    return bytes([tag, len(data)]) + data


def build_intent_tlv(
    coin_type: int,
    base_fee_rate: int,
    pegin_csv_timelock: int,
    payout_timelock: int,
    prepegin_txid: bytes,
    htlc_refund_timelock: int,
    depositor_path: List[int],
    keeper_count: int,
    challenger_count: int,
    vault_count: int = 1,
    pegin_anchor_value: int = 546,
) -> bytes:
    """Encode the 13 P1=0x00 scalar intent fields into a TLV payload (v19 format).

    Per-vault fields (vault_provider_pk, vault_amount, commission_fee,
    depositor_claim_value, pegin_max_fee, htlc_vout) are now sent in the P1=0x02
    group phase via build_group_tlv().
    """
    return (
        _tlv_u8   (TAG_STRUCTURE_TYPE,            VAULT_STRUCTURE_TYPE)    +
        _tlv_u8   (TAG_VERSION,                   VAULT_PROTOCOL_VERSION)  +
        _tlv_u32be(TAG_COIN_TYPE,                 coin_type)               +
        _tlv_u64be(TAG_BASE_FEE_RATE,             base_fee_rate)           +
        _tlv_u32be(TAG_PEGIN_CSV_TIMELOCK,        pegin_csv_timelock)      +
        _tlv_u32be(TAG_PAYOUT_TIMELOCK,           payout_timelock)         +
        _tlv_bytes(TAG_PREPEGIN_TXID,             prepegin_txid)           +
        _tlv_u32be(TAG_HTLC_REFUND_TIMELOCK,      htlc_refund_timelock)    +
        _tlv_path (TAG_DEPOSITOR_DERIVATION_PATH, depositor_path)          +
        _tlv_u8   (TAG_KEEPER_COUNT,              keeper_count)            +
        _tlv_u8   (TAG_CHALLENGER_COUNT,          challenger_count)        +
        _tlv_u64be(TAG_PEGIN_ANCHOR_VALUE,        pegin_anchor_value)      +
        _tlv_u8   (TAG_VAULT_COUNT,               vault_count)
    )


def build_group_tlv(
    htlc_vout: int,
    vault_provider_pk: bytes,
    vault_amount: int,
    commission_fee: int,
    depositor_claim_value: int,
    pegin_max_fee: int,
) -> bytes:
    """Encode one vault group into a P1=0x02 TLV payload (v19 format, NAPPS-1442)."""
    assert len(vault_provider_pk) == 32, f"vault_provider_pk must be 32-byte x-only key, got {len(vault_provider_pk)}"
    return (
        _tlv_u8   (TAG_GRP_HTLC_VOUT,             htlc_vout)              +
        _tlv_bytes(TAG_GRP_VAULT_PROVIDER_PK,      vault_provider_pk)      +
        _tlv_u64be(TAG_GRP_VAULT_AMOUNT,           vault_amount)           +
        _tlv_u64be(TAG_GRP_COMMISSION_FEE,         commission_fee)         +
        _tlv_u64be(TAG_GRP_DEPOSITOR_CLAIM_VALUE,  depositor_claim_value)  +
        _tlv_u64be(TAG_GRP_PEGIN_MAX_FEE,          pegin_max_fee)
    )


def _approve_exchange(client: "RaggerClient", p1: int, data: bytes) -> bytes:
    response = client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=p1,
        p2=P2_UNUSED,
        data=data,
    )
    return bytes(response.data)


def approve_vault_intent_with_nav(
    client: "RaggerClient",
    navigator: "Navigator",
    device: "Device",
    scalars_tlv: bytes,
    keeper_pks: List[bytes],
    challenger_pks: List[bytes],
    groups: Optional[List[bytes]] = None,
    path: Optional[Path] = None,
    test_case_name: Optional[Union[Path, str]] = None,
    n_swipes: Optional[int] = None,
) -> None:
    """Send APPROVE_VAULT_INTENT APDUs and navigate the approval screen.

    All batches except the last are sent synchronously (they respond SW_OK immediately).
    The final batch triggers the display; it is sent asynchronously while the navigator
    confirms the review screen.

    groups: list of pre-built P1=0x02 group TLV payloads (one per vault).  When
    provided they are sent between the P1=0x00 scalars and the P1=0x01 key batches.

    When path and test_case_name are provided, snapshot comparison is performed:
      - If n_swipes is given, navigate_and_compare is used with an explicit instruction
        list (deterministic — use instructions.vault_intent_1k1c_steps(device) for
        standard 1K+1C data).
      - If n_swipes is None, navigate_until_text_and_compare is used (timing-sensitive).
    When path is None, navigate_until_text is used (no comparison).
    """
    from .instructions import vault_intent_approve_nav, vault_intent_approve_instructions

    _approve_exchange(client, P1_SCALARS, scalars_tlv)

    for grp_tlv in (groups or []):
        _approve_exchange(client, P1_GROUP, grp_tlv)

    all_keys = keeper_pks + challenger_pks
    assert len(all_keys) > 0, "keeper_pks + challenger_pks must not be empty"
    batches = [all_keys[i : i + _KEYS_PER_BATCH] for i in range(0, len(all_keys), _KEYS_PER_BATCH)]

    for batch in batches[:-1]:
        _approve_exchange(client, P1_KEY_BATCH, b"".join(batch))

    with client.transport_client.exchange_async(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=P1_KEY_BATCH,
        p2=P2_UNUSED,
        data=b"".join(batches[-1]),
    ):
        if path is not None and test_case_name is not None:
            if n_swipes is not None:
                navigator.navigate_and_compare(
                    path=path,
                    test_case_name=test_case_name,
                    instructions=vault_intent_approve_instructions(device, n_swipes),
                    screen_change_before_first_instruction=True,
                )
            else:
                navigate_instr, confirm_instrs, search_text = vault_intent_approve_nav(device)
                navigator.navigate_until_text_and_compare(
                    navigate_instruction=navigate_instr,
                    validation_instructions=confirm_instrs,
                    text=search_text,
                    path=path,
                    test_case_name=test_case_name,
                    screen_change_before_first_instruction=False,
                )
        else:
            navigate_instr, confirm_instrs, search_text = vault_intent_approve_nav(device)
            navigator.navigate_until_text(
                navigate_instruction=navigate_instr,
                validation_instructions=confirm_instrs,
                text=search_text,
                screen_change_before_first_instruction=False,
            )


def approve_vault_intent(
    client: "RaggerClient",
    scalars_tlv: bytes,
    keeper_pks: List[bytes],
    challenger_pks: List[bytes],
    groups: Optional[List[bytes]] = None,
) -> None:
    """Send APPROVE_VAULT_INTENT APDUs (scalars + optional groups + keys).

    Sends one P1=0x00 APDU with the scalar TLV, then one P1=0x02 APDU per group
    (when groups is provided), then streams all keys in P1=0x01 batches of up to
    7 keys each (224 bytes per APDU).

    Raises ExceptionRAPDU on any non-OK SW.
    """
    _approve_exchange(client, P1_SCALARS, scalars_tlv)

    for grp_tlv in (groups or []):
        _approve_exchange(client, P1_GROUP, grp_tlv)

    all_keys = keeper_pks + challenger_pks
    for i in range(0, len(all_keys), _KEYS_PER_BATCH):
        batch = all_keys[i : i + _KEYS_PER_BATCH]
        _approve_exchange(client, P1_KEY_BATCH, b"".join(batch))


# ---------------------------------------------------------------------------
# sign_psbt screen-test helper
# ---------------------------------------------------------------------------

def sign_psbt_with_nav_and_compare(
    client: "RaggerClient",
    psbt,
    wallet,
    wallet_hmac,
    navigator: "Navigator",
    testname: str,
    nav_instructions: "List[NavInsID]",
) -> None:
    """Call sign_psbt while capturing all review screens into a single snapshot folder.

    The standard client.sign_psbt + Instructions approach stores one screenshot per
    sub-folder (testname_0_0/, testname_0_1/, …).  This helper instead uses
    navigate_and_compare so all screens land as numbered PNGs inside one folder:
        snapshots/<device>/<testname>/00000.png, 00001.png, …

    Works by temporarily replacing the ragger_navigate bound method on the client
    instance — ragger_bitcoin is a git submodule so we cannot modify it directly.

    Use for touch devices (Flex, Stax, Apex).  For Nano, pass an Instructions object
    to client.sign_psbt directly.
    """
    from ragger.utils import pack_APDU

    screenshot_dir = client.screenshot_dir

    def _flat_navigate(self, _nav, apdu, _instructions, _testname, index):
        cla, ins, p1, p2, data = apdu.values()
        self.transport_client.apdu_timeout = 1.0
        with self.transport_client.exchange_async_raw(pack_APDU(cla, ins, p1, p2, data)) as done:
            if not done:
                _nav.navigate_and_compare(
                    path=screenshot_dir,
                    test_case_name=_testname,
                    instructions=nav_instructions,
                    screen_change_before_first_instruction=True,
                )
                index += 1
        sw, response = self.last_async_response()
        return sw, response, index

    client.ragger_navigate = types.MethodType(_flat_navigate, client)
    try:
        client.sign_psbt(psbt, wallet, wallet_hmac, navigator, testname=testname)
    finally:
        del client.ragger_navigate
