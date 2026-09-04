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
P1_GROUP     = 0x01  # per-vault group phase
P1_KEY_BATCH = 0x02  # key batch phase
P2_UNUSED    = 0x00  # alias for P2_SHOW (backward compat)
P2_SHOW      = 0x00  # DERIVE_CONTEXT_HASH: show Screen 1, return 32-byte root
P2_SILENT    = 0x01  # DERIVE_CONTEXT_HASH: silent re-derivation, SW_OK only

# Max bytes per APDU data field
_CHUNK_SIZE     = 255
_KEYS_PER_BATCH = 7   # 7 × 35 (2B tag + 1B len + 32B key) = 245 bytes ≤ 255

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
SW_BAD_STATE              = _HexInt(0xB007)
SW_BAD_CPFP_ANCHOR        = _HexInt(0xB009)
SW_CAP_EXCEEDED           = _HexInt(0xB00A)

# P1=0x00 scalar 2-byte tags — must match src/vault_intent_tags.h (v21 scheme)
TAG_STRUCTURE_TYPE            = 0x0001
TAG_VERSION                   = 0x0002
TAG_COIN_TYPE                 = 0x0021
TAG_BASE_FEE_RATE             = 0x0100
TAG_PEGIN_CSV_TIMELOCK        = 0x0101
TAG_PAYOUT_TIMELOCK           = 0x0102
TAG_PREPEGIN_TXID             = 0x0027
TAG_HTLC_REFUND_TIMELOCK      = 0x0103
TAG_DEPOSITOR_DERIVATION_PATH = 0x0069
TAG_KEEPER_COUNT              = 0x0104
TAG_CHALLENGER_COUNT          = 0x0105
TAG_VAULT_COUNT               = 0x0106
TAG_PREPEGIN_MAX_FEE          = 0x010F

# P1=0x02 key batch 2-byte tags — must match src/vault_intent_tags.h
TAG_KEEPER_PK                 = 0x0107
TAG_CHALLENGER_PK             = 0x0108


def _ktlv(tag: int, key: bytes) -> bytes:
    """Encode a 32-byte x-only key as a 2-byte-tag TLV entry: tag(2B) | len(1B) | key(32B)."""
    return bytes([tag >> 8, tag & 0xFF, 32]) + key

# P1=0x01 per-vault group 2-byte tags — must match src/vault_intent_tags.h
TAG_GRP_HTLC_VOUT             = 0x0109
TAG_GRP_VAULT_PROVIDER_PK     = 0x010A
TAG_GRP_VAULT_AMOUNT          = 0x010B
TAG_GRP_COMMISSION_FEE        = 0x010C
TAG_GRP_DEPOSITOR_CLAIM_VALUE = 0x010D
TAG_GRP_PEGIN_MAX_FEE         = 0x010E

HARDENED = 0x80000000

# Protocol constants — must match src/vault_constants.h
VAULT_STRUCTURE_TYPE     = 0x01
VAULT_PROTOCOL_VERSION   = 0x01

# Canonical test vault-provider key: x-coordinate of secp256k1 generator G.
# Must be a valid curve point because the firmware calls crypto_tr_lift_x on it.
TEST_VP_KEY = bytes.fromhex('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')

# Valid secp256k1 x-only public keys for use in tests, sorted ascending.
# Mix of small multiples of G (2G..10G) and BIP-340 test-vector pubkeys — all
# are verified valid curve points and do not equal TEST_VP_KEY (1G).
TEST_VALID_KEYS = [
    bytes.fromhex('25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517'),  # BIP-340 vector
    bytes.fromhex('2F01E5E15CCA351DAFF3843FB70F3C2F0A1BDD05E5AF888A67784EF3E10A2A01'),  # 8G
    bytes.fromhex('2F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4'),  # 5G
    bytes.fromhex('5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC'),  # 7G
    bytes.fromhex('A0434D9E47F3C86235477C7B1AE6AE5D3442D49B1943C2B752A68E2A47E247C7'),  # 10G
    bytes.fromhex('ACD484E2F0C7F65309AD178A9F559ABDE09796974C57E714C35F110DFC27CCBE'),   # 9G
    bytes.fromhex('C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5'),  # 2G
    bytes.fromhex('DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659'),   # BIP-340 vector
    bytes.fromhex('E493DBF1C10D80F3581E4904930B1404CC6C13900EE0758474FA94ABE8C4CD13'),  # 4G
    bytes.fromhex('F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9'),   # BIP-340 vector
    bytes.fromhex('FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556'),   # 6G
]

# Guaranteed-invalid x-coordinate: x = p-2 gives (p-2)³+7 ≡ (-2)³+7 ≡ -1 (mod p).
# -1 is never a quadratic residue when p ≡ 3 (mod 4), which secp256k1's prime satisfies,
# so no point with this x exists. crypto_tr_lift_x must reject it.
# Note this value is a *canonical* encoding (p-2 < p); it exercises curve membership,
# not the BIP-340 field bound — see TEST_NONCANONICAL_XONLY_KEY for that.
TEST_INVALID_XONLY_KEY = bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2D')

# Non-canonical x-coordinate: x = p+1, which BIP-340 forbids (x must be < p) but which a
# modular curve check accepts as its residue x = 1 — and x = 1 *is* on secp256k1, since
# 1³+7 = 8 is a quadratic residue mod p. So this value passes a lift that reduces mod p
# and is caught only by an explicit field-bound check. Distinct from
# TEST_INVALID_XONLY_KEY, which is in range and simply off-curve.
TEST_NONCANONICAL_XONLY_KEY = bytes.fromhex(
    'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30')

# Pre-computed x-only depositor pubkeys for the test mnemonic (see conftest.py) at
# BIP-86 path m/86'/coin_type'/0'/0/0.  The firmware derives this key at the end of
# P1=0x02 batch processing via crypto_get_compressed_pubkey_at_path and checks that
# it doesn't collide with any role key (vault_check_depositor_uniqueness in
# approve_vault_intent_core.h).
# Derivation: PBKDF2(mnemonic) → BIP-32 master key → path → x-only (strip parity byte).
TEST_DEPOSITOR_XONLY_MAINNET = bytes.fromhex('FBB1F6159D2D75F87CD29137D3D58C3C52D6EB5E1F43D7433EF85840F3D97367')
TEST_DEPOSITOR_XONLY_TESTNET = bytes.fromhex('DC8D2F9EFF0C4F4DBDE070A48E330EFC908B62A766568D91E658F284B324B878')


def _require_sw_ok(response, command: str) -> bytes:
    """Return the response data, but only for an exact SW_OK.

    conftest whitelists 0x9000 and 0xE000 on the backend so the standard Bitcoin
    SIGN_PSBT client-command protocol can operate. The custom CLA 0xE1 handlers never
    legitimately use interrupted execution, so without this check a 0xE000 from those
    commands would be read as successful completion and mask an APDU-routing or
    state-machine regression (Cerberus V-037).
    """
    if response.status != SW_OK:
        raise AssertionError(f"{command} expected SW_OK, got {response.status:#06x}")
    return bytes(response.data)


def _dch_exchange(client: "RaggerClient", p1: int, p2: int, data: bytes) -> bytes:
    """Send one DERIVE_CONTEXT_HASH APDU and return the response data.

    Raises ExceptionRAPDU on any non-whitelisted SW (handled by caller), and
    AssertionError on a whitelisted-but-wrong SW such as 0xE000.
    """
    response = client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_DERIVE_CONTEXT_HASH,
        p1=p1,
        p2=p2,
        data=data,
    )
    return _require_sw_ok(response, "DERIVE_CONTEXT_HASH")


def _encode_bip32_path(path: List[int]) -> bytes:
    """Encode a BIP-32 path as path_len(1B) | level×u32-BE (Ledger wire convention)."""
    assert len(path) <= 10, "path too deep"
    return bytes([len(path)]) + b"".join(p.to_bytes(4, "big") for p in path)


def derive_context_hash(client: "RaggerClient",
                        app_name: bytes,
                        path: List[int],
                        context: bytes,
                        navigator: "Navigator",
                        device: "Device",
                        p2: int = P2_SHOW) -> bytes:
    """Send DERIVE_CONTEXT_HASH APDUs (chunked if needed), navigate Screen 1, return root.

    Wire format (NAPPS-1441 rev 2.1):
      P1=0x00: app_name_len(1B) | app_name | path_len(1B) | path(4·n B BE)
               | context_total_len(2B BE) | first_context_chunk
      P1=0x01: continuation context bytes (repeated until total received)

    P2=0x00 (P2_SHOW):   Screen 1 shown on final chunk; returns 32-byte root.
    P2=0x01 (P2_SILENT): No screen; returns b"".

    Args:
        client:    RaggerClient fixture from conftest.
        app_name:  UTF-8 app name, 1..64 bytes (host sends b"babylon-btc-vault").
        path:      connectedPubkey BIP-32 path (u32 levels, hardened bit set as usual).
        context:   vaultContext bytes; must be non-empty.
        navigator: Ragger Navigator fixture (only used for P2=0x00).
        device:    Ledgered Device fixture (selects Nano vs touch navigation).
        p2:        P2_SHOW (default) or P2_SILENT.

    Returns:
        32-byte root (P2_SHOW) or b"" (P2_SILENT).
    """
    from .instructions import derive_context_hash_nav

    assert 1 <= len(app_name) <= 64, "app_name must be 1..64 bytes"
    assert 1 <= len(context) <= 1024, "context must be 1..1024 bytes"

    # Build the P1=0x00 fixed header.
    path_bytes = _encode_bip32_path(path)
    context_total_len_bytes = len(context).to_bytes(2, "big")
    header = bytes([len(app_name)]) + app_name + path_bytes + context_total_len_bytes

    # Determine how much context fits in the first APDU (max Lc = 255).
    first_chunk_max = 255 - len(header)
    assert first_chunk_max > 0, "P1=0x00 header too large (app_name or path too long)"
    first_chunk = context[:first_chunk_max]
    remaining = context[first_chunk_max:]

    p1_0_payload = header + first_chunk

    # Prepare P1=0x01 continuation chunks (255 bytes each).
    cont_chunks = [remaining[i:i + 255] for i in range(0, len(remaining), 255)]

    if p2 == P2_SILENT:
        # All APDUs are non-blocking — no screen.
        _dch_exchange(client, P1_INITIAL, p2, p1_0_payload)
        for chunk in cont_chunks:
            _dch_exchange(client, P1_CONTINUE, p2, chunk)
        return b""

    # P2_SHOW: the final APDU triggers Screen 1; use exchange_async for it.
    nav_instr, confirm_instrs, search_text = derive_context_hash_nav(device)

    if not cont_chunks:
        # Single-chunk: P1=0x00 is the final APDU.
        with client.transport_client.exchange_async(
            cla=CLA_VAULT,
            ins=INS_DERIVE_CONTEXT_HASH,
            p1=P1_INITIAL,
            p2=p2,
            data=p1_0_payload,
        ):
            navigator.navigate_until_text(
                navigate_instruction=nav_instr,
                validation_instructions=confirm_instrs,
                text=search_text,
                screen_change_before_first_instruction=False,
            )
    else:
        # Multi-chunk: intermediate APDUs are non-blocking; last P1=0x01 triggers screen.
        _dch_exchange(client, P1_INITIAL, p2, p1_0_payload)
        for chunk in cont_chunks[:-1]:
            _dch_exchange(client, P1_CONTINUE, p2, chunk)
        with client.transport_client.exchange_async(
            cla=CLA_VAULT,
            ins=INS_DERIVE_CONTEXT_HASH,
            p1=P1_CONTINUE,
            p2=p2,
            data=cont_chunks[-1],
        ):
            navigator.navigate_until_text(
                navigate_instruction=nav_instr,
                validation_instructions=confirm_instrs,
                text=search_text,
                screen_change_before_first_instruction=False,
            )

    _sw, response_data = client.last_async_response()
    assert _sw == SW_OK, f"Expected SW_OK, got {_sw:#06x}"
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

    The small sleep absorbs the Speculos startup race: the first APDU after
    launch can return SW_BIP32_FAIL (0x6f00) if BIP32 key material hasn't
    finished loading yet.
    """
    import time
    time.sleep(0.1)
    ct = 0 if bitcoin_network == "main" else 1
    return derive_context_hash(client, VAULT_APP_NAME, depositor_path(ct), context, navigator, device)


# ---------------------------------------------------------------------------
# APPROVE_VAULT_INTENT helpers
# ---------------------------------------------------------------------------

def _tlv_u8(tag: int, val: int) -> bytes:
    return bytes([tag >> 8, tag & 0xFF, 1, val])

def _tlv_u32be(tag: int, val: int) -> bytes:
    return bytes([tag >> 8, tag & 0xFF, 4]) + val.to_bytes(4, "big")

def _tlv_u64be(tag: int, val: int) -> bytes:
    return bytes([tag >> 8, tag & 0xFF, 8]) + val.to_bytes(8, "big")

def _tlv_bytes(tag: int, val: bytes) -> bytes:
    assert len(val) <= 255
    return bytes([tag >> 8, tag & 0xFF, len(val)]) + val

def _tlv_path(tag: int, path: List[int]) -> bytes:
    data = b"".join(p.to_bytes(4, "big") for p in path)
    return bytes([tag >> 8, tag & 0xFF, len(data)]) + data


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
    prepegin_max_fee: int = 500_000,
    vault_count: int = 1,
) -> bytes:
    """Encode the 13 P1=0x00 scalar intent fields into a TLV payload (v21 2-byte tags).

    Per-vault fields are sent in P1=0x01 group APDUs via build_group_tlv().
    Keys are sent in P1=0x02 batch APDUs, each individually tagged.
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
        _tlv_u8   (TAG_VAULT_COUNT,               vault_count)             +
        _tlv_u64be(TAG_PREPEGIN_MAX_FEE,          prepegin_max_fee)
    )


def build_group_tlv(
    htlc_vout: int,
    vault_provider_pk: bytes,
    vault_amount: int,
    commission_fee: int,
    depositor_claim_value: int,
    pegin_max_fee: int,
) -> bytes:
    """Encode one vault group into a P1=0x01 TLV payload (v21 2-byte tags)."""
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
    """Send one synchronous APPROVE_VAULT_INTENT phase; requires exact SW_OK (V-037)."""
    response = client.transport_client.exchange(
        cla=CLA_VAULT,
        ins=INS_APPROVE_VAULT_INTENT,
        p1=p1,
        p2=P2_UNUSED,
        data=data,
    )
    return _require_sw_ok(response, "APPROVE_VAULT_INTENT")


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

    groups: list of pre-built P1=0x01 group TLV payloads (one per vault).  When
    provided they are sent between the P1=0x00 scalars and the P1=0x02 key batches.

    When path and test_case_name are provided, snapshot comparison is performed:
      - If n_swipes is given, navigate_and_compare is used with an explicit instruction
        list (deterministic — use instructions.vault_intent_steps(device, 1, 1) for
        standard 1K+1C data).
      - If n_swipes is None, navigate_until_text_and_compare is used (timing-sensitive).
    When path is None, navigate_until_text is used (no comparison).
    """
    from .instructions import vault_intent_approve_nav, vault_intent_approve_instructions

    _approve_exchange(client, P1_SCALARS, scalars_tlv)

    for grp_tlv in (groups or []):
        _approve_exchange(client, P1_GROUP, grp_tlv)

    all_keys_tlv = ([_tlv_bytes(TAG_KEEPER_PK, k) for k in keeper_pks] +
                    [_tlv_bytes(TAG_CHALLENGER_PK, k) for k in challenger_pks])
    assert len(all_keys_tlv) > 0, "keeper_pks + challenger_pks must not be empty"
    batches = [all_keys_tlv[i : i + _KEYS_PER_BATCH] for i in range(0, len(all_keys_tlv), _KEYS_PER_BATCH)]

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
        elif n_swipes is not None:
            navigator.navigate(
                instructions=vault_intent_approve_instructions(device, n_swipes),
                screen_change_before_first_instruction=True,
                screen_change_after_last_instruction=False,
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

    Sends one P1=0x00 APDU with the scalar TLV, then one P1=0x01 APDU per group
    (when groups is provided), then streams all keys in P1=0x02 batches of up to
    7 keys each (245 bytes per APDU).

    Raises ExceptionRAPDU on any non-OK SW.
    """
    _approve_exchange(client, P1_SCALARS, scalars_tlv)

    for grp_tlv in (groups or []):
        _approve_exchange(client, P1_GROUP, grp_tlv)

    all_keys_tlv = ([_tlv_bytes(TAG_KEEPER_PK, k) for k in keeper_pks] +
                    [_tlv_bytes(TAG_CHALLENGER_PK, k) for k in challenger_pks])
    for i in range(0, len(all_keys_tlv), _KEYS_PER_BATCH):
        batch = all_keys_tlv[i : i + _KEYS_PER_BATCH]
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
    require_review: bool = True,
):
    """Call sign_psbt while capturing all review screens into a single snapshot folder.

    The standard client.sign_psbt + Instructions approach stores one screenshot per
    sub-folder (testname_0_0/, testname_0_1/, …).  This helper instead uses
    navigate_and_compare so all screens land as numbered PNGs inside one folder:
        snapshots/<device>/<testname>/00000.png, 00001.png, …

    Works by temporarily replacing the ragger_navigate bound method on the client
    instance — ragger_bitcoin is a git submodule so we cannot modify it directly.

    Use for touch devices (Flex, Stax, Apex).  For Nano, pass an Instructions object
    to client.sign_psbt directly.

    Returns client.sign_psbt's result — the list of (input_index, PartialSignature) pairs —
    so callers can verify the signatures rather than only the screens.  Discarding it made
    cryptographic verification impossible at every call site (Cerberus V-035).

    require_review: assert that at least one APDU actually blocked for review.  This helper
    exists to prove review-required flows display and await approval, but every exchange
    completing synchronously (done=True) silently skips navigate_and_compare, so firmware
    that returned signatures with no confirmation screen would satisfy it (V-026).  Pass
    False only for a flow that is legitimately silent — in which case prefer
    client.sign_psbt directly.
    """
    from ragger.utils import pack_APDU

    screenshot_dir = client.screenshot_dir
    review_count = 0

    def _flat_navigate(self, _nav, apdu, _instructions, _testname, index):
        nonlocal review_count
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
                review_count += 1
                index += 1
        sw, response = self.last_async_response()
        return sw, response, index

    client.ragger_navigate = types.MethodType(_flat_navigate, client)
    try:
        result = client.sign_psbt(psbt, wallet, wallet_hmac, navigator, testname=testname)
    finally:
        del client.ragger_navigate

    if require_review:
        assert review_count > 0, (
            "SIGN_PSBT completed without ever blocking for a review screen — "
            "signatures were returned with no user confirmation"
        )
    return result

