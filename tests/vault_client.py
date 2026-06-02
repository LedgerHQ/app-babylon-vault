"""
Raw APDU helpers for Babylon Vault custom commands.

These functions bypass the ledger_bitcoin high-level client and send APDUs
directly via the ragger transport, which is necessary for vault-specific
INS codes that the bitcoin library doesn't know about.

Usage:
    from vault_client import derive_context_hash

    hashlock = derive_context_hash(client, app_name=b"BabylonVault", context=b"")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

CLA_VAULT                = 0xE1
INS_DERIVE_CONTEXT_HASH  = 0x81
INS_APPROVE_VAULT_INTENT = 0x80

P1_INITIAL   = 0x00
P1_CONTINUE  = 0x01
P1_SCALARS   = 0x00
P1_KEY_BATCH = 0x01
P2_UNUSED    = 0x00

# Max bytes per APDU data field
_CHUNK_SIZE     = 255
_KEYS_PER_BATCH = 7   # 7 × 32 = 224 bytes ≤ 255

# APDU status words
SW_OK               = 0x9000
SW_INCORRECT_DATA   = 0x6A80
SW_WRONG_DATA_LENGTH = 0x6A87
SW_WRONG_P1P2       = 0x6A86
SW_BAD_STATE        = 0xB007

# Tag byte assignments — must match src/vault_intent_tags.h
TAG_STRUCTURE_TYPE            = 0x01
TAG_VERSION                   = 0x02
TAG_COIN_TYPE                 = 0x03
TAG_VAULT_PROVIDER_PK         = 0x04
TAG_VAULT_AMOUNT              = 0x05
TAG_COMMISSION_FEE            = 0x06
TAG_DEPOSITOR_CLAIM_VALUE     = 0x07
TAG_BASE_FEE_RATE             = 0x08
TAG_PEGIN_MAX_FEE             = 0x09
TAG_PEGIN_CSV_TIMELOCK        = 0x0A
TAG_PAYOUT_TIMELOCK           = 0x0B
TAG_PREPEGIN_TXID             = 0x0C
TAG_HTLC_VOUT                 = 0x0D
TAG_HTLC_REFUND_TIMELOCK      = 0x0E
TAG_DEPOSITOR_DERIVATION_PATH = 0x0F
TAG_KEEPER_COUNT              = 0x10
TAG_CHALLENGER_COUNT          = 0x11

# Protocol constants — must match src/vault_constants.h
VAULT_STRUCTURE_TYPE     = 0x01
VAULT_PROTOCOL_VERSION   = 0x01

# Canonical test vault-provider key: x-coordinate of secp256k1 generator G.
# Must be a valid curve point because the firmware calls crypto_tr_lift_x on it.
TEST_VP_KEY = bytes.fromhex('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798')


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


def derive_context_hash(client: RaggerClient,
                        app_name: bytes,
                        context: bytes) -> bytes:
    """Send DERIVE_CONTEXT_HASH APDUs and return the 32-byte htlc_hashlock.

    Handles chunking automatically: sends P1=0x00 with the initial fields,
    then as many P1=0x01 chunks as needed.

    Args:
        client:    RaggerClient fixture from conftest.
        app_name:  UTF-8 app name, max 64 bytes.
        context:   Arbitrary context bytes; may be empty.

    Returns:
        32-byte htlc_hashlock = SHA256(htlc_preimage).
    """
    assert len(app_name) <= 64, "app_name must be ≤ 64 bytes"

    # Build P1=0x00 payload: app_name_len(1B) | app_name | context_total_len(2B BE)
    initial = (
        bytes([len(app_name)])
        + app_name
        + len(context).to_bytes(2, "big")
    )

    response_data = _exchange(client, P1_INITIAL, initial)

    if not context:
        # Zero-context path: device finalises immediately and returns hashlock
        assert len(response_data) == 32
        return response_data

    # Intermediate P1=0x00 response carries no data
    assert len(response_data) == 0

    # Stream context in chunks
    offset = 0
    while offset < len(context):
        chunk   = context[offset : offset + _CHUNK_SIZE]
        offset += len(chunk)
        is_last = offset == len(context)

        response_data = _exchange(client, P1_CONTINUE, chunk)

        if is_last:
            assert len(response_data) == 32
            return response_data
        else:
            assert len(response_data) == 0

    raise RuntimeError("unreachable")


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
    vault_provider_pk: bytes,
    vault_amount: int,
    commission_fee: int,
    depositor_claim_value: int,
    base_fee_rate: int,
    pegin_max_fee: int,
    pegin_csv_timelock: int,
    payout_timelock: int,
    prepegin_txid: bytes,
    htlc_vout: int,
    htlc_refund_timelock: int,
    depositor_path: List[int],
    keeper_count: int,
    challenger_count: int,
) -> bytes:
    """Encode all 17 scalar intent fields into a P1=0x00 TLV payload."""
    return (
        _tlv_u8   (TAG_STRUCTURE_TYPE,            VAULT_STRUCTURE_TYPE)    +
        _tlv_u8   (TAG_VERSION,                   VAULT_PROTOCOL_VERSION)  +
        _tlv_u32be(TAG_COIN_TYPE,                 coin_type)               +
        _tlv_bytes(TAG_VAULT_PROVIDER_PK,         vault_provider_pk)       +
        _tlv_u64be(TAG_VAULT_AMOUNT,              vault_amount)            +
        _tlv_u64be(TAG_COMMISSION_FEE,            commission_fee)          +
        _tlv_u64be(TAG_DEPOSITOR_CLAIM_VALUE,     depositor_claim_value)   +
        _tlv_u64be(TAG_BASE_FEE_RATE,             base_fee_rate)           +
        _tlv_u64be(TAG_PEGIN_MAX_FEE,             pegin_max_fee)           +
        _tlv_u32be(TAG_PEGIN_CSV_TIMELOCK,        pegin_csv_timelock)      +
        _tlv_u32be(TAG_PAYOUT_TIMELOCK,           payout_timelock)         +
        _tlv_bytes(TAG_PREPEGIN_TXID,             prepegin_txid)           +
        _tlv_u8   (TAG_HTLC_VOUT,                htlc_vout)               +
        _tlv_u32be(TAG_HTLC_REFUND_TIMELOCK,      htlc_refund_timelock)    +
        _tlv_path (TAG_DEPOSITOR_DERIVATION_PATH, depositor_path)          +
        _tlv_u8   (TAG_KEEPER_COUNT,              keeper_count)            +
        _tlv_u8   (TAG_CHALLENGER_COUNT,          challenger_count)
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


def approve_vault_intent(
    client: "RaggerClient",
    scalars_tlv: bytes,
    keeper_pks: List[bytes],
    challenger_pks: List[bytes],
) -> None:
    """Send APPROVE_VAULT_INTENT APDUs (both phases).

    Sends one P1=0x00 APDU with the scalar TLV, then streams all keys
    in P1=0x01 batches of up to 7 keys each (224 bytes per APDU).

    Raises ExceptionRAPDU on any non-OK SW.
    """
    _approve_exchange(client, P1_SCALARS, scalars_tlv)

    all_keys = keeper_pks + challenger_pks
    for i in range(0, len(all_keys), _KEYS_PER_BATCH):
        batch = all_keys[i : i + _KEYS_PER_BATCH]
        _approve_exchange(client, P1_KEY_BATCH, b"".join(batch))
