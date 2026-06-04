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
