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

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ragger_bitcoin import RaggerClient

CLA_VAULT               = 0xE1
INS_DERIVE_CONTEXT_HASH = 0x81

P1_INITIAL  = 0x00
P1_CONTINUE = 0x01
P2_UNUSED   = 0x00

# Max bytes per APDU data field
_CHUNK_SIZE = 255


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
