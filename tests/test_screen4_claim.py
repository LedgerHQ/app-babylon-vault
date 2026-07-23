"""Screen 4 — Claim: golden-snapshot tests for the Depositor Claim display.

The Claim transaction is a standalone SIGN_PSBT flow: the depositor spends the
Depositor Claim UTXO (leaf: <D> OP_CHECKSIG, 34 bytes) and the device shows
"Amount spent" + "Transaction fee" before the user approves.

Snapshots are stored under:
    tests/snapshots/<device>/screen4_claim/<test_case>_<network>/

Run with --golden_run to regenerate reference snapshots:

    pytest tests/test_screen4_claim.py --golden_run -k flex
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

from ledger_bitcoin.key import ExtendedKey, KeyOriginInfo
from ledger_bitcoin.psbt import PSBT, PartiallySignedInput, PartiallySignedOutput
from ledger_bitcoin.tx import CTransaction, CTxIn, CTxOut, COutPoint, CTxWitness

from test_utils.taproot import taproot_tweak_pubkey

from .vault_client import SW_DENY, sign_psbt_with_nav_and_compare
from .instructions import sign_psbt_claim_instructions, sign_psbt_claim_nav
from .test_sign_psbt_validate import (
    _NoWalletPolicy,
    _bip86_p2tr_spk,
    _tapleaf_hash,
    HARDENED,
    VAULT_NUMS_XONLY,
    VAULT_DUST_LIMIT,
)

ROOT_SCREENSHOT_PATH = Path(__file__).parent.resolve()


def _build_claim_psbt(
    fingerprint: bytes,
    leaf_key: bytes,
    coin_type: int,
    input_value: int = 1_200_000,
    connector_value: int = 600_000,
) -> PSBT:
    """Build a Claim PSBTv0 for Screen 4.

    Input 0: Depositor Claim UTXO — leaf <D> OP_CHECKSIG (34 bytes), single-leaf
             P2TR with NUMS internal key.  D is verified via TAP_BIP32_DERIVATION.
    Output 0: ClaimAssertConnector — host-provided; not checked by the device.
    Output 1: BIP-86 P2TR(D) CPFP anchor, value = VAULT_DUST_LIMIT.
              The device derives this key from D (leaf_key), not a separate out key.
    """
    claim_leaf = bytes([0x20]) + leaf_key + bytes([0xAC])  # 34 bytes
    leaf_hash = _tapleaf_hash(claim_leaf)
    parity, tweaked = taproot_tweak_pubkey(VAULT_NUMS_XONLY, leaf_hash)
    claim_spk = bytes([0x51, 0x20]) + tweaked
    control_block = bytes([0xC0 | parity]) + VAULT_NUMS_XONLY

    cpfp_spk = _bip86_p2tr_spk(leaf_key)

    dummy_connector_spk = bytes([0x51, 0x20]) + bytes(32)

    tx = CTransaction()
    tx.nVersion = 2
    tx.nLockTime = 0
    tx.vin = [CTxIn()]
    tx.vin[0].prevout = COutPoint(int.from_bytes(b'\xab' * 32, 'little'), 0)
    tx.vin[0].nSequence = 0xFFFFFFFF
    tx.vout = [
        CTxOut(connector_value, dummy_connector_spk),
        CTxOut(VAULT_DUST_LIMIT, cpfp_spk),
    ]
    tx.wit = CTxWitness()

    psbt = PSBT()
    psbt.version = 0
    psbt.tx = tx
    psbt.inputs = [PartiallySignedInput(0)]
    psbt.outputs = [PartiallySignedOutput(0), PartiallySignedOutput(0)]

    psbt.inputs[0].witness_utxo = CTxOut(input_value, claim_spk)
    psbt.inputs[0].tap_scripts[(claim_leaf, 0xC0)] = {control_block}
    psbt.inputs[0].tap_bip32_paths[leaf_key] = (
        {leaf_hash},
        KeyOriginInfo(fingerprint, [HARDENED | 86, HARDENED | coin_type, HARDENED | 0, 0, 0]),
    )

    return psbt


def test_sign_psbt_claim_screen(
    client: "RaggerClient",
    navigator: Navigator,
    device: Device,
    bitcoin_network: str,
) -> None:
    """Show Screen 4 (Claim) and capture all review pages as golden snapshots.

    Sends a valid Claim PSBT to the device.  Validation passes and the review
    screen is shown.  The test navigates through every page and then rejects,
    expecting SW_DENY.  Run once with --golden_run to create the reference images.
    """
    coin_type = 0 if bitcoin_network == "main" else 1

    fingerprint = client.get_master_fingerprint()
    leaf_key = ExtendedKey.deserialize(
        client.get_extended_pubkey(f"m/86'/{coin_type}'/0'/0/0", display=False)
    ).pubkey[1:]

    psbt = _build_claim_psbt(fingerprint, leaf_key, coin_type)
    dummy_wallet = _NoWalletPolicy("", "tr(@0/**)", [])
    tname = "screen4_claim/screen_" + bitcoin_network

    with pytest.raises(ExceptionRAPDU) as exc:
        if device.is_nano:
            client.sign_psbt(psbt, dummy_wallet, None, navigator,
                             testname=tname, instructions=sign_psbt_claim_instructions(device))
        else:
            sign_psbt_with_nav_and_compare(client, psbt, dummy_wallet, None, navigator,
                                           testname=tname, nav_instructions=sign_psbt_claim_nav(device))
    assert exc.value.status == SW_DENY
