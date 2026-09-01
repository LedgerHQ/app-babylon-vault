#!/usr/bin/env python3
"""Generate fuzzing seed inputs.

This script is the reviewable artifact, not its output. Seed blobs are generated into
``seeds/<target>/`` at build time and are gitignored: a committed 99-byte binary tells a
reviewer nothing and cannot be checked against any description, whereas the constructors
below name every field they write.

Usage::

    python3 generate_seeds.py            # write seeds/<target>/*
    python3 generate_seeds.py --dump     # annotated hex breakdown, writes nothing
    python3 generate_seeds.py --check    # verify on-disk seeds match (no writes)

Invoked from ``.clusterfuzzlite/build.sh`` before zipping, and from ``run_local.sh``.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SEEDS_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# P1=0x01 group TLV wire format — must match src/vault_intent_tags.h
# ---------------------------------------------------------------------------
TAG_GRP_HTLC_VOUT = 0x0109             # u8    HTLC output index in the Pre-PegIn tx
TAG_GRP_VAULT_PROVIDER_PK = 0x010A     # 32 B  vault provider x-only pubkey
TAG_GRP_VAULT_AMOUNT = 0x010B          # u64   total vault amount, satoshis
TAG_GRP_COMMISSION_FEE = 0x010C        # u64   vault provider commission (Fc)
TAG_GRP_DEPOSITOR_CLAIM_VALUE = 0x010D  # u64  depositor claim UTXO value (Dcv)
TAG_GRP_PEGIN_MAX_FEE = 0x010E         # u64   max acceptable PegIn fee

TAG_NAMES = {
    TAG_GRP_HTLC_VOUT: "htlc_vout",
    TAG_GRP_VAULT_PROVIDER_PK: "vault_provider_pk",
    TAG_GRP_VAULT_AMOUNT: "vault_amount",
    TAG_GRP_COMMISSION_FEE: "commission_fee",
    TAG_GRP_DEPOSITOR_CLAIM_VALUE: "depositor_claim_value",
    TAG_GRP_PEGIN_MAX_FEE: "pegin_max_fee",
}

# Distinct, obviously-synthetic keys. Nothing here needs to be a real curve point: both
# targets call functions that compare or copy key bytes, not functions that lift them.
VP_KEY = bytes(range(1, 33))
VP_KEY_2 = bytes(range(33, 65))
KEY_A = bytes([0x10]) + bytes(31)
KEY_B = bytes([0x20]) + bytes(31)

# Values inside the parser's accepted ranges, so a valid record stays valid.
VAULT_AMOUNT = 100_000
COMMISSION_FEE = 1_000
DEPOSITOR_CLAIM_VALUE = 10_000
PEGIN_MAX_FEE = 50_000


def tlv(tag: int, value: bytes, *, declared_len: int | None = None) -> bytes:
    """One TLV record: 2-byte big-endian tag, 1-byte length, value.

    declared_len overrides the length byte, to build a record whose header lies about
    its payload size.
    """
    length = len(value) if declared_len is None else declared_len
    assert 0 <= length <= 0xFF, f"length {length} does not fit one byte"
    return bytes([tag >> 8, tag & 0xFF, length]) + value


def u64(value: int) -> bytes:
    return value.to_bytes(8, "big")


def group_record(*, htlc_vout: int = 0, provider_pk: bytes = VP_KEY) -> bytes:
    """A complete, well-formed group record: all six tags in canonical order."""
    return (
        tlv(TAG_GRP_HTLC_VOUT, bytes([htlc_vout]))
        + tlv(TAG_GRP_VAULT_PROVIDER_PK, provider_pk)
        + tlv(TAG_GRP_VAULT_AMOUNT, u64(VAULT_AMOUNT))
        + tlv(TAG_GRP_COMMISSION_FEE, u64(COMMISSION_FEE))
        + tlv(TAG_GRP_DEPOSITOR_CLAIM_VALUE, u64(DEPOSITOR_CLAIM_VALUE))
        + tlv(TAG_GRP_PEGIN_MAX_FEE, u64(PEGIN_MAX_FEE))
    )


# ---------------------------------------------------------------------------
# fuzz_key_batch input layout — must match fuzzing/src/fuzz_key_batch.c
#   [0] keeper_count byte      -> (b % VAULT_MAX_KEEPERS) + 1
#   [1] challenger_count byte  -> (b % VAULT_MAX_CHALLENGERS) + 1
#   [2] control byte           -> bit 0 replays the provider key as a candidate
#   [3..34] groups[0].vault_provider_pk
#   [35..]  consecutive 32-byte key windows
# ---------------------------------------------------------------------------
CONTROL_REPLAY_PROVIDER_KEY = 0x01
CONTROL_NONE = 0x00


def key_batch(*, keeper_byte: int, challenger_byte: int, control: int,
              provider_pk: bytes = VP_KEY, keys: tuple[bytes, ...] = ()) -> bytes:
    assert len(provider_pk) == 32
    assert all(len(k) == 32 for k in keys)
    return bytes([keeper_byte, challenger_byte, control]) + provider_pk + b"".join(keys)


def seeds() -> dict[str, dict[str, bytes]]:
    """Every seed, keyed by target then filename. Each entry names the branch it reaches."""
    one = group_record()
    return {
        "fuzz_vault_group_tlv": {
            # Baseline: the parser's success path, all six tags present.
            "valid_single": one,
            # Two concatenated records — exercises the `consumed`-advance framing that the
            # single-record case never reaches.
            "valid_two_records": one + group_record(htlc_vout=1, provider_pk=VP_KEY_2),
            # Cut mid-record: the boundary checks must stop rather than read past the end.
            "truncated": one[: len(one) // 2],
            # Header declares 31 bytes for a 32-byte field: the wrong-length arm.
            "bad_length": (
                tlv(TAG_GRP_HTLC_VOUT, bytes([0]))
                + tlv(TAG_GRP_VAULT_PROVIDER_PK, VP_KEY[:31], declared_len=31)
            ),
            # Unknown tag ahead of a valid record: the unknown-tag rejection arm.
            "unknown_tag": tlv(0x0999, bytes([0])) + one,
        },
        "fuzz_key_batch": {
            # control bit 0 set -> the provider key is replayed as a candidate, so
            # VAULT_KEY_ERR_ROLE_COLLISION is reached without the fuzzer having to guess a
            # 32-byte equality. This is the branch V-023 found unreachable.
            "collision_1k1c": key_batch(
                keeper_byte=0, challenger_byte=0,
                control=CONTROL_REPLAY_PROVIDER_KEY, keys=(KEY_A, KEY_B),
            ),
            # Same shape, no replay: two distinct ascending keys take the success path.
            "accepted_1k1c": key_batch(
                keeper_byte=0, challenger_byte=0,
                control=CONTROL_NONE, keys=(KEY_A, KEY_B),
            ),
            # Exactly the 35-byte header and nothing else: the harness's minimum accepted
            # size, reaching only the depositor-uniqueness arm.
            "depositor_only": key_batch(
                keeper_byte=0, challenger_byte=0, control=CONTROL_NONE,
            ),
        },
    }


def dump() -> None:
    """Print an annotated breakdown. Keeps review independent of reading raw bytes."""
    for target, files in seeds().items():
        print(f"\n=== {target} ===")
        for name, blob in files.items():
            print(f"\n  {name}  ({len(blob)} bytes)")
            if target == "fuzz_key_batch":
                print(f"    [0]      keeper_count byte    0x{blob[0]:02X}")
                print(f"    [1]      challenger_count     0x{blob[1]:02X}")
                replay = "replay provider key" if blob[2] & 1 else "no replay"
                print(f"    [2]      control              0x{blob[2]:02X}  ({replay})")
                print(f"    [3..34]  provider_pk          {blob[3:35].hex()[:16]}…")
                rest = blob[35:]
                print(f"    [35..]   {len(rest) // 32} key window(s), "
                      f"{len(rest) % 32} B remainder")
            else:
                i = 0
                while i + 3 <= len(blob):
                    tag = (blob[i] << 8) | blob[i + 1]
                    ln = blob[i + 2]
                    val = blob[i + 3:i + 3 + ln]
                    label = TAG_NAMES.get(tag, "UNKNOWN")
                    note = "" if len(val) == ln else f"  <- TRUNCATED ({len(val)}/{ln})"
                    print(f"    0x{tag:04X} len={ln:<2} {label:<22} "
                          f"{val.hex()[:16]}{'…' if ln > 8 else ''}{note}")
                    if len(val) < ln:
                        break
                    i += 3 + ln
                if i < len(blob):
                    print(f"    -- {len(blob) - i} trailing byte(s)")


def write(check_only: bool = False) -> int:
    mismatched = 0
    for target, files in seeds().items():
        target_dir = SEEDS_DIR / target
        if not check_only:
            target_dir.mkdir(parents=True, exist_ok=True)
        for name, blob in files.items():
            path = target_dir / name
            if check_only:
                if not path.exists() or path.read_bytes() != blob:
                    print(f"MISMATCH: {path.relative_to(SEEDS_DIR)}", file=sys.stderr)
                    mismatched += 1
            else:
                path.write_bytes(blob)
    if not check_only:
        total = sum(len(b) for f in seeds().values() for b in f.values())
        count = sum(len(f) for f in seeds().values())
        print(f"generated {count} seed(s), {total} bytes total")
    return mismatched


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--dump", action="store_true",
                       help="print an annotated breakdown; write nothing")
    group.add_argument("--check", action="store_true",
                       help="verify on-disk seeds match this script; write nothing")
    args = parser.parse_args()

    if args.dump:
        dump()
        return 0
    return 1 if write(check_only=args.check) else 0


if __name__ == "__main__":
    sys.exit(main())
