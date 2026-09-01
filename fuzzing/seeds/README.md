# Fuzzing seed inputs

Seeds are **generated, not committed**. `generate_seeds.py` is the reviewable artifact; the
blobs it emits into `seeds/<target>/` are gitignored.

That split is deliberate. A committed 99-byte binary appears in review as
`Bin 0 -> 99 bytes`, which says nothing about what it is and cannot be checked against any
description of it. The generator instead names every field it writes, so a reviewer reads
intent rather than bytes:

```
python3 fuzzing/seeds/generate_seeds.py --dump    # annotated breakdown, writes nothing
python3 fuzzing/seeds/generate_seeds.py           # emit the blobs
python3 fuzzing/seeds/generate_seeds.py --check    # verify on-disk blobs match the source
```

## Three directories, three lifetimes

| | contents | tracked |
|---|---|---|
| `seeds/generate_seeds.py` | the source of every seed | **yes** |
| `seeds/<target>/` | blobs emitted by the generator | no |
| `corpus/<target>/` | everything libFuzzer discovers at runtime | no |

`run_local.sh` passes `corpus/<target>/` to libFuzzer as its writable corpus, so that
directory grows on every local run. Keeping all three separate means a local fuzzing
session cannot leave generated inputs staged for commit — which the previous layout, where
committed seeds shared a directory with libFuzzer's output, invited.

## Why seed at all

libFuzzer starts from an empty corpus on a cold run, and both targets have a structural
floor mutation is unlikely to clear:

- `fuzz_vault_group_tlv` must produce a well-formed 2-byte-tag TLV record before
  `vault_tlv_parse_group` gets past its framing checks.
- `fuzz_key_batch` ignores any input under 35 bytes, and its collision branches require a
  32-byte equality against the provider key.

Replaying the seeds takes `fuzz_key_batch` from `cov: 2` to `cov: 26`, and
`fuzz_vault_group_tlv` to `cov: 28`.

## Consumers

- `.clusterfuzzlite/build.sh` runs the generator, then zips each non-empty directory to
  `${OUT}/<target>_seed_corpus.zip` for ClusterFuzzLite to unpack.
- `run_local.sh` runs the generator, then copies the blobs into `corpus/<target>/` with
  `cp -n`, so local runs are seeded without clobbering discovered inputs.

## Adding a seed

Add a constructor call to `seeds()` in `generate_seeds.py`, named after the branch it is
meant to reach, with a comment saying why that branch is hard to reach by mutation. Keep it
minimal — a seed exists to reach a state cheaply, not to be a realistic transaction. If the
wire format changes, the tag constants at the top of the generator are the single place to
update; they mirror `src/vault_intent_tags.h`.
