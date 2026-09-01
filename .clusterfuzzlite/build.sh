#!/bin/bash -eu

pushd "$SRC/app-babylon-vault/fuzzing"

cmake \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
    -Bbuild -H.

make -C build -j"$(nproc)"

mv ./build/fuzz_* "${OUT}"

# Seeds are generated, not committed: seeds/generate_seeds.py is the reviewable source.
python3 seeds/generate_seeds.py

# Zip non-empty seed dirs. Reads seeds/, not corpus/ — the latter is libFuzzer's local
# working output and is gitignored. See fuzzing/seeds/README.md.
for target in fuzz_vault_tlv fuzz_key_batch fuzz_vault_group_tlv; do
    seeds=$(find "seeds/$target" -type f 2>/dev/null || true)
    if [ -n "$seeds" ]; then
        zip -j "${OUT}/${target}_seed_corpus.zip" $seeds
    fi
done

popd
