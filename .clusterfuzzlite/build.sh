#!/bin/bash -eu

pushd "$SRC/app-babylon-vault/fuzzing"

cmake \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DLIB_FUZZING_ENGINE="$LIB_FUZZING_ENGINE" \
    -Bbuild -H.

make -C build -j"$(nproc)"

mv ./build/fuzz_* "${OUT}"

# Zip non-empty seed corpus dirs (skip .gitkeep-only dirs)
for target in fuzz_vault_tlv fuzz_key_batch; do
    seeds=$(find "corpus/$target" -type f ! -name ".gitkeep" 2>/dev/null || true)
    if [ -n "$seeds" ]; then
        zip -j "${OUT}/${target}_seed_corpus.zip" $seeds
    fi
done

popd
