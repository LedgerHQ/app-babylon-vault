#!/usr/bin/env bash

# Each lcov stage is its own command. They used to be chained into a single && list, which
# defeated `set -e`: only the *last* member of an AND-list is subject to errexit, so a
# failure in any earlier stage short-circuited the rest, fell through to the unconditional
# cleanup, and returned that cleanup's exit status — zero. CI therefore reported coverage
# generation as successful with no tracefile produced.
set -Eeuo pipefail
set -x

cd -- "$(dirname -- "$0")"

BUILD_DIRECTORY="$(realpath -- build/)"

# Runs on any exit path, including failure, so the intermediates cannot be left behind.
trap 'rm -f coverage.base coverage.capture' EXIT

lcov --directory . -b "${BUILD_DIRECTORY}" --capture --initial -o coverage.base
lcov --rc lcov_branch_coverage=1 --directory . -b "${BUILD_DIRECTORY}" --capture -o coverage.capture
lcov --directory . -b "${BUILD_DIRECTORY}" --add-tracefile coverage.base --add-tracefile coverage.capture -o coverage.info
lcov --directory . -b "${BUILD_DIRECTORY}" --remove coverage.info '*/unit-tests/*' -o coverage.info

# Assert the artifacts actually exist rather than trusting the exit statuses above.
test -s coverage.info

# ---------------------------------------------------------------------------
# Scope guard (V-031)
#
# LCOV can only report translation units the build emitted .gcno files for, so a source
# that no unit target compiles disappears from the numerator *and* the denominator rather
# than showing as 0%. The percentage therefore describes the instrumented subset, not the
# application — which is why the artifact is published as "unit-subset-coverage".
#
# Two consequences, handled here:
#   1. The sources that ARE instrumented must stay instrumented. Dropping one would
#      silently raise the reported percentage, so their presence is asserted below.
#   2. The uninstrumented security-critical sources are listed explicitly rather than left
#      implicit. They are not host-compilable without substantial mocking (SDK, NBGL,
#      base-app dispatcher); their compensating coverage is the Ragger suite, which
#      exercises them on-device via Speculos.
# ---------------------------------------------------------------------------
instrumented_sources=(
  src/vault_tlv.c
  src/vault_context.c
  src/vault_script.c
  src/globals.c
  src/bip322.c
  src/sign_psbt_validate_helpers.c
)

# Not host-compiled; covered by tests/ (Ragger/Speculos) instead. Kept here so the gap is
# reviewable and so this list has to be shortened deliberately, never by accident.
uninstrumented_sources=(
  src/sign_psbt_validate.c
  src/sign_custom_inputs.c
  src/apdu_handler.c
  src/display.c
  src/handler/approve_vault_intent.c
  src/handler/derive_context_hash.c
)

repo_root="$(realpath -- ..)"
missing=0
for rel in "${instrumented_sources[@]}"; do
    source_path="$(realpath -- "$repo_root/$rel")"
    if ! grep -Fqx "SF:$source_path" coverage.info; then
        printf 'ERROR: instrumented source absent from coverage denominator: %s\n' "$rel" >&2
        missing=1
    fi
done
if [ "$missing" -ne 0 ]; then
    printf 'Coverage scope shrank. Either restore the target that compiled it, or move the\n' >&2
    printf 'file to uninstrumented_sources in this script with its compensating coverage.\n' >&2
    exit 1
fi

printf 'Coverage scope: %d instrumented, %d covered by Ragger only.\n' \
    "${#instrumented_sources[@]}" "${#uninstrumented_sources[@]}"

genhtml coverage.info -o coverage
test -d coverage

echo "Generated 'coverage.info'."
