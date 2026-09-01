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
genhtml coverage.info -o coverage
test -d coverage

echo "Generated 'coverage.info'."
