#!/usr/bin/env bash
# Local fuzzer runner for Babylon Vault fuzz targets.
# Builds if needed, then runs all targets in parallel for a configurable
# duration, saving corpus to fuzzing/corpus/ and crashes to fuzzing/crashes/.
#
# Usage:
#   ./fuzzing/run_local.sh                     # 60 s per target (default)
#   ./fuzzing/run_local.sh -t 300              # 5 minutes per target
#   ./fuzzing/run_local.sh -t 300 -j 4         # cap to 4 parallel jobs
#   ./fuzzing/run_local.sh -f fuzz_vault_tlv   # single target

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
CORPUS_DIR="$SCRIPT_DIR/corpus"
CRASH_DIR="$SCRIPT_DIR/crashes"

FUZZ_SECONDS=60
MAX_JOBS=$(( $(nproc) / 2 ))
MAX_JOBS=$(( MAX_JOBS < 1 ? 1 : MAX_JOBS ))
FILTER=""

usage() {
    echo "Usage: $0 [-t seconds] [-j jobs] [-f fuzzer_name]"
    echo "  -t  seconds per target (default: $FUZZ_SECONDS)"
    echo "  -j  max parallel jobs  (default: $MAX_JOBS)"
    echo "  -f  run only this one target (basename without path)"
    exit 1
}

while getopts "t:j:f:h" opt; do
    case $opt in
        t) FUZZ_SECONDS="$OPTARG" ;;
        j) MAX_JOBS="$OPTARG" ;;
        f) FILTER="$OPTARG" ;;
        h|*) usage ;;
    esac
done

# ── Build if needed ───────────────────────────────────────────────────────────
if [[ ! -d "$BUILD_DIR" ]] || [[ "$SCRIPT_DIR/CMakeLists.txt" -nt "$BUILD_DIR/Makefile" ]]; then
    echo "[build] Configuring and building fuzzers with clang..."
    cmake -DCMAKE_C_COMPILER=clang -B"$BUILD_DIR" -H"$SCRIPT_DIR"
    make -C "$BUILD_DIR" -j"$(nproc)"
fi

# ── Collect targets ───────────────────────────────────────────────────────────
if [[ -n "$FILTER" ]]; then
    TARGETS=("$BUILD_DIR/$FILTER")
    [[ -x "${TARGETS[0]}" ]] || { echo "error: '$FILTER' not found in $BUILD_DIR" >&2; exit 1; }
else
    mapfile -t TARGETS < <(find "$BUILD_DIR" -maxdepth 1 -name "fuzz_*" -perm /111 | sort)
fi

echo "[run] ${#TARGETS[@]} target(s), ${FUZZ_SECONDS}s each, up to ${MAX_JOBS} parallel"
echo "[run] corpus → $CORPUS_DIR   crashes → $CRASH_DIR"
echo

mkdir -p "$CRASH_DIR"

run_one() {
    local bin="$1"
    local name; name="$(basename "$bin")"
    local corpus="$CORPUS_DIR/$name"
    local logfile="$CRASH_DIR/${name}.log"
    mkdir -p "$corpus"

    "$bin" \
        -max_total_time="$FUZZ_SECONDS" \
        -artifact_prefix="$CRASH_DIR/${name}-" \
        -print_final_stats=1 \
        "$corpus" \
        >"$logfile" 2>&1

    if [[ $? -ne 0 ]]; then
        echo "[CRASH] $name — see $logfile"
    else
        local cov execs
        cov=$(grep  "cov:"                            "$logfile" | tail -1 | grep -oP "cov: \K[0-9]+")   || cov="?"
        execs=$(grep "stat::number_of_executed_units:" "$logfile" | grep -oP ": \K[0-9]+")               || execs="?"
        printf "[done] %-40s  cov: %s  execs: %s\n" "$name" "$cov" "$execs"
    fi
}

export -f run_one
export CRASH_DIR CORPUS_DIR FUZZ_SECONDS

running=0; pids=()
for bin in "${TARGETS[@]}"; do
    run_one "$bin" &
    pids+=($!)
    running=$(( running + 1 ))
    if (( running >= MAX_JOBS )); then
        wait "${pids[0]}"; pids=("${pids[@]:1}"); running=$(( running - 1 ))
    fi
done
wait

# ── Crash summary ─────────────────────────────────────────────────────────────
mapfile -t crash_files < <(find "$CRASH_DIR" -maxdepth 1 \
    \( -name "fuzz_*-crash-*" -o -name "fuzz_*-timeout-*" \) 2>/dev/null | sort)

if (( ${#crash_files[@]} > 0 )); then
    echo; echo "══ ${#crash_files[@]} crash(es) found ══"
    for f in "${crash_files[@]}"; do echo "  $f"; done
    echo; echo "Reproduce: $BUILD_DIR/<fuzzer> <crash-file>"
    exit 1
else
    echo; echo "No crashes found."
fi
