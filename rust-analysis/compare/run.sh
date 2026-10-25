#!/usr/bin/env bash
# Live differential regression: runs real Ghidra headless and ra on every
# corpus binary, then compares the two and enforces thresholds.toml.
#
#   GHIDRA_INSTALL_DIR=/path/to/ghidra compare/run.sh            # live
#   GHIDRA_INSTALL_DIR=... compare/run.sh --refresh-expected     # also update committed exports
#   compare/run.sh --offline                                     # use committed exports only
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$here/.."
mode=live
case "${1:-}" in
    --offline) mode=offline ;;
    --refresh-expected) mode=refresh ;;
    "") ;;
    *) echo "usage: $0 [--offline|--refresh-expected]"; exit 2 ;;
esac

cargo build --release -q --manifest-path "$root/Cargo.toml" -p ra-cli
ra="$root/target/release/ra"
expected="$here/expected"

if [ "$mode" != offline ]; then
    : "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR (or pass --offline)}"
    live="$here/work/live-expected"
    rm -rf "$live"; mkdir -p "$live"
    EXPECTED_DIR="$live" "$here/ghidra_export.sh"
    EXPECTED_DIR="$live" "$here/ghidra_demangle.sh"
    if [ "$mode" = refresh ]; then
        cp "$live"/*.json.gz "$expected"/
        mkdir -p "$expected/demangle"
        cp "$live"/demangle/ghidra.json.gz "$expected"/demangle/
    else
        # The committed exports must equal what this Ghidra produces, so the
        # offline `cargo test` gate tests the same thing.
        drift=0
        for f in "$live"/*.json.gz; do
            n="$(basename "$f")"
            if [ ! -e "$expected/$n" ] || ! python3 -I "$here/normalize_export.py" "$f" "$expected/$n"; then
                echo "DRIFT: $n differs from committed export (rerun with --refresh-expected)"; drift=1
            fi
        done
        if ! python3 -I -c 'import gzip,json,sys; sys.exit(json.load(gzip.open(sys.argv[1])) != json.load(gzip.open(sys.argv[2])))' \
                "$live/demangle/ghidra.json.gz" "$expected/demangle/ghidra.json.gz"; then
            echo "DRIFT: demangle/ghidra.json.gz differs from committed oracle"; drift=1
        fi
        if [ $drift != 0 ]; then
            echo "error: committed Ghidra exports are stale; rerun with --refresh-expected"
            exit 1
        fi
    fi
    expected="$live"
fi

"$ra" regress --corpus "$here/corpus/binaries" --expected "$expected" \
    --thresholds "$here/thresholds.toml" --report-dir "$here/work/report"
echo "full report: $here/work/report/report.md"
