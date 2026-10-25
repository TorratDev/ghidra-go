#!/usr/bin/env bash
# Runs Ghidra headless auto-analysis on each binary and writes the normalized
# export to expected/<binary>.json.
#   GHIDRA_INSTALL_DIR=/path/to/ghidra_X.Y_PUBLIC compare/ghidra_export.sh [bin...]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a Ghidra installation}"
out="${EXPECTED_DIR:-$here/expected}"
work="${WORK_DIR:-$here/work}"
mkdir -p "$out" "$work"
bins=("$@")
[ ${#bins[@]} -gt 0 ] || bins=("$here"/corpus/binaries/*)
for bin in "${bins[@]}"; do
    case "$bin" in *.log) continue ;; esac
    name="$(basename "$bin")"
    echo "== ghidra: $name"
    proj="$work/proj-$(echo "$name" | tr -c "A-Za-z0-9._\n-" _)"
    rm -rf "$proj"; mkdir -p "$proj"
    "$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$proj" p \
        -import "$bin" -overwrite \
        -scriptPath "$here/ghidra" \
        -postScript ExportAnalysis.java "$out/$name.json" \
        -analysisTimeoutPerFile 900 -deleteProject \
        >"$work/$name.ghidra.log" 2>&1 || { echo "ghidra failed for $name, see $work/$name.ghidra.log"; exit 1; }
    rm -rf "$proj"
    # Strip the machine-specific path, then gzip deterministically.
    python3 -I "$here/normalize_export.py" --strip-path "$out/$name.json"
    gzip -9 -n -f "$out/$name.json"
done
