#!/usr/bin/env bash
# Runs every Ghidra demangler over compare/demangle/names.txt and writes the
# results to expected/demangle/ghidra.json.gz (the demangle oracle).
#   GHIDRA_INSTALL_DIR=/path/to/ghidra compare/ghidra_demangle.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR to a Ghidra installation}"
out="${EXPECTED_DIR:-$here/expected}/demangle"
work="${WORK_DIR:-$here/work}"
mkdir -p "$out" "$work"
proj="$work/proj-demangle"
rm -rf "$proj"; mkdir -p "$proj"
# Any small binary will do: the script only needs a program context.
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$proj" p \
    -import "$here/corpus/binaries/freestanding-x86_64-clang-O2" -noanalysis \
    -scriptPath "$here/ghidra" \
    -postScript DemangleNames.java "$here/demangle/names.txt" "$out/ghidra.json" \
    -deleteProject >"$work/demangle.ghidra.log" 2>&1 || { echo "ghidra failed, see $work/demangle.ghidra.log"; exit 1; }
rm -rf "$proj"
gzip -9 -n -f "$out/ghidra.json"
echo "wrote $out/ghidra.json.gz"
