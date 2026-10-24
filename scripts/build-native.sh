#!/usr/bin/env bash
# Build the native decompiler tools from source into build/native/ (no JVM).
# Outputs: decompile, sleigh_opt, ARM8_le.sla. Builds in a copy so tracked
# generated files (xml.cc, grammar.cc, ...) are never rewritten in the clone.
# shortcut: checks tools exist but not their versions (tested only with the toolchain below), switch to a pinned container image when CI or a second distro needs it
# Tested with: g++ 13.3, GNU Make 4.3, Bison 3.8.2, flex 2.6.4, m4 1.4.19 on Ubuntu 24.04 x86_64.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cpp=$root/Ghidra/Features/Decompiler/src/decompile/cpp
lang=$root/Ghidra/Processors/ARM/data/languages
out=$root/build/native
work=$out/work

for tool in g++ make bison flex m4; do
  command -v "$tool" >/dev/null || { echo "missing prerequisite: $tool" >&2; exit 1; }
done

rm -rf "$work"
mkdir -p "$work"
cp -r "$cpp/." "$work/"

make -C "$work" -j"$(nproc)" ghidra_opt sleigh_opt
cp "$work/ghidra_opt" "$out/decompile"
cp "$work/sleigh_opt" "$out/sleigh_opt"
(cd "$lang" && "$out/sleigh_opt" ARM8_le.slaspec "$out/ARM8_le.sla")
rm -rf "$work"

# self-check: every output exists and is non-empty
for f in decompile sleigh_opt ARM8_le.sla; do
  [ -s "$out/$f" ] || { echo "build failed: $out/$f missing or empty" >&2; exit 1; }
done

cd "$out" && sha256sum decompile sleigh_opt ARM8_le.sla | sed "s#  #  $out/#"
