#!/usr/bin/env python3
"""Extracts demangler test inputs from Ghidra's Java tests and the corpus.

Writes:
  crates/ra-demangle/tests/vectors/msvc.json   [{mangled, ms_truth}]  (MDMangBaseTest)
  crates/ra-demangle/tests/vectors/gnu.json    [{mangled}]            (all Java tests)
  crates/ra-demangle/tests/vectors/rust.json   [{mangled}]            (Rust demangler tests)
  compare/demangle/names.txt                   every mangled input above plus every
                                               mangled symbol in compare/corpus/binaries,
                                               the input of compare/ghidra/DemangleNames.java

    python3 -I tools/extract_demangler_vectors.py
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
RA = os.path.normpath(os.path.join(HERE, ".."))
GHIDRA = os.path.normpath(os.path.join(RA, "..", "Ghidra"))
VEC = os.path.join(RA, "crates", "ra-demangle", "tests", "vectors")
NAMES = os.path.join(RA, "compare", "demangle", "names.txt")

LIT = r'"(?:[^"\\]|\\.)*"'
ASSIGN = re.compile(r"\b(mangled|msTruth)\s*=\s*((?:" + LIT + r"\s*\+?\s*)+);", re.S)


JAVA_ESC = re.compile(r"\\(u[0-9a-fA-F]{4}|.)")


def unescape(m):
    e = m.group(1)
    if e.startswith("u") and len(e) == 5:
        return chr(int(e[1:], 16))
    return {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "0": "\0"}.get(e, e)


def unquote(lits):
    return "".join(JAVA_ESC.sub(unescape, lit[1:-1]) for lit in re.findall(LIT, lits))


def java(path):
    with open(os.path.join(GHIDRA, path), encoding="utf-8") as f:
        return f.read()


def msvc_vectors():
    text = java("Features/MicrosoftDmang/src/test/java/mdemangler/MDMangBaseTest.java")
    out = []
    for method in text.split("@Test")[1:]:
        vals = {}
        for k, v in ASSIGN.findall(method):
            vals[k] = unquote(v)
        if "mangled" in vals:
            out.append({"mangled": vals["mangled"], "ms_truth": vals.get("msTruth")})
    return out


def test_sources():
    out = []
    for dirpath, _, files in os.walk(GHIDRA):
        if "/src/test" in dirpath:
            out += [os.path.relpath(os.path.join(dirpath, f), GHIDRA) for f in files if f.endswith(".java")]
    return sorted(out)


def literals(paths, prefixes):
    seen = []
    for p in paths:
        for lit in re.findall(LIT, java(p)):
            s = unquote(lit)
            if s.startswith(prefixes) and s not in seen:
                seen.append(s)
    return [{"mangled": s} for s in seen]


def corpus_symbols():
    names = set()
    bins = os.path.join(RA, "compare", "corpus", "binaries")
    for f in sorted(os.listdir(bins)):
        p = os.path.join(bins, f)
        for cmd in (["nm", "-a", p], ["nm", "-D", p]):
            r = subprocess.run(cmd, capture_output=True, text=True)
            for line in r.stdout.splitlines():
                parts = line.split()
                if parts:
                    names.add(parts[-1])
        r = subprocess.run(["objdump", "-p", p], capture_output=True, text=True)
        for m in re.finditer(r"^\s*\[\s*\d+\]\s+(\S+)$", r.stdout, re.M):
            names.add(m.group(1))
    return {n for n in names if n.startswith(("_Z", "__Z", "_R", "?", "_GLOBAL__"))}


def main():
    os.makedirs(VEC, exist_ok=True)
    sets = {
        "msvc": msvc_vectors(),
        # Every Itanium / Rust mangled literal in any Ghidra Java test.
        "gnu": [x for x in literals(test_sources(), ("_Z", "__Z")) if len(x["mangled"]) > 3 and " " not in x["mangled"]],
        "rust": literals(
            [p for p in test_sources() if "/rust/" in p.lower()], ("_R", "_ZN")),
    }
    names = set(corpus_symbols())
    for k, v in sets.items():
        with open(os.path.join(VEC, f"{k}.json"), "w") as f:
            json.dump(v, f, indent=1)
            f.write("\n")
        names.update(x["mangled"] for x in v)
    names = sorted(n for n in names if "\n" not in n and n.strip() == n and n)
    os.makedirs(os.path.dirname(NAMES), exist_ok=True)
    with open(NAMES, "w") as f:
        f.write("\n".join(names) + "\n")
    print(", ".join(f"{k}={len(v)}" for k, v in sets.items()), f"names.txt={len(names)}")


if __name__ == "__main__":
    sys.exit(main())
