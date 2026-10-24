#!/usr/bin/env python3
"""Generates rust-analysis/PARITY.md: every Ghidra Java component that the
Rust port must account for, with its Rust counterpart, milestone and status.

The inventory is scanned from the Java tree so nothing can be silently left
out; `crates/ra-cli/tests/parity_inventory.rs` fails if PARITY.md misses a
class that the same scan finds. Edit MAPPING below, then rerun:

    python3 -I tools/gen_parity.py
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, "..", ".."))
GHIDRA = os.path.join(ROOT, "Ghidra")
OUT = os.path.join(HERE, "..", "PARITY.md")

CLASS_RE = re.compile(
    r"^[ \t]*(public\s+)?(abstract\s+)?(final\s+)?class\s+(\w+)(\s*<[^{]*?>)?\s+(extends|implements)\s+([\w.]+)",
    re.M)


def kind_of(name, parent, rel):
    if name.endswith("ElfRelocationHandler"):
        return "elf_reloc"
    if name.endswith("MachoRelocationHandler"):
        return "macho_reloc"
    if name.endswith("_ElfExtension"):
        return "elf_ext"
    if parent.endswith("Analyzer") or parent == "AnalyzerAdapter":
        return "analyzer"
    if name.endswith("Loader") and parent.endswith("Loader"):
        return "loader"
    if parent in ("GFileSystemBase", "GFileSystem", "AbstractFileSystem", "AbstractSinglePayloadFileSystem"):
        return "filesystem"
    if parent == "Demangler":
        return "demangler"
    return None


def scan():
    found = {}
    for dirpath, dirnames, filenames in os.walk(GHIDRA):
        rel = os.path.relpath(dirpath, GHIDRA)
        if "/src/test" in "/" + rel or "/test/" in "/" + rel + "/" or "/build" in "/" + rel:
            dirnames[:] = []
            continue
        for f in filenames:
            if not f.endswith(".java"):
                continue
            path = os.path.join(dirpath, f)
            try:
                text = open(path, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            m = CLASS_RE.search(text)
            if not m or m.group(2):
                continue
            name, parent = m.group(4), m.group(7).split(".")[-1]
            k = kind_of(name, parent, rel)
            if k:
                module = "/".join(os.path.relpath(path, GHIDRA).split(os.sep)[:2])
                found.setdefault(k, {})[name] = module
    return found


def modules():
    out = []
    for group in ("Framework", "Features", "Processors", "Debug", "Extensions"):
        d = os.path.join(GHIDRA, group)
        if os.path.isdir(d):
            out += [f"{group}/{m}" for m in sorted(os.listdir(d)) if os.path.isdir(os.path.join(d, m))]
    return out


# name -> (rust counterpart, milestone, status, note)
M1 = "M1"
MAPPING = {
    # --- analyzers implemented in milestone 1
    "EntryPointAnalyzer": ("ra-analysis seeds + disassemble", M1, "done", ""),
    "ExternalEntryFunctionAnalyzer": ("ra-loader entry_points/seeds", M1, "done", ""),
    "FunctionAnalyzer": ("ra-analysis call targets -> functions", M1, "done", "Subroutine References"),
    "NoReturnFunctionAnalyzer": ("ra-analysis::noreturn (name lists from Base/data)", M1, "done", ""),
    "FindNoReturnFunctionsAnalyzer": ("ra-analysis compute_noreturn (port of evidence + only-calls-noreturn)", M1, "partial", "no flow repair/bookmarks"),
    "SharedReturnAnalyzer": ("ra-analysis is_tail_call (CALL_RETURN override)", M1, "done", ""),
    "SharedReturnJumpAnalyzer": ("ra-analysis is_tail_call", M1, "partial", ""),
    "CreateThunkAnalyzer": ("ra-analysis detect_thunks", M1, "partial", "single jump / lone no-return call; no multi-insn thunks"),
    "FunctionStartAnalyzer": ("ra-analysis::patterns", M1, "partial", "pre/post pairs, align, after=defined, validcode; no setcontext"),
    "FunctionStartFuncAnalyzer": ("ra-analysis::patterns", M1, "partial", ""),
    "FunctionStartPostAnalyzer": ("ra-analysis::patterns", M1, "partial", ""),
    "FunctionStartPreFuncAnalyzer": ("ra-analysis::patterns", M1, "partial", ""),
    "FunctionStartDataPostAnalyzer": ("ra-analysis::patterns", "M2", "planned", ""),
    "OperandReferenceAnalyzer": ("ra-sleigh data_refs + ra-analysis pointer_functions", M1, "partial", "operand constants"),
    "DataOperandReferenceAnalyzer": ("ra-sleigh data_refs", M1, "partial", ""),
    "ScalarOperandAnalyzer": ("ra-sleigh data_refs", "M2", "partial", ""),
    "ElfScalarOperandAnalyzer": ("ra-sleigh data_refs", "M2", "planned", ""),
    "MachoFunctionStartsAnalyzer": ("ra-loader LC_FUNCTION_STARTS", M1, "done", ""),
    "GccExceptionAnalyzer": ("ra-loader::eh_frame (gimli)", M1, "partial", "FDE starts only; LSDA/landing pads M2"),
    "ElfAnalyzer": ("ra-loader ELF markup", M1, "partial", "__DT_ labels, RELRO; header data types M2"),
    "PortableExecutableAnalyzer": ("ra-loader PE (.pdata, TLS)", M1, "partial", ""),
    "MachoAnalyzer": ("ra-loader Mach-O", M1, "partial", ""),
    "CondenseFillerBytesAnalyzer": ("ra-analysis", "M2", "planned", ""),
    "AggressiveInstructionFinderAnalyzer": ("ra-analysis::aggressive", "M2", "planned", "off by default in Ghidra"),
    "ArmAggressiveInstructionFinderAnalyzer": ("ra-analysis::aggressive", "M2", "planned", ""),
    "AddressTableAnalyzer": ("ra-analysis::data", "M2", "planned", ""),
    "StringsAnalyzer": ("ra-analysis::strings", "M2", "planned", ""),
    "EmbeddedMediaAnalyzer": ("ra-analysis::data", "M2", "planned", ""),
    "ConstantPropagationAnalyzer": ("ra-analysis propagate_constants", M1, "partial", "block-local registers + parameter refs; function-wide M3"),
    "X86Analyzer": ("ra-analysis propagate_constants", M1, "partial", "block-local"),
    "DecompilerSwitchAnalyzer": ("ra-analysis::switch", M1, "partial", "x86 absolute/relative jump tables; other arches M3"),
    "DecompilerFunctionAnalyzer": ("decompiler bridge (C++ decompiler via FFI)", "M3", "planned", ""),
    "DecompilerCallConventionAnalyzer": ("decompiler bridge", "M3", "planned", ""),
    "StackVariableAnalyzer": ("ra-analysis::stack", "M3", "planned", ""),
    "X86FunctionPurgeAnalyzer": ("ra-analysis::stack", "M3", "planned", ""),
    "CallFixupAnalyzer": ("ra-analysis::cc (cspec callfixup)", "M3", "planned", ""),
    "CallFixupChangeAnalyzer": ("ra-analysis::cc", "M3", "planned", ""),
    "GnuDemanglerAnalyzer": ("ra-demangle::gnu (cpp_demangle + GnuDemanglerParser port)", "M2", "done", "97% name agreement on Ghidra oracle; analyzer mode (all symbols)"),
    "MicrosoftDemanglerAnalyzer": ("ra-demangle::msvc (msvc-demangler + MDMang spelling)", "M2", "partial", "corpus 100%; 53% of MDMang torture vectors (crate parse gaps); MDMang port M4"),
    "RustDemanglerAnalyzer": ("ra-demangle::rust (legacy port + rustc-demangle v0)", "M2", "done", "100% on oracle; Rust detection via RUST_SIGNATURES"),
    "SwiftDemanglerAnalyzer": ("swift demangler port", "M4", "planned", ""),
    "DWARFAnalyzer": ("gimli", "M2", "planned", ""),
    "PdbUniversalAnalyzer": ("pdb crate", "M2", "planned", ""),
    "PdbAnalyzer": ("-", "-", "out-of-scope", "MSDIA is Windows-only"),
    "ApplyDataArchiveAnalyzer": ("-", "-", "out-of-scope", "needs Ghidra .gdt archives"),
    "PEExceptionAnalyzer": ("ra-analysis::seh", "M2", "planned", ""),
    "RttiAnalyzer": ("ra-analysis::rtti", "M3", "planned", ""),
    "FidAnalyzer": ("ra-fid (FID hashes)", "M4", "planned", ""),
    "ElfDefaultGotPltMarkup": ("ra-analysis markup_plt", M1, "done", ""),
    "GnuDemangler": ("ra-demangle::gnu", "M2", "done", ""),
    "RustDemangler": ("ra-demangle::rust", "M2", "done", ""),
    "MicrosoftDemangler": ("ra-demangle::msvc", "M2", "partial", ""),
    "SwiftDemangler": ("swift demangler port", "M4", "planned", "no Swift toolchain for the corpus"),
    "SummarizeAnalyzers": ("-", "-", "out-of-scope", "debug utility"),
    "TestAnalyzer": ("-", "-", "out-of-scope", "test helper"),
    # --- loaders
    "ElfLoader": ("ra-loader (object + goblin)", M1, "partial", "executables/shared objects; .o relocation M2"),
    "PeLoader": ("ra-loader (object + goblin)", M1, "partial", ""),
    "MachoLoader": ("ra-loader (object + goblin)", M1, "partial", "thin binaries; fat/universal M2"),
    "BinaryLoader": ("ra-loader load_raw", M1, "done", "--language required"),
    "CoffLoader": ("ra-loader (object coff)", "M2", "planned", ""),
    "MzLoader": ("ra-loader custom", "M2", "planned", ""),
    "NeLoader": ("ra-loader custom", "M2", "planned", ""),
    "IntelHexLoader": ("ihex crate", "M2", "planned", ""),
    "MotorolaHexLoader": ("srec crate", "M2", "planned", ""),
    "UnixAoutLoader": ("ra-loader custom", "M2", "planned", ""),
    "DyldCacheLoader": ("ra-loader custom", "M2", "planned", ""),
    "DexLoader": ("dex crate", "M2", "planned", ""),
    "JavaLoader": ("classfile parser", "M2", "planned", ""),
    "OmfLoader": ("ra-loader custom", "M3", "planned", ""),
    "Omf51Loader": ("ra-loader custom", "M3", "planned", ""),
    "PefLoader": ("ra-loader custom", "M3", "planned", ""),
    "SomLoader": ("ra-loader custom", "M3", "planned", ""),
    "DbgLoader": ("pdb/dbg parser", "M3", "planned", ""),
    "DefLoader": ("ra-loader custom", "M3", "planned", ""),
    "MapLoader": ("ra-loader custom", "M3", "planned", ""),
    "DumpFileLoader": ("minidump crate", "M3", "planned", ""),
    "SarifLoader": ("serde-sarif", "M5", "planned", ""),
    "XmlLoader": ("quick-xml", "M5", "planned", ""),
    "GzfLoader": ("-", "-", "out-of-scope", "Ghidra database format"),
    "GdtLoader": ("-", "-", "out-of-scope", "Ghidra database format"),
    "GztLoader": ("-", "-", "out-of-scope", "Ghidra database format"),
    "DecompileDebugXmlLoader": ("-", "-", "out-of-scope", "decompiler debugging"),
    "TenetLoader": ("-", "-", "out-of-scope", "trace format"),
    "TenetPlusPlusLoader": ("-", "-", "out-of-scope", "trace format"),
    "X86_64_ElfRelocationHandler": ("ra-loader dynamic relocs", M1, "partial", "RELATIVE/GLOB_DAT/JUMP_SLOT"),
    "X86_32_ElfRelocationHandler": ("ra-loader dynamic relocs", M1, "partial", "REL forms keep in-place addend"),
    "AARCH64_ElfRelocationHandler": ("ra-loader dynamic relocs", M1, "partial", ""),
    "ARM_ElfRelocationHandler": ("ra-loader dynamic relocs", M1, "partial", ""),
}

DEFAULTS = {
    "analyzer": ("ra-analysis (per-processor/format module)", "M3", "planned"),
    "loader": ("ra-loader", "M3", "planned"),
    "elf_reloc": ("ra-loader relocation handler", "M2", "planned"),
    "macho_reloc": ("ra-loader relocation handler", "M2", "planned"),
    "elf_ext": ("ra-loader ELF extension", "M2", "planned"),
    "filesystem": ("ra-fs (zip/tar/flate2/zstd/... crates or custom)", "M4", "planned"),
    "demangler": ("see demangler analyzers", "M2", "planned"),
}

MODULES = {
    "Framework/SoftwareModeling": ("ra-core (program model), ra-sleigh (SLEIGH)", M1, "partial"),
    "Framework/Emulation": ("icicle-vm", "M4", "planned"),
    "Framework/DB": ("-", "-", "out-of-scope"),
    "Framework/Docking": ("-", "-", "out-of-scope"),
    "Framework/Gui": ("-", "-", "out-of-scope"),
    "Framework/Help": ("-", "-", "out-of-scope"),
    "Framework/Graph": ("ra-analysis CFG data only", M1, "partial"),
    "Framework/Project": ("-", "-", "out-of-scope"),
    "Framework/FileSystem": ("-", "-", "out-of-scope"),
    "Framework/Pty": ("-", "-", "out-of-scope"),
    "Framework/Generic": ("std / crates", "-", "n/a"),
    "Framework/Utility": ("std / crates", "-", "n/a"),
    "Features/Base": ("ra-loader, ra-analysis", M1, "partial"),
    "Features/BytePatterns": ("ra-analysis::patterns", M1, "partial"),
    "Features/Decompiler": ("C++ decompiler bridge (FFI)", "M3", "planned"),
    "Features/DecompilerDependent": ("decompiler bridge", "M3", "planned"),
    "Features/FileFormats": ("ra-fs, ra-formats", "M4", "planned"),
    "Features/FunctionID": ("ra-fid", "M4", "planned"),
    "Features/GnuDemangler": ("ra-demangle::gnu", "M2", "done"),
    "Features/MicrosoftDemangler": ("ra-demangle::msvc", "M2", "partial"),
    "Features/MicrosoftDmang": ("msvc-demangler (MDMang port M4)", "M2", "partial"),
    "Features/MicrosoftCodeAnalyzer": ("ra-analysis::{rtti,seh}", "M3", "planned"),
    "Features/PDB": ("pdb crate", "M2", "planned"),
    "Features/Rust": ("ra-demangle::rust", "M2", "partial"),
    "Features/Swift": ("swift demangler", "M4", "planned"),
    "Features/Objective-C": ("ra-analysis::objc", "M4", "planned"),
    "Features/Recognizers": ("ra-fs magic recognizers", "M4", "planned"),
    "Features/Sarif": ("serde-sarif export", "M2", "planned"),
    "Features/BSim": ("ra-bsim (decompiler features)", "M5", "planned"),
    "Features/VersionTracking": ("ra-diff", "M5", "planned"),
    "Features/VersionTrackingBSim": ("ra-diff", "M5", "planned"),
    "Features/ProgramDiff": ("ra-diff", "M5", "planned"),
    "Features/CodeCompare": ("ra-diff", "M5", "planned"),
    "Features/WildcardAssembler": ("sleigh assembler", "M4", "planned"),
    "Features/SystemEmulation": ("icicle-vm", "M4", "planned"),
    "Features/PyGhidra": ("PyO3 bindings", "M5", "planned"),
    "Features/GhidraServer": ("-", "-", "out-of-scope"),
}


def module_row(m):
    if m in MODULES:
        return MODULES[m]
    if m.startswith("Processors/"):
        return ("ra-sleigh (.slaspec via Icicle) + processor analyzers", M1, "partial")
    if m.startswith("Debug/"):
        return ("-", "-", "out-of-scope")
    if m.startswith("Extensions/"):
        return ("-", "-", "out-of-scope")
    return ("-", "-", "out-of-scope")


TITLES = [
    ("analyzer", "Analyzers"),
    ("loader", "Loaders"),
    ("elf_reloc", "ELF relocation handlers"),
    ("macho_reloc", "Mach-O relocation handlers"),
    ("elf_ext", "ELF extensions"),
    ("demangler", "Demanglers"),
    ("filesystem", "File systems"),
]


def main():
    found = scan()
    out = []
    out.append("# Java → Rust parity matrix\n")
    out.append("Generated by `tools/gen_parity.py` from a scan of the Ghidra Java tree; ")
    out.append("`crates/ra-cli/tests/parity_inventory.rs` fails if a scanned class is missing here.\n\n")
    out.append("Status: **done** = matches Ghidra on the differential corpus; **partial** = implemented, known gaps; ")
    out.append("**planned** = milestone assigned; **out-of-scope** = not part of the headless analysis port.\n\n")
    out.append("Verification for every `done`/`partial` row is the Ghidra-vs-ra differential regression ")
    out.append("(`compare/`, gated by `compare/thresholds.toml`).\n\n")
    totals = {}
    sections = []
    for key, title in TITLES:
        rows = found.get(key, {})
        lines = [f"## {title} ({len(rows)})\n\n", "| Java class | module | Rust | milestone | status | notes |\n|---|---|---|---|---|---|\n"]
        for name in sorted(rows):
            rust, ms, status, note = MAPPING.get(name, DEFAULTS[key] + ("",))
            totals[status] = totals.get(status, 0) + 1
            lines.append(f"| `{name}` | {rows[name]} | {rust} | {ms} | {status} | {note} |\n")
        sections.append("".join(lines) + "\n")
    mods = modules()
    lines = [f"## Modules ({len(mods)})\n\n", "| module | Rust | milestone | status |\n|---|---|---|---|\n"]
    for m in mods:
        rust, ms, status = module_row(m)
        lines.append(f"| `{m}` | {rust} | {ms} | {status} |\n")
    sections.append("".join(lines) + "\n")
    out.append("## Summary\n\n| status | classes |\n|---|---|\n")
    for st in ("done", "partial", "planned", "out-of-scope"):
        out.append(f"| {st} | {totals.get(st, 0)} |\n")
    out.append("\n")
    out.extend(sections)
    text = "".join(out)
    if "--check" in sys.argv:
        current = open(OUT).read() if os.path.exists(OUT) else ""
        if current != text:
            print("PARITY.md is out of date with the Java tree; run python3 -I tools/gen_parity.py", file=sys.stderr)
            return 1
        print("PARITY.md up to date")
        return 0
    with open(OUT, "w") as f:
        f.write(text)
    print(f"wrote {os.path.relpath(OUT, ROOT)}: " + ", ".join(f"{k}={len(v)}" for k, v in found.items()))


if __name__ == "__main__":
    sys.exit(main())
