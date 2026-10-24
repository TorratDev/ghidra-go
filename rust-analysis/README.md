# rust-analysis

A Rust port of Ghidra's auto-analysis, as a single `ra` binary with JSON output. Every result is checked against real Ghidra.

- Instruction decoding uses Ghidra's own SLEIGH specs (`../Ghidra/Processors`), compiled at run time by [Icicle](https://github.com/icicle-emu/icicle-emu)'s SLEIGH implementation, so every Ghidra processor decodes.
- Regression testing is differential. Ghidra headless and `ra` analyze the same binaries, and `ra compare` diffs them category by category (functions, names, thunks, no-return, instructions, blocks, edges, references, imports and more). A ratchet in `compare/thresholds.toml` fails the build when any metric drops.
- `PARITY.md` maps every Java analyzer, loader, relocation handler, ELF extension, demangler, file system and module to its Rust counterpart, milestone and status. A test keeps it in sync with the Java tree.

## Layout

| crate | Java counterpart |
|---|---|
| `ra-core` | program model (`Memory`, symbols, functions, references) and the report schema |
| `ra-loader` | `ElfLoader`, `PeLoader`, `MachoLoader`, `BinaryLoader`, ELF/PE/Mach-O format markup, `.eh_frame` seeds |
| `ra-sleigh` | `SleighLanguage`, flow types, operand references, via Icicle |
| `ra-analysis` | entry points, PLT thunks, recursive descent, subroutine references, no-return (known and discovered), byte-pattern function starts, thunks, shared returns, jump tables, block-local constant propagation, `BasicBlockModel` |
| `ra-demangle` | `GnuDemangler` + `GnuDemanglerParser`, `RustDemangler`, `MicrosoftDemangler`, with Ghidra's naming rules (leaf name + namespace) |
| `ra-compare` | differential comparison, thresholds, report rendering |
| `ra-cli` | `ra analyze`, `ra compare`, `ra regress` |

## Usage

```sh
cargo build --release
./target/release/ra analyze /bin/ls -o ls.json
./target/release/ra analyze firmware.bin --language ARM:LE:32:v8   # raw image
./target/release/ra compare ghidra.json ra.json
```

## Regression against Ghidra

```sh
# Offline gate: ra vs the committed Ghidra exports in compare/expected/
cargo test --release

# Live: run Ghidra headless on the corpus now, check the committed exports
# are unchanged, and compare ra against the fresh exports
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC compare/run.sh

# After an improvement: raise the ratchet to the new results
./target/release/ra regress --update-thresholds
```

- `compare/corpus/src/`: corpus sources. `compare/corpus/build_corpus.sh` builds them, and the built binaries are committed so results never drift with the toolchain.
- `compare/ghidra/ExportAnalysis.java`: the GhidraScript that exports Ghidra's results in `ra`'s JSON schema.
- `compare/ghidra_export.sh`: runs Ghidra headless over the corpus and writes `compare/expected/*.json.gz`.
- `compare/ghidra/DemangleNames.java` and `compare/ghidra_demangle.sh`: the demangle oracle. Every Ghidra demangler runs over `compare/demangle/names.txt`, which holds every mangled symbol in the corpus plus every input extracted from Ghidra's Java demangler tests by `tools/extract_demangler_vectors.py`. `ra regress` reports agreement as the `demangle-oracle` pseudo-binary, with one category per Ghidra demangler class.
- `compare/thresholds.toml`: minimum recall and precision per binary and category.
- `ra regress --report-dir DIR`: writes `report.md` with per-category metrics and concrete mismatch samples (Ghidra-only and ra-only keys).

CI (`.github/workflows/rust-analysis.yml`) runs the offline gate, and also a live job that downloads the pinned Ghidra release (SHA-256 verified).

## Known gaps

These are measured by the differential report and listed in `PARITY.md`:

- **MSVC demangling:** 53% agreement on MDMang's own torture vectors (the corpus DLLs match 100%). The `msvc-demangler` crate can't parse many exotic forms, and full parity needs an MDMang port.
- **Function-wide constant propagation (M3):** propagation is block-local here, so references through registers set in other blocks are missed.
- **Jump tables:** recovery covers the x86 absolute and relative idioms. AArch64 and other architectures come in M3.
- **Static glibc internals:** IFUNC resolvers and libc-internal thunks and no-return functions differ.
- **ELF and PE header data markup:** references from header structures (`xrefs_from_data`) are not implemented.
