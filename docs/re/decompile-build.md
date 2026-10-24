# Building the standalone `decompile` executable (no JVM)

Directory: `Ghidra/Features/Decompiler/src/decompile/cpp/`

## Toolchain
- g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
- GNU Make 4.3
- GNU Bison 3.8.2 (needed: `xml.y` -> `xml.cc`, `grammar.y` -> `grammar.cc`).
  Not installed system-wide (no root); the Ubuntu `bison` + `m4` debs were
  unpacked with `dpkg -x` into a scratch dir and used via `PATH`,
  `BISON_PKGDATADIR` and `M4`.
- Linux x86_64, Ubuntu 24.04

## Build
```
cd Ghidra/Features/Decompiler/src/decompile/cpp
make -j$(nproc) ghidra_opt
cp ghidra_opt decompile
```
- Make target output name is `ghidra_opt` (g++ -std=c++11 -m64 -O2). It is
  copied to `decompile`, the name the Ghidra Java side expects.
- `make` regenerates the tracked files `xml.cc` and `grammar.cc` with the local
  bison; they were reverted with `git checkout` and not committed.
- `ghidra_opt` is gitignored; `decompile` is a build output and is not committed.

## Checksum
sha256 (`ghidra_opt` == `decompile`):
`a2e56c79a5f4b979ee0a90775a1b209c331b413f0d98670c912b6e1070906637`

## Empty-stdin check
`./decompile < /dev/null; echo $?` prints nothing and exits **1**, not 0.
This is by design, not a failure: `ArchitectureGhidra::readToAnyBurst`
(`ghidra_arch.cc:96`) calls `exit(1)` on EOF "to avoid a runaway process". Confirmed with gdb (breakpoint on `exit`, called from `readToAnyBurst`
<- `GhidraCapability::readCommand` <- `main`); no signal, no stderr output.
The binary starts, reads stdin, and terminates without crashing.
