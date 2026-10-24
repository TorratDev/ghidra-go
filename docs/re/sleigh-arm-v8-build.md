# SLEIGH compiler and ARM v8 (little-endian) .sla

Directory for the compiler: `Ghidra/Features/Decompiler/src/decompile/cpp/`
Toolchain: g++ 13.3.0, GNU Make 4.3, Bison 3.8.2 and m4 from unpacked Ubuntu
debs via `PATH`, `BISON_PKGDATADIR`, `M4` (no root); Ubuntu 24.04 x86_64.

## 1. Build the SLEIGH compiler
```
cd Ghidra/Features/Decompiler/src/decompile/cpp
make -j$(nproc) sleigh_opt
```
- `sleigh_opt`: 1084520 bytes, sha256
  `476d09c7ddb2779cb7005d9bcf05cdb051f17125c984d44c1142fe939fadde1b`
- The build rewrites tracked `slghparse.cc` / `slghparse.hh` with the local
  bison; they were reverted (`git checkout`) and are not committed.
- `sleigh_opt` is a build output and is not committed.

## 2. Compile ARM8_le.slaspec
```
cd Ghidra/Processors/ARM/data/languages
<cpp>/sleigh_opt ARM8_le.slaspec <outdir>/ARM8_le.sla
```
Took under 1 s. Only warnings (e.g. "8 unnecessary extensions/truncations were
converted to copies", `ARMneon.sinc:140: Unreferenced table 'Sreg2'`); no errors.

- `ARM8_le.sla`: 275984 bytes, sha256
  `781007bba617f91dbf1b8b4bdba63fa3683f099bdd9c0069cc65601bd4297a2d`
- Other v8 specs in the same directory (`ARM8_be.slaspec`, `ARM8m_le.slaspec`,
  `ARM8m_be.slaspec`) were deliberately not built; only `ARM8_le` was asked for.
- `ARM.ldefs` maps `ARM8_le.sla` to `ARM:LE:32:v8`, `ARM:LE:32:v8T` and
  `ARM:LEBE:32:v8LEInstruction`; all use `ARM.cspec` (default compiler).
  `ARM.cspec` sha256 `428cff0d02aa903b634d295a20bcc653672630e29fcb348ece400c19131def3d`.

## 3. Spec search path
Source: `sleigh_arch.cc` (`scanForSleighDirectories`, `buildSpecFile`),
`consolemain.cc`, `libdecomp.cc`.
- The console decompiler (`decomp_opt`) finds specs by directory search.
  `.ldefs`, `.cspec`, `.pspec` and `.sla` are all looked up by file name in the
  same set of directories (`FileManage::findFile`), so the `.sla` must sit next
  to `ARM.ldefs` and `ARM.cspec`.
- Directories come from: `-s <dir>` (repeatable), and the Ghidra root (found
  from the executable path, else `$SLEIGHHOME`), which is scanned for
  `Ghidra/Processors/*/data/languages` (and `contrib`).
- The `decompile` binary (`ghidra_opt`) does not search; Ghidra's Java side sends
  it the spec data over the pipe, so this applies to `decomp_opt` only.

## 4. Load verification
`decomp_opt` needs libbfd (not installed). It was built without BFD by
overriding make variables only (no source or Makefile edits):
```
make decomp_opt -j8 BFDLIB= EXTRA="callgraph ifacedecomp ifaceterm inject_sleigh interface libdecomp loadimage_xml raw_arch rulecompile sleigh_arch testfunction unify xml_arch"
```
Scratch spec dir = copies of `Ghidra/Processors/ARM/data/languages/*.{ldefs,cspec,pspec,opinion}`
+ the new `ARM8_le.sla`, plus an 8-byte raw file (`add r0,r0,#1; bx lr`):
```
printf 'load file ARM:LE:32:v8 t.bin\nquit\n' | decomp_opt -s <specdir>
```
Output: `t.bin successfully loaded: Generic ARM/Thumb v8 little endian`.
Negative control (`-s` pointing at a nonexistent dir):
`No sleigh specification for ARM:LE:32:v8` / `Could not create architecture`.
This confirms the .sla and ARM.cspec load. No decompilation output was checked.
