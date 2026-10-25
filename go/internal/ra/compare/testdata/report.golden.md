# Ghidra vs ra differential report

Oracle: `ghidra 12.1.4` · Implementation: `ra-go (dev)`

Values are `recall / precision` against Ghidra (Ghidra = ground truth).

| binary | memory_blocks | symbols | imports | exports | functions | function_names | demangled_names | function_bodies | thunks | no_return | instructions | instruction_details | blocks | edges | xrefs_flow | xrefs_data | xrefs_data_kinds | xrefs_from_data |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| prog-x86_64 | 0.955 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 1.000 / 1.000 | 0.800 / 0.889 | 1.000 / 0.500 |

**demangle-oracle** (vs `ghidra 12.1.4`)

| category | matched | ghidra-only | ra-only | recall / precision |
|---|---|---|---|---|
| GnuDemangler | 153 | 3 | 3 | 0.981 / 0.981 |
| MicrosoftDemangler | 1 | 1 | 0 | 0.500 / 1.000 |

## Gate violations

- prog-x86_64 / xrefs_data_kinds: recall 0.8000 < required 1.0000
- missing-bin: gated binary has no result
- demangle-oracle / RustDemangler: gated category has no result

## Mismatch samples

### prog-x86_64

language `x86:LE:64:default`, bias `0x100000`

- **memory_blocks**: matched 21, ghidra-only 1, ra-only 0
  - ghidra-only: `.got.plt 0x4a9fe8-0x4aa0b0 r--`
- **xrefs_data_kinds**: matched 8, ghidra-only 2, ra-only 1
  - ghidra-only: `0x10->0x500 Read`, `0x10->0x504 Data`
  - ra-only: `0x10->0x500 Write`
- **xrefs_from_data**: matched 3, ghidra-only 0, ra-only 3
  - ra-only: `0x600->0x700`, `0x608->0x710`, `0x610->0x720`

### demangle-oracle

language `-`, bias `0x0`

- **GnuDemangler**: matched 153, ghidra-only 3, ra-only 3
  - ghidra-only: `_Z1fv => f`
  - ra-only: `_Z1fv => g`
- **MicrosoftDemangler**: matched 1, ghidra-only 1, ra-only 0
  - ghidra-only: ``??_7Foo@@6B@ => Foo::`vftable'``, ``??_R0?AVBar@@@8 => `reference temporary'{1}'``

