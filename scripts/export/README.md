# Headless export of a Ghidra project

`ExportProject.java` is a read-only GhidraScript (written for Ghidra 11.4.3). It dumps the
open program to two files in the output directory:

- `export.json`: project and program info, memory blocks, symbols, functions (entry, body
  ranges, calling convention, prototype, parameters with storage) and the data types they use.
  Blocks are sorted by start address, symbols by address, functions by entry, data types by
  path name. No timestamps, so equal projects give equal files.
- `export.bin`: the bytes of every initialized memory block, concatenated in address order. Each
  block in the JSON gives its `sidecar_offset`/`sidecar_length`; the JSON names the file and its sha256.

Further sections carry what the decompiler callbacks read (all keys are added; existing ones are unchanged):

- `instructions`: listing instructions (`getInstructions(true)`) with address, length, parsed_length,
  length_overridden, mnemonic, bytes (hex), flow_override, fallthrough, default_fallthrough,
  fallthrough_overridden, delay_slot_depth, in_delay_slot and `references_from` (from, to, type name,
  primary, operand_index, source). **Known gap:** only code in the listing is recorded; addresses the
  decompiler disassembles on the fly (pseudoDisassemble) are not.
- `context`: context registers (name, bit_length), the default disassembly context (register, value, mask)
  and the value ranges of each context register (register, start, end, value, mask). Values are decimal strings.
- `registers`: every language register (name, space, space_id, offset, size, processor_context), sorted by name.
- `userops`: index and name for every index below `getNumberOfUserDefinedOpNames()`.
- `tracked_context`: `entries` holds, for each function entry, the value of every non-context register
  (`getValue(reg, entry, false)`: register, space, space_id, offset, size, decimal value), which is what the
  decompiler's gettrackedregisters callback asks; registers without a value are left out. This includes language
  defaults. `registers` lists explicitly set value ranges only (usually none: `getRegisterValueAddressRanges` does not
  report defaults), and `uniform_check` walks the range containing each hex address passed as a further script arg
  (at most 4,000,000 addresses; `uniform`, `addresses_checked`, `complete`).
- `comments`: EOL, PRE, POST, PLATE and REPEATABLE comments over the loaded, initialized memory
  (address, type name, text), sorted by address then type ordinal.
- `defined_data`: defined data items (address, data_type, length). Component coverage of structures and arrays is
  not checked.
- Functions also carry `calling_convention_explicit`, `stack_purge_size` (null when invalid or unknown), `stackshift`,
  `cc_extrapop`, `extrapop` and `local_variables` (name, data_type, length, storage, stack_offset, first_use_offset).
  The model is the function's own, else the compiler spec's default (never null), as `FunctionPrototype.grabFromFunction`
  does; this differs from a plain "null if no model" reading;
  `extrapop` is purge + stackshift when the purge is valid, else the model's extrapop.

All data types reached this way (function types, local variables, defined data) are in `data_types`.

`format_version` (currently 1) is the first key of `export.json`. A reader must reject a value it does not
know. Exports made before the field existed (including the ones with sha256 `d93b72f7…bb3d` and earlier) have no
`format_version`; the Go reader treats an absent field as 1. Adding keys does not change the version.

Addresses are `space:hexoffset` strings (`ram:02000d6c`). There is no universal ID: Ghidra generates a new one per
session for types it creates on the fly, so exporting it would make runs differ. `function_count` is the function
manager's count and includes external functions; the `functions` array holds the non-external
ones (`getFunctions(true)`).

## Run

    JAVA_HOME=<jdk 21> PATH=$JAVA_HOME/bin:$PATH \
    <ghidra>/support/analyzeHeadless <projdir> <project> -process <program> \
      -readOnly -noanalysis -scriptPath scripts/export -postScript ExportProject.java <outdir> [hexaddr ...]

`<outdir>` defaults to the current directory. Do not commit the output.
Note `-readOnly` still rewrites timestamps of the project's index files.
