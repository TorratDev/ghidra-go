# Decompiler wire protocol (Java Ghidra <-> native `decompile`)

The native `decompile` process talks to its client over stdin/stdout. This note documents the
framing, the commands, and the callback queries. Everything here is checked against the golden
transcripts in `testdata/golden/` (see its README) and the sources named in each section.
Anything a transcript does not exercise is marked **unverified**.

Conventions:

- Markers are hex bytes; decimal in parentheses. Java source writes them in decimal
  (`DecompileProcess.java:54-63`, `case 16:` etc.), the C++ source writes them as octal escapes
  (`"\000\000\001\020"` is `00 00 01 10`, decimal 16).
- `file:Lnnn` references a line of a golden hex file (`xxd -p`, 30 bytes = 60 hex chars per line).
  `@off` is the byte offset into the decoded transcript. Line = `off/30 + 1`.
- `in` = Java to native (`in.hex`, native stdin). `out` = native to Java (`out.hex`).
- Transcripts: A = `testdata/golden/02000d6c`, B = `testdata/golden/02018c80`.

## Framing

A marker is 4 bytes: `00 00 01 XX`. Payload bytes between markers are raw (a string) or packed
binary (see "Payload encoding"). Markers come in start/end pairs (start is even, end is start+1).

| Start/end | Dir | Meaning | Seen in transcripts |
|---|---|---|---|
| 02 / 03 | in | command: `02`, string with command name, 0..n argument strings, `03` | yes |
| 08 / 09 | in | answer to a native query (QRESP) | yes |
| 0e / 0f (14/15) | both | string: raw text or packed payload | yes |
| 04 / 05 | out | native query to Java | yes |
| 06 / 07 | out | command response header / closer | yes |
| 10 / 11 (16/17) | out | error text; empty text means success | yes (empty only) |
| 0a / 0b (10/11) | both | exception: type string, message string | **unverified** (absent) |
| 0c / 0d (12/13) | in | bytes (reply to getbytes, hex-pair text) | **unverified** (absent) |
| 12 / 13 (18/19) | out | warning text | **unverified** (absent) |

Source:

- Java defines constants only for 2, 3, 8-15 (`DecompileProcess.java:54-63`). Markers 4-7, 16, 17
  and 18 are handled as literals in its read loop (`:327-457`, `readToResponse` `:231-240`).
- Native writes: `06`/`07` and `10`/`11` in `ghidra_process.cc:107-113,128,151`; `04` in
  `ghidra_arch.cc:448`; `0a`/`0b` in `ghidra_arch.cc:244-247`; `12`/`13` in `ghidra_arch.cc:898-901`.

### Error marker: 10/11 or 16/17? Settled

Both are the same bytes, written in different notations. `ghidra_process.cc:111-113` writes the
octal escapes `\020` and `\021`, which are bytes `0x10`/`0x11` = decimal 16/17. Java's
`case 16:` / `case 17:` (`DecompileProcess.java:434-441`) matches. Decimal 10/11 (`0x0a`/`0x0b`) is the
*exception* pair, a different frame. Checked against the bytes: every response frame ends with
`00 00 01 10 00 00 01 11` (empty error text), except the last (deregisterProgram), which has none
(`DeregisterProgram::sendResult` writes its result string then calls `GhidraCommand::sendResult`,
which emits nothing once the architecture is released, `ghidra_process.cc:246-253,107-110`).
A: out@3965 (L133), @5603 (L187), @5628 (L188). B: out@3965, @5093 (L170), @5118 (L171).
Marker counts (both transcripts): out has `10`x3, `11`x3, and no `0a`, `0b`, `0c`, `0d`, `12`, `13`.

## Message flow

1. Java sends a command (`02`, name string, argument strings, `03`).
2. Native replies `06` immediately, then runs the command. While it runs it may emit any number of
   queries (`04` string `05`). Java answers each with `08` answer `09`, in order.
3. Native finishes with the result string (`0e` .. `0f`), the error frame (`10` text `11`), then `07`.

So the QRESPs for a command's queries follow that command's `03` in `in`, and all of them sit
inside that command's `06 .. 07` in `out`.

### Frame sequence per transcript

| | in | out |
|---|---|---|
| A (02000d6c) | 183 frames: CMD registerProgram, 170 QRESP, CMD decompileAt, 9 QRESP, CMD flushNative, CMD deregisterProgram | 4 response frames holding 179 queries (170 + 9 + 0 + 0) |
| B (02018c80) | 186 frames: same 4 CMD, 170 + 12 = 182 QRESP | 4 response frames holding 182 queries (170 + 12 + 0 + 0) |

Marker counts agree (A in: `02`x4, `03`x4, `08`x179, `09`x179; out: `04`x179, `05`x179, `06`x4, `07`x4).

Offsets (same in both transcripts unless noted):

| Item | in | out |
|---|---|---|
| CMD registerProgram | `02` @0 (L1) .. `03` @15884 (L530) | response `06` @0 (L1), result "0" @3956 (L132), `07` @3973 (L133) |
| strings in registerProgram | name @4, processor_spec @27, compiler_spec @2070 (L70), sleigh @5019 (L168), coretypes @13198 (L440) | |
| first QRESP (getuseropname 0) | @15888 (L530) | first query @4 (L1) |
| 170th QRESP/query (getregister) | @23536 (L785) | @3931 (L132) |
| CMD decompileAt | `02` @23563 (L786) .. `03` @23614 (L788) | A: `06` @3977 (L133) .. `07` @5611 (L188); B: `06` @3977 .. `07` @5101 (L171) |
| decompileAt result string | | A: `0e` @4248 (L142) .. `0f` @5599 (L187); B: @4341 (L145) .. @5089 (L170) |
| CMD flushNative | A: `02` @24996 (L834); B: @26226 (L875) | A: `06` @5615 (L188), result "0"; B: `06` @5105 (L171) |
| CMD deregisterProgram | A: `02` @25032 (L835); B: @26262 (L876) | A: `06` @5640 (L189), result "1" @5644, `07` @5653; B: `06` @5130 (L172), `07` @5143 |

## Commands (Java to native)

| Command | Arguments | Result string | Evidence |
|---|---|---|---|
| registerProgram | 5 strings: name, processor_spec, compiler_spec, sleigh, coretypes. All XML text except the name. | `0` | A in L1-L530; out@3956 |
| decompileAt | `0`, then a packed `<addr space=ram offset=N>`. N = 33557868 (0x02000d6c) in A, 33655936 (0x02018c80) in B. | packed `<doc>` (root element id 229). Body not decoded: **unverified**. | A in@23563-23614; out@4248 |
| flushNative | none | `0` | out@5619 (A) |
| deregisterProgram | none | `1` (a live architecture was released, `ghidra_process.cc:224-256`) | out@5644 (A) |

Other commands defined in `ghidra_process.cc` (structureGraph, setAction, setOptions) are
**unverified** here. An unknown command name gets `06`, an error frame `Bad command: <name>`, `07`
(`ghidra_process.cc:468-474`, source only).

## Payload encoding

- registerProgram arguments are plain XML text inside `0e`/`0f`.
- Everything else is the packed format of `marshal.hh` (`PackedFormat`, lines 503-527): a record header
  `0x40` element start, `0x80` element end, `0xc0` attribute. Low 5 bits are the id, and bit `0x20` says
  the id continues into the next byte (7 bits). An attribute is followed by a type byte (type code in
  the high nibble, length code in the low nibble) and then the value. The wire carries numeric ids only
  (ElementId/AttributeId tables in `ghidra_arch.cc:30-50` and `marshal.cc`/`.hh`).
- Exception: getuseropname answers are raw text, not packed.
- Ids decoded from the transcripts: attributes `index`=10, `name`=14, `offset`=16, `size`=19,
  `space`=20, `type`=22; elements `addr`=11, `doc`=229. Address-space values are encoded as type 5
  (address space) carrying the space index: `3` = ram, `4` = register (from the `<space ... index>`
  entries in the registerProgram sleigh string).
- Address: `<addr space=3 offset=N/>`.

## Callback queries (native to Java)

Query element ids come from `ghidra_arch.cc:30-50`; Java's constants are in
`Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/ElementId.java`.
Java dispatches on the id in `DecompileProcess.java:327-410` to `DecompileCallback`.
Each query is answered by the QRESP of the same position (pairing is by order; see below).

Exercised (counts: A / B). Line refs are the first occurrence in A `out` and A `in`:

| Query (id) | Fields | Count | Java method | Answer root | out / in (A) |
|---|---|---|---|---|---|
| command_getuseropname (257) | `index`=0..168 | 169 / 169 | `getUserOpName(int)` | raw string, one per name; index 168 answers empty (no name) | out@4 L1 / in@15888 L530 (index 168: in@23520 L785) |
| command_getregister (253) | `name`="sp" | 1 / 1 | `getRegister(name, enc)` | `<addr space=4 offset=84 size=4>` | out@3931 L132 / in@23536 L785 |
| command_getmappedsymbols (249) | `<addr>` | 2 / 3 | `getMappedSymbols(addr, enc)` | `<doc>` with `mapsym` (function or symbol) | out@3981 L133 / in@23618 L788 |
| command_getpcode (251) | `<addr>` | 4 / 6 | `getPcode(addr, enc)` | `<inst>` | out@4012 L134 / in@23762 L793 |
| command_getcallotherfixup (243) | `name`="setISAMode", `<context>` with two `<addr>` children (one empty) | 1 / 1 | `getPcodeInject(name, dec, CALLOTHERFIXUP_TYPE, enc)` | `<inst>` | out@4136 L138 / in@24768 L826 |
| command_gettrackedregisters (256) | `<addr>` | 1 / 1 | `getTrackedRegisters(addr, enc)` | `<tracked_pointset>` | out@4186 L140 / in@24833 L828 |
| command_getcomments (245) | `type`=58 (meaning **unverified**), `<addr>` | 1 / 1 | `getComments(addr, types, enc)` | `<commentdb/>` (empty) | out@5179 L173 / in@24976 L833 |

B line refs, same order: getregister out@3931 L132; getmappedsymbols out@3981, @4105, @4167;
getpcode out@4012, @4043, @4074, @4136, @4198, @4229; getcallotherfixup out@4260 L143;
gettrackedregisters out@4310 L144; getcomments out@4693 L157 (in@26206 L874).
B's extra mappedsymbols queries are for the callees (0x02018d10, 0x02018c98).

Not exercised by these transcripts. All **unverified** (source names only):
getBytes (`command_getbytes`, 240; reply uses `0c`/`0d`), isNameUsed (239), getRegisterName (254),
getCodeLabel (244), getDataType (247), getStringData (255), getExternalRef (248), getCPoolRef (246),
getNamespacePath (250), getPcodeInject for CALLFIXUP (241) / CALLMECH (242) / PCODEEXECUTABLE (252).
No exception (`0a`) frames appear.

Name mismatch (same id 255, not in the transcripts): Java names it `command_getstring`
(`ElementId.java:420-422`), C++ names it `command_getstringdata` (`ghidra_arch.cc:46`).

### Pairing is by order

Query k is answered by QRESP k. The transcripts support it: both have equal query and QRESP counts,
and for the 10 non-getuseropname queries of A and the 13 of B every answer root matches its query
(getregister->`addr`, getmappedsymbols->`doc`, getpcode->`inst`, getcallotherfixup->`inst`,
gettrackedregisters->`tracked_pointset`, getcomments->`commentdb`). There is no id on the wire.
Checked on these two transcripts only.

## Nested frames

A query can occur inside an open result string. In A, decompileAt's `0e` opens at @4248 (L142) and the
getcomments query `04` @5179 (L173) .. `05` @5209 (L174) sits inside it, before the string's `0f` at
@5599 (L187). B: result `0e` @4341, nested query `04` @4693 .. `05` @4723, string `0f` @5089.
The native writer streams the `<doc>` while the decompiler is still running, and the last callback
fires during that stream. Java copes because `case 4` services the query and then keeps ingesting the
open response (`DecompileProcess.java:327-457`).

A flat parser that treats `0e..0f` as one non-nesting span, or that stops a string at the first `05`/`0f`,
ends the result string at @5205 (the inner string's `0f`) and misreads the rest. The correct parser
keeps a stack: strings and queries nest, and the closer must match the innermost open marker.

## Verification

`testdata/golden/verify.sh <decompile>` replays both inputs; it printed OK for both. The marker counts
and offsets above were recomputed from the hex files for this note.
