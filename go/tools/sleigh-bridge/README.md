# sleigh-bridge

A temporary Java helper that decodes instructions through Ghidra's own SLEIGH
engine for the Go `ra` port. The Go side of the contract is
`go/internal/ra/sleigh`; the native Go port that replaces this bridge is
tracked in #19.

The bridge reads one JSON request line per batch on stdin and writes one
response line per batch entry on stdout (Ghidra's facts: addr, len, mnemonic,
text, FlowType name, has_fallthrough, direct targets, indirect, and the context
value used). See the comment at the top of `SleighBridge.java` and
`go/internal/ra/sleigh/contract.go` for the exact format.

## What it needs

- A **Ghidra 12.1.4** install (a release, not a source checkout), named by
  `GHIDRA_INSTALL_DIR`. The bridge reads `Ghidra/application.properties` and
  refuses any other `application.version` with a message.
- A **JDK 21**. Ghidra 12.1.4 declares `application.java.min=21`. The README's
  JDK 25 is for building Ghidra from source; compiling and running a bridge
  against an installed release only needs the JDK that release requires.

Nothing here edits a shell profile or system configuration: set the variables
per command, as below. Build output goes to a scratch directory and is never
committed (no jars, no class files).

## Build

```sh
export GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC
export JAVA_HOME=/path/to/jdk-21
OUT=/path/to/scratch/bridge-classes
CP=$(find "$GHIDRA_INSTALL_DIR/Ghidra" -name '*.jar' | tr '\n' ':')

mkdir -p "$OUT"
"$JAVA_HOME/bin/javac" -proc:none -cp "$CP" -d "$OUT" go/tools/sleigh-bridge/SleighBridge.java
```

## Run

Language record (one JSON line, parsed by `sleigh.ParseLanguage`); the optional
second argument is the compiler spec, which decides the calling convention
(x86-64 defaults to Visual Studio, pass `gcc` for ELF):

```sh
"$JAVA_HOME/bin/java" -cp "$OUT:$CP" SleighBridge --language-info x86:LE:64:default gcc
```

Decode a batch (requests on stdin, one line each):

```sh
echo '{"language":"x86:LE:64:default","batch":[{"addr":"0x1000","bytes":"e805000000","context":"0x8900000000000000"}]}' |
  "$JAVA_HOME/bin/java" -cp "$OUT:$CP" SleighBridge
```

Use the `initial_context` of the language record as the context of the first
instruction of a flow: a context of `0x0` decodes x86-64 bytes in 16-bit mode.

Start-up takes several seconds (Ghidra's class search and language load);
keep one bridge process for many batches.

## Rules

- Computed flows are normalized to the base FlowType name plus
  `"indirect":true` (`COMPUTED_JUMP` becomes `UNCONDITIONAL_JUMP`,
  `CONDITIONAL_COMPUTED_CALL` becomes `CONDITIONAL_CALL`, ...). Their `targets`
  are empty.
- FlowTypes outside the contract (`CALL_TERMINATOR`, `JUMP_TERMINATOR`,
  `CALLOTHER_OVERRIDE_*`, `INDIRECTION`, ...) are an `{"error":...}` for that
  entry.
- Every entry of a batch gets exactly one line, so an error never leaves the
  stream mid-batch. A request line that cannot be parsed (the batch size is
  unknown) is answered with one error line and the bridge exits with status 2.
- Anything the Ghidra libraries print goes to stderr; stdout carries only
  response lines.
- Headless initialization writes a log to
  `~/.config/ghidra/ghidra_12.1.4_PUBLIC/application.log` (under the user's
  home, outside the repository and the scratch directory).
- Each entry is decoded in a transaction on an in-memory program that is rolled
  back, with the request's context passed as the initial context.

## Tests

`go/internal/ra/sleigh/bridge_test.go` runs the bridge through the Go contract
parser. It skips unless these are set:

```sh
GHIDRA_INSTALL_DIR=...  RA_SLEIGH_BRIDGE_JAVA="$JAVA_HOME/bin/java"  RA_SLEIGH_BRIDGE_CP="$OUT:$CP" \
  go test -count=1 -run Bridge ./internal/ra/sleigh
```

It checks the language record, a fixture batch (call, conditional jump, return,
NOP, indirect call and jump, HLT, an invalid opcode, per-entry context), stream
recovery after errors, the version refusal, and every instruction of the
committed Ghidra export of `basic-x86_64-gcc-O2-stripped` (length, mnemonic and
direct flow targets).
