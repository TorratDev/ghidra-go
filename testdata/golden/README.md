# Golden decompiler transcripts

Wire transcripts between the Java Ghidra `DecompInterface` and the native `decompile` process,
recorded once (single JVM run) for two ARM functions. `in.hex` is what Java wrote to the
process's stdin, `out.hex` what it wrote to stdout (`xxd -p` dumps), `decompiled.c` the C text
Java returned.

| Function | Address | Calls |
|---|---|---|
| FUN_02000d6c | 0x02000d6c | none (16 bytes) |
| FUN_02018c80 | 0x02018c80 | FUN_02018d10, FUN_02018c98 |

Each function used its own `DecompInterface`, hence its own `decompile` process and transcript.

## Verify

    testdata/golden/verify.sh /path/to/decompile

Replays each `in.hex` into the binary and diffs stdout against `out.hex`. Result at capture: both OK.
`decompiled.c` matches the expected text (`return param_1 * 6 + DAT_02000d7c;` and
`FUN_02018d10(); FUN_02018c98(); return;`).

## Provenance

- Project copy: `rescue-arm9-c` (program `arm9.bin`), run through the already-running bridge
  script (`script_run` of `capture/Capture.java`); the bridge was not restarted.
- Java: OpenJDK Temurin 21.0.12.1+1 (`/home/torrat/tools/jdk-21.0.12.1+1`), Ghidra 11.4.3 PUBLIC.
- Binary: Ghidra 11.4.3 `os/linux_x86_64/decompile`, sha256
  `deff417328db63659ad1498bbf85ea9148fc541200e5c0ab1d3f2bf389b5cc77`.
- Method: `capture/Capture.java` sets the private static `DecompileProcessFactory.exepath` by
  reflection to `capture/wrap.c` (built with `gcc -O2 -DREAL_PATH=... -DLOG_DIR=...`), an
  unbuffered poll relay that logs both streams and runs the real `decompile` without a shell.
  Shipped code is unchanged. Paths in `Capture.java` are placeholders.

| File | sha256 |
|---|---|
| 02000d6c/in.hex | 920d8fb35fa63d22a92a438f87174013c4bc5660febcb0bf4adbe48429287362 |
| 02000d6c/out.hex | 69bc33bc7f286bb981c972dd89ab985cbc4386ce9ef295a96f1ab3d295004c38 |
| 02000d6c/decompiled.c | 4829074450b9e7568569d82b8e4b052e33ded9fb383f20669d9dfcdf7066c859 |
| 02018c80/in.hex | 80f67b2027da7c35d570ec5d15e54fdceadbf003076458c1eb141fb5749549b9 |
| 02018c80/out.hex | bea98fc94bdb2643164288da1ccdacb7a854728fda8919c11cbbdcd53fbbbee9 |
| 02018c80/decompiled.c | 03e1d4ef310b7c34617318653e720cc9b42374bdab5ef9c8ab9da9d43c619a63 |


## Replay test

`go/internal/proto/replay_test.go` runs the Go client against the real binary, answers queries
from `in.hex`, and compares the bytes the binary writes (and the client sends) with `out.hex`
(and `in.hex`). From `go/`:

    DECOMPILE_BIN=/path/to/decompile go test -count=1 -run Replay ./internal/proto

Without `DECOMPILE_BIN` the test skips. The binary's sha256 must match the one above
(`DECOMPILE_SKIP_HASH=1` overrides). Use `-count=1`: Go's test cache does not track these files.
