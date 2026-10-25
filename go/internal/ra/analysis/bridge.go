package analysis

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

// BridgeConfig says how to start the Java SLEIGH bridge (go/tools/sleigh-bridge).
type BridgeConfig struct {
	Java       string // the java launcher of a JDK 21
	ClassPath  string // the compiled bridge and Ghidra's jars
	GhidraDir  string // GHIDRA_INSTALL_DIR, a Ghidra 12.1.4 install
	LanguageID string
	// Compiler is the compiler spec id for the calling convention ("gcc"); empty
	// means the language's default.
	Compiler string
}

func (c BridgeConfig) command(args ...string) *exec.Cmd {
	cmd := exec.Command(c.Java, append([]string{"-cp", c.ClassPath, "SleighBridge"}, args...)...)
	cmd.Env = append(os.Environ(), "GHIDRA_INSTALL_DIR="+c.GhidraDir)
	return cmd
}

// BridgeDecoder is a Decoder backed by the Java bridge. The bridge supplies
// Ghidra's flow facts and the per-instruction p-code facts (IndirectVia,
// DataRefs, Addends, IndexedLoad). It is not a StateDecoder: register state
// does not carry between instructions, so block-local constant propagation
// does not run with it. That is the known gap of the contract.
type BridgeDecoder struct {
	cfg     BridgeConfig
	lang    *sleigh.Language
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	out     *bufio.Reader
	context sleigh.Context
	// contexts holds the context to decode an address with; an address not in
	// it uses the language's initial context. Used holds the context the
	// bridge reports having used for each decoded address.
	contexts map[uint64]sleigh.Context
	Used     map[uint64]sleigh.Context
	// Calls counts bridge round trips: one per instruction, not batched.
	Calls int
}

// SetContext sets the context value to decode addr with (ARM/Thumb mode, for
// instance). The analysis does not propagate context changes yet, so nothing
// calls this during Analyze; a caller that knows the mode can.
func (b *BridgeDecoder) SetContext(addr uint64, ctx sleigh.Context) { b.contexts[addr] = ctx }

// GapNotes are added to the analysis diagnostics.
func (b *BridgeDecoder) GapNotes() []string {
	return []string{
		fmt.Sprintf("gap: the Java bridge decodes one instruction per round trip, unbatched (%d so far); the static-glibc binary is too large to analyze this way", b.Calls),
		"gap: the analysis does not propagate context changes (Thumb mode switches); only addresses given to SetContext decode with another context",
	}
}

// StartBridge starts the bridge and reads the language record.
func StartBridge(cfg BridgeConfig) (*BridgeDecoder, *sleigh.Language, error) {
	args := []string{"--language-info", cfg.LanguageID}
	if cfg.Compiler != "" {
		args = append(args, cfg.Compiler)
	}
	rec, err := cfg.command(args...).Output()
	if err != nil {
		return nil, nil, fmt.Errorf("bridge --language-info: %w", err)
	}
	lang, err := sleigh.ParseLanguage(rec)
	if err != nil {
		return nil, nil, fmt.Errorf("bridge language record: %w", err)
	}
	cmd := cfg.command()
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return &BridgeDecoder{cfg: cfg, lang: lang, cmd: cmd, stdin: in, out: bufio.NewReader(out),
		context: sleigh.Context(lang.InitialContext), contexts: map[uint64]sleigh.Context{}, Used: map[uint64]sleigh.Context{}}, lang, nil
}

// Close ends the bridge process.
func (b *BridgeDecoder) Close() error {
	b.stdin.Close()
	return b.cmd.Wait()
}

// Decode decodes one instruction with the context set for its address, or the
// language's initial context. The bridge reads at most 16 bytes.
func (b *BridgeDecoder) Decode(addr uint64, bytes []byte) (*Decoded, bool) {
	if len(bytes) > 16 {
		bytes = bytes[:16]
	}
	ctx, ok := b.contexts[addr]
	if !ok {
		ctx = b.context
	}
	batch := []sleigh.Insn{{Addr: core.Addr(addr), Bytes: bytes, Context: ctx}}
	if err := sleigh.WriteRequest(b.stdin, sleigh.Request{Language: b.cfg.LanguageID, Batch: batch}); err != nil {
		return nil, false
	}
	b.Calls++
	res, err := sleigh.ReadResponses(b.out, batch)
	if err != nil || len(res) != 1 || res[0].Err != nil {
		return nil, false
	}
	s := res[0].Decoded
	b.Used[addr] = s.Context
	d := &Decoded{Addr: addr, Len: s.Len, Mnemonic: s.Mnemonic, Text: s.Text, Flow: s.Flow,
		HasFallthrough: s.HasFallthrough, Indirect: s.Indirect}
	for _, t := range s.Targets {
		d.Targets = append(d.Targets, uint64(t))
	}
	if s.IndirectVia != nil {
		v := uint64(*s.IndirectVia)
		d.IndirectVia = &v
	}
	for _, r := range s.DataRefs {
		acc := AccessAddress
		switch r.Access {
		case sleigh.AccessRead:
			acc = AccessRead
		case sleigh.AccessWrite:
			acc = AccessWrite
		}
		d.DataRefs = append(d.DataRefs, DataRef{uint64(r.Addr), acc})
	}
	for _, a := range s.Addends {
		d.Addends = append(d.Addends, uint64(a))
	}
	d.IndexedLoad = s.IndexedLoad
	return d, true
}
