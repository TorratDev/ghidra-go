package sleigh

import (
	"bufio"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/loader"
)

// These tests run the real Java bridge (go/tools/sleigh-bridge). They need a
// Ghidra 12.1.4 install and a compiled bridge, passed in the environment, and
// skip otherwise:
//
//	GHIDRA_INSTALL_DIR       the Ghidra 12.1.4 install
//	RA_SLEIGH_BRIDGE_JAVA    the java launcher of a JDK 21
//	RA_SLEIGH_BRIDGE_CP      the class path: the compiled bridge and Ghidra's jars
//
// See go/tools/sleigh-bridge/README.md for the commands that produce them.

func bridgeEnv(t *testing.T) (java, cp, ghidra string) {
	t.Helper()
	java, cp, ghidra = os.Getenv("RA_SLEIGH_BRIDGE_JAVA"), os.Getenv("RA_SLEIGH_BRIDGE_CP"), os.Getenv("GHIDRA_INSTALL_DIR")
	if java == "" || cp == "" || ghidra == "" {
		t.Skip("RA_SLEIGH_BRIDGE_JAVA, RA_SLEIGH_BRIDGE_CP and GHIDRA_INSTALL_DIR are not all set")
	}
	return
}

func bridgeCmd(t *testing.T, args ...string) *exec.Cmd {
	java, cp, ghidra := bridgeEnv(t)
	cmd := exec.Command(java, append([]string{"-cp", cp, "SleighBridge"}, args...)...)
	cmd.Env = append(os.Environ(), "GHIDRA_INSTALL_DIR="+ghidra)
	return cmd
}

type bridge struct {
	t     *testing.T
	stdin interface{ Write([]byte) (int, error) }
	out   *bufio.Reader
	cmd   *exec.Cmd
}

func startBridge(t *testing.T) *bridge {
	cmd := bridgeCmd(t)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Wait() })
	return &bridge{t, in, bufio.NewReader(out), cmd}
}

func (b *bridge) run(lang string, batch []Insn) []Result {
	b.t.Helper()
	if err := WriteRequest(b.stdin, Request{Language: lang, Batch: batch}); err != nil {
		b.t.Fatal(err)
	}
	res, err := ReadResponses(b.out, batch)
	if err != nil {
		b.t.Fatal(err)
	}
	return res
}

func languageInfo(t *testing.T, id string, extra ...string) *Language {
	t.Helper()
	out, err := bridgeCmd(t, append([]string{"--language-info", id}, extra...)...).Output()
	if err != nil {
		t.Fatalf("--language-info: %v", err)
	}
	l, err := ParseLanguage(out)
	if err != nil {
		t.Fatalf("language record %s: %v", out, err)
	}
	return l
}

func TestBridgeLanguageRecord(t *testing.T) {
	l := languageInfo(t, "x86:LE:64:default", "gcc")
	if l.ID != "x86:LE:64:default" || l.BigEndian || l.AddressSize != 8 || l.InitialContext == 0 ||
		l.PC.Size != 8 || l.SP != (Varnode{"register", 32, 8}) {
		t.Errorf("%+v", l)
	}
	// System V integer argument registers: RDI, RSI, RDX, RCX, R8, R9
	var offsets []uint64
	for _, v := range l.IntArgs {
		offsets = append(offsets, v.Offset)
	}
	if !slices.Equal(offsets, []uint64{56, 48, 16, 8, 128, 136}) {
		t.Errorf("int args %v", offsets)
	}
	arm := languageInfo(t, "ARM:LE:32:v8")
	if arm.AddressSize != 4 || arm.BigEndian || len(arm.IntArgs) != 4 {
		t.Errorf("%+v", arm)
	}
	// an unknown language ends the process with a message
	cmd := bridgeCmd(t, "--language-info", "nosuch:LE:1:x")
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), "Language not found") {
		t.Errorf("unknown language: %v %s", err, out)
	}
}

func TestBridgeRefusesOtherInstalls(t *testing.T) {
	java, cp, _ := bridgeEnv(t)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "Ghidra"), 0o755)
	os.WriteFile(filepath.Join(dir, "Ghidra/application.properties"), []byte("application.version=11.4\n"), 0o644)
	for name, env := range map[string]string{"GHIDRA_INSTALL_DIR=" + dir: "Ghidra 11.4", "GHIDRA_INSTALL_DIR=": "GHIDRA_INSTALL_DIR is not set"} {
		cmd := exec.Command(java, "-cp", cp, "SleighBridge", "--language-info", "x86:LE:64:default")
		cmd.Env = append(os.Environ(), name)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), env) {
			t.Errorf("%s: %v %s", name, err, out)
		}
	}
}

func TestBridgeFixtureBatch(t *testing.T) {
	ctx := languageInfo(t, "x86:LE:64:default", "gcc").InitialContext
	insn := func(addr core.Addr, hexBytes string, c Context) Insn {
		b, _ := hex.DecodeString(hexBytes)
		return Insn{addr, b, c}
	}
	br := startBridge(t)
	res := br.run("x86:LE:64:default", []Insn{
		insn(0x1000, "e805000000", ctx), // call
		insn(0x1005, "7402", ctx),       // je
		insn(0x1007, "c3", ctx),         // ret
		insn(0x1008, "90", ctx),         // nop
		insn(0x1009, "ffd0", ctx),       // call rax
		insn(0x100b, "ffe0", ctx),       // jmp rax
		insn(0x100d, "ff25f2ffffff", ctx),
		insn(0x1013, "f4", ctx),       // hlt
		insn(0x1016, "06", ctx),       // invalid in 64-bit mode
		insn(0x1000, "e805000000", 0), // same bytes with context 0
	})
	type want struct {
		len      uint32
		mnemonic string
		flow     FlowKind
		fall     bool
		targets  []core.Addr
		indirect bool
		context  Context
	}
	wants := []*want{
		{5, "CALL", FlowCall, true, []core.Addr{0x100a}, false, ctx},
		{2, "JZ", FlowCondJump, true, []core.Addr{0x1009}, false, ctx},
		{1, "RET", FlowReturn, false, nil, false, ctx},
		{1, "NOP", FlowFallthrough, true, nil, false, ctx},
		{2, "CALL", FlowCall, true, nil, true, ctx},
		{2, "JMP", FlowJump, false, nil, true, ctx},
		{6, "JMP", FlowJump, false, nil, true, ctx},
		{1, "HLT", FlowReturn, false, nil, false, ctx}, // TERMINATOR maps to Return
		nil, // an error entry
		{3, "CALL", FlowCall, true, []core.Addr{0x1008}, false, 0}, // 16-bit decoding: call rel16
	}
	for i, w := range wants {
		r := res[i]
		if w == nil {
			if r.Err == nil || !strings.Contains(r.Err.Error(), "no instruction at 0x1016") {
				t.Errorf("entry %d: %+v", i, r)
			}
			continue
		}
		d := r.Decoded
		if r.Err != nil {
			t.Errorf("entry %d: %v", i, r.Err)
			continue
		}
		if d.Len != w.len || d.Mnemonic != w.mnemonic || d.Flow != w.flow || d.HasFallthrough != w.fall ||
			d.Indirect != w.indirect || d.Context != w.context || len(d.Targets) != len(w.targets) ||
			(len(w.targets) > 0 && !slices.Equal(d.Targets, w.targets)) {
			t.Errorf("entry %d: got %+v, want %+v", i, *d, *w)
		}
	}
	// the stream stays usable after an error entry; an unknown language answers every entry
	next := br.run("x86:LE:64:default", []Insn{insn(0x3000, "90", ctx)})
	if next[0].Err != nil || next[0].Decoded.Addr != 0x3000 || next[0].Decoded.Mnemonic != "NOP" {
		t.Errorf("after the error: %+v", next[0])
	}
	bad := br.run("nosuch:LE:1:x", []Insn{insn(1, "90", 0), insn(2, "90", 0)})
	if len(bad) != 2 || bad[0].Err == nil || bad[1].Err == nil || !strings.Contains(bad[0].Err.Error(), "cannot load language") {
		t.Errorf("unknown language: %+v", bad)
	}
	again := br.run("x86:LE:64:default", []Insn{insn(0x3001, "90", ctx)})
	if again[0].Err != nil || again[0].Decoded.Addr != 0x3001 {
		t.Errorf("after the unknown language: %+v", again[0])
	}
}

func TestBridgeRejectsMalformedRequests(t *testing.T) {
	cmd := bridgeCmd(t)
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// a request whose batch size cannot be known is answered by one error line and the end
	fmt.Fprintln(in, `{"language":"x86:LE:64:default","batch":[{"addr":"0x1","bytes":"90","context":0}]}`)
	line, _ := bufio.NewReader(out).ReadString('\n')
	if !strings.Contains(line, `"error"`) || !strings.Contains(line, `must be a string`) {
		t.Errorf("response %q", line)
	}
	in.Close()
	if err := cmd.Wait(); err == nil {
		t.Error("bridge did not exit with an error status")
	}
}

// TestBridgeAgainstGhidraExport decodes every instruction of the Ghidra 12.1.4
// export of basic-x86_64-gcc-O2-stripped with its bytes from the Go loader,
// and compares length, mnemonic and direct flow targets.
func TestBridgeAgainstGhidraExport(t *testing.T) {
	const dir = "../../../../rust-analysis/compare"
	p, err := loader.LoadPath(filepath.Join(dir, "corpus/binaries/basic-x86_64-gcc-O2-stripped"), "")
	if err != nil {
		t.Skipf("corpus binary not available: %v", err)
	}
	f, err := os.Open(filepath.Join(dir, "expected/basic-x86_64-gcc-O2-stripped.json.gz"))
	if err != nil {
		t.Skipf("export not available: %v", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var exp struct {
		Instructions []struct {
			Addr     core.Addr
			Len      uint32
			Mnemonic string
		}
		Xrefs []struct {
			From, To core.Addr
			Kind     string
		}
	}
	if err := json.NewDecoder(zr).Decode(&exp); err != nil {
		t.Fatal(err)
	}
	flowTargets := map[core.Addr][]core.Addr{}
	for _, x := range exp.Xrefs {
		switch x.Kind {
		case "call", "jump", "cond_jump":
			flowTargets[x.From] = append(flowTargets[x.From], x.To)
		}
	}
	ctx := languageInfo(t, "x86:LE:64:default", "gcc").InitialContext
	var batch []Insn
	for _, i := range exp.Instructions {
		b := p.Memory.Read(uint64(i.Addr), 15)
		if b == nil { // near the end of a block: whatever is left
			if blk := p.Memory.BlockAt(uint64(i.Addr)); blk != nil {
				b = p.Memory.BytesFrom(uint64(i.Addr))
			}
		}
		if len(b) == 0 {
			t.Fatalf("no bytes at %#x", uint64(i.Addr))
		}
		batch = append(batch, Insn{i.Addr, append([]byte(nil), b...), ctx})
	}
	res := startBridge(t).run("x86:LE:64:default", batch)
	var okLen, okMnem, errs, flowChecked, flowOK int
	for i, r := range res {
		want := exp.Instructions[i]
		if r.Err != nil {
			errs++
			t.Logf("%#x: %v", uint64(want.Addr), r.Err)
			continue
		}
		if r.Decoded.Len == want.Len {
			okLen++
		} else {
			t.Logf("%#x: length %d, export %d", uint64(want.Addr), r.Decoded.Len, want.Len)
		}
		if r.Decoded.Mnemonic == want.Mnemonic {
			okMnem++
		} else {
			t.Logf("%#x: mnemonic %s, export %s", uint64(want.Addr), r.Decoded.Mnemonic, want.Mnemonic)
		}
		if exp := flowTargets[want.Addr]; len(exp) > 0 && !r.Decoded.Indirect {
			flowChecked++
			got := slices.Clone(r.Decoded.Targets)
			slices.Sort(got)
			slices.Sort(exp)
			if slices.Equal(got, exp) {
				flowOK++
			} else {
				t.Logf("%#x: targets %v, export %v", uint64(want.Addr), got, exp)
			}
		}
	}
	n := len(exp.Instructions)
	t.Logf("%d instructions: %d errors, length matches %d, mnemonic matches %d, direct flow targets %d of %d", n, errs, okLen, okMnem, flowOK, flowChecked)
	if errs != 0 || okLen != n || okMnem != n || flowOK != flowChecked {
		t.Errorf("the bridge disagrees with the Ghidra export")
	}
}

// The p-code facts of one instruction: the Rust ra-sleigh x86_64 tests
// (indirect_via, data_refs) and the two jump-table idioms (addends,
// indexed_load).
func TestBridgeFacts(t *testing.T) {
	ctx := languageInfo(t, "x86:LE:64:default", "gcc").InitialContext
	br := startBridge(t)
	cases := []struct {
		name, bytes string
		via         *core.Addr
		refs        []DataRef
		addends     []core.Addr
		indexed     bool
	}{
		{"jmp [rip+0x10]", "ff2510000000", addr(0x1016), []DataRef{{0x1016, AccessRead}}, nil, false},
		{"call [rip+0x10]", "ff1510000000", addr(0x1016), []DataRef{{0x1016, AccessRead}}, nil, false},
		{"mov rax,[rip+0x10]", "488b0510000000", nil, []DataRef{{0x1017, AccessRead}}, nil, false},
		{"mov [rip+0xf],rax", "4889050f000000", nil, []DataRef{{0x1016, AccessWrite}}, nil, false},
		{"lea rax,[rip+0x10]", "488d0510000000", nil, []DataRef{{0x1017, AccessAddress}}, nil, false},
		{"jmp [rax*8+0x2000] (absolute table)", "ff24c500200000", nil, nil, []core.Addr{0x2000}, true},
		{"lea rdx,[rip+0x10] (PIC base)", "488d1510000000", nil, []DataRef{{0x1017, AccessAddress}}, nil, false},
		{"movsxd rax,[rdx+rax*4] (PIC load)", "486304 82", nil, nil, nil, true},
		{"nop", "90", nil, nil, nil, false},
	}
	var batch []Insn
	for _, c := range cases {
		b, err := hex.DecodeString(strings.ReplaceAll(c.bytes, " ", ""))
		if err != nil {
			t.Fatal(err)
		}
		batch = append(batch, Insn{0x1000, b, ctx})
	}
	for i, r := range br.run("x86:LE:64:default", batch) {
		c := cases[i]
		if r.Err != nil {
			t.Errorf("%s: %v", c.name, r.Err)
			continue
		}
		d := r.Decoded
		if !reflect.DeepEqual(d.IndirectVia, c.via) || !slices.Equal(d.DataRefs, c.refs) ||
			!slices.Equal(d.Addends, c.addends) || d.IndexedLoad != c.indexed {
			t.Errorf("%s: via %v refs %v addends %v indexed %v, want %v %v %v %v", c.name,
				d.IndirectVia, d.DataRefs, d.Addends, d.IndexedLoad, c.via, c.refs, c.addends, c.indexed)
		}
	}
}

func addr(a core.Addr) *core.Addr { return &a }
