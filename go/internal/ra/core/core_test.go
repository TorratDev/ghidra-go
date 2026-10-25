package core

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func sp(s string) *string { return &s }
func ap(a Addr) *Addr     { return &a }

func fullReport() *AnalysisReport {
	return &AnalysisReport{
		SchemaVersion: SchemaVersion,
		Producer:      "ra 0.1.0",
		Binary:        BinaryInfo{Path: "/bin/x<&>", Sha256: "ab", Format: "ELF", Language: "x86:LE:64:default", ImageBase: 0x400000},
		Memory:        []MemoryInfo{{Name: ".text", Start: 0x401000, End: 0x402000, Read: true, Execute: true, Initialized: true}},
		Symbols:       []SymbolInfo{{Addr: 0xffffffff80000000, Name: "main", Namespace: sp("ns"), Kind: "function", Source: SourceImported}},
		Imports:       []ImportInfo{{Name: "puts", Namespace: sp("n"), Library: sp("libc"), Addr: ap(0x404000)}},
		Exports:       []ExportInfo{{Addr: 0, Name: "start"}},
		Functions: []FunctionInfo{{Entry: 0x401000, Name: "f", Namespace: sp("n"), Source: SourceAnalysis,
			Thunk: true, ThunkTarget: ap(0x10), NoReturn: true, Body: []AddrPair{{0x10, 0x20}}}},
		Instructions: []InstructionInfo{{Addr: 0x401000, Len: 3, Mnemonic: "MOV"}},
		Blocks:       []BlockInfo{{Start: 0x401000, End: 0x401010}},
		Edges:        []EdgeInfo{{From: 1, To: 2, Kind: EdgeCondJump}},
		Xrefs:        []XrefInfo{{From: 1, To: 2, Kind: XrefData}},
	}
}

func TestReportRoundTrip(t *testing.T) {
	r := fullReport()
	var buf bytes.Buffer
	if err := WriteReport(&buf, r, false); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{`"0xffffffff80000000"`, `"0x0"`, `"0x400000"`, `"0x10"`, `x<&>`, "\n  \"producer\""} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in %s", want, s)
		}
	}
	if strings.HasSuffix(s, "\n") {
		t.Error("trailing newline when stdout=false")
	}
	buf.Reset()
	WriteReport(&buf, r, true)
	if !strings.HasSuffix(buf.String(), "}\n") {
		t.Error("no trailing newline when stdout=true")
	}
	var back AnalysisReport
	if err := json.Unmarshal([]byte(s), &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(&back, r) {
		t.Errorf("round trip mismatch:\n%+v\n%+v", back, *r)
	}
}

func TestEnumNames(t *testing.T) {
	check := func(v any, want string) {
		b, _ := json.Marshal(v)
		if string(b) != `"`+want+`"` {
			t.Errorf("got %s want %s", b, want)
		}
	}
	for _, s := range []SymbolSource{SourceImported, SourceAnalysis, SourceDefault, SourceUser} {
		check(s, string(s))
	}
	for i, w := range []string{"imported", "analysis", "default", "user"} {
		check([]SymbolSource{SourceImported, SourceAnalysis, SourceDefault, SourceUser}[i], w)
	}
	for i, w := range []string{"fallthrough", "jump", "cond_jump"} {
		check([]EdgeKind{EdgeFallthrough, EdgeJump, EdgeCondJump}[i], w)
	}
	for i, w := range []string{"call", "jump", "cond_jump", "read", "write", "data"} {
		check([]XrefKind{XrefCall, XrefJump, XrefCondJump, XrefRead, XrefWrite, XrefData}[i], w)
	}
	var k XrefKind
	if json.Unmarshal([]byte(`"bogus"`), &k) == nil {
		t.Error("unknown enum accepted")
	}
}

func TestMissingFieldsDecodeToZero(t *testing.T) {
	var r AnalysisReport
	if err := json.Unmarshal([]byte(`{"schema_version":2,"producer":"p","binary":{"path":"a","format":"Raw","language":"l","image_base":4096},"functions":[{"entry":"0x1","name":"f","source":"user"}]}`), &r); err != nil {
		t.Fatal(err)
	}
	if r.Binary.Sha256 != "" || r.Binary.ImageBase != 0x1000 || r.Symbols != nil || r.Xrefs != nil {
		t.Errorf("%+v", r)
	}
	f := r.Functions[0]
	if f.Namespace != nil || f.ThunkTarget != nil || f.Thunk || f.NoReturn || f.Body != nil {
		t.Errorf("%+v", f)
	}
	var buf bytes.Buffer
	WriteReport(&buf, &r, false)
	if !strings.Contains(buf.String(), `"xrefs": []`) || !strings.Contains(buf.String(), `"namespace": null`) || !strings.Contains(buf.String(), `"body": []`) {
		t.Errorf("want [] lists and null options: %s", buf.String())
	}
}

func TestHexRejectsBadInput(t *testing.T) {
	for _, s := range []string{"", "0x", "zz", "0x1g", "-1", "+1", "0x10000000000000000", "1_0"} {
		if _, err := ParseHex(s); err == nil {
			t.Errorf("ParseHex(%q) succeeded", s)
		}
	}
	for _, s := range []string{`"nope"`, `-1`, `1.5`, `null`, `true`, `18446744073709551616`} {
		var a Addr
		if json.Unmarshal([]byte(s), &a) == nil {
			t.Errorf("Addr accepted %s", s)
		}
	}
	var p AddrPair
	if json.Unmarshal([]byte(`["0x1"]`), &p) == nil {
		t.Error("short pair accepted")
	}
	var a Addr
	if err := json.Unmarshal([]byte(`" 0XfF "`), &a); err != nil || a != 0xff {
		t.Errorf("%v %v", a, err)
	}
}

func TestNormalize(t *testing.T) {
	r := NewAnalysisReport()
	r.Edges = []EdgeInfo{{2, 3, EdgeCondJump}, {1, 2, EdgeJump}, {1, 2, EdgeFallthrough}, {1, 2, EdgeJump}}
	r.Symbols = []SymbolInfo{{Addr: 2, Name: "b"}, {Addr: 1, Name: "a", Namespace: sp("x")}, {Addr: 1, Name: "a", Namespace: sp("x")}}
	r.Imports = []ImportInfo{{Name: "p", Library: sp("l"), Addr: ap(1)}, {Name: "p", Library: sp("l")}, {Name: "p"}, {Name: "p"}}
	r.Blocks = []BlockInfo{{2, 3}, {1, 2}, {1, 2}}
	r.Functions = []FunctionInfo{{Entry: 1, Body: []AddrPair{{5, 6}, {1, 2}}}, {Entry: 0}}
	r.Xrefs = []XrefInfo{{1, 2, XrefData}, {1, 2, XrefCall}, {1, 2, XrefData}}
	r.Normalize()
	if len(r.Edges) != 3 || r.Edges[0].Kind != EdgeFallthrough || r.Edges[1].Kind != EdgeJump {
		t.Errorf("edges %+v", r.Edges)
	}
	if len(r.Symbols) != 2 || len(r.Blocks) != 2 || len(r.Xrefs) != 2 || r.Xrefs[0].Kind != XrefCall {
		t.Errorf("dedup failed: %+v %+v %+v", r.Symbols, r.Blocks, r.Xrefs)
	}
	if len(r.Imports) != 3 || r.Imports[0].Library != nil || r.Imports[2].Addr == nil {
		t.Errorf("imports %+v", r.Imports)
	}
	if r.Functions[0].Entry != 0 || r.Functions[0].Body == nil || r.Functions[1].Body[0] != (AddrPair{1, 2}) {
		t.Errorf("functions %+v", r.Functions)
	}
	b1, _ := json.Marshal(r)
	r.Normalize()
	b2, _ := json.Marshal(r)
	if !bytes.Equal(b1, b2) {
		t.Errorf("not idempotent:\n%s\n%s", b1, b2)
	}
}

func blk(start, size uint64) MemoryBlock {
	d := make([]byte, size)
	for i := range d {
		d[i] = byte(i)
	}
	return MemoryBlock{Name: "b", Start: start, Size: size, Data: d}
}

func TestMemoryMap(t *testing.T) {
	var m MemoryMap
	m.Add(blk(0x1000, 0x100))
	m.Add(blk(0x1080, 0x100)) // trimmed to 0x1100..0x1180
	m.Add(blk(0x0f00, 0x200)) // trimmed to 0x0f00..0x1000
	var got [][2]uint64
	for _, b := range m.Blocks() {
		got = append(got, [2]uint64{b.Start, b.Size})
	}
	if !reflect.DeepEqual(got, [][2]uint64{{0xf00, 0x100}, {0x1000, 0x100}, {0x1100, 0x80}}) {
		t.Fatalf("%x", got)
	}
	if !bytes.Equal(m.Read(0x1100, 1), []byte{0x80}) || m.IsMapped(0x1180) || m.Read(0x1100, 0x81) != nil {
		t.Error("lookup")
	}
	if v, _ := m.ReadUint(0x1000, 4, false); v != 0x03020100 {
		t.Errorf("%x", v)
	}
	if v, _ := m.ReadUint(0x1000, 4, true); v != 0x00010203 {
		t.Errorf("%x", v)
	}

	if !m.Write(0x1000, []byte{9, 9}) || m.Read(0x1001, 1)[0] != 9 || m.Write(0x10ff, []byte{1, 2}) || m.Write(0x5000, []byte{1}) {
		t.Error("write")
	}
	m.ClearWrite(0xf00, 0x1000)
	m.Add(MemoryBlock{Start: 0x2000, Size: 4, Perms: Perms{Write: true}, Data: []byte{1, 2, 3, 4}})
	m.ClearWrite(0x2000, 0x2004)
	if m.BlockAt(0x2000).Perms.Write {
		t.Error("clear_write")
	}
	m.Grow(0x2000, 8, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	if b := m.BlockAt(0x2007); b == nil || len(b.Data) != 8 {
		t.Error("grow")
	}
	m.Add(MemoryBlock{Start: 0x2004 + 4, Size: 4})
	m.Grow(0x2000, 100, make([]byte, 100)) // capped at next block
	if m.BlockAt(0x2000).Size != 8 {
		t.Error("grow past next block")
	}
}

func TestReadUintBadSizes(t *testing.T) {
	var m MemoryMap
	m.Add(blk(0, 16))
	for _, n := range []int{0, 9} {
		if _, ok := m.ReadUint(0, n, false); ok {
			t.Errorf("size %d returned a value", n)
		}
	}
	if v, ok := m.ReadUint(0, 8, true); !ok || v != 0x0001020304050607 {
		t.Errorf("%x %v", v, ok)
	}
}
