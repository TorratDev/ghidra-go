package export

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T) *Export {
	t.Helper()
	e, err := Load(filepath.Join("testdata", "export.json"))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func ram(off uint64) Address { return Address{"ram", off} }

func TestLoadSample(t *testing.T) {
	e := load(t)
	if e.Program != "sample.bin" || e.GhidraVersion != "11.4.3" || e.FormatVersion != FormatVersion || e.ImageBase != ram(0x02000000) {
		t.Errorf("header: %+v", e)
	}
	if len(e.Blocks) != 2 || len(e.Symbols) != 4 || len(e.Functions) != 2 || len(e.DataTypes) != 3 {
		t.Errorf("counts: %d blocks %d symbols %d functions %d types", len(e.Blocks), len(e.Symbols), len(e.Functions), len(e.DataTypes))
	}
}

func TestFunctionAt(t *testing.T) {
	e := load(t)
	f, ok := e.FunctionAt(ram(0x02000d80))
	if !ok || f.Name != "scale" || f.CallingConvention != "__stdcall" || len(f.Body) != 2 || f.Body[1].End != ram(0x02000da3) ||
		f.Namespace[0] != "Math" || f.ReturnType != "/int" || len(f.Parameters) != 2 || f.Parameters[1].DataType != "/point *" ||
		f.Parameters[1].Storage != "r1:4" {
		t.Errorf("scale: %+v ok=%v", f, ok)
	}
	if _, ok := e.FunctionAt(ram(0x02000d70)); ok { // inside a function but not its entry
		t.Error("found a function at a non-entry address")
	}
	f, ok = e.FunctionAt(ram(0x02000d6c))
	if !ok || f.Prototype != "undefined FUN_02000d6c()" || len(f.Parameters) != 0 {
		t.Errorf("FUN_02000d6c: %+v", f)
	}
}

func TestSymbolLookups(t *testing.T) {
	e := load(t)
	ss := e.SymbolsAt(ram(0x02000d7c))
	if len(ss) != 1 || ss[0].Name != "DAT_02000d7c" || ss[0].TypeID != 0 || ss[0].Type != "Label" {
		t.Errorf("at d7c: %+v", ss)
	}
	ss = e.SymbolsNamed("FUN_02000d6c")
	if len(ss) != 1 || ss[0].Address != ram(0x02000d6c) || ss[0].TypeID != 5 {
		t.Errorf("by name: %+v", ss)
	}
	ss = e.SymbolsNamed("EXT_FUN_0214d690")
	if len(ss) != 1 || ss[0].Address != (Address{"EXTERNAL", 1}) || ss[0].Namespace[0] != "<EXTERNAL>" {
		t.Errorf("external: %+v", ss)
	}
	ss = e.SymbolsNamed("orphan")
	if len(ss) != 1 || ss[0].HasAddress || len(e.SymbolsAt(Address{})) != 0 {
		t.Errorf("addressless symbol: %+v", ss)
	}
	if len(e.SymbolsAt(ram(0x1234))) != 0 || len(e.SymbolsNamed("nope")) != 0 {
		t.Error("missing symbol not empty")
	}
}

func TestBlockContaining(t *testing.T) {
	e := load(t)
	for _, c := range []struct {
		a    Address
		want string
	}{
		{ram(0x02000d00), "arm9"}, {ram(0x02000d7f), "arm9"}, {ram(0x02000e00), "arm9_bss"}, {ram(0x02000e0f), "arm9_bss"},
	} {
		if b, ok := e.BlockContaining(c.a); !ok || b.Name != c.want {
			t.Errorf("%s: %+v ok=%v, want %s", c.a, b, ok, c.want)
		}
	}
	// Outside every block, or in an unknown space: not found, no error.
	for _, a := range []Address{ram(0x02000cff), ram(0x02000d80), ram(0x02000e10), ram(0), {"other", 0x02000d00}, {}} {
		if b, ok := e.BlockContaining(a); ok || b != nil {
			t.Errorf("%s: unexpectedly found %+v", a, b)
		}
	}
}

func TestDataTypes(t *testing.T) {
	e := load(t)
	d, ok := e.DataType("/point")
	if !ok || d.Kind != "Structure" || len(d.Components) != 2 || d.Components[1].Offset != 4 {
		t.Errorf("point: %+v", d)
	}
	if p, ok := e.DataType("/point *"); !ok || p.Base != "/point" {
		t.Errorf("pointer: %+v", p)
	}
	if _, ok := e.DataType("/nope"); ok {
		t.Error("found a missing type")
	}
}

func TestReadBytes(t *testing.T) {
	e := load(t)
	b, err := e.ReadBytes(ram(0x02000d6c), 4) // 0x6c-0x00 = 108 into the block
	if err != nil || string(b) != string([]byte{108, 109, 110, 111}) {
		t.Fatalf("bytes: %v %v", b, err)
	}
	if b, err = e.ReadBytes(ram(0x02000d7e), 2); err != nil || b[1] != 127 { // last two bytes of the block
		t.Errorf("end of block: %v %v", b, err)
	}
	for _, c := range []struct {
		name string
		a    Address
		n    int
	}{
		{"outside", ram(0x02000d80), 1}, {"uninitialized", ram(0x02000e00), 1}, {"past end", ram(0x02000d7e), 3}, {"negative", ram(0x02000d00), -1},
	} {
		if _, err := e.ReadBytes(c.a, c.n); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", c.name, err)
		}
	}
}

func TestSidecarHashChecked(t *testing.T) {
	dir := t.TempDir()
	js, _ := os.ReadFile(filepath.Join("testdata", "export.json"))
	bin, _ := os.ReadFile(filepath.Join("testdata", "export.bin"))
	bin[5] ^= 1 // corrupt one byte
	os.WriteFile(filepath.Join(dir, "export.bin"), bin, 0o644)
	e, err := Parse(strings.NewReader(string(js)), dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.ReadBytes(ram(0x02000d00), 1); err == nil || !strings.Contains(err.Error(), "sha256") || errors.Is(err, ErrNotFound) {
		t.Errorf("err = %v, want a sha256 mismatch", err)
	}
	// A missing sidecar is an error too, and parsing alone does not need it.
	e, _ = Parse(strings.NewReader(string(js)), t.TempDir())
	if _, err := e.ReadBytes(ram(0x02000d00), 1); err == nil {
		t.Error("want error for missing sidecar")
	}
}

func TestRejects(t *testing.T) {
	const sc = `"sidecar":{"file":"export.bin","sha256":"471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"}`
	cases := []struct{ name, json, want string }{
		{"unknown version", `{"format_version":2,` + sc + `}`, "unsupported format version 2"},
		{"explicit zero version", `{"format_version":0,` + sc + `}`, "unsupported format version 0"},
		{"negative version", `{"format_version":-1,` + sc + `}`, "unsupported format version -1"},
		{"no sidecar", `{}`, "sidecar"},
		{"bad sidecar hash", `{"sidecar":{"file":"export.bin","sha256":"abc"}}`, "sidecar"},
		{"sidecar path", `{"sidecar":{"file":"../x","sha256":"471fb943aa23c511f6f72f8d1652d9c880cfa392ad80503120547703e56a2be5"}}`, "plain file name"},
		{"bad address", `{` + sc + `,"memory_blocks":[{"name":"b","start":"ram02000000","size":1}]}`, "bad address"},
		{"bad json", `{`, "export:"},
		{"block without bytes", `{` + sc + `,"memory_blocks":[{"name":"b","start":"ram:00","size":4,"initialized":true}]}`, "no matching sidecar range"},
	}
	for _, c := range cases {
		if _, err := Parse(strings.NewReader(c.json), "."); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	// An explicit current version and an absent one are both accepted.
	for _, v := range []string{`"format_version":1,`, ``} {
		if _, err := Parse(strings.NewReader(`{`+v+sc+`}`), "."); err != nil {
			t.Errorf("version %q: %v", v, err)
		}
	}
}
