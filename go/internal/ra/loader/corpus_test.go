package loader

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

const corpusDir = "../../../../rust-analysis/compare"

type expectedReport struct {
	Memory []struct {
		Name                 string
		Start, End           string
		Read, Write, Execute bool
		Initialized          bool
	}
	Symbols []struct{ Addr, Name string }
	Binary  struct {
		Sha256, Language string
		ImageBase        string `json:"image_base"`
	}
}

func loadExpected(t *testing.T, name string) expectedReport {
	f, err := os.Open(filepath.Join(corpusDir, "expected", name+".json.gz"))
	if err != nil {
		t.Skipf("expected report not available: %v", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var r expectedReport
	if err := json.NewDecoder(zr).Decode(&r); err != nil {
		t.Fatal(err)
	}
	return r
}

func loadCorpus(t *testing.T, name string) *Program {
	p, err := LoadPath(filepath.Join(corpusDir, "corpus/binaries", name), "")
	if err != nil {
		t.Skipf("corpus binary not available: %v", err)
	}
	return p
}

// TestCorpusMemoryAndDT compares the memory block list and the __DT_ labels
// with the Ghidra 12.1.4 export of the two basic-x86_64-gcc-O2 binaries.
func TestCorpusMemoryAndDT(t *testing.T) {
	for _, name := range []string{"basic-x86_64-gcc-O2", "basic-x86_64-gcc-O2-stripped", "basic-x86_64-gcc-O2-static-stripped"} {
		t.Run(name, func(t *testing.T) {
			want := loadExpected(t, name)
			p := loadCorpus(t, name)
			// Blocks are matched by name and range; permissions are compared
			// after, because Ghidra's RELRO handling differs from the loader's
			// for one block (see knownPermGaps).
			wantBlocks := map[string]string{}
			for _, m := range want.Memory {
				var s, e uint64
				fmt.Sscanf(m.Start, "0x%x", &s)
				fmt.Sscanf(m.End, "0x%x", &e)
				wantBlocks[fmt.Sprintf("%s %#x-%#x", m.Name, s, e)] = fmt.Sprintf("r=%t w=%t x=%t", m.Read, m.Write, m.Execute)
			}
			var extra, missing, permDiff []string
			gotBlocks := map[string]bool{}
			for _, b := range p.Memory.Blocks() {
				k := fmt.Sprintf("%s %#x-%#x", b.Name, b.Start, b.End())
				gotBlocks[k] = true
				perms := fmt.Sprintf("r=%t w=%t x=%t", b.Perms.Read, b.Perms.Write, b.Perms.Execute)
				switch w, ok := wantBlocks[k]; {
				case !ok:
					extra = append(extra, k)
				case w != perms:
					permDiff = append(permDiff, fmt.Sprintf("%s ghidra %s ours %s", k, w, perms))
				}
			}
			for k := range wantBlocks {
				if !gotBlocks[k] {
					missing = append(missing, k)
				}
			}
			slices.Sort(missing)
			t.Logf("blocks: ours %d, ghidra %d, missing %v, extra %v, permission differences %v",
				len(gotBlocks), len(wantBlocks), missing, extra, permDiff)
			if len(extra) > 0 {
				t.Errorf("blocks Ghidra does not have: %v", extra)
			}
			// Ghidra also maps the ELF header as a segment_N block, which the
			// loader does not produce.
			for _, k := range missing {
				if !strings.HasPrefix(k, "segment_") {
					t.Errorf("missing block %s", k)
				}
			}
			// knownPermGaps: Ghidra makes .got.plt of the static binary
			// read-only although it runs 0xb0 bytes past the end of
			// PT_GNU_RELRO; clear_write only covers blocks entirely inside.
			for _, d := range permDiff {
				if name != "basic-x86_64-gcc-O2-static-stripped" || !strings.HasPrefix(d, ".got.plt ") {
					t.Errorf("permission difference: %s", d)
				}
			}

			dt := func(addr func(i int) (string, string), n int) []string {
				var out []string
				for i := 0; i < n; i++ {
					a, nm := addr(i)
					if strings.HasPrefix(nm, "__DT_") {
						out = append(out, nm+"@"+a)
					}
				}
				slices.Sort(out)
				return out
			}
			wantDT := dt(func(i int) (string, string) { return want.Symbols[i].Addr, want.Symbols[i].Name }, len(want.Symbols))
			gotDT := dt(func(i int) (string, string) { return fmt.Sprintf("%#x", p.Symbols[i].Addr), p.Symbols[i].Name }, len(p.Symbols))
			t.Logf("__DT_ labels: ours %v", gotDT)
			if !slices.Equal(wantDT, gotDT) {
				t.Errorf("__DT_ labels differ:\n ghidra %v\n ours   %v", wantDT, gotDT)
			}
			if name == "basic-x86_64-gcc-O2-static-stripped" {
				for _, n := range []string{".init_array", ".fini_array"} {
					if !slices.ContainsFunc(p.Memory.Blocks(), func(b core.MemoryBlock) bool { return b.Name == n }) {
						t.Errorf("%s block missing", n)
					}
				}
			}
		})
	}
}

func TestCorpusProgram(t *testing.T) {
	const name = "basic-x86_64-gcc-O2-stripped"
	want := loadExpected(t, name)
	p := loadCorpus(t, name)
	if p.Sha256 != want.Binary.Sha256 || p.Language != want.Binary.Language || p.Format != "ELF" ||
		fmt.Sprintf("%#x", p.ImageBase) != want.Binary.ImageBase {
		t.Errorf("binary info: %s %s %#x, want %+v", p.Sha256, p.Language, p.ImageBase, want.Binary)
	}
	if p.Entry == nil || *p.Entry != 0x101250 || p.FallbackNames[0x101250] != "entry" ||
		p.FallbackNames[0x101000] != "_DT_INIT" || p.FallbackNames[0x1014c4] != "_DT_FINI" ||
		p.FallbackNames[1053424] != "_FINI_0" || p.FallbackNames[1053488] != "_INIT_0" {
		t.Errorf("entry %v names %v", p.Entry, p.FallbackNames)
	}
	libc := "libc.so.6"
	found := false
	for _, i := range p.Imports {
		if i.Name == "__libc_start_main" && i.Library != nil && *i.Library == libc && i.Slot != nil && *i.Slot == 0x103fc0 {
			found = true
		}
	}
	if !found {
		t.Errorf("__libc_start_main import missing: %+v", p.Imports)
	}
	if p.MarkedPointers[0x103d30] != 1053488 || p.MarkedPointers[0x103d38] != 1053424 {
		t.Errorf("init/fini array pointers: %v", p.MarkedPointers)
	}
}
