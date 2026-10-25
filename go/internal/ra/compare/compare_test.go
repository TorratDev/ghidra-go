package compare

import (
	"slices"
	"sort"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

func sp(s string) *string { return &s }

func memInfo(name string, start, end uint64) core.MemoryInfo {
	return core.MemoryInfo{Name: name, Start: core.Addr(start), End: core.Addr(end), Read: true, Execute: true}
}

func report(base uint64, funcs ...uint64) *core.AnalysisReport {
	r := core.NewAnalysisReport()
	r.Memory = []core.MemoryInfo{memInfo(".text", base+0x1000, base+0x2000)}
	for _, f := range funcs {
		a := core.Addr(base + f)
		r.Functions = append(r.Functions, core.FunctionInfo{Entry: a, Name: "f", Source: core.SourceImported,
			Body: []core.AddrPair{{a, a + 4}}})
	}
	return r
}

func set(keys ...string) map[string]struct{} {
	m := map[string]struct{}{}
	for _, k := range keys {
		m[k] = struct{}{}
	}
	return m
}

func keys(m map[string]struct{}) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestBiasAndSetMetrics(t *testing.T) {
	g := report(0x100000, 0x1000, 0x1010, 0x1020, 0x1030)
	r := report(0, 0x1000, 0x1010, 0x1040)
	c := Compare("t", g, r)
	if c.Bias != 0x100000 {
		t.Fatalf("bias %#x", c.Bias)
	}
	f := c.Category("functions")
	if f.Matched != 2 || f.GhidraOnly != 2 || f.RaOnly != 1 || f.Recall != 0.5 || f.Precision != 2.0/3 {
		t.Errorf("%+v", f)
	}
	// Bodies are only compared for functions present on both sides.
	if b := c.Category("function_bodies"); b.Matched != 2 || b.GhidraOnly != 0 || b.RaOnly != 0 {
		t.Errorf("%+v", b)
	}
	if len(c.Categories) != len(Categories) {
		t.Errorf("%d categories", len(c.Categories))
	}
}

func TestBiasFallbacks(t *testing.T) {
	g, r := core.NewAnalysisReport(), core.NewAnalysisReport()
	g.Memory = []core.MemoryInfo{memInfo(".data", 0x5000, 0x5100), memInfo(".bss", 0x6000, 0x6010)}
	r.Memory = []core.MemoryInfo{memInfo(".data", 0x1000, 0x1100), memInfo(".bss", 0x2000, 0x2010)}
	// same-size blocks vote: .bss 0x4000 and .data 0x4000
	if b := DetectBias(g, r); b != 0x4000 {
		t.Errorf("vote bias %#x", b)
	}
	// a tie goes to the larger bias (Rust's max_by_key keeps the last maximum)
	r.Memory = []core.MemoryInfo{memInfo(".data", 0x1000, 0x1100), memInfo(".bss", 0x1000, 0x1010)}
	if b := DetectBias(g, r); b != 0x5000 {
		t.Errorf("tie bias %#x", b)
	}
	g.Memory, r.Memory = nil, nil
	g.Binary.ImageBase, r.Binary.ImageBase = 0x100000, 0x400000
	if b := DetectBias(g, r); b != -0x300000 {
		t.Errorf("image base bias %#x", b)
	}
}

// Recall and precision are 1.0 when the denominator is 0: nothing to miss or
// nothing extra. Both sides empty is a perfect score; one side empty scores 0
// on the metric that has a denominator.
func TestEmptyDenominatorIsPerfect(t *testing.T) {
	c := FromSets("x", set(), set())
	if c.Recall != 1 || c.Precision != 1 || c.Matched != 0 {
		t.Errorf("%+v", c)
	}
	c = FromSets("x", set("a"), set())
	if c.Recall != 0 || c.Precision != 1 {
		t.Errorf("ra empty: %+v", c)
	}
	c = FromSets("x", set(), set("a"))
	if c.Recall != 1 || c.Precision != 0 {
		t.Errorf("ghidra empty: %+v", c)
	}
	if got := c.F1(); got != 0 {
		t.Errorf("f1 %v", got)
	}
}

func TestSamplesAreSortedAndCapped(t *testing.T) {
	g := set()
	for i := 0; i < Samples+10; i++ {
		g[string(rune('a'+i%26))+string(rune('a'+i/26))] = struct{}{}
	}
	c := FromSets("x", g, set())
	if len(c.GhidraOnlySamples) != Samples || c.GhidraOnly != Samples+10 || !sort.StringsAreSorted(c.GhidraOnlySamples) {
		t.Errorf("%d samples, %d only", len(c.GhidraOnlySamples), c.GhidraOnly)
	}
	if c.RaOnlySamples == nil {
		t.Error("nil samples encode as null")
	}
}

func TestSymbolsAreImportedOnly(t *testing.T) {
	r := core.NewAnalysisReport()
	r.Symbols = []core.SymbolInfo{
		{Addr: 0x10, Name: "a", Source: core.SourceImported},
		{Addr: 0x20, Name: "b", Source: core.SourceAnalysis},
		{Addr: 0x30, Name: "c", Source: core.SourceDefault},
		{Addr: 0x40, Name: "d", Source: core.SourceUser},
	}
	if got := keys(newView(r, 0).set("symbols")); !slices.Equal(got, []string{"0x10 a"}) {
		t.Errorf("%v", got)
	}
}

func TestDemangledNamesNamespaceKey(t *testing.T) {
	r := core.NewAnalysisReport()
	r.Symbols = []core.SymbolInfo{
		{Addr: 0x10, Name: "_ZN2ns1C1fEv", Source: core.SourceImported},
		{Addr: 0x10, Name: "f", Namespace: sp("ns::C"), Source: core.SourceAnalysis},
		{Addr: 0x20, Name: "?g@@YAXXZ", Source: core.SourceImported},
		{Addr: 0x20, Name: "g", Source: core.SourceAnalysis},
		{Addr: 0x30, Name: "plain", Source: core.SourceImported}, // not mangled
		{Addr: 0x30, Name: "other", Source: core.SourceAnalysis},
		{Addr: 0x40, Name: "h", Source: core.SourceAnalysis}, // no mangled symbol here
		{Addr: 0x50, Name: "_Rfoo", Source: core.SourceDefault},
		{Addr: 0x50, Name: "i", Source: core.SourceAnalysis}, // mangled but not imported
	}
	want := []string{"0x10 ns::C::f", "0x20 g"}
	if got := keys(newView(r, 0).set("demangled_names")); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// the bias applies to the address part only
	if got := keys(newView(r, 0x100).set("demangled_names")); !slices.Equal(got, []string{"0x110 ns::C::f", "0x120 g"}) {
		t.Errorf("biased %v", got)
	}
}

func xrefReport() *core.AnalysisReport {
	r := core.NewAnalysisReport()
	r.Instructions = []core.InstructionInfo{{Addr: 0x10, Len: 3, Mnemonic: "MOV"}, {Addr: 0x20, Len: 1, Mnemonic: "RET"}}
	r.Xrefs = []core.XrefInfo{
		{From: 0x10, To: 0x500, Kind: core.XrefRead},
		{From: 0x10, To: 0x504, Kind: core.XrefData},
		{From: 0x20, To: 0x30, Kind: core.XrefCall},   // flow: neither data category
		{From: 0x600, To: 0x700, Kind: core.XrefData}, // from data
		{From: 0x608, To: 0x710, Kind: core.XrefRead}, // data, not an instruction, not Data kind
		{From: 0x20, To: 0x800, Kind: core.XrefCondJump},
	}
	return r
}

func TestXrefCategoryKeys(t *testing.T) {
	v := newView(xrefReport(), 0)
	for cat, want := range map[string][]string{
		"xrefs_flow":       {"0x20->0x30 Call", "0x20->0x800 CondJump"},
		"xrefs_data":       {"0x10->0x500", "0x10->0x504"},
		"xrefs_data_kinds": {"0x10->0x500 Read", "0x10->0x504 Data"},
		"xrefs_from_data":  {"0x600->0x700"},
	} {
		if got := keys(v.set(cat)); !slices.Equal(got, want) {
			t.Errorf("%s: got %v, want %v", cat, got, want)
		}
	}
}

func TestXrefDataKindsOnlyComparesCommonPairs(t *testing.T) {
	g, r := xrefReport(), xrefReport()
	g.Xrefs = []core.XrefInfo{
		{From: 0x10, To: 0x500, Kind: core.XrefRead},  // kind differs
		{From: 0x10, To: 0x504, Kind: core.XrefData},  // equal
		{From: 0x10, To: 0x508, Kind: core.XrefWrite}, // pair only in ghidra: counted under xrefs_data, not here
	}
	r.Xrefs = []core.XrefInfo{
		{From: 0x10, To: 0x500, Kind: core.XrefWrite},
		{From: 0x10, To: 0x504, Kind: core.XrefData},
		{From: 0x20, To: 0x900, Kind: core.XrefData}, // pair only in ra
	}
	c := Compare("t", g, r)
	k := c.Category("xrefs_data_kinds")
	if k.Matched != 1 || k.GhidraOnly != 1 || k.RaOnly != 1 {
		t.Errorf("kinds %+v", k)
	}
	if !slices.Equal(k.GhidraOnlySamples, []string{"0x10->0x500 Read"}) || !slices.Equal(k.RaOnlySamples, []string{"0x10->0x500 Write"}) {
		t.Errorf("kinds samples %v %v", k.GhidraOnlySamples, k.RaOnlySamples)
	}
	d := c.Category("xrefs_data")
	// the pairs only one side has still count here: this is where they are scored once
	if d.Matched != 2 || d.GhidraOnly != 1 || d.RaOnly != 1 {
		t.Errorf("xrefs_data %+v", d)
	}
}

func TestInstructionDetailsRestrictedToCommonAddresses(t *testing.T) {
	g, r := core.NewAnalysisReport(), core.NewAnalysisReport()
	g.Instructions = []core.InstructionInfo{{Addr: 1, Len: 2, Mnemonic: "MOV"}, {Addr: 3, Len: 1, Mnemonic: "RET"}}
	r.Instructions = []core.InstructionInfo{{Addr: 1, Len: 2, Mnemonic: "ADD"}, {Addr: 9, Len: 1, Mnemonic: "NOP"}}
	c := Compare("t", g, r)
	if d := c.Category("instruction_details"); d.Matched != 0 || d.GhidraOnly != 1 || d.RaOnly != 1 {
		t.Errorf("details %+v", d) // only address 1 is on both sides
	}
	if i := c.Category("instructions"); i.Matched != 1 || i.GhidraOnly != 1 || i.RaOnly != 1 {
		t.Errorf("instructions %+v", i)
	}
}

func TestMemoryBlocksImportsAndEdges(t *testing.T) {
	r := core.NewAnalysisReport()
	r.Memory = []core.MemoryInfo{
		memInfo(".text", 0x1000, 0x2000), memInfo("segment_0.1", 0, 0x10),
		memInfo("Headers", 0, 0x10), memInfo("tdb", 0, 0x10),
		{Name: ".data", Start: 0x3000, End: 0x3010, Read: true, Write: true},
	}
	r.Imports = []core.ImportInfo{{Name: "printf@GLIBC_2.2.5"}, {Name: "puts"}}
	r.Edges = []core.EdgeInfo{{From: 1, To: 2, Kind: core.EdgeCondJump}, {From: 2, To: 3, Kind: core.EdgeFallthrough}}
	v := newView(r, 0)
	if got := keys(v.set("memory_blocks")); !slices.Equal(got, []string{".data 0x3000-0x3010 rw-", ".text 0x1000-0x2000 r-x"}) {
		t.Errorf("%v", got)
	}
	if got := keys(v.set("imports")); !slices.Equal(got, []string{"printf", "puts"}) {
		t.Errorf("%v", got)
	}
	if got := keys(v.set("edges")); !slices.Equal(got, []string{"0x1->0x2 CondJump", "0x2->0x3 Fallthrough"}) {
		t.Errorf("%v", got)
	}
}
