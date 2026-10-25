package analysis

import (
	"slices"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/loader"
	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

func blocksOf(r *core.AnalysisReport) [][2]uint64 {
	var out [][2]uint64
	for _, b := range r.Blocks {
		out = append(out, [2]uint64{uint64(b.Start), uint64(b.End)})
	}
	return out
}

func reportOf(t *testing.T, p *loader.Program, d fake) *core.AnalysisReport {
	t.Helper()
	return Report(p, run(t, p, d))
}

// 8. A block starts at an instruction with a symbol or any reference to it,
// data references included (SimpleBlockModel.isBlockStart is
// SymbolTable.hasSymbol), and after an instruction without fallthrough or one
// that ends a block.
func TestBlockStartsFollowGhidrasRule(t *testing.T) {
	read := ins(0x1000, 1, "MOV", fall)
	read.DataRefs = []DataRef{{0x1002, AccessRead}, {0x1003, AccessAddress}} // data-only references to instructions
	d := fake{}.add(read, ins(0x1001, 1, "NOP", fall), ins(0x1002, 1, "NOP", fall), ins(0x1003, 1, "NOP", fall), ins(0x1004, 1, "RET", ret))
	r := reportOf(t, newProg(0x1000, 0x100, seeds(0x1000), block(".data", 0x4000, 8, false)), d)
	if got := blocksOf(r); !slices.Equal(got, [][2]uint64{{0x1000, 0x1002}, {0x1002, 0x1003}, {0x1003, 0x1005}}) {
		t.Errorf("data references: %#x", got)
	}
	if len(r.Xrefs) != 2 {
		t.Errorf("xrefs %v", r.Xrefs)
	}
	// the same code without the references is one block
	plain := fake{}.add(ins(0x1000, 1, "MOV", fall), ins(0x1001, 1, "NOP", fall), ins(0x1002, 1, "NOP", fall), ins(0x1003, 1, "NOP", fall), ins(0x1004, 1, "RET", ret))
	if got := blocksOf(reportOf(t, newProg(0x1000, 0x100, seeds(0x1000)), plain)); !slices.Equal(got, [][2]uint64{{0x1000, 0x1005}}) {
		t.Errorf("no references: %#x", got)
	}
	// a jump from another function to 0x1002 starts a block there
	other := fake{}.add(ins(0x1000, 1, "MOV", fall), ins(0x1001, 1, "NOP", fall), ins(0x1002, 1, "NOP", fall), ins(0x1003, 1, "NOP", fall), ins(0x1004, 1, "RET", ret),
		ins(0x1100, 1, "NOP", fall), ins(0x1101, 5, "JMP", jmp, 0x1002))
	r = reportOf(t, newProg(0x1000, 0x200, seeds(0x1000, 0x1100)), other)
	if got := blocksOf(r); !slices.Equal(got, [][2]uint64{{0x1000, 0x1002}, {0x1002, 0x1005}, {0x1100, 0x1106}}) {
		t.Errorf("flow target: %#x", got)
	}
}

// A flow reference into the middle of an instruction starts no block: Ghidra
// asks hasSymbol of the instruction's own address.
func TestOffcutReferenceStartsNoBlock(t *testing.T) {
	d := fake{}.add(ins(0x1000, 1, "NOP", fall), ins(0x1001, 3, "MOV", fall), ins(0x1004, 1, "RET", ret),
		ins(0x1100, 1, "NOP", fall), ins(0x1101, 5, "JMP", jmp, 0x1002))
	r := reportOf(t, newProg(0x1000, 0x200, seeds(0x1000, 0x1100)), d)
	if got := blocksOf(r); !slices.Equal(got, [][2]uint64{{0x1000, 0x1005}, {0x1100, 0x1106}}) {
		t.Errorf("%#x", got)
	}
}

func TestBlockEndsAndEdges(t *testing.T) {
	d := fake{}.add(
		ins(0x1000, 1, "NOP", fall),
		ins(0x1001, 2, "JZ", cjmp, 0x1010), // conditional: ends the block, edges to both
		ins(0x1003, 1, "NOP", fall),
		ins(0x1004, 5, "JMP", jmp, 0x1000), // unconditional back to the start: a jump edge
		ins(0x1010, 5, "CALL", call, 0x1100),
		ins(0x1015, 1, "RET", ret),
		ins(0x1100, 1, "RET", ret))
	r := reportOf(t, newProg(0x1000, 0x200, seeds(0x1000)), d)
	// the call does not end a block: 0x1010..0x1016 is one block
	if got := blocksOf(r); !slices.Equal(got, [][2]uint64{{0x1000, 0x1003}, {0x1003, 0x1009}, {0x1010, 0x1016}, {0x1100, 0x1101}}) {
		t.Errorf("blocks %#x", got)
	}
	want := map[core.EdgeInfo]bool{
		{From: 0x1000, To: 0x1003, Kind: core.EdgeFallthrough}: true,
		{From: 0x1000, To: 0x1010, Kind: core.EdgeCondJump}:    true,
		{From: 0x1003, To: 0x1000, Kind: core.EdgeJump}:        true,
	}
	if len(r.Edges) != len(want) {
		t.Fatalf("edges %+v", r.Edges)
	}
	for _, e := range r.Edges {
		if !want[e] {
			t.Errorf("unexpected edge %+v", e)
		}
	}
}

// 8. Block ends use the instruction's own has_fallthrough, not the flow cut
// after a call to a no-return function: the instruction after such a call
// stays in the block.
func TestNoReturnCallDoesNotEndTheBlock(t *testing.T) {
	call := Decoded{Addr: 0x1000, Len: 5, Mnemonic: "CALL", Flow: sleigh.FlowCall, HasFallthrough: true, Targets: []uint64{0x1100}}
	an := &Analysis{
		Insns: map[uint64]*Insn{
			0x1000: {D: call}, // no fallthrough after cutting: HasFT false
			0x1005: {D: ins(0x1005, 1, "NOP", fall), FT: 0x1006, HasFT: true},
			0x1006: {D: ins(0x1006, 1, "RET", ret)},
		},
		SortedInsns: []uint64{0x1000, 0x1005, 0x1006},
		Functions:   map[uint64]*Function{0x1000: {Entry: 0x1000}},
		SwitchJumps: map[uint64]bool{},
	}
	r := Report(newProg(0x1000, 0x200), an)
	if got := blocksOf(r); !slices.Equal(got, [][2]uint64{{0x1000, 0x1007}}) {
		t.Errorf("%#x", got)
	}
}

func TestReportNamesAndSources(t *testing.T) {
	d := fake{}.add(
		ins(0x1000, 1, "RET", ret), ins(0x1010, 1, "RET", ret), ins(0x1020, 1, "RET", ret),
		ins(0x1030, 1, "RET", ret), ins(0x1040, 6, "JMP", jmp).indirectVia(0x3000).noFall(),
		ins(0x1050, 1, "RET", ret))
	p := newProg(0x1000, 0x200, seeds(0x1000, 0x1010, 0x1020, 0x1030, 0x1040), block(".got", 0x3000, 8, false), func(p *loader.Program) {
		p.Symbols = []loader.LoadedSymbol{
			{Addr: 0x1000, Name: "_Z3foov", IsFunction: true}, // demangled: name foo, source analysis
			{Addr: 0x1010, Name: "plain", IsFunction: true},   // function symbol: imported
			{Addr: 0x1050, Name: "label_only"},                // not a function
			{Addr: 0x3000, Name: "got_slot", IsData: true},
		}
		p.FallbackNames[0x1020] = "_INIT_0"
		p.ImportSlots[0x3000] = "puts"
	})
	r := reportOf(t, p, d)
	byAddr := map[core.Addr]core.FunctionInfo{}
	for _, f := range r.Functions {
		byAddr[f.Entry] = f
	}
	check := func(addr core.Addr, name string, src core.SymbolSource) {
		t.Helper()
		if f := byAddr[addr]; f.Name != name || f.Source != src {
			t.Errorf("%#x: %q %v, want %q %v", uint64(addr), f.Name, f.Source, name, src)
		}
	}
	check(0x1000, "foo", core.SourceAnalysis)
	check(0x1010, "plain", core.SourceImported)
	check(0x1020, "_INIT_0", core.SourceImported)
	check(0x1030, "FUN_00001030", core.SourceDefault)
	// a PLT-style stub with a named slot: the thunk's external name, default source
	if f := byAddr[0x1040]; f.Name != "puts" || !f.Thunk || f.ThunkTarget != nil {
		t.Errorf("external thunk %+v", f)
	}
	// symbols: the mangled one stays, the demangled one is added; kinds by what is at the address
	kinds := map[string]string{}
	for _, s := range r.Symbols {
		kinds[s.Name] = s.Kind
	}
	if kinds["_Z3foov"] != "function" || kinds["foo"] != "function" || kinds["label_only"] != "label" || kinds["got_slot"] != "data" {
		t.Errorf("symbol kinds %v", kinds)
	}
	if kinds["FUN_00001030"] != "function" {
		t.Error("default-named function has no symbol")
	}
}

func TestReportXrefKinds(t *testing.T) {
	via := uint64(0x3000)
	pltjmp := ins(0x1100, 6, "JMP", jmp, 0x1200).indirectVia(via) // PLT0-style: jump that falls through
	pltjmp.HasFallthrough = true
	rw := ins(0x1010, 1, "MOV", fall)
	rw.DataRefs = []DataRef{{0x4000, AccessRead}, {0x4001, AccessWrite}, {0x4002, AccessAddress}, {0x9999, AccessRead}}
	jmpSlot := ins(0x1020, 6, "JMP", jmp).indirectVia(0x4000).noFall()
	jmpSlot.DataRefs = []DataRef{{0x4000, AccessRead}}
	callSlot := ins(0x1030, 6, "CALL", call).indirectVia(0x4000)
	callSlot.DataRefs = []DataRef{{0x4000, AccessRead}}
	d := fake{}.add(
		ins(0x1000, 5, "CALL", call, 0x1300), ins(0x1005, 2, "JZ", cjmp, 0x1007), ins(0x1007, 5, "JMP", jmp, 0x1300), // tail call to a function
		ins(0x1300, 1, "RET", ret),
		rw.noFall(), jmpSlot, callSlot, pltjmp,
		ins(0x1200, 2, "JMP", jmp, 0x1200).noFall(), // jump to itself: no flow xref
	)
	p := newProg(0x1000, 0x400, seeds(0x1000, 0x1010, 0x1020, 0x1030, 0x1100, 0x1200), block(".data", 0x4000, 8, false), func(p *loader.Program) {
		p.MarkedPointers[0x4000] = 0x1300
	})
	r := reportOf(t, p, d)
	got := map[[3]uint64]core.XrefKind{}
	for _, x := range r.Xrefs {
		got[[3]uint64{uint64(x.From), uint64(x.To), 0}] = x.Kind
	}
	for k, want := range map[[3]uint64]core.XrefKind{
		{0x1000, 0x1300, 0}: core.XrefCall,
		{0x1005, 0x1007, 0}: core.XrefCondJump,
		{0x1007, 0x1300, 0}: core.XrefCall, // jump to another function's entry: a tail call
		{0x1010, 0x4000, 0}: core.XrefRead,
		{0x1010, 0x4001, 0}: core.XrefWrite,
		{0x1010, 0x4002, 0}: core.XrefData,
		{0x1020, 0x4000, 0}: core.XrefData, // the slot of an indirect jump
		{0x1030, 0x4000, 0}: core.XrefRead, // the slot of an indirect call
		{0x1100, 0x1200, 0}: core.XrefCall, // jump with fallthrough: PLT0 call override
		{0x4000, 0x1300, 0}: core.XrefData, // marked pointer
	} {
		if got[k] != want {
			t.Errorf("%#x -> %#x: %q, want %q", k[0], k[1], got[k], want)
		}
	}
	if _, ok := got[[3]uint64{0x1200, 0x1200, 0}]; ok {
		t.Error("self flow reference reported")
	}
	if _, ok := got[[3]uint64{0x1010, 0x9999, 0}]; ok {
		t.Error("reference to unmapped memory reported")
	}
	if len(r.Instructions) != 9 {
		t.Errorf("%d instructions", len(r.Instructions))
	}
}

func TestReportIrelativeThunkTarget(t *testing.T) {
	d := fake{}.add(ins(0x2000, 6, "JMP", jmp).indirectVia(0x3000).noFall(), ins(0x1100, 1, "RET", ret))
	p := newProg(0x1000, 0x200, block(".iplt", 0x2000, 0x20, true), block(".got", 0x3000, 8, false), func(p *loader.Program) {
		p.Pointers[0x3000] = 0x1100
	})
	r := reportOf(t, p, d)
	for _, f := range r.Functions {
		if f.Entry == 0x2000 && (!f.Thunk || f.ThunkTarget == nil || *f.ThunkTarget != 0x1100) {
			t.Errorf("%+v", f)
		}
	}
}

// A call cut by no-return analysis (HasFT false) has no fallthrough edge to
// the block that starts right after it, though the block set is unchanged.
func TestNoFallthroughEdgeAfterNoReturnCall(t *testing.T) {
	call := Decoded{Addr: 0x1000, Len: 5, Mnemonic: "CALL", Flow: sleigh.FlowCall, HasFallthrough: true, Targets: []uint64{0x1100}}
	an := &Analysis{
		Insns: map[uint64]*Insn{
			0x1000: {D: call}, // cut: HasFT false
			0x1005: {D: ins(0x1005, 1, "RET", ret)},
		},
		SortedInsns: []uint64{0x1000, 0x1005},
		Functions:   map[uint64]*Function{0x1000: {Entry: 0x1000}, 0x1005: {Entry: 0x1005}},
		SwitchJumps: map[uint64]bool{},
	}
	r := Report(newProg(0x1000, 0x200), an)
	if got := blocksOf(r); !slices.Equal(got, [][2]uint64{{0x1000, 0x1005}, {0x1005, 0x1006}}) {
		t.Errorf("blocks %#x", got)
	}
	if len(r.Edges) != 0 {
		t.Errorf("edges %+v", r.Edges)
	}
}
