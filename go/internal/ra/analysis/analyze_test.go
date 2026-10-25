package analysis

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/loader"
)

func TestRecursiveDescentAndCalls(t *testing.T) {
	// main: call f; ret.   f: nop; ret.   An unreached instruction stays undecoded.
	d := fake{}.add(
		ins(0x1000, 5, "CALL", call, 0x1010), ins(0x1005, 1, "RET", ret),
		ins(0x1010, 1, "NOP", fall), ins(0x1011, 1, "RET", ret),
		ins(0x1020, 1, "NOP", fall),
	)
	a := run(t, newProg(0x1000, 0x100, seeds(0x1000)), d)
	wantFuncs(t, a, 0x1000, 0x1010)
	if len(a.Insns) != 4 || a.Insns[0x1020] != nil {
		t.Errorf("instructions %d", len(a.Insns))
	}
	if a.Functions[0x1010].Source != SourceCall || a.Functions[0x1000].Source != SourceSeed {
		t.Errorf("sources %v %v", a.Functions[0x1010].Source, a.Functions[0x1000].Source)
	}
	if f := a.Functions[0x1000]; len(f.Body) != 1 || f.Body[0] != [2]uint64{0x1000, 0x1006} {
		t.Errorf("body %v", f.Body)
	}
}

// 1. A PLT or static stub that jumps through a slot with no import name is a
// thunk to the address an IRELATIVE relocation put in the slot.
func TestIrelativeStubThunk(t *testing.T) {
	iplt := func(opts ...progOpt) *loader.Program {
		return newProg(0x1000, 0x200, append([]progOpt{block(".iplt", 0x2000, 0x20, true), block(".got", 0x3000, 0x10, false)}, opts...)...)
	}
	d := func() fake {
		return fake{}.add(
			ins(0x2000, 6, "JMP", jmp).indirectVia(0x3000).noFall(),
			ins(0x2010, 6, "JMP", jmp).indirectVia(0x3008).noFall(),
			ins(0x1100, 1, "NOP", fall), ins(0x1101, 1, "RET", ret),
		)
	}
	p := iplt(func(p *loader.Program) { p.Pointers[0x3000] = 0x1100 })
	a := run(t, p, d())
	f := a.Functions[0x2000]
	if f == nil || f.Thunk == nil || f.Thunk.IsExternal() || f.Thunk.Internal != 0x1100 || f.Source != SourcePlt {
		t.Fatalf("IRELATIVE stub: %+v", f)
	}
	if a.Functions[0x1100] == nil {
		t.Error("the thunked function was not created")
	}
	// a slot with neither an import name nor an addend makes no thunk
	if g := a.Functions[0x2010]; g != nil && g.Thunk != nil {
		t.Errorf("stub without a target: %+v", g.Thunk)
	}
	// an addend that is not code makes none either
	p = iplt(func(p *loader.Program) { p.Pointers[0x3000] = 0x3008 })
	if f := run(t, p, d()).Functions[0x2000]; f != nil && f.Thunk != nil {
		t.Errorf("non-code addend: %+v", f.Thunk)
	}
	// the import name wins over an addend
	p = iplt(func(p *loader.Program) { p.Pointers[0x3000] = 0x1100; p.ImportSlots[0x3000] = "puts" })
	f = run(t, p, d()).Functions[0x2000]
	if f == nil || f.Thunk == nil || !f.Thunk.IsExternal() || f.Thunk.External != "puts" {
		t.Errorf("named slot: %+v", f)
	}
}

// 2. A function whose only instruction is a call to a no-return function is
// not a thunk, and so does not inherit no-return; a jump stub still is a
// thunk and still inherits it.
func TestLoneCallIsNotAThunk(t *testing.T) {
	d := fake{}.add(
		ins(0x1000, 5, "CALL", call, 0x1100), // lone call to exit: the old rule made this a thunk
		ins(0x1006, 5, "JMP", jmp, 0x1100),   // jump stub to exit: a thunk
		ins(0x1100, 1, "RET", ret),
	)
	p := newProg(0x1000, 0x200, seeds(0x1000, 0x1006), func(p *loader.Program) {
		p.Symbols = []loader.LoadedSymbol{{Addr: 0x1100, Name: "exit", IsFunction: true}}
		p.Seeds[0x1100] = loader.SeedSymbol
	})
	a := run(t, p, d)
	if f := a.Functions[0x1000]; f.Thunk != nil || f.NoReturn {
		t.Errorf("lone call: thunk %v, no-return %v", f.Thunk, f.NoReturn)
	}
	if !a.Functions[0x1100].NoReturn {
		t.Error("exit is not no-return")
	}
	if f := a.Functions[0x1006]; f.Thunk == nil || f.Thunk.Internal != 0x1100 || !f.NoReturn {
		t.Errorf("jump stub: thunk %v, no-return %v", f.Thunk, f.NoReturn)
	}
}

// 3. An unconditional jump that leaves its function creates a function at its
// target (SharedReturnAnalysisCmd, contiguous functions assumed).
func TestJumpOutOfFunctionCreatesFunction(t *testing.T) {
	d := fake{}.add(
		// f1 at 0x1000 jumps forward past f2's entry to 0x1180
		ins(0x1000, 2, "NOP", fall), ins(0x1002, 5, "JMP", jmp, 0x1180),
		ins(0x1100, 1, "NOP", fall), ins(0x1101, 1, "RET", ret),
		ins(0x117f, 1, "RET", ret), ins(0x1180, 1, "NOP", fall), ins(0x1181, 1, "RET", ret),
		// f3 at 0x1200 jumps back before f2's entry to 0x1050
		ins(0x1200, 5, "JMP", jmp, 0x1050),
		ins(0x104f, 1, "RET", ret), ins(0x1050, 1, "NOP", fall), ins(0x1051, 1, "RET", ret),
	)
	p := newProg(0x1000, 0x300, seeds(0x1000, 0x1100, 0x1200))
	wantFuncs(t, run(t, p, d), 0x1000, 0x1050, 0x1100, 0x1180, 0x1200)
	if f := run(t, p, d).Functions[0x1180]; f.Source != SourceJump {
		t.Errorf("source %v", f.Source)
	}
}

func TestJumpWithinFunctionOrToFallthroughTargetCreatesNone(t *testing.T) {
	// Every function starts with a MOV: a function whose first real instruction
	// is a lone jump is a thunk, and that rule would create the target itself.
	mov := ins(0x1000, 5, "MOV", fall)
	base := func() fake {
		return fake{}.add(mov,
			ins(0x1100, 1, "NOP", fall), ins(0x1101, 1, "RET", ret),
			ins(0x117f, 1, "RET", ret), ins(0x1180, 1, "NOP", fall), ins(0x1181, 1, "RET", ret),
		)
	}
	p := newProg(0x1000, 0x300, seeds(0x1000, 0x1100))
	// jump forward but still before the next function's entry: stays in the function
	d := base().add(ins(0x1005, 5, "JMP", jmp, 0x1010), ins(0x1010, 1, "RET", ret))
	wantFuncs(t, run(t, p, d), 0x1000, 0x1100)
	// the target is also a conditional jump target
	d = base().add(ins(0x1005, 2, "JNZ", cjmp, 0x1180), ins(0x1007, 5, "JMP", jmp, 0x1180))
	wantFuncs(t, run(t, p, d), 0x1000, 0x1100)
	// the target can be reached by fallthrough from the previous instruction
	d = base().add(ins(0x1005, 5, "JMP", jmp, 0x1180))
	d[0x1100] = ins(0x1100, 0x7f, "NOP", fall) // the second function runs on into 0x1180
	d[0x117f] = ins(0x117f, 1, "NOP", fall)
	d[0x1180] = ins(0x1180, 1, "NOP", fall)
	wantFuncs(t, run(t, p, d), 0x1000, 0x1100)
	// the target is a lone terminator (it might be fallen into later)
	d = base().add(ins(0x1005, 5, "JMP", jmp, 0x1180))
	d[0x1180] = ins(0x1180, 1, "RET", ret)
	wantFuncs(t, run(t, p, d), 0x1000, 0x1100)
	// a jump with a recovered table (several targets) is not a single flow
	d = base().add(ins(0x1005, 5, "JMP", jmp, 0x1180, 0x1181))
	wantFuncs(t, run(t, p, d), 0x1000, 0x1100)
	// and the positive case with the same layout: the unconditional jump out creates it
	d = base().add(ins(0x1005, 5, "JMP", jmp, 0x1180))
	wantFuncs(t, run(t, p, d), 0x1000, 0x1100, 0x1180)
}

// 4. Operand references and data pointers no longer create functions.
func TestDataPointersDoNotCreateFunctions(t *testing.T) {
	lea := ins(0x1000, 7, "LEA", fall)
	lea.DataRefs = []DataRef{{0x1100, AccessAddress}} // address-taken code
	d := fake{}.add(lea, ins(0x1007, 1, "RET", ret), ins(0x1100, 1, "NOP", fall), ins(0x1101, 1, "RET", ret),
		ins(0x1200, 1, "NOP", fall), ins(0x1201, 1, "RET", ret))
	p := newProg(0x1000, 0x300, seeds(0x1000), func(p *loader.Program) {
		p.Pointers[0x4000] = 0x1200 // a relocated code pointer
	})
	wantFuncs(t, run(t, p, d), 0x1000)
}

// 7. Function entries without a decoded instruction are dropped, counted and logged.
func TestDroppedEntriesAreCounted(t *testing.T) {
	d := fake{}.add(ins(0x1000, 1, "RET", ret))
	p := newProg(0x1000, 0x100, seeds(0x1000, 0x1040, 0x1050))
	var logged []string
	a := run(t, p, d, func(o *Options) {
		o.Logf = func(f string, args ...any) { logged = append(logged, fmt.Sprintf(f, args...)) }
	})
	wantFuncs(t, a, 0x1000)
	if len(a.DroppedEntries) != 2 || a.DroppedEntries[0] != 0x1040 || a.DroppedEntries[1] != 0x1050 {
		t.Errorf("dropped %#x", a.DroppedEntries)
	}
	if !slices.Contains(logged, "dropped 2 function entries without a decoded instruction: [0x1040 0x1050]") ||
		!slices.Equal(logged, a.Diagnostics) {
		t.Errorf("diagnostics %q logged %q", a.Diagnostics, logged)
	}
}

// The decoder's missing facts are recorded in the diagnostics, once each.
func TestGapsAreRecorded(t *testing.T) {
	a := run(t, newProg(0x1000, 0x100, seeds(0x1000)), fake{}.add(ins(0x1000, 1, "RET", ret)))
	want := []string{"indirect_via", "addends or data references", "data references", "register state"}
	for _, w := range want {
		found := false
		for _, d := range a.Diagnostics {
			found = found || (len(d) > 4 && d[:4] == "gap:" && strings.Contains(d, w))
		}
		if !found {
			t.Errorf("no gap note for %q in %q", w, a.Diagnostics)
		}
	}
	// a decoder that has the facts has no such notes
	slot := uint64(0x3000)
	jmpd := ins(0x1000, 6, "JMP", jmp).noFall()
	jmpd.IndirectVia, jmpd.DataRefs, jmpd.Addends = &slot, []DataRef{{0x3000, AccessRead}}, []uint64{1}
	sd := stateFake{fake: fake{}.add(jmpd), step: nil}
	a = run(t, newProg(0x1000, 0x100, seeds(0x1000), block(".got", 0x3000, 8, false)), sd)
	if len(a.Diagnostics) != 0 {
		t.Errorf("diagnostics %q", a.Diagnostics)
	}
}
