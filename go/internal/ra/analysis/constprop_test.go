package analysis

import (
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

var rdi = sleigh.Varnode{Space: "register", Offset: 56, Size: 8}

func propLang() *Language {
	return &Language{Language: sleigh.Language{ID: "x86:LE:64:default", AddressSize: 8, IntArgs: []sleigh.Varnode{rdi}}}
}

func setReg(reg string, v uint64) func(*RegState) []DataRef {
	return func(s *RegState) []DataRef {
		*s = append(*s, RegValue{reg, v})
		return nil
	}
}

// 9. Block-local constant propagation: constants flow along a basic block, and
// the constant pointer passed in a parameter register at a call is referenced
// from the instruction that set it.
func TestConstantPropagation(t *testing.T) {
	rdiKey := regKey(rdi)
	useReg := func(s *RegState) []DataRef { // a load through the register: a read at the use site
		for _, rv := range *s {
			if rv.Reg == rdiKey {
				return []DataRef{{rv.Value, AccessRead}}
			}
		}
		return nil
	}
	sd := stateFake{
		fake: fake{}.add(
			ins(0x1000, 1, "NOP", fall),
			ins(0x1001, 5, "MOV", fall), // RDI = 0x4000
			ins(0x1006, 1, "MOV", fall), // reads through RDI
			ins(0x1007, 5, "CALL", call, 0x1100),
			ins(0x100c, 1, "MOV", fall), // after the call the state is gone
			ins(0x100d, 1, "RET", ret),
			ins(0x1100, 1, "MOV", fall), ins(0x1101, 1, "RET", ret)),
		step: map[uint64]func(*RegState) []DataRef{
			0x1001: setReg(rdiKey, 0x4000), 0x1006: useReg, 0x100c: useReg, 0x1100: useReg,
		},
	}
	p := newProg(0x1000, 0x200, seeds(0x1000), block(".data", 0x4000, 0x10, false))
	a := Analyze(p, propLang(), sd, Options{})
	if refs := a.Insns[0x1006].D.DataRefs; len(refs) != 1 || refs[0] != (DataRef{0x4000, AccessRead}) {
		t.Errorf("use site: %v", refs)
	}
	// the writer is referenced because the pointer is passed to the call
	if refs := a.Insns[0x1001].D.DataRefs; len(refs) != 1 || refs[0] != (DataRef{0x4000, AccessAddress}) {
		t.Errorf("writer: %v", refs)
	}
	if refs := a.Insns[0x100c].D.DataRefs; len(refs) != 0 {
		t.Errorf("state survived the call: %v", refs)
	}
	// a block start (the function entry) begins with an empty state
	if refs := a.Insns[0x1100].D.DataRefs; len(refs) != 0 {
		t.Errorf("state crossed into the callee: %v", refs)
	}
	for _, m := range a.Diagnostics {
		if m == "gap: the decoder has no register state: block-local constant propagation did not run" {
			t.Error("a state decoder was reported as having no register state")
		}
	}
}

func TestConstantPropagationNeedsAStateDecoder(t *testing.T) {
	d := fake{}.add(ins(0x1000, 1, "MOV", fall), ins(0x1001, 1, "RET", ret))
	a := Analyze(newProg(0x1000, 0x100, seeds(0x1000)), propLang(), d, Options{})
	if len(a.Insns[0x1000].D.DataRefs) != 0 {
		t.Error("references without a state decoder")
	}
}

// A constant is not carried into an instruction that is a jump target.
func TestConstantPropagationResetsAtBlockStarts(t *testing.T) {
	rdiKey := regKey(rdi)
	useReg := func(s *RegState) []DataRef {
		for _, rv := range *s {
			if rv.Reg == rdiKey {
				return []DataRef{{rv.Value, AccessRead}}
			}
		}
		return nil
	}
	sd := stateFake{
		fake: fake{}.add(
			ins(0x1000, 1, "MOV", fall), ins(0x1001, 2, "JZ", cjmp, 0x1004),
			ins(0x1003, 1, "NOP", fall), ins(0x1004, 1, "MOV", fall), ins(0x1005, 1, "RET", ret)),
		step: map[uint64]func(*RegState) []DataRef{0x1000: setReg(rdiKey, 0x4000), 0x1003: useReg, 0x1004: useReg},
	}
	p := newProg(0x1000, 0x100, seeds(0x1000), block(".data", 0x4000, 0x10, false))
	a := Analyze(p, propLang(), sd, Options{})
	// 0x1003 follows the conditional jump by fallthrough in the same block region
	if refs := a.Insns[0x1003].D.DataRefs; len(refs) != 1 {
		t.Errorf("fallthrough keeps the state: %v", refs)
	}
	if refs := a.Insns[0x1004].D.DataRefs; len(refs) != 0 {
		t.Errorf("jump target must start with no state: %v", refs)
	}
}

// The bridge carries register state as regKey strings; the round trip keeps
// the varnode and the value, and a key that is not one is refused.
func TestRegisterKeyRoundTrip(t *testing.T) {
	want := sleigh.Register{Varnode: rdi, Value: 0x4000}
	got, ok := registerOf(RegValue{regKey(rdi), 0x4000})
	if !ok || got != want {
		t.Errorf("registerOf: %+v %v, want %+v", got, ok, want)
	}
	if _, ok := registerOf(RegValue{"register:x:8", 1}); ok {
		t.Error("a key with a bad offset is accepted")
	}
}
