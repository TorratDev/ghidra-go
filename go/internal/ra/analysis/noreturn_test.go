package analysis

import (
	"slices"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/loader"
)

func TestNoReturnNames(t *testing.T) {
	n := noReturnNamesFor("ELF")
	for _, name := range []string{"exit", "_exit", "__assert_fail", "abort@GLIBC_2.2.5"} {
		if !n.contains(name) {
			t.Errorf("%s not in the list", name)
		}
	}
	if n.contains("printf") {
		t.Error("printf")
	}
	if !noReturnNamesFor("PE").contains("ExitProcess") && len(noReturnNamesFor("PE")) == 0 {
		t.Error("PE list empty")
	}
}

// A named no-return function cuts the flow after a call to it, which takes a
// second round; the result is stable.
func TestNoReturnCutsFlowAndConverges(t *testing.T) {
	d := fake{}.add(
		ins(0x1000, 5, "CALL", call, 0x1100), ins(0x1005, 1, "NOP", fall), ins(0x1006, 1, "RET", ret),
		ins(0x1100, 1, "RET", ret))
	p := newProg(0x1000, 0x200, seeds(0x1000), func(p *loader.Program) {
		p.Symbols = []loader.LoadedSymbol{{Addr: 0x1100, Name: "exit", IsFunction: true}}
		p.Seeds[0x1100] = loader.SeedSymbol
	})
	a := run(t, p, d)
	if !a.Functions[0x1100].NoReturn || a.Insns[0x1005] != nil || a.NoReturnRoundLimit {
		t.Errorf("no-return %v, after call %v, capped %v", a.Functions[0x1100].NoReturn, a.Insns[0x1005], a.NoReturnRoundLimit)
	}
	if a.Insns[0x1000].HasFT || !a.Insns[0x1000].D.HasFallthrough {
		t.Error("the call keeps its fallthrough fact but loses its flow")
	}
}

// 7. Reaching the round limit is logged and flagged.
func TestNoReturnRoundLimitIsLogged(t *testing.T) {
	d := fake{}.add(
		ins(0x1000, 5, "CALL", call, 0x1100), ins(0x1005, 1, "RET", ret), ins(0x1100, 1, "RET", ret))
	p := newProg(0x1000, 0x200, seeds(0x1000), func(p *loader.Program) {
		p.Symbols = []loader.LoadedSymbol{{Addr: 0x1100, Name: "exit", IsFunction: true}}
		p.Seeds[0x1100] = loader.SeedSymbol
	})
	old := maxRounds
	defer func() { maxRounds = old }()
	maxRounds = 1
	a := run(t, p, d)
	if !a.NoReturnRoundLimit {
		t.Fatal("limit not flagged")
	}
	found := false
	for _, m := range a.Diagnostics {
		found = found || m == "no-return analysis did not converge after 1 rounds; the last round's result is used"
	}
	if !found {
		t.Errorf("diagnostics %q", a.Diagnostics)
	}
	maxRounds = 8
	if a = run(t, p, d); a.NoReturnRoundLimit {
		t.Error("converges within 8 rounds")
	}
}

// 7. The evidence for a target is its own set of call sites. Three call sites
// that each call two targets are three pieces of evidence for each target; the
// Rust version counted a site for the first target only and found just one of
// the two.
func TestNoReturnEvidenceIsPerTarget(t *testing.T) {
	d := fake{}
	for _, site := range []uint64{0x1000, 0x1010, 0x1020} {
		d.add(ins(site, 5, "CALL", call, 0x2000, 0x2100), ins(site+5, 1, "INT3", fall), ins(site+6, 1, "RET", ret))
	}
	d.add(ins(0x2000, 1, "RET", ret), ins(0x2100, 1, "RET", ret))
	p := newProg(0x1000, 0x2000, seeds(0x1000, 0x1010, 0x1020))
	a := run(t, p, d)
	if !a.Functions[0x2000].NoReturn || !a.Functions[0x2100].NoReturn {
		t.Errorf("no-return: %v %v", a.Functions[0x2000].NoReturn, a.Functions[0x2100].NoReturn)
	}
	// two sites are not enough
	d2 := fake{}
	for _, site := range []uint64{0x1000, 0x1010} {
		d2.add(ins(site, 5, "CALL", call, 0x2000), ins(site+5, 1, "INT3", fall), ins(site+6, 1, "RET", ret))
	}
	d2.add(ins(0x2000, 1, "RET", ret))
	a = run(t, newProg(0x1000, 0x2000, seeds(0x1000, 0x1010)), d2)
	if a.Functions[0x2000].NoReturn {
		t.Error("two call sites made a no-return function")
	}
}

func TestOnlyCallsNoReturnMakesTheCalleeNoReturn(t *testing.T) {
	// 0x2000 is called once, from a suspicious site, and only ever calls abort
	d := fake{}.add(
		ins(0x1000, 5, "CALL", call, 0x2000), ins(0x1005, 1, "INT3", fall), ins(0x1006, 1, "RET", ret),
		ins(0x2000, 5, "CALL", call, 0x3000).noFall(), // every path of 0x2000 ends in a call to exit
		ins(0x3000, 1, "RET", ret))
	p := newProg(0x1000, 0x3000, seeds(0x1000), func(p *loader.Program) {
		p.Symbols = []loader.LoadedSymbol{{Addr: 0x3000, Name: "abort", IsFunction: true}}
		p.Seeds[0x3000] = loader.SeedSymbol
	})
	a := run(t, p, d)
	if !a.Functions[0x2000].NoReturn || !a.Functions[0x3000].NoReturn {
		t.Errorf("only-calls-noreturn: %v", funcAddrs(a))
	}
}

func TestSortedHelpers(t *testing.T) {
	if got := sortedKeys(map[uint64]bool{3: true, 1: true, 2: true}); !slices.Equal(got, []uint64{1, 2, 3}) {
		t.Error(got)
	}
	if e, ok := functionContaining([]uint64{0x10, 0x20}, 0x25); !ok || e != 0x20 {
		t.Error("functionContaining")
	}
	if _, ok := functionContaining([]uint64{0x10, 0x20}, 0x5); ok {
		t.Error("before the first function")
	}
}
