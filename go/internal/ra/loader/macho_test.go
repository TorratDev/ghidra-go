package loader

import (
	"fmt"
	"slices"
	"testing"
)

// TestCorpusMachoMemory compares the Mach-O block list, in address order, with
// the Ghidra 12.1.4 export: names, ranges, permissions and initialized flags.
func TestCorpusMachoMemory(t *testing.T) {
	const name = "freestanding-x86_64-macho-clang-O2"
	want := loadExpected(t, name)
	p := loadCorpus(t, name)
	var exp, got []string
	for _, m := range want.Memory {
		var s, e uint64
		fmt.Sscanf(m.Start, "0x%x", &s)
		fmt.Sscanf(m.End, "0x%x", &e)
		exp = append(exp, fmt.Sprintf("%s %#x-%#x r%t w%t x%t i%t", m.Name, s, e, m.Read, m.Write, m.Execute, m.Initialized))
	}
	for _, b := range p.Memory.Blocks() {
		got = append(got, fmt.Sprintf("%s %#x-%#x r%t w%t x%t i%t", b.Name, b.Start, b.End(), b.Perms.Read, b.Perms.Write, b.Perms.Execute, b.IsInitialized()))
	}
	if !slices.Equal(got, exp) {
		t.Errorf("memory blocks differ from Ghidra:\nours:   %q\nghidra: %q", got, exp)
	}
}
