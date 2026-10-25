package analysis

import (
	"slices"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/loader"
	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

// fake is a Decoder over a table of hand-written instructions; the bytes of
// the program are not looked at.
type fake map[uint64]Decoded

func (f fake) Decode(addr uint64, _ []byte) (*Decoded, bool) {
	d, ok := f[addr]
	if !ok {
		return nil, false
	}
	return &d, true
}

// stateFake is a StateDecoder: step runs the instruction at addr over the
// incoming register state.
type stateFake struct {
	fake
	step map[uint64]func(*RegState) []DataRef
}

func (s stateFake) DecodeIn(addr uint64, _ []byte, state *RegState) (*Decoded, bool) {
	d, ok := s.fake[addr]
	if !ok {
		return nil, false
	}
	if st := s.step[addr]; st != nil {
		d.DataRefs = st(state)
	}
	return &d, true
}

const (
	fall = sleigh.FlowFallthrough
	jmp  = sleigh.FlowJump
	cjmp = sleigh.FlowCondJump
	call = sleigh.FlowCall
	ret  = sleigh.FlowReturn
)

// ins builds a decoded instruction that falls through unless it is a jump or
// a return.
func ins(addr uint64, n uint32, mnemonic string, flow sleigh.FlowKind, targets ...uint64) Decoded {
	d := Decoded{Addr: addr, Len: n, Mnemonic: mnemonic, Text: mnemonic, Flow: flow, Targets: targets,
		HasFallthrough: flow != jmp && flow != ret && flow != sleigh.FlowTerminator}
	return d
}

func (d Decoded) indirectVia(slot uint64) Decoded {
	d.Indirect, d.IndirectVia = true, &slot
	return d
}

func (d Decoded) noFall() Decoded { d.HasFallthrough = false; return d }

func (f fake) add(ds ...Decoded) fake {
	for _, d := range ds {
		f[d.Addr] = d
	}
	return f
}

type progOpt func(*loader.Program)

// newProg is an ELF program with an executable .text of the given size at
// base, zero filled, plus whatever opts add.
func newProg(base, size uint64, opts ...progOpt) *loader.Program {
	p := &loader.Program{
		Path: "test", Format: "ELF", Language: "x86:LE:64:default", PointerSize: 8,
		Seeds: map[uint64]loader.SeedKind{}, ImportSlots: map[uint64]string{},
		Pointers: map[uint64]uint64{}, MarkedPointers: map[uint64]uint64{},
		EntryPoints: map[uint64]bool{}, FallbackNames: map[uint64]string{},
	}
	p.Memory.Add(core.MemoryBlock{Name: ".text", Start: base, Size: size, Data: make([]byte, size),
		Perms: core.Perms{Read: true, Execute: true}})
	for _, o := range opts {
		o(p)
	}
	return p
}

func seeds(addrs ...uint64) progOpt {
	return func(p *loader.Program) {
		for _, a := range addrs {
			p.Seeds[a] = loader.SeedEntry
		}
	}
}

func block(name string, start, size uint64, exec bool) progOpt {
	return func(p *loader.Program) {
		p.Memory.Add(core.MemoryBlock{Name: name, Start: start, Size: size, Data: make([]byte, size),
			Perms: core.Perms{Read: true, Execute: exec}})
	}
}

func testLang() *Language {
	return &Language{Language: sleigh.Language{ID: "x86:LE:64:default", AddressSize: 8}}
}

func run(t *testing.T, p *loader.Program, d Decoder, opts ...func(*Options)) *Analysis {
	t.Helper()
	o := Options{CallTables: true}
	for _, f := range opts {
		f(&o)
	}
	return Analyze(p, testLang(), d, o)
}

func funcAddrs(a *Analysis) []uint64 { return sortedKeys(a.Functions) }

func wantFuncs(t *testing.T, a *Analysis, want ...uint64) {
	t.Helper()
	if got := funcAddrs(a); !slices.Equal(got, want) {
		t.Errorf("functions %#x, want %#x", got, want)
	}
}
