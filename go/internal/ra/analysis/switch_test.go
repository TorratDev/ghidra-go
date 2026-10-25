package analysis

import (
	"encoding/binary"
	"slices"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/loader"
	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

// switchMem has code at 0x1000 and 0x5000 and a data block at 0x3000 holding
// the given 8-byte entries, then at 0x3800 a block of signed 32-bit offsets.
func switchMem(entries []uint64, rel []int32) *core.MemoryMap {
	m := &core.MemoryMap{}
	m.Add(core.MemoryBlock{Name: ".text", Start: 0x1000, Size: 0x100, Data: make([]byte, 0x100), Perms: core.Perms{Read: true, Execute: true}})
	m.Add(core.MemoryBlock{Name: ".text2", Start: 0x5000, Size: 0x100, Data: make([]byte, 0x100), Perms: core.Perms{Read: true, Execute: true}})
	data := make([]byte, 8*len(entries))
	for i, e := range entries {
		binary.LittleEndian.PutUint64(data[8*i:], e)
	}
	m.Add(core.MemoryBlock{Name: ".rodata", Start: 0x3000, Size: uint64(len(data)), Data: data, Perms: core.Perms{Read: true}})
	rdata := make([]byte, 4*len(rel))
	for i, e := range rel {
		binary.LittleEndian.PutUint32(rdata[4*i:], uint32(e))
	}
	if len(rdata) > 0 {
		m.Add(core.MemoryBlock{Name: ".rodata2", Start: 0x3800, Size: uint64(len(rdata)), Data: rdata, Perms: core.Perms{Read: true}})
	}
	return m
}

type code struct {
	insns  map[uint64]*Insn
	sorted []uint64
}

func mk(ds ...Decoded) code {
	c := code{insns: map[uint64]*Insn{}}
	for _, d := range ds {
		c.insns[d.Addr] = &Insn{D: d}
		c.sorted = append(c.sorted, d.Addr)
	}
	slices.Sort(c.sorted)
	return c
}

func absJump(addr, base uint64) Decoded {
	d := ins(addr, 7, "JMP", jmp).indirectVia(0)
	d.IndirectVia = nil
	d.Addends = []uint64{base}
	return d.noFall()
}

func cmpJcc(cmpAddr uint64, imm, jcc string) []Decoded {
	c := ins(cmpAddr, 3, "CMP", fall)
	c.Text = "CMP EAX," + imm
	j := ins(cmpAddr+3, 2, jcc, cjmp, 0x1ff0)
	return []Decoded{c, j}
}

func TestSwitchBoundFromFollowingJcc(t *testing.T) {
	mem := switchMem([]uint64{0x1000, 0x1010, 0x1020, 0x1030, 0x1040, 0x1050}, nil)
	for _, c := range []struct {
		jcc  string
		want int // entries
	}{{"JA", 4}, {"JNBE", 4}, {"JAE", 3}, {"JNB", 3}, {"JNC", 3}} {
		ds := append(cmpJcc(0x1000, "0x3", c.jcc), absJump(0x1006, 0x3000))
		cd := mk(ds...)
		tb := recoverSwitch(0x1006, cd.insns, cd.sorted, mem, false, 8)
		if tb == nil || len(tb.targets) != c.want {
			t.Errorf("%s: %+v", c.jcc, tb)
		}
	}
	// a jump that is not ja/jae gives no bound: entries are read to the first non-target
	for _, jcc := range []string{"JB", "JBE", "JZ"} {
		ds := append(cmpJcc(0x1000, "0x3", jcc), absJump(0x1006, 0x3000))
		cd := mk(ds...)
		if tb := recoverSwitch(0x1006, cd.insns, cd.sorted, mem, false, 8); tb == nil || len(tb.targets) != 6 {
			t.Errorf("%s: %+v", jcc, tb)
		}
	}
	// with a bound, a table shorter than the bound is rejected
	short := switchMem([]uint64{0x1000, 0x1010, 0x77777}, nil)
	ds := append(cmpJcc(0x1000, "0x3", "JA"), absJump(0x1006, 0x3000))
	cd := mk(ds...)
	if tb := recoverSwitch(0x1006, cd.insns, cd.sorted, short, false, 8); tb != nil {
		t.Errorf("short table accepted: %+v", tb)
	}
	// decimal immediates work too
	ds = append(cmpJcc(0x1000, "2", "JA"), absJump(0x1006, 0x3000))
	cd = mk(ds...)
	if tb := recoverSwitch(0x1006, cd.insns, cd.sorted, mem, false, 8); tb == nil || len(tb.targets) != 3 {
		t.Errorf("decimal: %+v", tb)
	}
}

func TestSwitchStopsAtFirstNonTargetAndAcceptsAnyExecutableBlock(t *testing.T) {
	// entries: code, code in the second executable block, a non-code value, more code
	mem := switchMem([]uint64{0x1000, 0x5010, 0x9999, 0x1020}, nil)
	cd := mk(absJump(0x1006, 0x3000))
	tb := recoverSwitch(0x1006, cd.insns, cd.sorted, mem, false, 8)
	if tb == nil || !slices.Equal(tb.targets, []uint64{0x1000, 0x5010}) || tb.start != 0x3000 || tb.end != 0x3010 {
		t.Fatalf("%+v", tb)
	}
	if len(tb.refs) != 1 || tb.refs[0] != (tableRef{0x1006, 0x3000, AccessAddress}) {
		t.Errorf("refs %+v", tb.refs)
	}
	// a single entry is not a table
	one := switchMem([]uint64{0x1000, 0x9999}, nil)
	if recoverSwitch(0x1006, cd.insns, cd.sorted, one, false, 8) != nil {
		t.Error("one entry accepted")
	}
}

// A candidate base whose table does not read goes on to the next candidate.
func TestSwitchContinuesToNextCandidate(t *testing.T) {
	// 0x3000 holds garbage that is not an offset to code; 0x3800 holds offsets
	// from its own address to code at 0x1010, 0x1020, 0x1030
	mem := switchMem([]uint64{0x7777777777777777, 0x7777777777777777}, []int32{0x1010 - 0x3800, 0x1020 - 0x3800, 0x1030 - 0x3800})
	good := ins(0x1000, 7, "LEA", fall)
	good.DataRefs = []DataRef{{0x3800, AccessAddress}}
	bad := ins(0x1007, 7, "LEA", fall) // nearer to the jump, so it is tried first
	bad.DataRefs = []DataRef{{0x3000, AccessAddress}}
	load := ins(0x100e, 4, "MOVSXD", fall)
	load.IndexedLoad = true
	jmpReg := ins(0x1012, 2, "JMP", jmp).noFall()
	jmpReg.Indirect = true
	cd := mk(good, bad, load, jmpReg)
	tb := recoverSwitch(0x1012, cd.insns, cd.sorted, mem, false, 8)
	if tb == nil || tb.start != 0x3800 || !slices.Equal(tb.targets, []uint64{0x1010, 0x1020, 0x1030}) {
		t.Fatalf("%+v", tb)
	}
	// the indexed load references the table too
	if len(tb.refs) != 1 || tb.refs[0].from != 0x100e || tb.refs[0].to != 0x3800 {
		t.Errorf("refs %+v", tb.refs)
	}
	// a LEA whose table is the only candidate and does not read recovers nothing
	cd = mk(bad, load, jmpReg)
	if recoverSwitch(0x1012, cd.insns, cd.sorted, mem, false, 8) != nil {
		t.Error("garbage table accepted")
	}
}

// Through the analyzer: the jump's targets are disassembled, the table's
// references are added, and the jump is reported as a switch jump.
func TestResolveSwitchesInAnalysis(t *testing.T) {
	prog := newProg(0x1000, 0x100, seeds(0x1000), func(p *loader.Program) {
		data := make([]byte, 24)
		for i, e := range []uint64{0x1020, 0x1030, 0x1040} {
			binary.LittleEndian.PutUint64(data[8*i:], e)
		}
		p.Memory.Add(core.MemoryBlock{Name: ".rodata", Start: 0x3000, Size: 24, Data: data, Perms: core.Perms{Read: true}})
	})
	cmp := ins(0x1000, 3, "CMP", fall)
	cmp.Text = "CMP EAX,0x2"
	d := fake{}.add(cmp, ins(0x1003, 2, "JA", cjmp, 0x1050), absJump(0x1005, 0x3000),
		ins(0x1020, 1, "RET", ret), ins(0x1030, 1, "RET", ret), ins(0x1040, 1, "RET", ret), ins(0x1050, 1, "RET", ret))
	a := run(t, prog, d)
	if !a.SwitchJumps[0x1005] || !slices.Equal(a.Insns[0x1005].D.Targets, []uint64{0x1020, 0x1030, 0x1040}) {
		t.Fatalf("switch jumps %v targets %v", a.SwitchJumps, a.Insns[0x1005].D.Targets)
	}
	for _, t0 := range []uint64{0x1020, 0x1030, 0x1040} {
		if a.Insns[t0] == nil {
			t.Errorf("case %#x not disassembled", t0)
		}
	}
	if !hasRef(a.Insns[0x1005].D.DataRefs, 0x3000) {
		t.Errorf("table reference missing: %v", a.Insns[0x1005].D.DataRefs)
	}
}

func TestCallTable(t *testing.T) {
	mem := switchMem([]uint64{0x1000, 0x5010, 0x9999}, nil)
	call := ins(0x1100, 7, "CALL", sleigh.FlowCall)
	call.Indirect, call.Addends = true, []uint64{0x3000}
	tb := recoverCallTable(&Insn{D: call}, mem, false, 8, func(uint64) bool { return true })
	if tb == nil || !slices.Equal(tb.targets, []uint64{0x1000, 0x5010}) || len(tb.refs) != 2 || tb.refs[0].access != AccessRead {
		t.Fatalf("%+v", tb)
	}
	// code that does not decode ends the table; a base in code is not a table
	if recoverCallTable(&Insn{D: call}, mem, false, 8, func(a uint64) bool { return a == 0x1000 }) != nil {
		t.Error("one entry accepted")
	}
	call.Addends = []uint64{0x1000}
	if recoverCallTable(&Insn{D: call}, mem, false, 8, func(uint64) bool { return true }) != nil {
		t.Error("executable base accepted")
	}
}
