package analysis

import (
	"strconv"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

// Jump table recovery for indirect jumps (a stand-in for Ghidra's
// DecompilerSwitchAnalyzer, which uses the decompiler). Two compiler idioms:
//
//   - absolute: JMP [T + idx*S] (non-PIC x86, i386, x86-64 -fno-pic)
//   - relative: LEA r, [T]; MOVSXD x, [r + idx*4]; ADD x, r; JMP x
//     (x86-64 PIC, PE x64)
//
// Both need the table base from the instruction facts (Addends, DataRefs).

type table struct {
	start, end uint64
	targets    []uint64
	// refs are the references Ghidra creates for the table: (from, to, access).
	refs []tableRef
}

type tableRef struct {
	from, to uint64
	access   Access
}

const (
	maxEntries = 1024
	lookback   = 12
)

// recoverSwitch recovers the table of the indirect jump at jump. insns is the
// decoded code; sorted its addresses in order.
func recoverSwitch(jump uint64, insns map[uint64]*Insn, sorted []uint64, mem *core.MemoryMap, be bool, ptr uint32) *table {
	ji := insns[jump]
	if ji == nil {
		return nil
	}
	prev := precedingInsns(jump, insns, sorted, lookback)
	bound, hasBound := findBound(prev)

	// Absolute table: the jump itself adds a constant base to idx*S.
	for _, base := range ji.D.Addends {
		if !mem.IsMapped(base) {
			continue
		}
		for _, size := range []uint64{uint64(ptr), 4} {
			if t := readTable(mem, base, size, bound, hasBound, be, func(v uint64) uint64 { return v }); t != nil {
				t.refs = append(t.refs, tableRef{jump, base, AccessAddress})
				return t
			}
		}
	}
	// Relative table: a preceding LEA of a mapped address; the entries are
	// signed 32-bit offsets from the table base. A candidate whose table does
	// not read goes on to the next candidate.
	for _, i := range prev {
		if i.D.Flow != sleigh.FlowFallthrough {
			break
		}
		for _, r := range i.D.DataRefs {
			if r.Access != AccessAddress || !mem.IsMapped(r.Addr) {
				continue
			}
			base := r.Addr
			t := readTable(mem, base, 4, bound, hasBound, be, func(v uint64) uint64 {
				return base + uint64(int64(int32(uint32(v))))
			})
			if t == nil {
				continue
			}
			// Ghidra also references the table from the indexed load.
			for _, p := range prev {
				if p.D.IndexedLoad {
					t.refs = append(t.refs, tableRef{p.D.Addr, base, AccessAddress})
					break
				}
			}
			return t
		}
	}
	return nil
}

// precedingInsns are up to n instructions before addr, nearest first.
func precedingInsns(addr uint64, insns map[uint64]*Insn, sorted []uint64, n int) []*Insn {
	lo, hi := 0, len(sorted)
	for lo < hi {
		m := (lo + hi) / 2
		if sorted[m] < addr {
			lo = m + 1
		} else {
			hi = m
		}
	}
	var out []*Insn
	for k := lo - 1; k >= 0 && len(out) < n; k-- {
		out = append(out, insns[sorted[k]])
	}
	return out
}

// recoverCallTable recovers the function-pointer table behind an indirect call
// CALL [T + idx*S]: entries are read while they point at decodable code in an
// executable block (Ghidra resolves these through computed-call references).
func recoverCallTable(call *Insn, mem *core.MemoryMap, be bool, ptr uint32, isCode func(uint64) bool) *table {
	for _, base := range call.D.Addends {
		if !mem.IsMapped(base) || mem.IsExecutable(base) {
			continue
		}
		var targets []uint64
		var refs []tableRef
		n := uint64(0)
		for n < 64 {
			slot := base + n*uint64(ptr)
			t, ok := mem.ReadUint(slot, int(ptr), be)
			if !ok || !mem.IsExecutable(t) || !isCode(t) {
				break
			}
			if !containsU(targets, t) {
				targets = append(targets, t)
			}
			refs = append(refs, tableRef{call.D.Addr, slot, AccessRead})
			n++
		}
		if n >= 2 {
			return &table{start: base, end: base + n*uint64(ptr), targets: targets, refs: refs}
		}
	}
	return nil
}

func containsU(s []uint64, v uint64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// findBound derives the entry count from a CMP reg, imm followed by a
// conditional jump to the default case: ja / jnbe means indices 0..imm, so
// imm+1 entries; jae / jnb / jnc means 0..imm-1, so imm entries. Any other
// jump, or none, gives no bound. prev is nearest first.
func findBound(prev []*Insn) (uint64, bool) {
	var jcc string
	for _, i := range prev {
		m := strings.ToUpper(i.D.Mnemonic)
		if i.D.Flow == sleigh.FlowCondJump {
			jcc = m // the last one seen going back is the one right after the CMP
			continue
		}
		text := strings.ToUpper(i.D.Text)
		rest, ok := strings.CutPrefix(text, "CMP ")
		if !ok {
			continue
		}
		parts := strings.Split(rest, ",")
		imm := strings.TrimSpace(parts[len(parts)-1])
		var v uint64
		var err error
		if h, ok := strings.CutPrefix(imm, "0X"); ok {
			v, err = strconv.ParseUint(h, 16, 64)
		} else {
			v, err = strconv.ParseUint(imm, 10, 64)
		}
		if err != nil {
			return 0, false
		}
		switch jcc {
		case "JA", "JNBE":
			return v + 1, true
		case "JAE", "JNB", "JNC":
			return v, true
		}
		return 0, false
	}
	return 0, false
}

// readTable reads entries of the given size from base, decoding each with
// decode. It stops at the first entry that is not an executable address (in any
// executable block) and, when a bound is known, at the bound. A table needs at
// least two entries and, with a bound, all of them.
func readTable(mem *core.MemoryMap, base, size, bound uint64, hasBound, be bool, decode func(uint64) uint64) *table {
	limit := uint64(maxEntries)
	if hasBound && bound < limit {
		limit = bound
	}
	var targets []uint64
	n := uint64(0)
	for n < limit {
		raw, ok := mem.ReadUint(base+n*size, int(size), be)
		if !ok {
			break
		}
		t := decode(raw)
		if !mem.IsExecutable(t) {
			break
		}
		if !containsU(targets, t) {
			targets = append(targets, t)
		}
		n++
	}
	if n < 2 || (hasBound && n < bound) {
		return nil
	}
	return &table{start: base, end: base + n*size, targets: targets}
}
