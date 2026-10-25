package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/loader"
	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

// maxRounds bounds the no-return fixpoint: flows after calls to no-return
// functions are cut, which can change everything downstream. A variable so a
// test can lower it.
var maxRounds = 8

// noReturnEvidence is the threshold of FindNoReturnFunctionsAnalyzer
// ("Function Non-return Threshold", default 3).
const noReturnEvidence = 3

type funcInfo struct {
	source FuncSource
	seed   loader.SeedKind
}

type analyzer struct {
	prog     *loader.Program
	lang     *Language
	dec      Decoder
	sdec     StateDecoder
	opts     Options
	names    noReturnNames
	patterns patternSet

	insns  map[uint64]*Insn
	sorted []uint64
	funcs  map[uint64]funcInfo
	// extra functions found by patterns; kept across fixpoint rounds.
	extra          map[uint64]funcInfo
	codeBoundaries map[uint64]bool
	noreturn       map[uint64]bool
	thunks         map[uint64]ThunkTarget
	// switches are the recovered jump tables: jump address -> table.
	switches map[uint64]*table

	cache  map[uint64]*Decoded // raw decoder results, nil for failures
	diags  []string
	capped bool
}

// Analyze runs the analysis over a loaded program.
func Analyze(prog *loader.Program, lang *Language, dec Decoder, opts Options) *Analysis {
	compiler := opts.Compiler
	if compiler == "" {
		compiler = defaultCompiler(prog.Format)
	}
	a := &analyzer{
		prog: prog, lang: lang, dec: dec, opts: opts,
		names:          noReturnNamesFor(prog.Format),
		extra:          map[uint64]funcInfo{},
		codeBoundaries: map[uint64]bool{},
		noreturn:       map[uint64]bool{},
		switches:       map[uint64]*table{},
		cache:          map[uint64]*Decoded{},
	}
	a.sdec, _ = dec.(StateDecoder)
	if opts.Patterns {
		a.patterns = loadPatternSet(lang.PatternsDir, lang.ID, compiler)
	}
	a.run()
	a.propagateConstants()
	a.noteGaps()
	res := &Analysis{
		Insns: a.insns, SortedInsns: a.sorted, SwitchJumps: map[uint64]bool{},
		NoReturnRoundLimit: a.capped,
	}
	res.Functions, res.DroppedEntries = a.buildFunctions()
	if len(res.DroppedEntries) > 0 {
		a.logf("dropped %d function entries without a decoded instruction: %#x", len(res.DroppedEntries), res.DroppedEntries)
	}
	for j := range a.switches {
		if i := a.insns[j]; i != nil && i.D.Flow == sleigh.FlowJump {
			res.SwitchJumps[j] = true
		}
	}
	res.Diagnostics = a.diags
	return res
}

// noteGaps records in the diagnostics which analyses did not run because the
// decoder does not supply the facts they need (the Java bridge contract has
// no indirect_via, data_refs, addends, indexed_load or register state).
func (a *analyzer) noteGaps() {
	var via, refs, addends bool
	for _, i := range a.insns {
		via = via || i.D.IndirectVia != nil
		refs = refs || len(i.D.DataRefs) > 0
		addends = addends || len(i.D.Addends) > 0
	}
	if !via {
		a.logf("gap: the decoder supplies no indirect_via: PLT stubs are not thunks to imports by slot name, and calls through import slots are not matched against the no-return names")
	}
	if !addends && !refs {
		a.logf("gap: the decoder supplies no addends or data references: jump tables and call tables are not recovered")
	}
	if !refs {
		a.logf("gap: the decoder supplies no data references: the report has no data xrefs")
	}
	if n, ok := a.dec.(Noter); ok {
		for _, note := range n.GapNotes() {
			a.logf("%s", note)
		}
	}
	if a.sdec == nil {
		a.logf("gap: the decoder has no register state: block-local constant propagation did not run")
	}
}

func defaultCompiler(format string) string {
	switch format {
	case "PE":
		return "windows"
	case "MachO":
		return "clang"
	}
	return "gcc"
}

func (a *analyzer) logf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	a.diags = append(a.diags, msg)
	if a.opts.Logf != nil {
		a.opts.Logf("%s", msg)
	}
}

func sortedKeys[V any](m map[uint64]V) []uint64 {
	keys := make([]uint64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	return keys
}

func (a *analyzer) run() {
	a.capped = true
	for round := 0; round < maxRounds; round++ {
		a.insns = map[uint64]*Insn{}
		a.sorted = a.sorted[:0]
		a.funcs = map[uint64]funcInfo{}
		a.thunks = map[uint64]ThunkTarget{}
		for addr, k := range a.prog.Seeds {
			a.funcs[addr] = funcInfo{SourceSeed, k}
		}
		for addr, f := range a.extra {
			if _, ok := a.funcs[addr]; !ok {
				a.funcs[addr] = f
			}
		}
		a.markupPlt()
		starts := sortedKeys(a.funcs)
		starts = append(starts, sortedKeys(a.codeBoundaries)...)
		for _, s := range starts {
			a.disassemble(s)
		}
		for k := 0; k < 16; k++ {
			changed := a.resolveSwitches()
			if a.opts.Patterns {
				changed = a.patternPass() || changed
			}
			changed = a.sharedReturn() || changed
			if !changed {
				break
			}
		}
		a.detectThunks()
		before := len(a.noreturn)
		a.computeNoreturn()
		if len(a.noreturn) == before {
			a.capped = false
			break
		}
	}
	if a.capped {
		a.logf("no-return analysis did not converge after %d rounds; the last round's result is used", maxRounds)
	}
}

// ---------------------------------------------------------------- instruction index

func (a *analyzer) addInsn(i *Insn) {
	k := sort.Search(len(a.sorted), func(k int) bool { return a.sorted[k] >= i.D.Addr })
	a.sorted = append(a.sorted, 0)
	copy(a.sorted[k+1:], a.sorted[k:])
	a.sorted[k] = i.D.Addr
	a.insns[i.D.Addr] = i
}

// insnContaining is the instruction containing addr (not necessarily starting at it).
func (a *analyzer) insnContaining(addr uint64) *Insn {
	k := sort.Search(len(a.sorted), func(k int) bool { return a.sorted[k] > addr })
	if k == 0 {
		return nil
	}
	if i := a.insns[a.sorted[k-1]]; addr < i.end() {
		return i
	}
	return nil
}

func (a *analyzer) conflicts(addr uint64, n uint32) bool {
	if a.insnContaining(addr) != nil {
		return true
	}
	k := sort.Search(len(a.sorted), func(k int) bool { return a.sorted[k] > addr })
	return k < len(a.sorted) && a.sorted[k] < addr+uint64(n)
}

// decode decodes the instruction at addr, or reports false. Results are
// cached: the bytes do not change between rounds.
func (a *analyzer) decode(addr uint64) (Decoded, bool) {
	if !a.prog.Memory.IsExecutable(addr) {
		return Decoded{}, false
	}
	raw, seen := a.cache[addr]
	if !seen {
		bytes := a.prog.Memory.BytesFrom(addr)
		if bytes != nil {
			if d, ok := a.dec.Decode(addr, bytes); ok {
				raw = d
			}
		}
		a.cache[addr] = raw
	}
	if raw == nil {
		return Decoded{}, false
	}
	d := *raw
	d.Targets = append([]uint64(nil), raw.Targets...)
	d.DataRefs = append([]DataRef(nil), raw.DataRefs...)
	// Lazy-binding PLT entries jump to PLT0; Ghidra's PLT markup treats that
	// jump as a call that falls through to the next entry. The flow stays Jump
	// (it still ends the basic block); only the reference becomes a call.
	if b := a.prog.Memory.BlockAt(addr); b != nil && a.prog.Format == "ELF" && b.Name == ".plt" &&
		d.Flow == sleigh.FlowJump && len(d.Targets) == 1 && d.Targets[0] == b.Start {
		d.HasFallthrough = true
	}
	return d, true
}

func (a *analyzer) importNameOfSlot(slot uint64) (string, bool) {
	n, ok := a.prog.ImportSlots[slot]
	return n, ok
}

func (a *analyzer) callIsNoReturn(d *Decoded) bool {
	if d.Flow != sleigh.FlowCall {
		return false
	}
	for _, t := range d.Targets {
		if a.noreturn[t] {
			return true
		}
	}
	if d.IndirectVia != nil {
		if n, ok := a.importNameOfSlot(*d.IndirectVia); ok {
			return a.names.contains(n)
		}
	}
	return false
}

// disassemble is recursive descent from start.
func (a *analyzer) disassemble(start uint64) {
	work := []uint64{start}
	for len(work) > 0 {
		addr := work[len(work)-1]
		work = work[:len(work)-1]
		if _, done := a.insns[addr]; done {
			continue
		}
		d, ok := a.decode(addr)
		if !ok || a.conflicts(addr, d.Len) {
			continue
		}
		if t, ok := a.switches[addr]; ok {
			d.Targets = append([]uint64(nil), t.targets...)
		}
		for _, t := range a.switches {
			for _, r := range t.refs {
				if r.from == addr && !hasRef(d.DataRefs, r.to) {
					d.DataRefs = append(d.DataRefs, DataRef{r.to, r.access})
				}
			}
		}
		i := &Insn{D: d}
		if d.HasFallthrough && !a.callIsNoReturn(&d) {
			i.FT, i.HasFT = d.end(), true
		}
		for _, t := range d.Targets {
			if (d.Flow == sleigh.FlowCall || d.Flow == sleigh.FlowCondCall) && a.prog.Memory.IsExecutable(t) {
				if _, ok := a.funcs[t]; !ok {
					a.funcs[t] = funcInfo{source: SourceCall}
				}
			}
			work = append(work, t)
		}
		if i.HasFT {
			work = append(work, i.FT)
		}
		a.addInsn(i)
	}
}

func hasRef(refs []DataRef, addr uint64) bool {
	for _, r := range refs {
		if r.Addr == addr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- PLT

func isLandingPad(m string) bool { return m == "ENDBR64" || m == "ENDBR32" || m == "BTI" }
func isMarker(m string) bool     { return isLandingPad(m) || m == "NOP" }

// markupPlt marks up PLT-like stub sections: stub starts are found by a linear
// sweep (each stub begins after the previous stub's final jump, skipping
// padding NOPs) and then disassembled by flow; stubs that jump through an
// import slot become thunks to the import (Ghidra ElfDefaultGotPltMarkup).
// When the slot has no import name but an IRELATIVE relocation put an address
// in it (static glibc), the stub is a thunk to that address.
func (a *analyzer) markupPlt() {
	if a.prog.Format != "ELF" {
		return
	}
	type blk struct {
		name       string
		start, end uint64
	}
	var blocks []blk
	for _, b := range a.prog.Memory.Blocks() {
		switch b.Name {
		case ".plt", ".plt.sec", ".plt.got", ".iplt":
			if b.Perms.Execute {
				blocks = append(blocks, blk{b.Name, b.Start, b.End()})
			}
		}
	}
	for _, b := range blocks {
		var stubs []uint64
		prevTerminated := true
		var prevAddr, prevLen uint64
		var prevMnemonic string
		havePrev := false
		for addr := b.start; addr < b.end; {
			d, ok := a.decode(addr)
			if !ok {
				addr++
				continue
			}
			isNop := strings.HasPrefix(d.Mnemonic, "NOP")
			if prevTerminated && !isNop {
				stubs = append(stubs, addr)
				prevTerminated = false
			}
			if !d.HasFallthrough {
				prevTerminated = true
			}
			if d.IndirectVia != nil && d.Flow == sleigh.FlowJump {
				// The thunk starts at the jump, or at the landing pad
				// (ENDBR64/BTI) immediately before it.
				entry := addr
				if havePrev && isLandingPad(prevMnemonic) && prevAddr+prevLen == addr {
					entry = prevAddr
				}
				slot := *d.IndirectVia
				if name, ok := a.importNameOfSlot(slot); ok {
					a.funcs[entry] = funcInfo{source: SourcePlt}
					a.thunks[entry] = ThunkTarget{External: name}
				} else if target, ok := a.prog.Pointers[slot]; ok && a.prog.Memory.IsExecutable(target) {
					a.funcs[entry] = funcInfo{source: SourcePlt}
					a.thunks[entry] = ThunkTarget{Internal: target}
					if _, ok := a.funcs[target]; !ok {
						a.funcs[target] = funcInfo{source: SourceJump}
					}
				}
			}
			prevAddr, prevLen, prevMnemonic, havePrev = addr, uint64(d.Len), d.Mnemonic, true
			addr += uint64(d.Len)
		}
		if b.name == ".plt" {
			if _, ok := a.funcs[b.start]; !ok {
				a.funcs[b.start] = funcInfo{source: SourcePlt}
			}
		}
		for _, s := range stubs {
			a.disassemble(s)
		}
	}
}

// ---------------------------------------------------------------- code validity and patterns

// validCode reports whether n instructions (or fewer ending in a terminator)
// decode by straight-line flow from addr without running into existing code.
func (a *analyzer) validCode(addr uint64, n uint32) bool {
	cur := addr
	for k := uint32(0); k < max(n, 1); k++ {
		if k > 0 {
			if _, ok := a.insns[cur]; ok {
				return true
			}
		}
		d, ok := a.decode(cur)
		if !ok || a.conflicts(cur, d.Len) {
			return false
		}
		if !d.HasFallthrough {
			return true
		}
		cur += uint64(d.Len)
	}
	return true
}

type found struct {
	addr  uint64
	act   patternAction
	valid uint32
}

// patternPass is the byte-pattern function start search over undefined
// executable bytes. Each rule's own validcode applies to its own match.
func (a *analyzer) patternPass() bool {
	if len(a.patterns.rules) == 0 {
		return false
	}
	var hits []found
	for _, b := range a.prog.Memory.Blocks() {
		if !b.Perms.Execute || !b.IsInitialized() {
			continue
		}
		for addr := b.Start; addr < b.Start+uint64(len(b.Data)); {
			if i := a.insnContaining(addr); i != nil {
				addr = i.end()
				continue
			}
			off := int(addr - b.Start)
			bytes := b.Data[off:]
			for ri := range a.patterns.rules {
				rule := &a.patterns.rules[ri]
				if rule.hasAlign && rule.alignBits > 0 && addr&(1<<rule.alignBits-1) != rule.alignMark {
					continue
				}
				if !anyMatch(rule.post, bytes) {
					continue
				}
				if len(rule.pre) > 0 {
					ok := false
					for _, p := range rule.pre {
						n := len(p)
						if off >= n && p.matches(b.Data[off-n:off]) {
							ok = true
							break
						}
					}
					if !ok {
						continue
					}
				}
				if rule.c.afterDefined && off > 0 && a.insnContaining(addr-1) == nil {
					continue
				}
				// Rules that only apply at existing functions never discover
				// one; after="data" needs defined data or no memory before the
				// match, and the analysis defines no data (known gap).
				if rule.c.existingFunction || (rule.c.afterData && off > 0) {
					continue
				}
				// The first action of the first matching rule wins.
				if len(rule.actions) > 0 {
					hits = append(hits, found{addr, rule.actions[0], rule.c.validCode})
					break
				}
			}
			addr++
		}
	}
	changed := false
	for _, h := range hits {
		if _, ok := a.insns[h.addr]; ok || a.insnContaining(h.addr) != nil {
			continue
		}
		if !a.validCode(h.addr, min(max(h.valid, 1), 5)) {
			continue
		}
		switch h.act {
		case actFuncStart, actPossibleFuncStart:
			a.funcs[h.addr] = funcInfo{source: SourcePattern}
			a.extra[h.addr] = funcInfo{source: SourcePattern}
		case actCodeBoundary:
			a.codeBoundaries[h.addr] = true
		}
		a.disassemble(h.addr)
		changed = true
	}
	return changed
}

func anyMatch(ps []bytePattern, b []byte) bool {
	for _, p := range ps {
		if p.matches(b) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- shared return (tail jumps)

// sharedReturn is SharedReturnAnalysisCmd with assumeContiguousFunctions: it
// assumes a function occupies the addresses between its entry and the next
// function's entry, so "outside the function" is decided from the function
// entries alone, not from the flow. An unconditional jump that leaves the function (forward past the next
// function's entry, or backward before the previous function's entry) makes a
// function of its target, unless the target is also a conditional jump target
// or could be reached by fallthrough.
func (a *analyzer) sharedReturn() bool {
	entries := sortedKeys(a.funcs)
	if len(entries) == 0 {
		return false
	}
	condTarget := map[uint64]bool{}
	for _, i := range a.insns {
		switch i.D.Flow {
		case sleigh.FlowCondJump, sleigh.FlowCondCall, sleigh.FlowCondReturn:
			for _, t := range i.D.Targets {
				condTarget[t] = true
			}
		}
	}
	changed := false
	for _, src := range a.sorted {
		i := a.insns[src]
		// A single unconditional jump flow; jumps with several flows (tables)
		// are ignored.
		if i.D.Flow != sleigh.FlowJump || i.D.HasFallthrough || len(i.D.Targets) != 1 {
			continue
		}
		dest := i.D.Targets[0]
		if dest == src || condTarget[dest] || !a.prog.Memory.IsMapped(dest) {
			continue
		}
		if _, ok := a.funcs[dest]; ok {
			continue
		}
		create := false
		if src < dest {
			// forward jump: needs a function after src, and dest at or past it
			k := sort.Search(len(entries), func(k int) bool { return entries[k] > src })
			create = k < len(entries) && dest >= entries[k]
		} else {
			// backward jump: needs a function before src, and dest before it
			k := sort.Search(len(entries), func(k int) bool { return entries[k] >= src })
			create = k > 0 && dest < entries[k-1]
		}
		if !create || a.couldFallThroughTo(dest) {
			continue
		}
		a.funcs[dest] = funcInfo{source: SourceJump}
		entries = sortedKeys(a.funcs)
		changed = true
	}
	return changed
}

// couldFallThroughTo is checkIfCouldHaveFallThruTo: no instruction at the
// location yet, an instruction that falls into it, or a lone terminator.
func (a *analyzer) couldFallThroughTo(loc uint64) bool {
	i := a.insns[loc]
	if i == nil {
		return true
	}
	if prev := a.insnEndingAt(loc); prev != nil && prev.D.HasFallthrough {
		return true
	}
	return i.D.Flow == sleigh.FlowReturn || i.D.Flow == sleigh.FlowTerminator
}

func (a *analyzer) insnEndingAt(loc uint64) *Insn {
	k := sort.Search(len(a.sorted), func(k int) bool { return a.sorted[k] >= loc })
	if k == 0 {
		return nil
	}
	if p := a.insns[a.sorted[k-1]]; p.end() == loc {
		return p
	}
	return nil
}

// ---------------------------------------------------------------- thunks

// detectThunks marks as a thunk a function whose first real instruction is an
// unconditional jump to another instruction of the program or through an
// import slot. The lone-call rule of the Rust version (a stub whose only
// instruction is a call to a no-return function) is gone: Ghidra's rule
// depends on analysis order, which static state cannot reproduce.
func (a *analyzer) detectThunks() {
	for _, e := range sortedKeys(a.funcs) {
		if _, ok := a.thunks[e]; ok {
			continue
		}
		cur := e
		for steps := 0; ; {
			i := a.insns[cur]
			if i == nil {
				break
			}
			steps++
			if steps > 3 {
				break
			}
			if isMarker(i.D.Mnemonic) && i.HasFT {
				cur = i.end()
				continue
			}
			if i.D.Flow == sleigh.FlowJump && !i.D.HasFallthrough {
				if len(i.D.Targets) == 1 {
					// CreateThunkFunctionCmd creates the thunked function
					// when it does not exist yet.
					if t := i.D.Targets[0]; t != e && a.insns[t] != nil {
						if _, ok := a.funcs[t]; !ok {
							a.funcs[t] = funcInfo{source: SourceJump}
						}
						a.thunks[e] = ThunkTarget{Internal: t}
					}
				} else if i.D.IndirectVia != nil {
					if name, ok := a.importNameOfSlot(*i.D.IndirectVia); ok {
						a.thunks[e] = ThunkTarget{External: name}
					}
				}
			}
			break
		}
	}
}

// ---------------------------------------------------------------- switches

func (a *analyzer) resolveSwitches() bool {
	var jumps, calls []uint64
	for _, addr := range a.sorted {
		i := a.insns[addr]
		if _, done := a.switches[addr]; done {
			continue
		}
		switch {
		case i.D.Flow == sleigh.FlowJump && i.D.Indirect && len(i.D.Targets) == 0 && i.D.IndirectVia == nil:
			jumps = append(jumps, addr)
		case a.opts.CallTables && i.D.Flow == sleigh.FlowCall && i.D.Indirect && len(i.D.Targets) == 0 && len(i.D.Addends) > 0:
			calls = append(calls, addr)
		}
	}
	changed := false
	for _, c := range calls {
		t := recoverCallTable(a.insns[c], &a.prog.Memory, a.prog.BigEndian, a.prog.PointerSize, func(t uint64) bool {
			_, ok := a.insns[t]
			return ok || (a.insnContaining(t) == nil && a.validCode(t, 2))
		})
		if t == nil {
			continue
		}
		for _, tgt := range t.targets {
			if _, ok := a.funcs[tgt]; !ok {
				a.funcs[tgt] = funcInfo{source: SourceCall}
			}
			if _, ok := a.extra[tgt]; !ok {
				a.extra[tgt] = funcInfo{source: SourceTable}
			}
		}
		a.applyTable(c, t)
		changed = true
	}
	for _, j := range jumps {
		t := recoverSwitch(j, a.insns, a.sorted, &a.prog.Memory, a.prog.BigEndian, a.prog.PointerSize)
		if t == nil {
			continue
		}
		a.applyTable(j, t)
		changed = true
	}
	return changed
}

func (a *analyzer) applyTable(at uint64, t *table) {
	if i := a.insns[at]; i != nil {
		i.D.Targets = append([]uint64(nil), t.targets...)
	}
	for _, r := range t.refs {
		if i := a.insns[r.from]; i != nil && !hasRef(i.D.DataRefs, r.to) {
			i.D.DataRefs = append(i.D.DataRefs, DataRef{r.to, r.access})
		}
	}
	a.switches[at] = t
	for _, tgt := range t.targets {
		a.disassemble(tgt)
	}
}

// ---------------------------------------------------------------- block-local constants

func regKey(v sleigh.Varnode) string { return fmt.Sprintf("%s:%d:%d", v.Space, v.Offset, v.Size) }

// propagateConstants is a reduced ConstantPropagationAnalyzer: it re-decodes
// every instruction with the register constants flowing in from its basic
// block predecessor, so references through registers (ADRP+LDR, LEA+MOV [reg])
// land on the instruction that uses them. State is reset at block starts and
// after calls. It needs a StateDecoder (p-code constants); without one nothing
// happens, which is the known gap of the Java bridge contract.
func (a *analyzer) propagateConstants() {
	if a.sdec == nil {
		return
	}
	starts := map[uint64]bool{}
	for addr := range a.funcs {
		starts[addr] = true
	}
	for _, i := range a.insns {
		for _, t := range i.D.Targets {
			starts[t] = true
		}
	}
	args := map[string]bool{}
	for _, v := range a.lang.IntArgs {
		args[regKey(v)] = true
	}
	var state RegState
	writer := map[string]uint64{} // register -> instruction that last wrote its constant
	var prevFT uint64
	havePrevFT := false
	type paramRef struct{ writer, val uint64 }
	var params []paramRef
	for _, addr := range a.sorted {
		if starts[addr] || !havePrevFT || prevFT != addr {
			state.clear()
			clear(writer)
		}
		bytes := a.prog.Memory.BytesFrom(addr)
		if bytes == nil {
			continue
		}
		before := append(RegState(nil), state...)
		nd, ok := a.sdec.DecodeIn(addr, bytes, &state)
		if !ok {
			state.clear()
			clear(writer)
			continue
		}
		for _, rv := range state {
			if !containsReg(before, rv) {
				writer[rv.Reg] = addr
			}
		}
		for reg := range writer {
			if !hasReg(state, reg) {
				delete(writer, reg)
			}
		}
		i := a.insns[addr]
		refs := append([]DataRef(nil), nd.DataRefs...)
		for _, t := range a.switches {
			for _, r := range t.refs {
				if r.from == addr && !hasRef(refs, r.to) {
					refs = append(refs, DataRef{r.to, r.access})
				}
			}
		}
		i.D.DataRefs = refs
		if i.D.Flow == sleigh.FlowCall || i.D.Flow == sleigh.FlowCondCall {
			// Constant pointers passed in parameter registers are referenced
			// from the instruction that set them.
			for _, rv := range state {
				if w, ok := writer[rv.Reg]; ok && args[rv.Reg] && a.prog.Memory.IsMapped(rv.Value) {
					params = append(params, paramRef{w, rv.Value})
				}
			}
			state.clear()
			clear(writer)
		}
		prevFT, havePrevFT = i.FT, i.HasFT
	}
	for _, p := range params {
		if i := a.insns[p.writer]; i != nil && !hasRef(i.D.DataRefs, p.val) {
			i.D.DataRefs = append(i.D.DataRefs, DataRef{p.val, AccessAddress})
		}
	}
}

func containsReg(s RegState, v RegValue) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func hasReg(s RegState, reg string) bool {
	for _, x := range s {
		if x.Reg == reg {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- functions

func (a *analyzer) functionName(entry uint64) (string, bool) {
	syms := a.prog.Symbols
	k := sort.Search(len(syms), func(k int) bool { return syms[k].Addr >= entry })
	best, haveBest := "", false
	for ; k < len(syms) && syms[k].Addr == entry; k++ {
		if syms[k].IsFunction {
			return syms[k].Name, true
		}
		if !haveBest {
			best, haveBest = syms[k].Name, true
		}
	}
	return best, haveBest
}

// bodyOf is the set of instructions reachable from entry without crossing
// another function's entry or a call.
func (a *analyzer) bodyOf(entry uint64) map[uint64]bool {
	seen := map[uint64]bool{}
	work := []uint64{entry}
	for len(work) > 0 {
		addr := work[len(work)-1]
		work = work[:len(work)-1]
		if _, isFunc := a.funcs[addr]; (addr != entry && isFunc) || seen[addr] {
			continue
		}
		seen[addr] = true
		i := a.insns[addr]
		if i == nil {
			delete(seen, addr)
			continue
		}
		if i.HasFT {
			work = append(work, i.FT)
		}
		if i.D.Flow != sleigh.FlowCall && i.D.Flow != sleigh.FlowCondCall {
			work = append(work, i.D.Targets...)
		}
	}
	return seen
}

// ranges merges sorted (start, end) pairs that touch or overlap.
func ranges(pairs [][2]uint64) [][2]uint64 {
	var out [][2]uint64
	for _, p := range pairs {
		if n := len(out); n > 0 && p[0] <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], p[1])
		} else {
			out = append(out, p)
		}
	}
	return out
}

// buildFunctions turns the function set into Functions. Entries without a
// decoded instruction are dropped and returned.
func (a *analyzer) buildFunctions() (map[uint64]*Function, []uint64) {
	out := map[uint64]*Function{}
	var dropped []uint64
	for _, e := range sortedKeys(a.funcs) {
		if a.insns[e] == nil {
			dropped = append(dropped, e)
			continue
		}
		body := a.bodyOf(e)
		pairs := make([][2]uint64, 0, len(body))
		for _, addr := range sortedKeys(body) {
			pairs = append(pairs, [2]uint64{addr, a.insns[addr].end()})
		}
		f := &Function{Entry: e, Source: a.funcs[e].source, Seed: a.funcs[e].seed,
			NoReturn: a.noreturn[e], Body: ranges(pairs)}
		if t, ok := a.thunks[e]; ok {
			tt := t
			f.Thunk = &tt
		}
		out[e] = f
	}
	return out, dropped
}
