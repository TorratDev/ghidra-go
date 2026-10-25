package analysis

import (
	"fmt"
	"slices"
	"sort"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/demangle"
	"github.com/TorratDev/ghidra/go/internal/ra/loader"
	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

// Producer names this implementation in reports.
const Producer = "ra-go (dev)"

// demangleSymbol is what Ghidra's demangler analyzers apply to a symbol: the
// Rust demangler first for Rust programs, then GNU with every symbol passed
// (analyzer mode). MSVC names are not demangled yet (#17).
func demangleSymbol(name string, rust bool) *demangle.Demangled {
	if rust {
		if d := demangle.DemangleRust(name); d != nil {
			return d
		}
	}
	return demangle.DemangleGnuOpts(name, false)
}

// demangledSymbols is one demangled name per address: the primary symbol or
// else the first alternate that demangles.
func demangledSymbols(prog *loader.Program) map[uint64]*demangle.Demangled {
	byAddr := map[uint64][]*loader.LoadedSymbol{}
	for i := range prog.Symbols {
		s := &prog.Symbols[i]
		byAddr[s.Addr] = append(byAddr[s.Addr], s)
	}
	out := map[uint64]*demangle.Demangled{}
	for addr, syms := range byAddr {
		// Primary first: function symbols, then unversioned names.
		sort.SliceStable(syms, func(i, j int) bool {
			ki := [2]bool{!syms[i].IsFunction, hasByte(syms[i].Name, '@')}
			kj := [2]bool{!syms[j].IsFunction, hasByte(syms[j].Name, '@')}
			if ki[0] != kj[0] {
				return !ki[0]
			}
			return !ki[1] && kj[1]
		})
		for _, s := range syms {
			if d := demangleSymbol(s.Name, prog.IsRust); d != nil {
				out[addr] = d
				break
			}
		}
	}
	return out
}

func hasByte(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}

// ghidraDefaultName is Ghidra's default label: prefix plus the address
// zero-padded to 8 digits.
func ghidraDefaultName(prefix string, addr uint64) string {
	return fmt.Sprintf("%s_%08x", prefix, addr)
}

func nsPtr(d *demangle.Demangled) *string { return d.NamespaceString() }

// isTailCall: a jump without fallthrough to a single target that is a function.
func isTailCall(i *Insn, isFunc func(uint64) bool) bool {
	return i.D.Flow == sleigh.FlowJump && !i.D.HasFallthrough && len(i.D.Targets) == 1 && isFunc(i.D.Targets[0])
}

// Report converts analysis results into the normalized report.
func Report(prog *loader.Program, an *Analysis) *core.AnalysisReport {
	mem := &prog.Memory
	r := core.NewAnalysisReport()
	r.Producer = Producer
	r.Binary = core.BinaryInfo{Path: prog.Path, Sha256: prog.Sha256, Format: prog.Format,
		Language: prog.Language, ImageBase: core.Addr(prog.ImageBase)}
	for _, b := range mem.Blocks() {
		r.Memory = append(r.Memory, core.MemoryInfo{Name: b.Name, Start: core.Addr(b.Start), End: core.Addr(b.End()),
			Read: b.Perms.Read, Write: b.Perms.Write, Execute: b.Perms.Execute, Initialized: b.IsInitialized()})
	}

	// Demangler analyzers: one demangled name per address, from the primary
	// symbol or else the first alternate that demangles; it becomes the primary
	// name, the mangled one stays a label.
	demangled := demangledSymbols(prog)
	named := map[uint64]bool{}
	dataAt := map[uint64]bool{}
	for _, s := range prog.Symbols {
		if s.IsData {
			dataAt[s.Addr] = true
		}
	}
	kindOf := func(addr uint64) string {
		switch {
		case an.Functions[addr] != nil:
			return "function"
		case dataAt[addr]:
			return "data"
		}
		return "label"
	}
	for _, s := range prog.Symbols {
		named[s.Addr] = true
		kind := "label"
		if an.Functions[s.Addr] != nil {
			kind = "function"
		} else if s.IsData {
			kind = "data"
		}
		r.Symbols = append(r.Symbols, core.SymbolInfo{Addr: core.Addr(s.Addr), Name: s.Name, Kind: kind, Source: s.Source})
	}
	for _, addr := range sortedKeys(demangled) {
		d := demangled[addr]
		r.Symbols = append(r.Symbols, core.SymbolInfo{Addr: core.Addr(addr), Name: d.Name, Namespace: nsPtr(d),
			Kind: kindOf(addr), Source: core.SourceAnalysis})
	}
	importNames := map[string]*demangle.Demangled{}
	for _, i := range prog.Imports {
		if d := demangleSymbol(i.Name, prog.IsRust); d != nil {
			importNames[i.Name] = d
		}
	}

	symsAt := map[uint64][]*loader.LoadedSymbol{}
	for i := range prog.Symbols {
		s := &prog.Symbols[i]
		symsAt[s.Addr] = append(symsAt[s.Addr], s)
	}
	for _, e := range sortedKeys(an.Functions) {
		f := an.Functions[e]
		// Name priority: demangled name, function symbol, loader fallback name
		// (entry, _INIT_0, _DT_INIT), other label, thunked import, FUN_.
		var symName string
		haveSym := false
		for _, s := range symsAt[e] {
			if s.IsFunction {
				symName, haveSym = s.Name, true
				break
			}
		}
		if !haveSym {
			if n, ok := prog.FallbackNames[e]; ok {
				symName, haveSym = n, true
			}
		}
		if !haveSym {
			for _, s := range symsAt[e] {
				if len(s.Name) < 5 || s.Name[:5] != "__DT_" {
					symName, haveSym = s.Name, true
					break
				}
			}
		}
		var name string
		var ns *string
		var source core.SymbolSource
		switch d := demangled[e]; {
		case d != nil:
			name, ns, source = d.Name, nsPtr(d), core.SourceAnalysis
		case haveSym:
			name, source = symName, core.SourceImported
		case f.Thunk != nil && f.Thunk.IsExternal():
			if d := importNames[f.Thunk.External]; d != nil {
				name, ns, source = d.Name, nsPtr(d), core.SourceDefault
			} else {
				name, source = f.Thunk.External, core.SourceDefault
			}
		default:
			name, source = ghidraDefaultName("FUN", e), core.SourceDefault
		}
		if demangled[e] == nil && !slices.ContainsFunc(symsAt[e], func(s *loader.LoadedSymbol) bool { return s.Name == name }) {
			r.Symbols = append(r.Symbols, core.SymbolInfo{Addr: core.Addr(e), Name: name, Namespace: ns, Kind: "function", Source: source})
		}
		fi := core.FunctionInfo{Entry: core.Addr(e), Name: name, Namespace: ns, Source: source,
			Thunk: f.Thunk != nil, NoReturn: f.NoReturn}
		if f.Thunk != nil && !f.Thunk.IsExternal() {
			t := core.Addr(f.Thunk.Internal)
			fi.ThunkTarget = &t
		}
		for _, b := range f.Body {
			fi.Body = append(fi.Body, core.AddrPair{core.Addr(b[0]), core.Addr(b[1])})
		}
		r.Functions = append(r.Functions, fi)
	}

	for _, i := range prog.Imports {
		d := importNames[i.Name]
		imp := core.ImportInfo{Name: i.Name, Library: i.Library}
		if d != nil {
			imp.Name, imp.Namespace = d.Name, nsPtr(d)
		}
		if i.Slot != nil {
			s := core.Addr(*i.Slot)
			imp.Addr = &s
		}
		r.Imports = append(r.Imports, imp)
	}
	exported := map[uint64]bool{}
	for _, e := range prog.Exports {
		r.Exports = append(r.Exports, core.ExportInfo{Addr: core.Addr(e.Addr), Name: e.Name})
		exported[e.Addr] = true
	}
	for _, addr := range sortedKeys(demangled) {
		if exported[addr] {
			r.Exports = append(r.Exports, core.ExportInfo{Addr: core.Addr(addr), Name: demangled[addr].Name})
		}
	}

	// Owning function of each instruction, for tail-call classification: a
	// jump back to the function's own entry is a loop, not a tail call.
	owner := map[uint64]uint64{}
	for _, e := range sortedKeys(an.Functions) {
		for _, b := range an.Functions[e].Body {
			k := sort.Search(len(an.SortedInsns), func(k int) bool { return an.SortedInsns[k] >= b[0] })
			for ; k < len(an.SortedInsns) && an.SortedInsns[k] < b[1]; k++ {
				if _, ok := owner[an.SortedInsns[k]]; !ok {
					owner[an.SortedInsns[k]] = e
				}
			}
		}
	}
	tail := func(i *Insn) bool {
		return isTailCall(i, func(t uint64) bool {
			o, ok := owner[i.D.Addr]
			return an.Functions[t] != nil && !(ok && o == t)
		})
	}
	for _, addr := range an.SortedInsns {
		i := an.Insns[addr]
		r.Instructions = append(r.Instructions, core.InstructionInfo{Addr: core.Addr(addr), Len: i.D.Len, Mnemonic: i.D.Mnemonic})
		flowKind := core.XrefJump
		switch {
		case i.D.Flow == sleigh.FlowCall || i.D.Flow == sleigh.FlowCondCall:
			flowKind = core.XrefCall
		case i.D.Flow == sleigh.FlowJump && i.D.HasFallthrough: // PLT0 call override
			flowKind = core.XrefCall
		case tail(i):
			flowKind = core.XrefCall
		case i.D.Flow == sleigh.FlowCondJump:
			flowKind = core.XrefCondJump
		}
		for _, t := range i.D.Targets {
			// Ghidra records no flow reference from an instruction to itself
			// (HLT is goto inst_start).
			if mem.IsMapped(t) && t != addr {
				r.Xrefs = append(r.Xrefs, core.XrefInfo{From: core.Addr(addr), To: core.Addr(t), Kind: flowKind})
			}
		}
		for _, dr := range i.D.DataRefs {
			if !mem.IsMapped(dr.Addr) || slices.Contains(i.D.Targets, dr.Addr) {
				continue
			}
			var kind core.XrefKind
			switch {
			case dr.Access == AccessRead && i.D.IndirectVia != nil && *i.D.IndirectVia == dr.Addr && i.D.Flow == sleigh.FlowJump:
				kind = core.XrefData // the pointer slot of an indirect jump is a DATA ref (READ for calls)
			case dr.Access == AccessRead:
				kind = core.XrefRead
			case dr.Access == AccessWrite:
				kind = core.XrefWrite
			default:
				kind = core.XrefData
			}
			r.Xrefs = append(r.Xrefs, core.XrefInfo{From: core.Addr(addr), To: core.Addr(dr.Addr), Kind: kind})
		}
	}
	for _, slot := range sortedKeys(prog.MarkedPointers) {
		if t := prog.MarkedPointers[slot]; mem.IsMapped(t) {
			r.Xrefs = append(r.Xrefs, core.XrefInfo{From: core.Addr(slot), To: core.Addr(t), Kind: core.XrefData})
		}
	}

	buildBlocks(r, an, named, tail)
	r.Normalize()
	return r
}

// buildBlocks is Ghidra's BasicBlockModel (isBlockStart inherited from SimpleBlockModel). A block starts at an instruction
// that has a symbol or any reference to it (isBlockStart asks
// SymbolTable.hasSymbol, which is true for a symbol or any reference to the
// address: flow or data, SymbolManager.hasSymbol), and after an instruction
// that has no fallthrough or ends a block (jump, return, terminator;
// BasicBlockModel.hasEndOfBlockFlow); calls do not end blocks. Fallthrough is the instruction's own has_fallthrough, not the
// flow cut after a call to a no-return function.
func buildBlocks(r *core.AnalysisReport, an *Analysis, named map[uint64]bool, tail func(*Insn) bool) {
	labels := map[uint64]bool{}
	for a := range named {
		labels[a] = true
	}
	for e := range an.Functions {
		labels[e] = true
	}
	for a := range an.SwitchJumps {
		labels[a] = true
	}
	insns := an.Insns
	sorted := an.SortedInsns
	for _, x := range r.Xrefs {
		labels[uint64(x.To)] = true // any reference, flow or data
	}
	endsBlock := func(i *Insn) bool {
		if !i.D.HasFallthrough {
			return true
		}
		switch i.D.Flow {
		case sleigh.FlowJump, sleigh.FlowCondJump, sleigh.FlowReturn, sleigh.FlowCondReturn, sleigh.FlowTerminator:
			return true
		}
		return false
	}
	type blk struct{ start, end, last uint64 }
	var blocks []blk
	var cur *blk
	var prev *Insn
	for _, addr := range sorted {
		i := insns[addr]
		contiguous := prev != nil && prev.D.HasFallthrough && prev.end() == addr && !endsBlock(prev)
		if !contiguous || labels[addr] {
			if cur != nil {
				cur.last = prev.D.Addr
				blocks = append(blocks, *cur)
			}
			cur = &blk{start: addr, end: i.end()}
		} else {
			cur.end = i.end()
		}
		prev = i
	}
	if cur != nil {
		cur.last = prev.D.Addr
		blocks = append(blocks, *cur)
	}
	starts := map[uint64]bool{}
	for _, b := range blocks {
		starts[b.start] = true
	}
	for _, b := range blocks {
		r.Blocks = append(r.Blocks, core.BlockInfo{Start: core.Addr(b.start), End: core.Addr(b.end)})
		li := insns[b.last]
		if li.HasFT && li.D.Flow != sleigh.FlowJump && starts[li.end()] {
			r.Edges = append(r.Edges, core.EdgeInfo{From: core.Addr(b.start), To: core.Addr(li.end()), Kind: core.EdgeFallthrough})
		}
		overridden := li.D.Flow == sleigh.FlowJump && li.D.HasFallthrough
		if (li.D.Flow == sleigh.FlowJump || li.D.Flow == sleigh.FlowCondJump) && !tail(li) && !overridden {
			kind := core.EdgeJump
			if li.D.Flow == sleigh.FlowCondJump {
				kind = core.EdgeCondJump
			}
			for _, t := range li.D.Targets {
				if starts[t] && t != b.last {
					r.Edges = append(r.Edges, core.EdgeInfo{From: core.Addr(b.start), To: core.Addr(t), Kind: kind})
				}
			}
		}
	}
}
