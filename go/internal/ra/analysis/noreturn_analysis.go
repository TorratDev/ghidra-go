package analysis

import (
	"sort"

	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

// refTo is a reference to an address: where from, whether it is a call, and
// whether it is a data read or write.
type refTo struct {
	from   uint64
	isCall bool
	rw     bool
}

// computeNoreturn computes the known plus discovered non-returning functions.
// Discovery is a port of FindNoReturnFunctionsAnalyzer: a call site is
// suspicious when what follows it looks like it is never reached
// (checkNonReturningIndicators); a target becomes non-returning after
// noReturnEvidence suspicious call sites, or when every path through it ends
// in a call to a non-returning function (targetOnlyCallsNoReturn).
func (a *analyzer) computeNoreturn() {
	nr := make(map[uint64]bool, len(a.noreturn))
	for k := range a.noreturn {
		nr[k] = true
	}
	for e := range a.funcs {
		named := false
		if n, ok := a.functionName(e); ok {
			named = a.names.contains(n)
		}
		t, isThunk := a.thunks[e]
		if named || (isThunk && t.IsExternal() && a.names.contains(t.External)) {
			nr[e] = true
		}
	}
	refs := map[uint64][]refTo{}
	callers := map[uint64][]uint64{}
	for _, addr := range a.sorted {
		i := a.insns[addr]
		isCall := i.D.Flow == sleigh.FlowCall || i.D.Flow == sleigh.FlowCondCall
		for _, t := range i.D.Targets {
			refs[t] = append(refs[t], refTo{addr, isCall, false})
			if isCall {
				callers[t] = append(callers[t], addr)
			}
		}
		for _, r := range i.D.DataRefs {
			refs[r.Addr] = append(refs[r.Addr], refTo{addr, false, r.Access != AccessAddress})
		}
	}
	entries := sortedKeys(a.funcs)
	// The indicators of a call site depend only on the decoded code, so each
	// is computed once.
	indicators := map[uint64]bool{}
	suspicious := func(i *Insn) bool {
		v, ok := indicators[i.D.Addr]
		if !ok {
			v = a.noreturnIndicators(i, entries, refs)
			indicators[i.D.Addr] = v
		}
		return v
	}
	for {
		changed := false
		a.inheritThunkNoreturn(nr)
		for _, addr := range a.sorted {
			i := a.insns[addr]
			if i.D.Flow != sleigh.FlowCall || !i.D.HasFallthrough || !suspicious(i) {
				continue
			}
			for _, t := range i.D.Targets {
				if nr[t] {
					continue
				}
				// Evidence for t is its own set of call sites: the site being
				// examined plus other callers with the same indicators. A caller
				// counted for another target counts again here.
				count := 1
				seen := map[uint64]bool{addr: true}
				for _, c := range callers[t] {
					if seen[c] {
						continue
					}
					seen[c] = true
					if ci := a.insns[c]; ci != nil && suspicious(ci) {
						count++
						if count >= noReturnEvidence {
							break
						}
					}
				}
				if count >= noReturnEvidence || a.onlyCallsNoreturn(t, nr) {
					nr[t] = true
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	a.inheritThunkNoreturn(nr)
	a.noreturn = nr
}

// inheritThunkNoreturn makes a thunk to a non-returning function
// non-returning. (The thunks made by the Rust lone-call rule are gone, so
// only jump and IRELATIVE thunks feed this.)
func (a *analyzer) inheritThunkNoreturn(nr map[uint64]bool) {
	for {
		added := false
		for e, t := range a.thunks {
			if !nr[e] && !t.IsExternal() && nr[t.Internal] {
				nr[e] = true
				added = true
			}
		}
		if !added {
			return
		}
	}
}

// noreturnIndicators is checkNonReturningIndicators: it walks the fallthrough
// chain after a call looking for signs it is never executed.
func (a *analyzer) noreturnIndicators(call *Insn, entries []uint64, refs map[uint64][]refTo) bool {
	ft := call.end()
	calling, hasCalling := functionContaining(entries, call.D.Addr)
	k := sort.Search(len(entries), func(k int) bool { return entries[k] >= ft })
	nextFunc, hasNext := uint64(0), false
	if k < len(entries) {
		nextFunc, hasNext = entries[k], true
	}
	x86 := len(a.lang.ID) >= 3 && a.lang.ID[:3] == "x86"
	for {
		if hasNext && nextFunc == ft {
			return true // function defined after call
		}
		i := a.insns[ft]
		if i == nil {
			return true // falls into data / undefined bytes
		}
		if hasNext && nextFunc > ft && nextFunc < i.end() {
			return true // function defined inside instruction after call
		}
		for _, r := range refs[ft] {
			if r.isCall {
				return true // call reference after call
			}
			if f, ok := functionContaining(entries, r.from); r.rw && r.from < ft && hasCalling && ok && f == calling {
				return true // data reference from the same function after call
			}
		}
		if x86 && i.D.Mnemonic == "INT3" {
			return true
		}
		if i.D.Flow == sleigh.FlowFallthrough && i.D.HasFallthrough {
			ft = i.end()
		} else {
			return false
		}
	}
}

// functionContaining is the nearest function entry at or before addr: it is
// what Ghidra's contiguous bodies give in practice, and cheap. entries is sorted.
func functionContaining(entries []uint64, addr uint64) (uint64, bool) {
	k := sort.Search(len(entries), func(k int) bool { return entries[k] > addr })
	if k == 0 {
		return 0, false
	}
	return entries[k-1], true
}

// onlyCallsNoreturn is targetOnlyCallsNoReturn: every path from entry ends in
// a call to a non-returning function.
func (a *analyzer) onlyCallsNoreturn(entry uint64, nr map[uint64]bool) bool {
	work := []uint64{entry}
	seen := map[uint64]bool{}
	hit := false
	for len(work) > 0 {
		addr := work[len(work)-1]
		work = work[:len(work)-1]
		if seen[addr] {
			continue
		}
		seen[addr] = true
		i := a.insns[addr]
		if i == nil {
			return false
		}
		switch i.D.Flow {
		case sleigh.FlowReturn, sleigh.FlowCondReturn, sleigh.FlowTerminator:
			return false
		case sleigh.FlowCall, sleigh.FlowCondCall:
			for _, t := range i.D.Targets {
				if nr[t] {
					hit = true
				} else if !i.HasFT {
					return false
				}
			}
			if len(i.D.Targets) == 0 && !i.HasFT {
				return false
			}
			if i.HasFT {
				work = append(work, i.FT)
			}
		case sleigh.FlowJump, sleigh.FlowCondJump:
			if len(i.D.Targets) == 0 && !i.HasFT {
				return false // unresolved indirect jump
			}
			for _, t := range i.D.Targets {
				if nr[t] {
					hit = true
				} else {
					work = append(work, t)
				}
			}
			if i.HasFT {
				work = append(work, i.FT)
			}
		case sleigh.FlowFallthrough:
			if !i.HasFT {
				return false
			}
			work = append(work, i.FT)
		}
	}
	return hit
}
