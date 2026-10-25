// Package analysis is the Go port of the analysis core of
// rust-analysis/crates/ra-analysis: entry points, PLT and static stub thunks,
// recursive descent, function creation, subroutine references, no-return,
// byte-pattern function starts, switch tables, block-local constant
// propagation and the basic block model.
//
// Java counterparts, in pass order:
//   - EntryPointAnalyzer, ExternalEntryFunctionAnalyzer: seed functions from the
//     entry point, exports and symbols (the seeds come from the loader).
//   - ElfDefaultGotPltMarkup: disassemble PLT sections, create thunks.
//   - DisassembleCommand and the Subroutine References analyzer: recursive
//     descent; call targets become functions.
//   - SharedReturnAnalysisCmd: jumps out of a function create functions.
//   - NoReturnFunctionAnalyzer, FindNoReturnFunctionsAnalyzer.
//   - FunctionStartAnalyzer: byte-pattern function starts.
//   - CreateThunkAnalyzer: single-jump thunks.
//   - BasicBlockModel.
//
// Decoding is behind the Decoder interface. The Java bridge (go/tools/
// sleigh-bridge) supplies Ghidra's flow facts; the Rust crate also read
// p-code-derived facts (indirect_via, data_refs, addends, indexed_load and the
// register state of constant propagation) that the bridge contract does not
// carry. They are optional fields here: a decoder that has them gets the
// analyses that need them (PLT thunks by import name, jump tables, data
// references, constant propagation), one that has not gets the rest.
package analysis

import (
	"github.com/TorratDev/ghidra/go/internal/ra/loader"
	"github.com/TorratDev/ghidra/go/internal/ra/sleigh"
)

// Access is how an instruction touches a constant address.
type Access int

const (
	AccessRead Access = iota
	AccessWrite
	// AccessAddress means the address is computed but not dereferenced here.
	AccessAddress
)

type DataRef struct {
	Addr   uint64
	Access Access
}

// Decoded is one decoded instruction: Ghidra's flow facts plus the optional
// p-code-derived facts (see the package comment).
type Decoded struct {
	Addr           uint64
	Len            uint32
	Mnemonic       string
	Text           string
	Flow           sleigh.FlowKind
	HasFallthrough bool
	// Targets are direct branch and call targets.
	Targets []uint64
	// Indirect is a branch or call whose target is computed at run time.
	Indirect bool

	// IndirectVia is the constant address an indirect jump or call reads its
	// target from (JMP [0x1234], CALL qword ptr [RIP+x]).
	IndirectVia *uint64
	// DataRefs are constant addresses read, written or computed.
	DataRefs []DataRef
	// Addends are constants added to a run-time value (the table base in
	// JMP [T + RCX*8]).
	Addends []uint64
	// IndexedLoad is a load from a run-time computed address.
	IndexedLoad bool
}

func (d *Decoded) end() uint64 { return d.Addr + uint64(d.Len) }

// RegState holds the register values known to be constant at an instruction
// boundary, as (register key, value) pairs; the key is the decoder's.
type RegState []RegValue

type RegValue struct {
	Reg   string
	Value uint64
}

func (s *RegState) clear() { *s = (*s)[:0] }

// Decoder decodes the instruction at addr from bytes, which start at addr.
type Decoder interface {
	Decode(addr uint64, bytes []byte) (*Decoded, bool)
}

// StateDecoder is a Decoder that can also run an instruction with incoming
// register constants (block-local constant propagation) and report the
// constants it leaves behind, and the data references it finds at the use
// site. Decoders without p-code facts do not implement it.
type StateDecoder interface {
	Decoder
	DecodeIn(addr uint64, bytes []byte, state *RegState) (*Decoded, bool)
}

// Language is the part of the language record and install the analysis needs.
type Language struct {
	sleigh.Language
	// PatternsDir is the processor's data/patterns directory (with
	// patternconstraints.xml); empty disables the pattern pass.
	PatternsDir string
}

type Options struct {
	// Patterns runs the byte-pattern function start search.
	Patterns bool
	// Compiler selects pattern files ("gcc", "windows", ...); empty means
	// the format's default.
	Compiler string
	// CallTables resolves CALL [T + idx*S] function-pointer tables.
	CallTables bool
	// Logf receives diagnostics (round limit reached, dropped entries); nil
	// discards them. They are also kept in Analysis.Diagnostics.
	Logf func(format string, args ...any)
}

func DefaultOptions() Options { return Options{Patterns: true, CallTables: true} }

// FuncSource says why a function exists. Functions come from seeds, the PLT,
// call targets, jump targets that leave their function, jump tables and
// patterns; operand references and data pointers do not create functions.
type FuncSource int

const (
	SourceSeed FuncSource = iota
	SourcePlt
	SourceCall
	// SourceJump is a function created at the target of a jump out of its
	// function (SharedReturnAnalysisCmd) or of a thunk's jump.
	SourceJump
	// SourceTable is a function at a jump or call table entry.
	SourceTable
	SourcePattern
)

type ThunkTarget struct {
	// Internal is the thunked function's entry when External is empty.
	Internal uint64
	External string
}

func (t ThunkTarget) IsExternal() bool { return t.External != "" }

type Insn struct {
	D Decoded
	// FT is the fallthrough address after no-return call cutting.
	FT    uint64
	HasFT bool
}

func (i *Insn) end() uint64 { return i.D.end() }

type Function struct {
	Entry    uint64
	Source   FuncSource
	Seed     loader.SeedKind
	Thunk    *ThunkTarget
	NoReturn bool
	Body     [][2]uint64
}

// Analysis is the result of Analyze, before conversion to the report schema.
type Analysis struct {
	Insns     map[uint64]*Insn
	Functions map[uint64]*Function
	// SwitchJumps are indirect jumps whose tables were recovered.
	SwitchJumps map[uint64]bool
	// DroppedEntries are function entries without a decoded instruction.
	DroppedEntries []uint64
	// Diagnostics are the messages also sent to Options.Logf.
	Diagnostics []string
	// NoReturnRoundLimit is set when the no-return fixpoint hit its limit.
	NoReturnRoundLimit bool
	// SortedInsns are the instruction addresses in order.
	SortedInsns []uint64
}
