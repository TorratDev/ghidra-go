package core

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"slices"
)

// SchemaVersion 2: namespace on symbols, functions and imports.
const SchemaVersion = 2

type SymbolSource string

const (
	SourceImported SymbolSource = "imported"
	SourceAnalysis SymbolSource = "analysis"
	SourceDefault  SymbolSource = "default"
	SourceUser     SymbolSource = "user"
)

type EdgeKind string

const (
	EdgeFallthrough EdgeKind = "fallthrough"
	EdgeJump        EdgeKind = "jump"
	EdgeCondJump    EdgeKind = "cond_jump"
)

type XrefKind string

const (
	XrefCall     XrefKind = "call"
	XrefJump     XrefKind = "jump"
	XrefCondJump XrefKind = "cond_jump"
	XrefRead     XrefKind = "read"
	XrefWrite    XrefKind = "write"
	XrefData     XrefKind = "data"
)

// Ranks follow the Rust declaration order, which its derived Ord sorts by.
var (
	symbolSourceRank = map[SymbolSource]int{SourceImported: 0, SourceAnalysis: 1, SourceDefault: 2, SourceUser: 3}
	edgeKindRank     = map[EdgeKind]int{EdgeFallthrough: 0, EdgeJump: 1, EdgeCondJump: 2}
	xrefKindRank     = map[XrefKind]int{XrefCall: 0, XrefJump: 1, XrefCondJump: 2, XrefRead: 3, XrefWrite: 4, XrefData: 5}
)

func unmarshalEnum[T ~string](b []byte, dst *T, ranks map[T]int) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if _, ok := ranks[T(s)]; !ok {
		return fmt.Errorf("unknown %T %q", *dst, s)
	}
	*dst = T(s)
	return nil
}

func (s *SymbolSource) UnmarshalJSON(b []byte) error { return unmarshalEnum(b, s, symbolSourceRank) }
func (k *EdgeKind) UnmarshalJSON(b []byte) error     { return unmarshalEnum(b, k, edgeKindRank) }
func (k *XrefKind) UnmarshalJSON(b []byte) error     { return unmarshalEnum(b, k, xrefKindRank) }

// IsFlow reports whether the reference is a control-flow transfer.
func (k XrefKind) IsFlow() bool { return k == XrefCall || k == XrefJump || k == XrefCondJump }

// AnalysisReport is the interchange format between the Rust analyzer and the
// Ghidra headless exporter. Field order is the Rust declaration order.
type AnalysisReport struct {
	SchemaVersion uint32 `json:"schema_version"`
	// Producer is e.g. "ra 0.1.0" or "ghidra 12.1.4".
	Producer     string            `json:"producer"`
	Binary       BinaryInfo        `json:"binary"`
	Memory       []MemoryInfo      `json:"memory"`
	Symbols      []SymbolInfo      `json:"symbols"`
	Imports      []ImportInfo      `json:"imports"`
	Exports      []ExportInfo      `json:"exports"`
	Functions    []FunctionInfo    `json:"functions"`
	Instructions []InstructionInfo `json:"instructions"`
	Blocks       []BlockInfo       `json:"blocks"`
	Edges        []EdgeInfo        `json:"edges"`
	Xrefs        []XrefInfo        `json:"xrefs"`
}

type BinaryInfo struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
	// Format is ELF, PE, MachO or Raw.
	Format string `json:"format"`
	// Language is a Ghidra language id, e.g. x86:LE:64:default.
	Language string `json:"language"`
	// ImageBase: all addresses in the report are absolute; comparisons subtract this.
	ImageBase Addr `json:"image_base"`
}

type MemoryInfo struct {
	Name  string `json:"name"`
	Start Addr   `json:"start"`
	// End is exclusive.
	End         Addr `json:"end"`
	Read        bool `json:"read"`
	Write       bool `json:"write"`
	Execute     bool `json:"execute"`
	Initialized bool `json:"initialized"`
}

type SymbolInfo struct {
	Addr Addr   `json:"addr"`
	Name string `json:"name"`
	// Namespace is the parent namespace path, nil for global.
	Namespace *string `json:"namespace"`
	// Kind is function, label or data.
	Kind   string       `json:"kind"`
	Source SymbolSource `json:"source"`
}

type ImportInfo struct {
	Name      string  `json:"name"`
	Namespace *string `json:"namespace"`
	Library   *string `json:"library"`
	// Addr is the thunk/stub or pointer slot that refers to the import.
	Addr *Addr `json:"addr"`
}

type ExportInfo struct {
	Addr Addr   `json:"addr"`
	Name string `json:"name"`
}

type FunctionInfo struct {
	Entry       Addr         `json:"entry"`
	Name        string       `json:"name"`
	Namespace   *string      `json:"namespace"`
	Source      SymbolSource `json:"source"`
	Thunk       bool         `json:"thunk"`
	ThunkTarget *Addr        `json:"thunk_target"`
	NoReturn    bool         `json:"no_return"`
	// Body is the address ranges [start, end) making up the function.
	Body []AddrPair `json:"body"`
}

type InstructionInfo struct {
	Addr Addr   `json:"addr"`
	Len  uint32 `json:"len"`
	// Mnemonic is upper-case as printed by SLEIGH (MOV, CALL, ...).
	Mnemonic string `json:"mnemonic"`
}

type BlockInfo struct {
	Start Addr `json:"start"`
	// End is exclusive.
	End Addr `json:"end"`
}

type EdgeInfo struct {
	// From and To are start addresses of the source and destination blocks.
	From Addr     `json:"from"`
	To   Addr     `json:"to"`
	Kind EdgeKind `json:"kind"`
}

type XrefInfo struct {
	// From is the referencing instruction (or data item).
	From Addr     `json:"from"`
	To   Addr     `json:"to"`
	Kind XrefKind `json:"kind"`
}

// NewAnalysisReport returns a report with the current schema version and all
// lists empty (not nil), so they encode as [].
func NewAnalysisReport() *AnalysisReport {
	r := &AnalysisReport{SchemaVersion: SchemaVersion}
	r.fixNil()
	return r
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// fixNil makes every list non-nil; decoding missing lists leaves them nil.
func (r *AnalysisReport) fixNil() {
	r.Memory = nonNil(r.Memory)
	r.Symbols = nonNil(r.Symbols)
	r.Imports = nonNil(r.Imports)
	r.Exports = nonNil(r.Exports)
	r.Functions = nonNil(r.Functions)
	r.Instructions = nonNil(r.Instructions)
	r.Blocks = nonNil(r.Blocks)
	r.Edges = nonNil(r.Edges)
	r.Xrefs = nonNil(r.Xrefs)
	for i := range r.Functions {
		r.Functions[i].Body = nonNil(r.Functions[i].Body)
	}
}

// cmpPtr orders nil before non-nil, like Rust's Option.
func cmpPtr[T cmp.Ordered](a, b *T) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return cmp.Compare(*a, *b)
}

func eqPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// Normalize sorts every list so serialized reports are deterministic, drops
// exact duplicates where the Rust version does, and makes lists non-nil.
// Sort keys match Rust (namespace is deliberately not a key).
func (r *AnalysisReport) Normalize() {
	r.fixNil()
	slices.SortStableFunc(r.Memory, func(a, b MemoryInfo) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(a.End, b.End))
	})
	slices.SortStableFunc(r.Symbols, func(a, b SymbolInfo) int {
		return cmp.Or(cmp.Compare(a.Addr, b.Addr), cmp.Compare(a.Name, b.Name))
	})
	r.Symbols = slices.CompactFunc(r.Symbols, func(a, b SymbolInfo) bool {
		return a.Addr == b.Addr && a.Name == b.Name && eqPtr(a.Namespace, b.Namespace) &&
			a.Kind == b.Kind && a.Source == b.Source
	})
	slices.SortStableFunc(r.Imports, func(a, b ImportInfo) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmpPtr(a.Library, b.Library), cmpPtr(a.Addr, b.Addr))
	})
	r.Imports = slices.CompactFunc(r.Imports, func(a, b ImportInfo) bool {
		return a.Name == b.Name && eqPtr(a.Namespace, b.Namespace) && eqPtr(a.Library, b.Library) && eqPtr(a.Addr, b.Addr)
	})
	slices.SortStableFunc(r.Exports, func(a, b ExportInfo) int {
		return cmp.Or(cmp.Compare(a.Addr, b.Addr), cmp.Compare(a.Name, b.Name))
	})
	r.Exports = slices.Compact(r.Exports)
	slices.SortStableFunc(r.Functions, func(a, b FunctionInfo) int { return cmp.Compare(a.Entry, b.Entry) })
	for i := range r.Functions {
		slices.SortStableFunc(r.Functions[i].Body, func(a, b AddrPair) int {
			return cmp.Or(cmp.Compare(a[0], b[0]), cmp.Compare(a[1], b[1]))
		})
	}
	slices.SortStableFunc(r.Instructions, func(a, b InstructionInfo) int { return cmp.Compare(a.Addr, b.Addr) })
	slices.SortStableFunc(r.Blocks, func(a, b BlockInfo) int {
		return cmp.Or(cmp.Compare(a.Start, b.Start), cmp.Compare(a.End, b.End))
	})
	r.Blocks = slices.Compact(r.Blocks)
	slices.SortStableFunc(r.Edges, func(a, b EdgeInfo) int {
		return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To), cmp.Compare(edgeKindRank[a.Kind], edgeKindRank[b.Kind]))
	})
	r.Edges = slices.Compact(r.Edges)
	slices.SortStableFunc(r.Xrefs, func(a, b XrefInfo) int {
		return cmp.Or(cmp.Compare(a.From, b.From), cmp.Compare(a.To, b.To), cmp.Compare(xrefKindRank[a.Kind], xrefKindRank[b.Kind]))
	})
	r.Xrefs = slices.Compact(r.Xrefs)
}

// WriteReport writes r as two-space-indented JSON. The trailing newline is
// written only when stdout is true (the report goes to a terminal/pipe).
func WriteReport(w io.Writer, r *AnalysisReport, stdout bool) error {
	r.fixNil()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return err
	}
	out := buf.Bytes()
	if !stdout {
		out = bytes.TrimSuffix(out, []byte("\n"))
	}
	_, err := w.Write(out)
	return err
}
