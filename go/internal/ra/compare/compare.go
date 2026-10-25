// Package compare is the Go port of rust-analysis/crates/ra-compare and the
// regress driver of ra-cli: differential comparison of a Ghidra export (the
// oracle) with an ra report, the thresholds ratchet and the markdown report.
//
// Every category is compared as a set of keys. Keys present in both are true
// positives; Ghidra-only keys are misses (they lower recall); ra-only keys
// are extras (they lower precision).
package compare

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

// Samples is the number of mismatch samples kept per category and side.
const Samples = 25

type CategoryResult struct {
	Name              string   `json:"name"`
	Matched           int      `json:"matched"`
	GhidraOnly        int      `json:"ghidra_only"`
	RaOnly            int      `json:"ra_only"`
	Precision         float64  `json:"precision"`
	Recall            float64  `json:"recall"`
	GhidraOnlySamples []string `json:"ghidra_only_samples"`
	RaOnlySamples     []string `json:"ra_only_samples"`
}

// ratio is n/d, or 1.0 when d is 0: an empty category has nothing to miss and
// nothing extra, so it scores perfectly (and passes any gate). A category that
// should not be empty is caught by the gate on the other side of the
// comparison, not by this value.
func ratio(n, d int) float64 {
	if d == 0 {
		return 1.0
	}
	return float64(n) / float64(d)
}

// FromSets compares the key sets of one category.
func FromSets(name string, ghidra, ra map[string]struct{}) CategoryResult {
	var matched int
	var gOnly, rOnly []string
	for k := range ghidra {
		if _, ok := ra[k]; ok {
			matched++
		} else {
			gOnly = append(gOnly, k)
		}
	}
	for k := range ra {
		if _, ok := ghidra[k]; !ok {
			rOnly = append(rOnly, k)
		}
	}
	sort.Strings(gOnly)
	sort.Strings(rOnly)
	return CategoryResult{
		Name: name, Matched: matched, GhidraOnly: len(gOnly), RaOnly: len(rOnly),
		Precision:         ratio(matched, matched+len(rOnly)),
		Recall:            ratio(matched, matched+len(gOnly)),
		GhidraOnlySamples: head(gOnly), RaOnlySamples: head(rOnly),
	}
}

func head(s []string) []string {
	if len(s) > Samples {
		s = s[:Samples]
	}
	return append([]string{}, s...)
}

func (c CategoryResult) F1() float64 {
	if c.Precision+c.Recall == 0 {
		return 0
	}
	return 2 * c.Precision * c.Recall / (c.Precision + c.Recall)
}

type Comparison struct {
	Binary         string `json:"binary"`
	GhidraProducer string `json:"ghidra_producer"`
	RaProducer     string `json:"ra_producer"`
	Language       string `json:"language"`
	// Bias is ghidra_addr - ra_addr.
	Bias       int64            `json:"bias"`
	Categories []CategoryResult `json:"categories"`
}

func (c *Comparison) Category(name string) *CategoryResult {
	for i := range c.Categories {
		if c.Categories[i].Name == name {
			return &c.Categories[i]
		}
	}
	return nil
}

// Categories lists every compared category, in report order.
var Categories = []string{
	"memory_blocks", "symbols", "imports", "exports", "functions", "function_names",
	"demangled_names", "function_bodies", "thunks", "no_return", "instructions",
	"instruction_details", "blocks", "edges", "xrefs_flow", "xrefs_data",
	"xrefs_data_kinds", "xrefs_from_data",
}

// DetectBias finds the address bias between the two reports by matching
// memory block names (Ghidra rebases position independent images), falling
// back to the image base difference.
func DetectBias(ghidra, ra *core.AnalysisReport) int64 {
	find := func(r *core.AnalysisReport, name string) *core.MemoryInfo {
		for i := range r.Memory {
			if r.Memory[i].Name == name {
				return &r.Memory[i]
			}
		}
		return nil
	}
	for _, name := range []string{".text", "__text", ".init", ".plt"} {
		if g, r := find(ghidra, name), find(ra, name); g != nil && r != nil {
			return int64(g.Start - r.Start)
		}
	}
	votes := map[int64]int{}
	for _, g := range ghidra.Memory {
		for _, r := range ra.Memory {
			if r.Name == g.Name && r.End-r.Start == g.End-g.Start {
				votes[int64(g.Start-r.Start)]++
				break
			}
		}
	}
	if len(votes) > 0 {
		// Rust's max_by_key keeps the last maximum in key order.
		keys := make([]int64, 0, len(votes))
		for k := range votes {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
		best := keys[0]
		for _, k := range keys {
			if votes[k] >= votes[best] {
				best = k
			}
		}
		return best
	}
	return int64(ghidra.Binary.ImageBase - ra.Binary.ImageBase)
}

func hex(a uint64) string { return fmt.Sprintf("%#x", uint64(a)) }

type view struct {
	r         *core.AnalysisReport
	bias      int64
	insnAddrs map[core.Addr]bool
}

func newView(r *core.AnalysisReport, bias int64) *view {
	v := &view{r: r, bias: bias, insnAddrs: map[core.Addr]bool{}}
	for _, i := range r.Instructions {
		v.insnAddrs[i.Addr] = true
	}
	return v
}

// a maps an address into Ghidra's address space.
func (v *view) a(addr core.Addr) string { return hex(uint64(addr) + uint64(v.bias)) }

func rwx(r, w, x bool) string {
	b := []byte("---")
	if r {
		b[0] = 'r'
	}
	if w {
		b[1] = 'w'
	}
	if x {
		b[2] = 'x'
	}
	return string(b)
}

// debugKind is the Rust Debug spelling of an edge or xref kind.
func debugKind(k string) string {
	var sb strings.Builder
	for _, p := range strings.Split(k, "_") {
		sb.WriteString(strings.ToUpper(p[:1]) + p[1:])
	}
	return sb.String()
}

func isFlow(k core.XrefKind) bool { return k.IsFlow() }

func isMangled(name string) bool {
	for _, p := range []string{"_Z", "__Z", "_R", "__R", "?"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

func stripVersion(name string) string {
	n, _, _ := strings.Cut(name, "@")
	return n
}

func (v *view) set(cat string) map[string]struct{} {
	out := map[string]struct{}{}
	add := func(s string) { out[s] = struct{}{} }
	r := v.r
	switch cat {
	case "memory_blocks":
		for _, m := range r.Memory {
			// `tdb` is Ghidra's synthetic Windows thread data block.
			if strings.HasPrefix(m.Name, "segment_") || m.Name == "Headers" || m.Name == "tdb" {
				continue
			}
			add(fmt.Sprintf("%s %s-%s %s", m.Name, v.a(m.Start), v.a(m.End), rwx(m.Read, m.Write, m.Execute)))
		}
	case "symbols":
		for _, s := range r.Symbols {
			if s.Source == core.SourceImported {
				add(fmt.Sprintf("%s %s", v.a(s.Addr), s.Name))
			}
		}
	case "imports":
		for _, i := range r.Imports {
			add(stripVersion(i.Name))
		}
	case "exports":
		for _, e := range r.Exports {
			add(fmt.Sprintf("%s %s", v.a(e.Addr), e.Name))
		}
	case "functions":
		for _, f := range r.Functions {
			add(v.a(f.Entry))
		}
	case "function_names":
		for _, f := range r.Functions {
			if f.Source != core.SourceDefault {
				add(fmt.Sprintf("%s %s", v.a(f.Entry), f.Name))
			}
		}
	case "demangled_names":
		// Names a demangler applied: analysis-source symbols at addresses
		// that also carry a mangled imported symbol.
		mangled := map[core.Addr]bool{}
		for _, s := range r.Symbols {
			if s.Source == core.SourceImported && isMangled(s.Name) {
				mangled[s.Addr] = true
			}
		}
		for _, s := range r.Symbols {
			if s.Source != core.SourceAnalysis || !mangled[s.Addr] {
				continue
			}
			if s.Namespace != nil {
				add(fmt.Sprintf("%s %s::%s", v.a(s.Addr), *s.Namespace, s.Name))
			} else {
				add(fmt.Sprintf("%s %s", v.a(s.Addr), s.Name))
			}
		}
	case "function_bodies":
		for _, f := range r.Functions {
			body := make([]string, len(f.Body))
			for i, b := range f.Body {
				body[i] = v.a(b[0]) + "-" + v.a(b[1])
			}
			add(fmt.Sprintf("%s [%s]", v.a(f.Entry), strings.Join(body, ",")))
		}
	case "thunks":
		for _, f := range r.Functions {
			if f.Thunk {
				add(v.a(f.Entry))
			}
		}
	case "no_return":
		for _, f := range r.Functions {
			if f.NoReturn {
				add(v.a(f.Entry))
			}
		}
	case "instructions":
		for _, i := range r.Instructions {
			add(v.a(i.Addr))
		}
	case "instruction_details":
		for _, i := range r.Instructions {
			add(fmt.Sprintf("%s %d %s", v.a(i.Addr), i.Len, i.Mnemonic))
		}
	case "blocks":
		for _, b := range r.Blocks {
			add(v.a(b.Start) + "-" + v.a(b.End))
		}
	case "edges":
		for _, e := range r.Edges {
			add(fmt.Sprintf("%s->%s %s", v.a(e.From), v.a(e.To), debugKind(string(e.Kind))))
		}
	case "xrefs_flow":
		for _, x := range r.Xrefs {
			if isFlow(x.Kind) {
				add(fmt.Sprintf("%s->%s %s", v.a(x.From), v.a(x.To), debugKind(string(x.Kind))))
			}
		}
	case "xrefs_data":
		for _, x := range r.Xrefs {
			if !isFlow(x.Kind) && v.insnAddrs[x.From] {
				add(fmt.Sprintf("%s->%s", v.a(x.From), v.a(x.To)))
			}
		}
	case "xrefs_data_kinds":
		for _, x := range r.Xrefs {
			if !isFlow(x.Kind) && v.insnAddrs[x.From] {
				add(fmt.Sprintf("%s->%s %s", v.a(x.From), v.a(x.To), debugKind(string(x.Kind))))
			}
		}
	case "xrefs_from_data":
		for _, x := range r.Xrefs {
			if x.Kind == core.XrefData && !v.insnAddrs[x.From] {
				add(fmt.Sprintf("%s->%s", v.a(x.From), v.a(x.To)))
			}
		}
	}
	return out
}

// restrict keeps only the keys whose key(…) part exists on both sides, so a
// missing instruction or function is counted once (under instructions or
// functions), not twice (under the detail category).
func restrict(g, r map[string]struct{}, key func(string) string) {
	gk, rk := map[string]bool{}, map[string]bool{}
	for s := range g {
		gk[key(s)] = true
	}
	for s := range r {
		rk[key(s)] = true
	}
	for s := range g {
		if !rk[key(s)] {
			delete(g, s)
		}
	}
	for s := range r {
		if !gk[key(s)] {
			delete(r, s)
		}
	}
}

func firstField(s string) string {
	f, _, _ := strings.Cut(s, " ")
	return f
}

func dropLastField(s string) string {
	if i := strings.LastIndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return ""
}

// Compare compares a Ghidra export with an ra report of the same binary.
func Compare(binary string, ghidra, ra *core.AnalysisReport) *Comparison {
	bias := DetectBias(ghidra, ra)
	gv, rv := newView(ghidra, 0), newView(ra, bias)
	c := &Comparison{
		Binary: binary, GhidraProducer: ghidra.Producer, RaProducer: ra.Producer,
		Language: ghidra.Binary.Language, Bias: bias,
	}
	for _, cat := range Categories {
		g, r := gv.set(cat), rv.set(cat)
		switch cat {
		case "xrefs_data_kinds":
			restrict(g, r, dropLastField)
		case "instruction_details", "function_bodies":
			restrict(g, r, firstField)
		}
		c.Categories = append(c.Categories, FromSets(cat, g, r))
	}
	return c
}

// LoadReport loads a report; .gz files are decompressed (large Ghidra
// exports are committed gzipped).
func LoadReport(path string) (*core.AnalysisReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	defer f.Close()
	var rd io.Reader = f
	if filepath.Ext(path) == ".gz" {
		zr, err := gzip.NewReader(f)
		if err != nil {
			return nil, fmt.Errorf("decompressing %s: %w", path, err)
		}
		defer zr.Close()
		rd = zr
	}
	r := core.NewAnalysisReport()
	if err := json.NewDecoder(rd).Decode(r); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	r.Normalize()
	return r, nil
}

// ExpectedPath is the Ghidra export for corpus binary name in dir, gzipped
// or not; the second result is false when there is none.
func ExpectedPath(dir, name string) (string, bool) {
	for _, f := range []string{name + ".json.gz", name + ".json"} {
		p := filepath.Join(dir, f)
		if _, err := os.Stat(p); err == nil {
			return p, true
		}
	}
	return "", false
}
