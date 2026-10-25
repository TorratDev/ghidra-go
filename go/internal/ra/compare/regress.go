package compare

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/demangle"
)

// DemangleOracle is the pseudo-binary under which demangler agreement is
// reported and gated (its categories are Ghidra demangler classes).
const DemangleOracle = "demangle-oracle"

// DemangleOraclePath is the oracle's location below the expected directory.
const DemangleOraclePath = "demangle/ghidra.json.gz"

// RaProducer names this implementation in reports.
const RaProducer = "ra-go (dev)"

// DemangleComparison compares ra's demanglers with Ghidra's on the oracle
// written by compare/ghidra_demangle.sh. For each Ghidra demangler class the
// keys are `mangled => namespace::name`; recall is agreement over the names
// Ghidra demangled, precision over the names ra demangled. The Go port has
// no MSVC demangler yet (#17), so MicrosoftDemangler has no result and its
// gate fails.
func DemangleComparison(oraclePath string) (*Comparison, error) {
	f, err := os.Open(oraclePath)
	if err != nil {
		return nil, fmt.Errorf("reading demangle oracle: %w", err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("decompressing %s: %w", oraclePath, err)
	}
	defer zr.Close()
	var o struct {
		Producer string `json:"producer"`
		Results  []struct {
			Mangled    string `json:"mangled"`
			Demanglers []struct {
				Demangler string  `json:"demangler"`
				Name      string  `json:"name"`
				Namespace *string `json:"namespace"`
			} `json:"demanglers"`
		} `json:"results"`
	}
	if err := json.NewDecoder(zr).Decode(&o); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", oraclePath, err)
	}
	key := func(m string, ns *string, n string) string {
		if ns != nil {
			return fmt.Sprintf("%s => %s::%s", m, *ns, n)
		}
		return fmt.Sprintf("%s => %s", m, n)
	}
	c := &Comparison{Binary: DemangleOracle, GhidraProducer: o.Producer, RaProducer: RaProducer, Language: "-"}
	for _, scheme := range []demangle.Scheme{demangle.Gnu, demangle.Rust} {
		class := scheme.GhidraClass()
		g, r := map[string]struct{}{}, map[string]struct{}{}
		for _, e := range o.Results {
			for _, x := range e.Demanglers {
				if x.Demangler == class {
					g[key(e.Mangled, x.Namespace, x.Name)] = struct{}{}
					break
				}
			}
			if d := demangle.DemangleWith(scheme, e.Mangled); d != nil {
				r[key(e.Mangled, d.NamespaceString(), d.Name)] = struct{}{}
			}
		}
		c.Categories = append(c.Categories, FromSets(class, g, r))
	}
	return c, nil
}

// Analyzer produces ra's report for one corpus binary.
type Analyzer func(path string) (*core.AnalysisReport, error)

type Config struct {
	Corpus, Expected, Thresholds string
	// ReportDir, when set, receives <binary>.ra.json, report.md and report.json.
	ReportDir string
	// UpdateThresholds ratchets the gates to the current results; it is also
	// the only way to create a missing thresholds file.
	UpdateThresholds bool
	// Filter keeps the binaries whose name contains it ("demangle-oracle"
	// included); the gates are checked for the same set.
	Filter string
	// Analyze is nil while the Go analysis side does not exist: no binary then
	// has a result, and every gated binary is a violation.
	Analyze Analyzer
}

type Outcome struct {
	Results    []*Comparison
	Violations []Violation
	// MissingExpected lists corpus binaries with no Ghidra export.
	MissingExpected []string
	// OracleMissing is set when the demangle oracle is selected by the filter
	// but the file does not exist.
	OracleMissing bool
	Markdown      string
}

// Failures counts everything that must fail the run.
func (o *Outcome) Failures() int {
	n := len(o.Violations) + len(o.MissingExpected)
	if o.OracleMissing {
		n++
	}
	return n
}

// Regress analyzes every corpus binary, compares it with its Ghidra export,
// and checks (or ratchets) the thresholds. Nothing that is missing is
// skipped: see Outcome.Failures. A missing thresholds file is an error unless
// UpdateThresholds asks to create it.
func Regress(cfg Config) (*Outcome, error) {
	entries, err := os.ReadDir(cfg.Corpus)
	if err != nil {
		return nil, fmt.Errorf("reading corpus: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) != ".log" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := &Outcome{}
	for _, name := range names {
		if !strings.Contains(name, cfg.Filter) {
			continue
		}
		expected, ok := ExpectedPath(cfg.Expected, name)
		if !ok {
			out.MissingExpected = append(out.MissingExpected, name)
			continue
		}
		ghidra, err := LoadReport(expected)
		if err != nil {
			return nil, err
		}
		if cfg.Analyze == nil {
			continue
		}
		ours, err := cfg.Analyze(filepath.Join(cfg.Corpus, name))
		if err != nil {
			return nil, fmt.Errorf("analyzing %s: %w", name, err)
		}
		if cfg.ReportDir != "" {
			if err := writeJSON(filepath.Join(cfg.ReportDir, name+".ra.json"), ours); err != nil {
				return nil, err
			}
		}
		out.Results = append(out.Results, Compare(name, ghidra, ours))
	}
	if strings.Contains(DemangleOracle, cfg.Filter) {
		path := filepath.Join(cfg.Expected, DemangleOraclePath)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			out.OracleMissing = true
		} else {
			c, err := DemangleComparison(path)
			if err != nil {
				return nil, err
			}
			out.Results = append(out.Results, c)
		}
	}
	th, err := LoadThresholds(cfg.Thresholds)
	switch {
	case errors.Is(err, ErrNoThresholds) && cfg.UpdateThresholds:
		th = &Thresholds{Binaries: map[string]map[string]Gate{}}
	case err != nil:
		if errors.Is(err, ErrNoThresholds) {
			err = fmt.Errorf("%w (pass --update-thresholds to create it)", err)
		}
		return nil, err
	}
	if cfg.UpdateThresholds {
		for _, c := range out.Results {
			th.Ratchet(c)
		}
		if err := th.Save(cfg.Thresholds); err != nil {
			return nil, err
		}
	}
	out.Violations = th.Check(out.Results, cfg.Filter)
	out.Markdown = Markdown(out.Results, out.Violations)
	if cfg.ReportDir != "" {
		if err := os.WriteFile(filepath.Join(cfg.ReportDir, "report.md"), []byte(out.Markdown), 0o644); err != nil {
			return nil, err
		}
		if err := writeJSON(filepath.Join(cfg.ReportDir, "report.json"), out.Results); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
