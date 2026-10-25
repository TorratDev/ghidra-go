package compare

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

const realExpected = "../../../../rust-analysis/compare/expected"

// fixture is a one-binary corpus with its export, oracle and thresholds.
type fixture struct {
	cfg  Config
	root string
}

func writeReport(t *testing.T, path string, r *core.AnalysisReport) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"corpus", "expected/demangle"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "corpus/prog"), []byte("elf"), 0o755); err != nil {
		t.Fatal(err)
	}
	// a build log in the corpus directory is not a binary
	os.WriteFile(filepath.Join(root, "corpus/prog.log"), []byte("log"), 0o644)
	writeReport(t, filepath.Join(root, "expected/prog.json"), report(0, 0x1000, 0x1010))
	f := &fixture{root: root, cfg: Config{
		Corpus:     filepath.Join(root, "corpus"),
		Expected:   filepath.Join(root, "expected"),
		Thresholds: filepath.Join(root, "thresholds.toml"),
		Filter:     "prog", // keeps the oracle out unless a test wants it
		Analyze: func(string) (*core.AnalysisReport, error) {
			return report(0, 0x1000, 0x1010), nil
		},
	}}
	return f
}

func (f *fixture) thresholds(t *testing.T, th *Thresholds) {
	t.Helper()
	if err := th.Save(f.cfg.Thresholds); err != nil {
		t.Fatal(err)
	}
}

func perfectGates() *Thresholds {
	g := map[string]Gate{}
	for _, c := range Categories {
		g[c] = Gate{1, 1}
	}
	return &Thresholds{Binaries: map[string]map[string]Gate{"prog": g}}
}

func TestRegressPasses(t *testing.T) {
	f := newFixture(t)
	f.thresholds(t, perfectGates())
	f.cfg.ReportDir = filepath.Join(f.root, "report")
	out, err := Regress(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if out.Failures() != 0 || len(out.Results) != 1 || !strings.Contains(out.Markdown, "**Gates: all passing.**") {
		t.Errorf("%d failures, %v\n%s", out.Failures(), out.Violations, out.Markdown)
	}
	for _, name := range []string{"prog.ra.json", "report.md", "report.json"} {
		if _, err := os.Stat(filepath.Join(f.cfg.ReportDir, name)); err != nil {
			t.Error(err)
		}
	}
}

func TestRegressMissingThresholdsFile(t *testing.T) {
	f := newFixture(t)
	_, err := Regress(f.cfg)
	if !errors.Is(err, ErrNoThresholds) || !strings.Contains(err.Error(), "--update-thresholds") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(f.cfg.Thresholds); err == nil {
		t.Error("the file was created without being asked to")
	}
	// asking for it creates it, from the current results
	f.cfg.UpdateThresholds = true
	out, err := Regress(f.cfg)
	if err != nil || out.Failures() != 0 {
		t.Fatalf("%v %v", err, out)
	}
	th, err := LoadThresholds(f.cfg.Thresholds)
	if err != nil || len(th.Binaries["prog"]) != len(Categories) {
		t.Errorf("created thresholds: %v %+v", err, th)
	}
}

func TestRegressNoAnalysisFailsEveryGate(t *testing.T) {
	f := newFixture(t)
	f.thresholds(t, perfectGates())
	f.cfg.Analyze = nil
	out, err := Regress(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 0 || len(out.Violations) != 1 || out.Violations[0].String() != "prog: gated binary has no result" {
		t.Errorf("%v", out.Violations)
	}
	if out.Failures() == 0 {
		t.Error("a gated binary with no result passed")
	}
}

func TestRegressMissingCategoryIsAViolation(t *testing.T) {
	f := newFixture(t)
	th := perfectGates()
	th.Binaries["prog"]["not_a_category"] = Gate{1, 1}
	f.thresholds(t, th)
	out, err := Regress(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Violations) != 1 || out.Violations[0].String() != "prog / not_a_category: gated category has no result" {
		t.Errorf("%v", out.Violations)
	}
}

func TestRegressCorpusBinaryWithoutExportFails(t *testing.T) {
	f := newFixture(t)
	f.thresholds(t, perfectGates())
	os.WriteFile(filepath.Join(f.root, "corpus/prog2"), []byte("elf"), 0o755)
	f.cfg.Filter = "prog"
	out, err := Regress(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.MissingExpected) != 1 || out.MissingExpected[0] != "prog2" || out.Failures() != 1 {
		t.Errorf("missing %v, failures %d", out.MissingExpected, out.Failures())
	}
}

func TestRegressFilterLimitsBinariesAndGates(t *testing.T) {
	f := newFixture(t)
	th := perfectGates()
	th.Binaries["other"] = map[string]Gate{"functions": {1, 1}}
	f.thresholds(t, th)
	os.WriteFile(filepath.Join(f.root, "corpus/other"), []byte("elf"), 0o755) // no export: filtered out
	out, err := Regress(f.cfg)                                                // filter "prog"
	if err != nil || out.Failures() != 0 || len(out.MissingExpected) != 0 {
		t.Fatalf("%v %v %v", err, out.Violations, out.MissingExpected)
	}
	f.cfg.Filter = ""
	if out, _ = Regress(f.cfg); out.Failures() == 0 {
		t.Error("without the filter the other binary must fail")
	}
}

func TestRegressMissingOracleFails(t *testing.T) {
	f := newFixture(t)
	f.thresholds(t, perfectGates())
	f.cfg.Filter = ""
	out, err := Regress(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !out.OracleMissing || out.Failures() != 1 {
		t.Errorf("oracle missing %t, failures %d", out.OracleMissing, out.Failures())
	}
	// a filter that does not match demangle-oracle does not need it
	f.cfg.Filter = "prog"
	if out, _ = Regress(f.cfg); out.OracleMissing {
		t.Error("oracle required by a filter that excludes it")
	}
	// "demangle-oracle" is selected by any substring of it
	f.cfg.Filter = "oracle"
	if out, _ = Regress(f.cfg); !out.OracleMissing {
		t.Error("filter \"oracle\" should include the demangle oracle")
	}
}

func TestDemangleOracleComparison(t *testing.T) {
	path := filepath.Join(realExpected, DemangleOraclePath)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("oracle not available: %v", err)
	}
	c, err := DemangleComparison(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Binary != DemangleOracle || c.GhidraProducer != "ghidra 12.1.4" || len(c.Categories) != 2 {
		t.Fatalf("%+v", c)
	}
	gnu, rust := c.Category("GnuDemangler"), c.Category("RustDemangler")
	if gnu.Matched != 153 || gnu.GhidraOnly != 3 || gnu.RaOnly != 3 || rust.Matched != 91 || rust.GhidraOnly != 0 || rust.RaOnly != 0 {
		t.Errorf("gnu %+v rust %+v", gnu, rust)
	}
	if c.Category("MicrosoftDemangler") != nil {
		t.Error("no MSVC demangler yet (#17)")
	}
}

// A corrupt oracle is an error, not an empty comparison.
func TestDemangleOracleCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ghidra.json.gz")
	f, _ := os.Create(p)
	zw := gzip.NewWriter(f)
	zw.Write([]byte("{not json"))
	zw.Close()
	f.Close()
	if _, err := DemangleComparison(p); err == nil {
		t.Error("corrupt oracle accepted")
	}
	if _, err := DemangleComparison(filepath.Join(t.TempDir(), "absent.gz")); err == nil {
		t.Error("absent oracle accepted")
	}
}

func TestLoadReportGzipAndExpectedPath(t *testing.T) {
	dir := t.TempDir()
	r := report(0, 0x1000)
	b, _ := json.Marshal(r)
	f, _ := os.Create(filepath.Join(dir, "a.json.gz"))
	zw := gzip.NewWriter(f)
	zw.Write(b)
	zw.Close()
	f.Close()
	os.WriteFile(filepath.Join(dir, "b.json"), b, 0o644)
	if p, ok := ExpectedPath(dir, "a"); !ok || filepath.Base(p) != "a.json.gz" {
		t.Errorf("%q %v", p, ok)
	}
	if p, ok := ExpectedPath(dir, "b"); !ok || filepath.Base(p) != "b.json" {
		t.Errorf("%q %v", p, ok)
	}
	if _, ok := ExpectedPath(dir, "c"); ok {
		t.Error("c found")
	}
	for _, n := range []string{"a.json.gz", "b.json"} {
		got, err := LoadReport(filepath.Join(dir, n))
		if err != nil || len(got.Functions) != 1 || got.Functions[0].Entry != 0x1000 {
			t.Errorf("%s: %v %+v", n, err, got)
		}
	}
	if _, err := LoadReport(filepath.Join(dir, "none.json")); err == nil {
		t.Error("missing report accepted")
	}
}

// The committed Ghidra export compared with itself is a perfect score in every
// category: the comparison reads the real export format.
func TestCommittedExportAgainstItself(t *testing.T) {
	p, ok := ExpectedPath(realExpected, "basic-x86_64-gcc-O2-stripped")
	if !ok {
		t.Skip("committed export not available")
	}
	g, err := LoadReport(p)
	if err != nil {
		t.Fatal(err)
	}
	c := Compare("basic-x86_64-gcc-O2-stripped", g, g)
	for _, r := range c.Categories {
		if r.Recall != 1 || r.Precision != 1 {
			t.Errorf("%s: %+v", r.Name, r)
		}
	}
	if len(g.Functions) == 0 || c.Category("functions").Matched != len(g.Functions) {
		t.Errorf("functions matched %d of %d", c.Category("functions").Matched, len(g.Functions))
	}
}
