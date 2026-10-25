package compare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

// TestParityWithRustRegress checks the Go comparison against the Rust one on
// the same inputs. Set RA_RUST_REPORT_DIR to the --report-dir of a Rust
// `ra regress` run over the corpus (it holds <binary>.ra.json files and
// report.json); the committed Ghidra exports are the other side. Every
// category of every binary must agree on matched, ghidra-only and ra-only
// counts and on the bias, and the Go regress over those reports must give the
// same gate verdicts as the committed thresholds.
func TestParityWithRustRegress(t *testing.T) {
	dir := os.Getenv("RA_RUST_REPORT_DIR")
	if dir == "" {
		t.Skip("RA_RUST_REPORT_DIR not set")
	}
	b, err := os.ReadFile(filepath.Join(dir, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var rust []*Comparison
	if err := json.Unmarshal(b, &rust); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, rc := range rust {
		if rc.Binary == DemangleOracle {
			continue
		}
		p, ok := ExpectedPath(realExpected, rc.Binary)
		if !ok {
			t.Fatalf("no export for %s", rc.Binary)
		}
		g, err := LoadReport(p)
		if err != nil {
			t.Fatal(err)
		}
		ours, err := LoadReport(filepath.Join(dir, rc.Binary+".ra.json"))
		if err != nil {
			t.Fatal(err)
		}
		c := Compare(rc.Binary, g, ours)
		if c.Bias != rc.Bias || c.Language != rc.Language || len(c.Categories) != len(rc.Categories) {
			t.Errorf("%s: bias %#x/%#x language %q/%q", rc.Binary, c.Bias, rc.Bias, c.Language, rc.Language)
		}
		for i, want := range rc.Categories {
			got := c.Categories[i]
			if got.Name != want.Name || got.Matched != want.Matched || got.GhidraOnly != want.GhidraOnly || got.RaOnly != want.RaOnly {
				t.Errorf("%s / %s: go %d/%d/%d, rust %d/%d/%d", rc.Binary, want.Name,
					got.Matched, got.GhidraOnly, got.RaOnly, want.Matched, want.GhidraOnly, want.RaOnly)
			}
			if got.Recall != want.Recall || got.Precision != want.Precision {
				t.Errorf("%s / %s: recall %v/%v precision %v/%v", rc.Binary, want.Name, got.Recall, want.Recall, got.Precision, want.Precision)
			}
			if !equalStrings(got.GhidraOnlySamples, want.GhidraOnlySamples) || !equalStrings(got.RaOnlySamples, want.RaOnlySamples) {
				t.Errorf("%s / %s: samples differ", rc.Binary, want.Name)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no binaries compared")
	}
	t.Logf("%d binaries agree with the Rust comparison", checked)

	// Gate the Rust reports with the committed thresholds through Regress.
	th := "../../../../rust-analysis/compare/thresholds.toml"
	out, err := Regress(Config{
		Corpus: "../../../../rust-analysis/compare/corpus/binaries", Expected: realExpected, Thresholds: th,
		Analyze: func(path string) (*core.AnalysisReport, error) {
			return LoadReport(filepath.Join(dir, filepath.Base(path)+".ra.json"))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Known gaps only: the four PE binaries are not in the corpus (#20) and
	// the Go port has no MSVC demangler (#17).
	want := map[string]bool{
		"cxx-msvc-i386.dll: gated binary has no result (the PE binaries are not in the corpus yet, #20)":                   true,
		"cxx-msvc-x86_64.dll: gated binary has no result (the PE binaries are not in the corpus yet, #20)":                 true,
		"freestanding-i386-pe-clang-O2.exe: gated binary has no result (the PE binaries are not in the corpus yet, #20)":   true,
		"freestanding-x86_64-pe-clang-O2.exe: gated binary has no result (the PE binaries are not in the corpus yet, #20)": true,
		"demangle-oracle / MicrosoftDemangler: gated category has no result (the Go port has no MSVC demangler yet, #17)":  true,
	}
	got := map[string]bool{}
	for _, v := range out.Violations {
		got[v.String()] = true
	}
	for v := range got {
		if !want[v] {
			t.Errorf("unexpected violation: %s", v)
		}
	}
	for v := range want {
		if !got[v] {
			t.Errorf("expected known violation is gone: %s", v)
		}
	}
	if len(out.MissingExpected) != 0 || out.OracleMissing {
		t.Errorf("missing exports %v, oracle missing %t", out.MissingExpected, out.OracleMissing)
	}
	t.Logf("regress over the Rust reports: %d results, %d violations, %d missing exports", len(out.Results), len(out.Violations), len(out.MissingExpected))
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
