package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TorratDev/ghidra/go/internal/ra/compare"
	"github.com/TorratDev/ghidra/go/internal/ra/loader"
)

// TestMeasureAgainstGhidraExports runs the analysis through the Java bridge on
// corpus binaries and compares with the committed Ghidra exports. It needs
// GHIDRA_INSTALL_DIR, RA_SLEIGH_BRIDGE_JAVA and RA_SLEIGH_BRIDGE_CP (see
// go/tools/sleigh-bridge/README.md) and RA_MEASURE (comma separated corpus
// binary names, or "all-x86_64"); it only logs, the thresholds are the gate.
func TestMeasureAgainstGhidraExports(t *testing.T) {
	java, cp, ghidra := os.Getenv("RA_SLEIGH_BRIDGE_JAVA"), os.Getenv("RA_SLEIGH_BRIDGE_CP"), os.Getenv("GHIDRA_INSTALL_DIR")
	names := os.Getenv("RA_MEASURE")
	if java == "" || cp == "" || ghidra == "" || names == "" {
		t.Skip("bridge environment or RA_MEASURE not set")
	}
	const dir = "../../../../rust-analysis/compare"
	for _, name := range strings.Split(names, ",") {
		t.Run(name, func(t *testing.T) {
			prog, err := loader.LoadPath(filepath.Join(dir, "corpus/binaries", name), "")
			if err != nil {
				t.Skip(err)
			}
			exp, ok := compare.ExpectedPath(filepath.Join(dir, "expected"), name)
			if !ok {
				t.Skip("no export")
			}
			want, err := compare.LoadReport(exp)
			if err != nil {
				t.Fatal(err)
			}
			dec, lang, err := StartBridge(BridgeConfig{Java: java, ClassPath: cp, GhidraDir: ghidra, LanguageID: prog.Language, Compiler: "gcc"})
			if err != nil {
				t.Fatal(err)
			}
			defer dec.Close()
			start := time.Now()
			an := Analyze(prog, &Language{Language: *lang, PatternsDir: filepath.Join("../../../../Ghidra/Processors/x86/data/patterns")},
				dec, DefaultOptions())
			rep := Report(prog, an)
			c := compare.Compare(name, want, rep)
			t.Logf("%s: %d instructions, %d functions, %d bridge calls, %v", name, len(an.Insns), len(an.Functions), dec.Calls, time.Since(start).Round(time.Millisecond))
			for _, cat := range []string{"functions", "function_names", "thunks", "no_return", "instructions", "instruction_details", "function_bodies", "blocks", "edges", "xrefs_flow", "xrefs_data", "symbols", "imports"} {
				r := c.Category(cat)
				t.Logf("  %-20s recall %.3f precision %.3f (matched %d, ghidra-only %d, ra-only %d)", cat, r.Recall, r.Precision, r.Matched, r.GhidraOnly, r.RaOnly)
			}
			for _, d := range an.Diagnostics {
				t.Logf("  note: %s", d)
			}
		})
	}
}
