// Command ra is the Go port of the ra CLI: analyze, compare and regress.
// Instruction decoding goes through the Java SLEIGH bridge, set up by
// GHIDRA_INSTALL_DIR, RA_SLEIGH_BRIDGE_CP and RA_SLEIGH_BRIDGE_JAVA (or
// JAVA_HOME); see go/tools/sleigh-bridge/README.md.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/analysis"
	"github.com/TorratDev/ghidra/go/internal/ra/compare"
	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "analyze":
		err = runAnalyze(os.Args[2:])
	case "compare":
		err = runCompare(os.Args[2:])
	case "regress":
		err = runRegress(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ra analyze [flags] BINARY | ra compare [--json] GHIDRA RA | ra regress [flags]")
	os.Exit(2)
}

// bridgeFromEnv reads the bridge setup from the environment.
func bridgeFromEnv() (analysis.BridgeConfig, string, error) {
	cfg := analysis.BridgeConfig{
		Java:      os.Getenv("RA_SLEIGH_BRIDGE_JAVA"),
		ClassPath: os.Getenv("RA_SLEIGH_BRIDGE_CP"),
		GhidraDir: os.Getenv("GHIDRA_INSTALL_DIR"),
	}
	if cfg.Java == "" && os.Getenv("JAVA_HOME") != "" {
		cfg.Java = filepath.Join(os.Getenv("JAVA_HOME"), "bin", "java")
	}
	if cfg.Java == "" || cfg.ClassPath == "" || cfg.GhidraDir == "" {
		return cfg, "", fmt.Errorf("the SLEIGH bridge is not configured: set GHIDRA_INSTALL_DIR, RA_SLEIGH_BRIDGE_CP and RA_SLEIGH_BRIDGE_JAVA (or JAVA_HOME)")
	}
	return cfg, filepath.Join(cfg.GhidraDir, "Ghidra", "Processors"), nil
}

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	language := fs.String("language", "", "Ghidra language id (required for raw binaries)")
	output := fs.String("o", "", "write the report here instead of stdout")
	fs.StringVar(output, "output", "", "same as -o")
	noPatterns := fs.Bool("no-patterns", false, "skip the byte-pattern function start search")
	processors := fs.String("processors", "", "Ghidra Processors directory (default: GHIDRA_INSTALL_DIR/Ghidra/Processors)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ra analyze [flags] BINARY\nAnalyze a binary and print the normalized JSON report.")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	bridge, proc, err := bridgeFromEnv()
	if err != nil {
		return err
	}
	if *processors != "" {
		proc = *processors
	}
	opts := analysis.DefaultOptions()
	opts.Patterns = !*noPatterns
	report, err := analysis.AnalyzeFile(fs.Arg(0), *language, bridge, proc, opts)
	if err != nil {
		return err
	}
	return writeReport(report, *output)
}

func writeReport(r *core.AnalysisReport, output string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if output == "" {
		fmt.Println(string(b))
		return nil
	}
	return os.WriteFile(output, b, 0o644)
}

func runCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the full JSON comparison instead of markdown")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: ra compare [--json] GHIDRA RA\nCompare a Ghidra export with an ra report (.json or .json.gz).")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 2 {
		fs.Usage()
		os.Exit(2)
	}
	g, err := compare.LoadReport(fs.Arg(0))
	if err != nil {
		return err
	}
	r, err := compare.LoadReport(fs.Arg(1))
	if err != nil {
		return err
	}
	c := compare.Compare(comparisonName(fs.Arg(0)), g, r)
	if *asJSON {
		b, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}
	fmt.Print(compare.Markdown([]*compare.Comparison{c}, nil))
	return nil
}

// comparisonName is Rust's Path::file_stem: only the last extension goes, so
// x.json.gz is named "x.json" and x.json is "x".
func comparisonName(path string) string {
	base := filepath.Base(path)
	return strings.TrimSuffix(base, filepath.Ext(base))
}

func runRegress(args []string) error {
	fs := flag.NewFlagSet("regress", flag.ExitOnError)
	cfg := compare.Config{}
	fs.StringVar(&cfg.Corpus, "corpus", "compare/corpus/binaries", "directory of corpus binaries")
	fs.StringVar(&cfg.Expected, "expected", "compare/expected", "directory of Ghidra exports (and demangle/ghidra.json.gz)")
	fs.StringVar(&cfg.Thresholds, "thresholds", "compare/thresholds.toml", "thresholds file; it must exist unless --update-thresholds creates it")
	fs.StringVar(&cfg.ReportDir, "report-dir", "", "write per-binary reports, report.md and report.json here")
	fs.BoolVar(&cfg.UpdateThresholds, "update-thresholds", false, "raise thresholds to the current results (ratchet); also creates a missing thresholds file")
	fs.StringVar(&cfg.Filter, "filter", "", "substring match on the binary name: only matching corpus binaries are run and only matching gates are checked; \"demangle-oracle\" is included when the filter is a substring of it")
	processors := fs.String("processors", "", "Ghidra Processors directory (default: GHIDRA_INSTALL_DIR/Ghidra/Processors)")
	fs.Parse(args)
	bridge, proc, err := bridgeFromEnv()
	if err != nil {
		return err
	}
	if *processors != "" {
		proc = *processors
	}
	cfg.Analyze = func(path string) (*core.AnalysisReport, error) {
		return analysis.AnalyzeFile(path, "", bridge, proc, analysis.DefaultOptions())
	}
	out, err := compare.Regress(cfg)
	if err != nil {
		return err
	}
	md, _, _ := strings.Cut(out.Markdown, "## Mismatch samples")
	fmt.Print(md)
	for _, m := range out.MissingExpected {
		fmt.Fprintf(os.Stderr, "FAIL: no Ghidra export for corpus binary %s; run compare/ghidra_export.sh\n", m)
	}
	if out.OracleMissing {
		fmt.Fprintf(os.Stderr, "FAIL: demangle oracle %s is missing; run compare/ghidra_demangle.sh\n",
			filepath.Join(cfg.Expected, compare.DemangleOraclePath))
	}
	if n := out.Failures(); n > 0 {
		return fmt.Errorf("%d failure(s): %d gate violation(s), %d corpus binary(ies) without an export, oracle missing: %t",
			n, len(out.Violations), len(out.MissingExpected), out.OracleMissing)
	}
	return nil
}
