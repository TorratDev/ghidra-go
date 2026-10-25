// Command ra is the Go port of the ra CLI. So far it has the compare and
// regress subcommands; analysis is not ported yet.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/compare"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
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
	fmt.Fprintln(os.Stderr, "usage: ra compare [--json] GHIDRA RA | ra regress [flags]")
	os.Exit(2)
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
	base := filepath.Base(fs.Arg(0))
	name := strings.TrimSuffix(strings.TrimSuffix(base, ".gz"), ".json")
	c := compare.Compare(name, g, r)
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

func runRegress(args []string) error {
	fs := flag.NewFlagSet("regress", flag.ExitOnError)
	cfg := compare.Config{}
	fs.StringVar(&cfg.Corpus, "corpus", "compare/corpus/binaries", "directory of corpus binaries")
	fs.StringVar(&cfg.Expected, "expected", "compare/expected", "directory of Ghidra exports (and demangle/ghidra.json.gz)")
	fs.StringVar(&cfg.Thresholds, "thresholds", "compare/thresholds.toml", "thresholds file; it must exist unless --update-thresholds creates it")
	fs.StringVar(&cfg.ReportDir, "report-dir", "", "write per-binary reports, report.md and report.json here")
	fs.BoolVar(&cfg.UpdateThresholds, "update-thresholds", false, "raise thresholds to the current results (ratchet); also creates a missing thresholds file")
	fs.StringVar(&cfg.Filter, "filter", "", "substring match on the binary name: only matching corpus binaries are run and only matching gates are checked; \"demangle-oracle\" is included when the filter is a substring of it")
	fs.Parse(args)
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
