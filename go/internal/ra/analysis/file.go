package analysis

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
	"github.com/TorratDev/ghidra/go/internal/ra/loader"
)

// AnalyzeFile loads, analyzes and reports one binary through the Java bridge
// (the Go counterpart of ra_cli::analyze_file). bridge supplies Java,
// ClassPath and GhidraDir; the language and compiler come from the binary.
// processors is Ghidra's Processors directory, for the pattern files; empty
// or opts.Patterns false disables the pattern pass.
func AnalyzeFile(path, language string, bridge BridgeConfig, processors string, opts Options) (*core.AnalysisReport, error) {
	prog, err := loader.LoadPath(path, language)
	if err != nil {
		return nil, err
	}
	bridge.LanguageID = prog.Language
	if bridge.Compiler == "" {
		bridge.Compiler = defaultCompiler(prog.Format)
	}
	dec, lang, err := StartBridge(bridge)
	if err != nil && bridge.Compiler != "" {
		// shortcut: any failure retries with the language's default compiler
		// (AARCH64 has no "gcc" spec); tell the two apart if it hides errors.
		bridge.Compiler = ""
		dec, lang, err = StartBridge(bridge)
	}
	if err != nil {
		return nil, fmt.Errorf("loading language %s: %w", prog.Language, err)
	}
	defer dec.Close()
	l := &Language{Language: *lang}
	if processors != "" && opts.Patterns {
		l.PatternsDir = PatternsDir(processors, prog.Language)
	}
	report := Report(prog, Analyze(prog, l, dec, opts))
	report.Binary.Path = filepath.Base(path)
	return report, nil
}

// PatternsDir is the data/patterns directory of the processor named by the
// first field of a language id ("x86:LE:64:default" -> processors/x86).
func PatternsDir(processors, languageID string) string {
	proc, _, _ := strings.Cut(languageID, ":")
	return filepath.Join(processors, proc, "data", "patterns")
}
