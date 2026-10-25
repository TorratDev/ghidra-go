package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

func TestComparisonName(t *testing.T) {
	for in, want := range map[string]string{
		"compare/expected/basic-x86_64-gcc-O2.json.gz": "basic-x86_64-gcc-O2.json",
		"basic.json": "basic",
		"dir/noext":  "noext",
		"a.b.c":      "a.b",
	} {
		if got := comparisonName(in); got != want {
			t.Errorf("comparisonName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBridgeFromEnv(t *testing.T) {
	for _, k := range []string{"RA_SLEIGH_BRIDGE_JAVA", "RA_SLEIGH_BRIDGE_CP", "GHIDRA_INSTALL_DIR", "JAVA_HOME"} {
		t.Setenv(k, "")
	}
	if _, _, err := bridgeFromEnv(); err == nil {
		t.Fatal("no error without a bridge setup")
	}
	t.Setenv("JAVA_HOME", "/jdk")
	t.Setenv("RA_SLEIGH_BRIDGE_CP", "/cp")
	t.Setenv("GHIDRA_INSTALL_DIR", "/g")
	cfg, proc, err := bridgeFromEnv()
	if err != nil || cfg.Java != "/jdk/bin/java" || proc != "/g/Ghidra/Processors" {
		t.Fatalf("got %+v %q %v", cfg, proc, err)
	}
}

func TestWriteReportOutput(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.json")
	if err := writeReport(core.NewAnalysisReport(), out); err != nil {
		t.Fatal(err)
	}
	var r core.AnalysisReport
	if b, err := os.ReadFile(out); err != nil || json.Unmarshal(b, &r) != nil {
		t.Fatalf("report not written as JSON: %v", err)
	}
}
