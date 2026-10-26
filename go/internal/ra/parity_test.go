package ra

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// TestParityMatrixCoversJavaTree fails when rust-analysis/PARITY.md no longer
// matches what tools/gen_parity.py scans from the Ghidra Java tree, so a class
// missing from the matrix cannot pass silently.
func TestParityMatrixCoversJavaTree(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	script, err := filepath.Abs("../../../rust-analysis/tools/gen_parity.py")
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("python3", "-I", script, "--check").CombinedOutput()
	if err != nil {
		t.Fatalf("PARITY.md does not cover the Java scan:\n%s", out)
	}
}
