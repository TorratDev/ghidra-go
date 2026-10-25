package analysis

import "testing"

func TestPatternsDir(t *testing.T) {
	if got := PatternsDir("/p", "AARCH64:LE:64:v8A"); got != "/p/AARCH64/data/patterns" {
		t.Fatal(got)
	}
}
