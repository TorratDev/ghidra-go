package main

import "testing"

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
