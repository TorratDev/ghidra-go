package compare

import (
	"os"
	"strings"
	"testing"
)

func TestCodeSpan(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                         "`plain`",
		"":                              "``",
		"`vftable'":                     "`` `vftable' ``",
		"x `reference temporary' for y": "``x `reference temporary' for y``",
		"a``b":                          "```a``b```",
		"`a`":                           "`` `a` ``",
		"trailing`":                     "`` trailing` ``",
		"line\nbreak":                   "`line break`",
	} {
		if got := codeSpan(in); got != want {
			t.Errorf("codeSpan(%q) = %q, want %q", in, got, want)
		}
	}
}

// A span closes at the first backtick run of the same length as its fence, so
// the fence must differ from every run in the sample.
func TestCodeSpanNeverClosesEarly(t *testing.T) {
	for _, s := range []string{"`", "``", "```x", "a`b``c```d", "`vftable'", "``", "x` `y"} {
		span := codeSpan(s)
		fence := span[:len(span)-len(strings.TrimLeft(span, "`"))]
		inner := span[len(fence) : len(span)-len(fence)]
		if inner != strings.TrimSpace(inner) && !strings.Contains(inner, "`") {
			t.Errorf("padding without a backtick: %q", span)
		}
		for _, run := range strings.FieldsFunc(inner, func(r rune) bool { return r != '`' }) {
			if len(run) == len(fence) {
				t.Errorf("%q: run of %d backticks closes a fence of %d", s, len(run), len(fence))
			}
		}
	}
}

func goldenComparisons() ([]*Comparison, []Violation) {
	prog := &Comparison{Binary: "prog-x86_64", GhidraProducer: "ghidra 12.1.4", RaProducer: "ra-go (dev)", Language: "x86:LE:64:default", Bias: 0x100000}
	for i, name := range Categories {
		c := CategoryResult{Name: name, Matched: 10, Recall: 1, Precision: 1, GhidraOnlySamples: []string{}, RaOnlySamples: []string{}}
		switch name {
		case "xrefs_data_kinds":
			c.Matched, c.GhidraOnly, c.RaOnly = 8, 2, 1
			c.Recall, c.Precision = 0.8, 8.0/9
			c.GhidraOnlySamples = []string{"0x10->0x500 Read", "0x10->0x504 Data"}
			c.RaOnlySamples = []string{"0x10->0x500 Write"}
		case "memory_blocks":
			c.Matched, c.GhidraOnly = 21, 1
			c.Recall = 21.0 / 22
			c.GhidraOnlySamples = []string{".got.plt 0x4a9fe8-0x4aa0b0 r--"}
		case "xrefs_from_data":
			c.Matched, c.RaOnly, c.Precision = 3, 3, 0.5
			c.RaOnlySamples = []string{"0x600->0x700", "0x608->0x710", "0x610->0x720"}
		}
		_ = i
		prog.Categories = append(prog.Categories, c)
	}
	oracle := &Comparison{Binary: DemangleOracle, GhidraProducer: "ghidra 12.1.4", RaProducer: "ra-go (dev)", Language: "-",
		Categories: []CategoryResult{
			{Name: "GnuDemangler", Matched: 153, GhidraOnly: 3, RaOnly: 3, Recall: 153.0 / 156, Precision: 153.0 / 156,
				GhidraOnlySamples: []string{"_Z1fv => f"}, RaOnlySamples: []string{"_Z1fv => g"}},
			{Name: "MicrosoftDemangler", Matched: 1, GhidraOnly: 1, Recall: 0.5, Precision: 1,
				GhidraOnlySamples: []string{"??_7Foo@@6B@ => Foo::`vftable'", "??_R0?AVBar@@@8 => `reference temporary'{1}'"}, RaOnlySamples: []string{}},
		}}
	violations := []Violation{
		{Binary: "prog-x86_64", Category: "xrefs_data_kinds", Metric: "recall", Actual: 0.8, Required: 1},
		{Binary: "missing-bin", Metric: "result"},
		{Binary: DemangleOracle, Category: "RustDemangler", Metric: "result"},
	}
	return []*Comparison{prog, oracle}, violations
}

func TestMarkdownGolden(t *testing.T) {
	results, violations := goldenComparisons()
	got := Markdown(results, violations)
	const path = "testdata/report.golden.md"
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Errorf("report differs from %s (rerun with UPDATE_GOLDEN=1 to accept):\n%s", path, got)
	}
}

func TestMarkdownSummaryListsEveryCategory(t *testing.T) {
	results, _ := goldenComparisons()
	md := Markdown(results[:1], nil)
	header := strings.SplitN(strings.SplitN(md, "| binary |", 2)[1], "\n", 2)[0]
	for _, c := range Categories {
		if !strings.Contains(header, " "+c+" ") {
			t.Errorf("summary table has no %s column", c)
		}
	}
	if !strings.Contains(md, "**Gates: all passing.**") {
		t.Error("no violations should print the passing line")
	}
}

func TestMarkdownBacktickSamplesStayInOneSpan(t *testing.T) {
	results, _ := goldenComparisons()
	md := Markdown(results, nil)
	if !strings.Contains(md, "- ghidra-only: ``??_7Foo@@6B@ => Foo::`vftable'``, ``??_R0?AVBar@@@8 => `reference temporary'{1}'``") {
		t.Errorf("backtick samples are not fenced:\n%s", md)
	}
}
