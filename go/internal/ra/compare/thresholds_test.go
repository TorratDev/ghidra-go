package compare

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestFloor3Boundary(t *testing.T) {
	for _, c := range []struct{ in, want float64 }{
		{1.0, 1.0}, {0, 0}, {0.5, 0.5},
		{0.9999, 0.999}, // a floor, not a rounding
		{0.9995, 0.999}, // never rounds up
		{2.0 / 3, 0.666},
		{153.0 / 156, 0.98},
		{0.974, 0.974}, // gates written by floor3 are fixed points
		{0.916, 0.916},
		{math.Nextafter(0.974, 0), 0.973}, // one ulp under is below the gate
	} {
		if got := floor3(c.in); got != c.want {
			t.Errorf("floor3(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func cmp(binary string, cats ...CategoryResult) *Comparison {
	return &Comparison{Binary: binary, Categories: cats}
}

func cat(name string, recall, precision float64) CategoryResult {
	return CategoryResult{Name: name, Recall: recall, Precision: precision}
}

func gates(binary string, g map[string]Gate) *Thresholds {
	return &Thresholds{Binaries: map[string]map[string]Gate{binary: g}}
}

func TestCheckGateBoundary(t *testing.T) {
	th := gates("b", map[string]Gate{"functions": {0.974, 0.98}})
	if v := th.Check([]*Comparison{cmp("b", cat("functions", 0.974, 0.98))}, ""); len(v) != 0 {
		t.Errorf("on the gate: %v", v)
	}
	if v := th.Check([]*Comparison{cmp("b", cat("functions", 0.9749999, 0.9809))}, ""); len(v) != 0 {
		t.Errorf("floor3 of 0.9749999 is 0.974: %v", v)
	}
	v := th.Check([]*Comparison{cmp("b", cat("functions", 0.9739, 0.9))}, "")
	if len(v) != 2 || v[0].Metric != "recall" || v[1].Metric != "precision" {
		t.Errorf("%v", v)
	}
	if got := v[0].String(); got != "b / functions: recall 0.9739 < required 0.9740" {
		t.Error(got)
	}
}

func TestCheckMissingBinaryAndCategory(t *testing.T) {
	th := &Thresholds{Binaries: map[string]map[string]Gate{
		"has":     {"functions": {1, 1}, "blocks": {1, 1}},
		"missing": {"functions": {1, 1}},
		"other":   {"functions": {1, 1}},
	}}
	results := []*Comparison{cmp("has", cat("functions", 1, 1))} // no blocks category
	v := th.Check(results, "")
	got := map[string]bool{}
	for _, x := range v {
		got[x.String()] = true
		if x.Metric != "result" {
			t.Errorf("unexpected %v", x)
		}
	}
	for _, want := range []string{
		"has / blocks: gated category has no result",
		"missing: gated binary has no result",
		"other: gated binary has no result",
	} {
		if !got[want] {
			t.Errorf("missing violation %q in %v", want, got)
		}
	}
	if len(v) != 3 {
		t.Errorf("%v", v)
	}
	// the filter limits the gates that are checked, by substring
	v = th.Check(results, "miss")
	if len(v) != 1 || v[0].Binary != "missing" {
		t.Errorf("filtered %v", v)
	}
	// a result without gates is not an error
	if v := (&Thresholds{}).Check(results, ""); len(v) != 0 {
		t.Errorf("%v", v)
	}
}

func TestRatchetOnlyRaises(t *testing.T) {
	th := &Thresholds{}
	th.Ratchet(cmp("t", cat("functions", 0.5, 2.0/3)))
	if g := th.Binaries["t"]["functions"]; g.Recall != 0.5 || g.Precision != 0.666 {
		t.Fatalf("%+v", g)
	}
	worse := cmp("t", cat("functions", 0.1, 0.9999))
	th.Ratchet(worse)
	g := th.Binaries["t"]["functions"]
	if g.Recall != 0.5 || g.Precision != 0.999 { // max(old gate, floor3(current))
		t.Errorf("%+v", g)
	}
	// the check runs after the ratchet and still fails on the lowered recall
	v := th.Check([]*Comparison{worse}, "")
	if len(v) != 1 || v[0].Metric != "recall" {
		t.Errorf("%v", v)
	}
}

func TestLoadThresholdsMissingFile(t *testing.T) {
	_, err := LoadThresholds(filepath.Join(t.TempDir(), "nope.toml"))
	if !errors.Is(err, ErrNoThresholds) {
		t.Errorf("err %v", err)
	}
}

func TestThresholdsSaveLoadRoundTrip(t *testing.T) {
	th := &Thresholds{Binaries: map[string]map[string]Gate{
		"plain":      {"blocks": {1, 0.916}},
		"with.dot":   {"edges": {0, 0.5}},
		"demangle-x": {"GnuDemangler": {0.974, 0.98}},
	}}
	p := filepath.Join(t.TempDir(), "t.toml")
	if err := th.Save(p); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	want := thresholdsHeader + "[binaries.demangle-x.GnuDemangler]\nrecall = 0.974\nprecision = 0.98\n\n" +
		"[binaries.plain.blocks]\nrecall = 1.0\nprecision = 0.916\n\n" +
		"[binaries.\"with.dot\".edges]\nrecall = 0.0\nprecision = 0.5\n"
	if string(b) != want {
		t.Errorf("saved:\n%s\nwant:\n%s", b, want)
	}
	back, err := LoadThresholds(p)
	if err != nil || back.Binaries["with.dot"]["edges"] != (Gate{0, 0.5}) || back.Binaries["plain"]["blocks"].Precision != 0.916 {
		t.Errorf("%v %+v", err, back)
	}
}

// Loading and saving the committed file reproduces it byte for byte, so a
// ratchet run changes only the gates that rose.
func TestCommittedThresholdsRoundTrip(t *testing.T) {
	const committed = "../../../../rust-analysis/compare/thresholds.toml"
	orig, err := os.ReadFile(committed)
	if err != nil {
		t.Skipf("committed thresholds not available: %v", err)
	}
	th, err := LoadThresholds(committed)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "t.toml")
	if err := th.Save(p); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); string(got) != string(orig) {
		t.Error("round trip changed the committed thresholds file")
	}
}

func TestParseThresholdsRejectsMalformed(t *testing.T) {
	ok := "[binaries.a.b]\nrecall = 1.0\nprecision = 0.5\n"
	if th, err := parseThresholds([]byte("# c\n\n" + ok + "\n[binaries.\"x.y\".\"c\"]\nrecall = 0.1\nprecision = 0.2\n")); err != nil ||
		th.Binaries["a"]["b"] != (Gate{1, 0.5}) || th.Binaries["x.y"]["c"] != (Gate{0.1, 0.2}) {
		t.Fatalf("%v %+v", err, th)
	}
	for name, in := range map[string]string{
		"key outside a table": "recall = 1.0\n",
		"missing precision":   "[binaries.a.b]\nrecall = 1.0\n",
		"unknown key":         "[binaries.a.b]\nrecall = 1.0\nprecision = 1.0\nrecal = 1.0\n",
		"duplicate key":       "[binaries.a.b]\nrecall = 1.0\nrecall = 1.0\nprecision = 1.0\n",
		"not a float":         "[binaries.a.b]\nrecall = high\nprecision = 1.0\n",
		"wrong table depth":   "[binaries.a]\nrecall = 1.0\nprecision = 1.0\n",
		"wrong root":          "[gates.a.b]\nrecall = 1.0\nprecision = 1.0\n",
		"unterminated header": "[binaries.a.b\nrecall = 1.0\nprecision = 1.0\n",
		"unterminated quote":  "[binaries.\"a.b]\nrecall = 1.0\nprecision = 1.0\n",
		"duplicate table":     ok + ok,
		"empty key":           "[binaries..b]\nrecall = 1.0\nprecision = 1.0\n",
	} {
		if _, err := parseThresholds([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
