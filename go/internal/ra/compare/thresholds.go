package compare

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

type Gate struct {
	Recall    float64 `toml:"recall"`
	Precision float64 `toml:"precision"`
}

// Thresholds is thresholds.toml: [binaries."<name>".<category>] with recall
// and precision minimums.
type Thresholds struct {
	Binaries map[string]map[string]Gate `toml:"binaries"`
}

// Violation is a failed gate. Metric is "recall", "precision", or "result"
// when the gated binary or category produced no result at all.
type Violation struct {
	Binary, Category, Metric string
	Actual, Required         float64
}

func (v Violation) String() string {
	switch {
	case v.Metric != "result":
		return fmt.Sprintf("%s / %s: %s %.4f < required %.4f", v.Binary, v.Category, v.Metric, v.Actual, v.Required)
	case v.Category == "":
		return fmt.Sprintf("%s: gated binary has no result", v.Binary)
	}
	return fmt.Sprintf("%s / %s: gated category has no result", v.Binary, v.Category)
}

// floor3 floors to 3 decimals so tiny float noise never trips a gate. It is a
// floor, not a rounding: 0.9999 is 0.999, and a value one ulp under a gate's
// 3-decimal value (0.9739999999999999 for 0.974) fails it.
func floor3(v float64) float64 { return math.Floor(v*1000) / 1000 }

// ErrNoThresholds means the thresholds file does not exist.
var ErrNoThresholds = errors.New("thresholds file not found")

// LoadThresholds reads path. A missing file is ErrNoThresholds, never an
// empty default: an empty set of gates would pass everything.
func LoadThresholds(path string) (*Thresholds, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrNoThresholds, path)
	}
	if err != nil {
		return nil, err
	}
	t := &Thresholds{}
	if _, err := toml.NewDecoder(bytes.NewReader(b)).Decode(t); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if t.Binaries == nil {
		t.Binaries = map[string]map[string]Gate{}
	}
	return t, nil
}

const thresholdsHeader = "# Minimum precision/recall per binary and category, versus Ghidra.\n" +
	"# Ratchet: `ra regress --update-thresholds` only ever raises these.\n\n"

// Save writes the file in the same layout as the committed one, so a ratchet
// run changes only the lines whose gates rose.
func (t *Thresholds) Save(path string) error {
	var buf bytes.Buffer
	buf.WriteString(thresholdsHeader)
	for _, bin := range sortedKeys(t.Binaries) {
		for _, cat := range sortedKeys(t.Binaries[bin]) {
			g := t.Binaries[bin][cat]
			fmt.Fprintf(&buf, "[binaries.%s.%s]\nrecall = %s\nprecision = %s\n\n", tomlKey(bin), tomlKey(cat), tomlFloat(g.Recall), tomlFloat(g.Precision))
		}
	}
	return os.WriteFile(path, append(bytes.TrimRight(buf.Bytes(), "\n"), '\n'), 0o644)
}

// tomlKey quotes a key unless it is a bare key.
func tomlKey(k string) string {
	for _, r := range k {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return strconv.Quote(k)
		}
	}
	return k
}

func tomlFloat(v float64) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// Check gates the results. Every gated binary whose name contains filter
// (all of them when filter is empty) must have a result, and every gated
// category of it must be in that result; otherwise it is a violation, not a
// skip. Results for binaries without gates are not checked.
func (t *Thresholds) Check(results []*Comparison, filter string) []Violation {
	byName := map[string]*Comparison{}
	for _, c := range results {
		byName[c.Binary] = c
	}
	var out []Violation
	for _, bin := range sortedKeys(t.Binaries) {
		if !strings.Contains(bin, filter) {
			continue
		}
		c := byName[bin]
		if c == nil {
			out = append(out, Violation{Binary: bin, Metric: "result"})
			continue
		}
		gates := t.Binaries[bin]
		for _, cat := range sortedKeys(gates) {
			res := c.Category(cat)
			if res == nil {
				out = append(out, Violation{Binary: bin, Category: cat, Metric: "result"})
				continue
			}
			g := gates[cat]
			for _, m := range []struct {
				name             string
				actual, required float64
			}{{"recall", res.Recall, g.Recall}, {"precision", res.Precision, g.Precision}} {
				if floor3(m.actual) < m.required {
					out = append(out, Violation{bin, cat, m.name, m.actual, m.required})
				}
			}
		}
	}
	return out
}

// Ratchet raises gates to the current results; it never lowers them:
// max(old gate, floor3(current)).
func (t *Thresholds) Ratchet(c *Comparison) {
	if t.Binaries == nil {
		t.Binaries = map[string]map[string]Gate{}
	}
	gates := t.Binaries[c.Binary]
	if gates == nil {
		gates = map[string]Gate{}
		t.Binaries[c.Binary] = gates
	}
	for _, res := range c.Categories {
		g := gates[res.Name]
		g.Recall = math.Max(g.Recall, floor3(res.Recall))
		g.Precision = math.Max(g.Precision, floor3(res.Precision))
		gates[res.Name] = g
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
