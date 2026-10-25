package compare

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Gate struct {
	Recall    float64
	Precision float64
}

// Thresholds is thresholds.toml: [binaries."<name>".<category>] with recall
// and precision minimums.
type Thresholds struct {
	Binaries map[string]map[string]Gate
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
	t, err := parseThresholds(b)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return t, nil
}

// parseThresholds reads the only layout the file has: `#` comments, blank
// lines, [binaries.<name>.<category>] tables (a name with characters outside
// A-Za-z0-9_- is a quoted key) and `recall = <float>` / `precision = <float>`
// lines. Anything else is an error, so a typo cannot silently drop a gate.
func parseThresholds(b []byte) (*Thresholds, error) {
	t := &Thresholds{Binaries: map[string]map[string]Gate{}}
	var cur *Gate
	var bin, cat string
	seen := map[string]bool{}
	flush := func() error {
		if cur == nil {
			return nil
		}
		if !seen["recall"] || !seen["precision"] {
			return fmt.Errorf("[binaries.%s.%s] needs recall and precision", bin, cat)
		}
		if t.Binaries[bin] == nil {
			t.Binaries[bin] = map[string]Gate{}
		}
		t.Binaries[bin][cat] = *cur
		return nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "["):
			if err := flush(); err != nil {
				return nil, err
			}
			parts, err := tableName(line)
			if err != nil || len(parts) != 3 || parts[0] != "binaries" {
				return nil, fmt.Errorf("line %d: want [binaries.<name>.<category>], got %q", n, line)
			}
			if _, dup := t.Binaries[parts[1]][parts[2]]; dup {
				return nil, fmt.Errorf("line %d: duplicate table %q", n, line)
			}
			bin, cat, cur, seen = parts[1], parts[2], &Gate{}, map[string]bool{}
		default:
			key, val, ok := strings.Cut(line, "=")
			key, val = strings.TrimSpace(key), strings.TrimSpace(val)
			f, err := strconv.ParseFloat(val, 64)
			if !ok || cur == nil || err != nil || seen[key] || (key != "recall" && key != "precision") {
				return nil, fmt.Errorf("line %d: unexpected %q", n, line)
			}
			seen[key] = true
			if key == "recall" {
				cur.Recall = f
			} else {
				cur.Precision = f
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return t, nil
}

// tableName splits "[a."b.c".d]" into its dotted key parts, unquoting the
// quoted ones.
func tableName(line string) ([]string, error) {
	inner, ok := strings.CutSuffix(strings.TrimPrefix(line, "["), "]")
	if !ok {
		return nil, errors.New("unterminated table header")
	}
	var parts []string
	for inner != "" {
		var part string
		if inner[0] == '"' {
			end := 1
			for end < len(inner) && inner[end] != '"' {
				if inner[end] == '\\' {
					end++
				}
				end++
			}
			if end >= len(inner) {
				return nil, errors.New("unterminated quoted key")
			}
			var err error
			if part, err = strconv.Unquote(inner[:end+1]); err != nil {
				return nil, err
			}
			inner = inner[end+1:]
		} else {
			end := strings.IndexByte(inner, '.')
			if end < 0 {
				end = len(inner)
			}
			part, inner = inner[:end], inner[end:]
			if part == "" {
				return nil, errors.New("empty key")
			}
		}
		parts = append(parts, part)
		if inner != "" {
			if inner[0] != '.' || len(inner) == 1 {
				return nil, errors.New("bad key separator")
			}
			inner = inner[1:]
		}
	}
	return parts, nil
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
