package compare

import (
	"fmt"
	"strings"
)

// codeSpan wraps s in a Markdown code span that s cannot close: the fence is
// one backtick longer than the longest backtick run in s, and s is padded
// with a space when it starts or ends with a backtick. MSVC names contain
// backticks (`vftable', `reference temporary'), so a plain `…` span breaks.
func codeSpan(s string) string {
	s = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(s)
	longest, run := 0, 0
	for _, r := range s {
		if r == '`' {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	fence := strings.Repeat("`", longest+1)
	pad := ""
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		pad = " "
	}
	return fence + pad + s + pad + fence
}

func spans(samples []string) string {
	out := make([]string, len(samples))
	for i, s := range samples {
		out[i] = codeSpan(s)
	}
	return strings.Join(out, ", ")
}

// Markdown renders the report. The summary table has a column for every
// compared category (and so every gated one); comparisons that are not whole
// programs, like the demangle oracle, get their own table.
func Markdown(results []*Comparison, violations []Violation) string {
	var s strings.Builder
	s.WriteString("# Ghidra vs ra differential report\n\n")
	if len(results) > 0 {
		fmt.Fprintf(&s, "Oracle: %s · Implementation: %s\n\n", codeSpan(results[0].GhidraProducer), codeSpan(results[0].RaProducer))
	}
	s.WriteString("Values are `recall / precision` against Ghidra (Ghidra = ground truth).\n\n")
	var programs, others []*Comparison
	for _, c := range results {
		if c.Category("functions") != nil {
			programs = append(programs, c)
		} else {
			others = append(others, c)
		}
	}
	if len(programs) > 0 {
		s.WriteString("| binary |")
		for _, c := range Categories {
			fmt.Fprintf(&s, " %s |", c)
		}
		s.WriteString("\n|---|")
		for range Categories {
			s.WriteString("---|")
		}
		s.WriteByte('\n')
		for _, c := range programs {
			fmt.Fprintf(&s, "| %s |", c.Binary)
			for _, name := range Categories {
				if r := c.Category(name); r != nil {
					fmt.Fprintf(&s, " %.3f / %.3f |", r.Recall, r.Precision)
				} else {
					s.WriteString(" - |")
				}
			}
			s.WriteByte('\n')
		}
		s.WriteByte('\n')
	}
	for _, c := range others {
		fmt.Fprintf(&s, "**%s** (vs %s)\n\n| category | matched | ghidra-only | ra-only | recall / precision |\n|---|---|---|---|---|\n",
			c.Binary, codeSpan(c.GhidraProducer))
		for _, r := range c.Categories {
			fmt.Fprintf(&s, "| %s | %d | %d | %d | %.3f / %.3f |\n", r.Name, r.Matched, r.GhidraOnly, r.RaOnly, r.Recall, r.Precision)
		}
		s.WriteByte('\n')
	}
	if len(violations) == 0 {
		s.WriteString("**Gates: all passing.**\n\n")
	} else {
		s.WriteString("## Gate violations\n\n")
		for _, v := range violations {
			fmt.Fprintf(&s, "- %s\n", v)
		}
		s.WriteByte('\n')
	}
	s.WriteString("## Mismatch samples\n\n")
	for _, c := range results {
		fmt.Fprintf(&s, "### %s\n\nlanguage %s, bias %s\n\n", c.Binary, codeSpan(c.Language), codeSpan(fmt.Sprintf("%#x", uint64(c.Bias))))
		for _, r := range c.Categories {
			if r.GhidraOnly == 0 && r.RaOnly == 0 {
				continue
			}
			fmt.Fprintf(&s, "- **%s**: matched %d, ghidra-only %d, ra-only %d\n", r.Name, r.Matched, r.GhidraOnly, r.RaOnly)
			if len(r.GhidraOnlySamples) > 0 {
				fmt.Fprintf(&s, "  - ghidra-only: %s\n", spans(r.GhidraOnlySamples))
			}
			if len(r.RaOnlySamples) > 0 {
				fmt.Fprintf(&s, "  - ra-only: %s\n", spans(r.RaOnlySamples))
			}
		}
		s.WriteByte('\n')
	}
	return s.String()
}
