package demangle

import (
	"regexp"
	"strings"
	"unicode"
)

// symbolPath is SymbolPathParser.parse(name, false): it splits at "::"
// outside templates and parentheses; if those are unbalanced, it splits at
// every "::".
func symbolPath(name string) []string {
	if !strings.Contains(name, "::") {
		return []string{name}
	}
	split := func(balanced bool) ([]string, bool) {
		var out []string
		tpl, paren, start := 0, 0, 0
		for i := 0; i < len(name); i++ {
			if name[i] == ':' && i+1 < len(name) && name[i+1] == ':' {
				if (!balanced || (tpl == 0 && paren == 0)) && i > start {
					out = append(out, name[start:i])
					start = i + 2
					i++
				}
			} else if balanced {
				switch name[i] {
				case '<':
					tpl++
				case '>':
					tpl--
				case '(':
					paren++
				case ')':
					paren--
				}
			}
		}
		return append(out, name[start:]), tpl == 0 && paren == 0
	}
	if out, ok := split(true); ok {
		return out
	}
	out, _ := split(false)
	return out
}

var unnamedType = regexp.MustCompile(`\{unnamed type#\d+\}`)

// condense is CondensedString: inside <> or () a space between two letters or
// digits becomes "_", other spaces are dropped.
func condense(input string, fixUnnamed bool) string {
	if fixUnnamed {
		input = unnamedType.ReplaceAllStringFunc(input, func(s string) string {
			return strings.Replace(s, " ", "_", 1)
		})
	}
	chars := []rune(input)
	var out strings.Builder
	depth := 0
	var last rune
	for i, ch := range chars {
		if ch == '<' || ch == '(' {
			depth++
		} else if (ch == '>' || ch == ')') && depth != 0 {
			depth--
		}
		if depth > 0 && ch == ' ' {
			var next rune
			if i+1 < len(chars) {
				next = chars[i+1]
			}
			if last != 0 && next != 0 && isLetterOrDigit(last) && isLetterOrDigit(next) {
				out.WriteByte('_')
			}
		} else {
			out.WriteRune(ch)
		}
		last = ch
	}
	return strings.TrimSpace(out.String())
}

// isLetterOrDigit is Java's Character.isLetterOrDigit.
func isLetterOrDigit(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

var (
	spaceBefore = regexp.MustCompile(` ([*&)])`)
	spaceAfter  = regexp.MustCompile(`([(,]) `)
)

// sanitizeName is DemangledObject.setName: stripSuperfluousSignatureSpaces,
// trim, and spaces to "_".
func sanitizeName(name string) string {
	s := spaceBefore.ReplaceAllString(name, "$1")
	s = spaceAfter.ReplaceAllString(s, "$1")
	return strings.ReplaceAll(strings.TrimSpace(s), " ", "_")
}
