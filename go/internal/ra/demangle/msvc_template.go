package demangle

import "strings"

// templateName parses "?$name" and its arguments, and returns "name<args>",
// as Ghidra prints a template name. A name in a qualified name is closed by its
// argument terminator; a bare template type may end at the end of the symbol.
func (p *msvcParser) templateName(bare bool) (text string, empty bool, err error) {
	if !p.positionStartsWith("?$") {
		return "", false, errMsvc
	}
	p.i += len("?$")
	start := p.i
	for isIdent(p.peek()) {
		p.i++
	}
	if p.i == start || !isIdentStart(p.s[start]) || !p.take('@') {
		return "", false, errMsvc
	}
	name := p.s[start : p.i-1]
	args, err := p.templateArgs(bare)
	if err != nil {
		return "", false, err
	}
	if strings.HasSuffix(args, ">") {
		args += " " // "A<B<int> >"
	}
	return name + "<" + args + ">", false, nil
}

// templateArgs ports MDTemplateArgumentsList for the subset whose backreference
// table is certain: basic types, the extended '_' types and class, struct and
// union names. Those are printed without their class keyword. Anything else
// (pointers, digit backreferences, '$' and void) is rejected, not guessed.
func (p *msvcParser) templateArgs(bare bool) (string, error) {
	var args []string
	for {
		c := p.peek()
		switch {
		case c == '@':
			p.i++
			return strings.Join(args, ","), nil
		case c == 0:
			if !bare {
				return "", errMsvc
			}
			return strings.Join(args, ","), nil
		case c == 'X' || c == '$' || c == '?' || c == 'Z':
			return "", errMsvc
		case c == 'V' || c == 'U' || c == 'T':
			p.i++
			n, err := p.mdQualifiedName()
			if err != nil {
				return "", err
			}
			args = append(args, n.String())
		case c == '_' || msvcBasicTypes[c] != "":
			t, err := p.mdDataTypeParser()
			if err != nil {
				return "", err
			}
			args = append(args, t)
		default:
			return "", errMsvc
		}
	}
}
