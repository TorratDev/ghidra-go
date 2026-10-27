package demangle

import (
	"fmt"
	"strconv"
	"strings"
)

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
	// The arguments are parsed in a template context (MDContext TEMPLATE): their
	// names and types are their own tables, which start with the template's base
	// name, and the outer tables come back afterwards.
	outerNames, outerTypes, outerArg := p.names, p.types, p.asArg
	p.names, p.types, p.asArg = []string{name}, nil, true
	args, err := p.templateArgs(bare)
	p.names, p.types, p.asArg = outerNames, outerTypes, outerArg
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
		case c == '$' && p.s[min(p.i+1, len(p.s)-1)] == '0' && p.i+1 < len(p.s):
			// MDTemplateConstant "$0": an integer, a signed encoded number.
			p.i += len("$0")
			v, err := p.signedNumber()
			if err != nil {
				return "", err
			}
			args = append(args, strconv.Itoa(v))
		case c == '$' && p.peek1() == '$':
			// "$$" types: arrays "$$BY", rvalue references and nullptr, as in the arguments of a function.
			t, err := p.mdDataTypeParser()
			if err != nil {
				return "", err
			}
			args = append(args, t)
		case c == '$' && p.peek1() == 'F':
			// MDTemplateConstant "$F": two signed numbers, "{a,b}".
			p.i += len("$F")
			a, err := p.signedNumber()
			if err != nil {
				return "", err
			}
			b, err := p.signedNumber()
			if err != nil {
				return "", err
			}
			args = append(args, fmt.Sprintf("{%d,%d}", a, b))
		case (c == 'P' || c == 'Q') && p.peek1() == '6':
			// A function pointer: Ghidra's spacing of its signature is not ported.
			return "", errMsvc
		case c == 'P' || c == 'Q' || c == 'R' || c == 'A':
			t, err := p.mdDataTypeParser()
			if err != nil {
				return "", err
			}
			args = append(args, t)
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
