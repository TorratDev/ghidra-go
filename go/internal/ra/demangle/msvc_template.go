package demangle

import (
	"fmt"
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
	return p.templateBody(bare)
}

// templateBody parses a template's name and arguments after its "?$" (or after
// the "$" of "??$").
func (p *msvcParser) templateBody(bare bool) (text string, empty bool, err error) {
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

// templateArgs ports MDTemplateArgumentsList. Arguments are basic types, class,
// struct and union names, pointers and references, "$$" types, template
// constants, "?x" template parameters, and digit backreferences into the
// template-parameter table. A function type in an argument is rejected, as its
// spacing is not ported.
func (p *msvcParser) templateArgs(bare bool) (string, error) {
	var args []string
	// add appends an argument. Those of a class, pointer, extended or constant
	// kind also join the template-parameter table (MDTemplateArgumentsList).
	add := func(kind byte, t string) error {
		if strings.Contains(t, "(") || p.unrendered {
			return errMsvc
		}
		args = append(args, t)
		if tpKind(kind) {
			p.tparams = append(p.tparams, t)
		}
		return nil
	}
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
		case c >= '0' && c <= '9':
			// A digit refers to the template-parameter table; it is not added again.
			p.i++
			idx := int(c - '0')
			if idx >= len(p.tparams) {
				return "", errMsvc
			}
			args = append(args, p.tparams[idx])
		case c == '?':
			// "?x": a template parameter, named by its number.
			p.i++
			n, err := p.mdEncodedNumber()
			if err != nil {
				return "", err
			}
			if err := add(c, fmt.Sprintf("`template-parameter-%d'", n)); err != nil {
				return "", err
			}
		case c == '$' && p.peek1() == '0':
			// MDTemplateConstant "$0": an integer, a signed encoded number.
			p.i += len("$0")
			v, err := p.signedText()
			if err != nil {
				return "", err
			}
			if err := add(c, v); err != nil {
				return "", err
			}
		case c == '$' && p.peek1() == 'F':
			// MDTemplateConstant "$F": two signed numbers, "{a,b}".
			p.i += len("$F")
			a, err := p.signedText()
			if err != nil {
				return "", err
			}
			b, err := p.signedText()
			if err != nil {
				return "", err
			}
			if err := add(c, "{"+a+","+b+"}"); err != nil {
				return "", err
			}
		case c == '$' && p.peek1() == 'G':
			// MDTemplateConstant "$G": three signed numbers, "{a,b,c}".
			p.i += len("$G")
			var v [3]string
			for k := range v {
				n, err := p.signedText()
				if err != nil {
					return "", err
				}
				v[k] = n
			}
			if err := add(c, "{"+v[0]+","+v[1]+","+v[2]+"}"); err != nil {
				return "", err
			}
		case c == '$' && p.peek1() == 'D':
			// MDTemplateConstant "$D": a template parameter, numbered by a signed number.
			p.i += len("$D")
			n, err := p.signedText()
			if err != nil {
				return "", err
			}
			if err := add(c, "`template-parameter"+n+"'"); err != nil {
				return "", err
			}
		case c == '$' && p.peek1() == 'Q':
			// MDTemplateConstant "$Q": a non-type template parameter, numbered by a signed number.
			p.i += len("$Q")
			n, err := p.signedText()
			if err != nil {
				return "", err
			}
			if err := add(c, "`non-type-template-parameter"+n+"'"); err != nil {
				return "", err
			}
		case c == '$' && p.peek1() == '2':
			// MDTemplateConstant "$2": a floating constant, "[-]d.ddde<exp>" from two signed numbers.
			p.i += len("$2")
			a, err := p.signedText()
			if err != nil {
				return "", err
			}
			b, err := p.signedText()
			if err != nil {
				return "", err
			}
			if err := add(c, floatConstant(a, b)); err != nil {
				return "", err
			}
		case c == '$' && p.peek1() == '$':
			// "$$" types: arrays "$$BY", rvalue references and nullptr.
			t, err := p.mdDataTypeParser()
			if err != nil {
				return "", err
			}
			if err := add(c, t); err != nil {
				return "", err
			}
		case (c == 'P' || c == 'Q') && p.peek1() == '6':
			// A function pointer: Ghidra's spacing of its signature is not ported.
			return "", errMsvc
		case c == 'P' || c == 'Q' || c == 'R' || c == 'A':
			t, err := p.mdDataTypeParser()
			if err != nil {
				return "", err
			}
			if err := add(c, t); err != nil {
				return "", err
			}
		case c == 'X' || c == '$' || c == 'Z':
			return "", errMsvc
		case c == 'V' || c == 'U' || c == 'T':
			p.i++
			n, err := p.mdQualifiedName()
			if err != nil {
				return "", err
			}
			if err := add(c, n.String()); err != nil {
				return "", err
			}
		case c == '_' || msvcBasicTypes[c] != "":
			t, err := p.mdDataTypeParser()
			if err != nil {
				return "", err
			}
			if err := add(c, t); err != nil {
				return "", err
			}
		default:
			return "", errMsvc
		}
	}
}

// tpKind reports whether an argument of this first character joins the
// template-parameter table: a class, pointer or reference, an extended type
// ('_'), a "$" constant or a "$$" type. Basic types and digits do not.
func tpKind(c byte) bool {
	switch c {
	case '?', '$', 'P', 'Q', 'R', 'A', 'V', 'U', 'T', '_':
		return true
	}
	return false
}

// floatConstant is MDTemplateConstant.parseFloatingPointConstant: the sign, the
// first digit, a point, the other digits, and "e" with the exponent.
func floatConstant(aStr, b string) string {
	str := ""
	if strings.HasPrefix(aStr, "-") {
		str = "-"
		aStr = aStr[1:]
	}
	str += aStr[:1] + "."
	if len(aStr) > 1 {
		str += aStr[1:]
	}
	return str + "e" + b
}

// functionTemplate ports "??$" names: a function whose name is a template
// instance, "name<args>" under its namespace, as in "??$largest@H@geo@@YAHPBHH@Z".
func (p *msvcParser) functionTemplate() (*Demangled, error) {
	text, _, err := p.templateBody(false)
	if err != nil {
		return nil, err
	}
	p.addName(text)
	name, err := p.qualifiedNameFrom(msvcName{parts: []string{text}})
	if err != nil {
		return nil, err
	}
	scope := name.parts
	d := &Demangled{Scheme: Msvc, Name: scope[0], IsFunction: true}
	if len(scope) > 1 {
		d.Namespace = name.outermost()[:len(scope)-1]
	}
	kind := p.next()
	switch {
	case kind == 'Y', hasThis(kind) || kind == 'S':
		return p.functionResult(d, kind, false, false)
	}
	return nil, errMsvc
}
