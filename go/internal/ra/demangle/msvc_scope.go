package demangle

import (
	"fmt"
	"strings"
)

// localScope parses a local scope, "?<n>??<function>": a local of the function
// that follows. Ghidra writes the local as "__l<n+1>" inside the function's
// text, "`<function>'", and the function is parsed as a nested object: it
// shares the symbol's name table, as MDNestedName does. The result is the two
// components, innermost first.
func (p *msvcParser) localScope() ([]string, error) {
	p.i++ // the '?'
	num, err := p.mdEncodedNumber()
	if err != nil {
		return nil, err
	}
	if !p.positionStartsWith("??") {
		return nil, errMsvc
	}
	p.i += len("??")
	fn, err := p.mdQualifiedName()
	if err != nil {
		return nil, err
	}
	kind := p.next()
	if kind == '9' && p.peek() == '@' {
		// A vcall type code with no encoding: Ghidra's text is the name alone.
		return []string{fmt.Sprintf("__l%d", num), "`" + fn.String() + "'"}, nil
	}
	// Only global and static functions: a member's this pointer is not rendered yet.
	if !strings.ContainsRune("YSKC", rune(kind)) {
		return nil, errMsvc
	}
	sig, err := p.function(kind)
	if err != nil {
		return nil, err
	}
	// The scope's text is only certain for a rendered signature with no return marker.
	if p.unrendered || sig.noRet || unrenderable(sig) {
		return nil, errMsvc
	}
	text := fnAccessColon[kind] + sig.ret + " " + sig.cc + " " + fn.String() + "(" + argsText(sig.args) + ")"
	return []string{fmt.Sprintf("__l%d", num), "`" + text + "'"}, nil
}

// staticLocalLeaf reads the leaf of a static local whose scope follows: a
// fragment "$S1", "$TSS<n>" or "$RT<n>" (the guards and temporaries), or "$S<n>".
// Ghidra names these from the fragment and not as templates, so "?$S1@" is
// not a template when "?1??" follows it. The fragment joins the name table.
func (p *msvcParser) staticLocalLeaf() (string, bool) {
	end := strings.IndexByte(p.s[p.i:], '@')
	if end < 0 || !strings.HasPrefix(p.s[p.i+end+1:], "?1??") {
		return "", false
	}
	frag := p.s[p.i : p.i+end]
	var leaf string
	switch {
	case frag == "$S1":
		leaf = "`nonvisible static guard{1}'"
	case strings.HasPrefix(frag, "$TSS") && isDigits(frag[len("$TSS"):]):
		leaf = "`thread safe static guard{" + frag[len("$TSS"):] + "}'"
	case strings.HasPrefix(frag, "$RT") && isDigits(frag[len("$RT"):]):
		leaf = "`reference temporary{" + frag[len("$RT"):] + "}'"
	case strings.HasPrefix(frag, "$S") && isDigits(frag[len("$S"):]):
		leaf = frag
	default:
		return "", false
	}
	p.i += end + 1
	p.addName(frag)
	return leaf, true
}

// staticLocalSymbol parses a static local whose leaf is a fragment from
// staticLocalLeaf: its scope, then the data kind and type.
func (p *msvcParser) staticLocalSymbol(leaf string) (*Demangled, error) {
	name, err := p.qualifiedNameFrom(msvcName{parts: []string{leaf}})
	if err != nil {
		return nil, err
	}
	if !name.local || p.next() != '4' {
		return nil, errMsvc
	}
	return p.localData(name)
}

// localData parses the data of a static local, after its kind '4': the leaf is
// the variable, and the scope is its namespace.
func (p *msvcParser) localData(name msvcName) (*Demangled, error) {
	d := &Demangled{
		Scheme: Msvc, Name: name.parts[0],
		Namespace: name.outermost()[:len(name.parts)-1],
	}
	return p.dataSymbol(d)
}

// localGuard ports the guard "??_B" of a static local: the scope names the
// guard, and the number follows its '5' type code, as in "??_B?1??f@@YAXXZ@51"
// which is "`local static guard'{2}'" in "`f'::__l2".
func (p *msvcParser) localGuard() (*Demangled, error) {
	name, err := p.mdQualification()
	if err != nil {
		return nil, err
	}
	if !name.local || len(name.parts) != 2 || !p.take('5') {
		return nil, errMsvc
	}
	num, err := p.mdEncodedNumber()
	if err != nil || p.i != len(p.s) {
		return nil, errMsvc
	}
	return &Demangled{
		Scheme: Msvc, Name: fmt.Sprintf("`local static guard'{%d}'", num),
		Namespace: name.outermost(),
	}, nil
}

// isDigits reports whether s is a non-empty run of decimal digits.
func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s != ""
}
