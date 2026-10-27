package demangle

import (
	"fmt"
	"strings"
)

// special parses the "??_" special names: vftable (7), vbtable (8) and the RTTI
// descriptors (R), and vcall thunks (9) with the one-letter tail. Guards (B)
// are not ported yet and give no result rather than a guessed name.
func (p *msvcParser) special() (*Demangled, error) {
	p.i++ // the '_'
	code := p.next()
	switch code {
	case '7':
		return p.vtable("`vftable'", '6')
	case '8':
		return p.vtable("`vbtable'", '7')
	case '9':
		return p.vcall("`vcall'")
	case '_':
		return p.doubleUnderscore()
	case 'R':
		return p.rtti()
	}
	if text, ok := msvcUnderscoreOperators[code]; ok {
		return p.namedOperator(text)
	}
	return nil, errMsvc
}

// vcall ports the vcall thunk "??_9 class $B index thunk A" (MDVCall). Only
// the one-letter tail is ported; the thunk 'A' (near this, call and vfptr)
// adds the "{index,{flat}}" modifier, other thunks give the bare name.
func (p *msvcParser) vcall(leaf string) (*Demangled, error) {
	cls, err := p.mdQualifiedName()
	if err != nil {
		return nil, err
	}
	if !p.positionStartsWith("$B") {
		return nil, errMsvc
	}
	p.i += len("$B")
	index, err := p.mdEncodedNumber()
	if err != nil {
		return nil, err
	}
	thunk := p.next()
	if p.i+1 != len(p.s) || p.peek() != 'A' {
		return nil, errMsvc
	}
	p.i++
	name, spaced := strings.ReplaceAll(leaf, " ", "_"), leaf
	if thunk == 'A' {
		name += fmt.Sprintf("{%d,{flat}}'_}'", index)
		spaced += fmt.Sprintf("{%d,{flat}}' }'", index)
	}
	return &Demangled{
		Scheme: Msvc, Namespace: cls.outermost(), Name: name,
		Full: "[thunk]:__thiscall " + cls.String() + "::" + spaced + "(void)",
	}, nil
}

// msvcIteratorNames are the thunk names of "??__" followed by a letter, the
// vcall shape with a different leaf.
var msvcIteratorNames = map[byte]string{
	'A': "`managed vector constructor iterator'", 'B': "`managed vector destructor iterator'",
	'C': "`eh vector copy constructor iterator'", 'D': "`eh vector vbase copy constructor iterator'",
	'G': "`vector copy constructor iterator'", 'H': "`vector vbase copy constructor iterator'",
	'I': "`managed vector copy constructor iterator'",
}

// doubleUnderscore ports the "??__" names: the iterator thunks, and the dynamic
// initializer "??__E" of a global variable.
func (p *msvcParser) doubleUnderscore() (*Demangled, error) {
	code := p.next()
	if leaf, ok := msvcIteratorNames[code]; ok {
		return p.vcall(leaf)
	}
	if code != 'E' {
		return nil, errMsvc
	}
	v, err := p.mdQualifiedName()
	if err != nil {
		return nil, err
	}
	// shortcut: only a plain global variable; a member or a typed initializer ("??__E?var@@3HA") is not ported.
	if len(v.parts) != 1 || p.next() != 'Y' {
		return nil, errMsvc
	}
	d := &Demangled{Scheme: Msvc, Name: "`dynamic initializer for '" + v.parts[0] + "''", IsFunction: true}
	res, err := p.functionResult(d, 'Y', false, false)
	if err == nil && p.i != len(p.s) {
		return nil, errMsvc
	}
	return finishOperator(res, err)
}

// vtable ports the vftable and vbtable names: the class, the type code that
// MDVxTable parses, the cv letter, and the base qualifiers in "{for `a'}".
// Ghidra writes the name with spaces as '_' (the oracle's leaf names do).
func (p *msvcParser) vtable(base string, typeCode byte) (*Demangled, error) {
	cls, err := p.mdQualifiedName()
	if err != nil {
		return nil, err
	}
	if !p.take(typeCode) {
		return nil, errMsvc
	}
	cv, ok := msvcCVQualifiers[p.next()]
	if !ok {
		return nil, errMsvc
	}
	var quals []string
	for p.peek() != '@' {
		q, err := p.mdQualifiedName()
		if err != nil {
			return nil, err
		}
		quals = append(quals, q.String())
	}
	p.i++ // the list terminator
	name := base
	if len(quals) > 0 {
		name += "{for_`" + strings.Join(quals, "'s_`") + "'}"
	}
	prefix := ""
	if c := strings.TrimSpace(cv); c != "" {
		prefix = c + " "
	}
	return &Demangled{
		Scheme: Msvc, Namespace: cls.outermost(), Name: name,
		Full: prefix + cls.String() + "::" + name,
	}, nil
}

// rtti ports the RTTI descriptors. The leaf names are fixed text except for
// the type descriptor (R0), which spells its class, and the base class
// descriptor (R1), which carries four numbers. The outer qualifiers, which
// are often empty, follow, and the name ends with '8'.
func (p *msvcParser) rtti() (*Demangled, error) {
	var leaf string
	switch p.next() {
	case '0':
		if !p.take('?') || !p.take('A') {
			return nil, errMsvc
		}
		word, ok := map[byte]string{'V': "class", 'U': "struct", 'T': "union"}[p.next()]
		if !ok {
			return nil, errMsvc
		}
		typ, err := p.mdQualifiedName()
		if err != nil {
			return nil, err
		}
		leaf = word + " " + typ.String() + " `RTTI_Type_Descriptor'"
	case '1':
		a, err := p.signedNumber()
		if err != nil {
			return nil, err
		}
		b, err := p.signedNumber()
		if err != nil {
			return nil, err
		}
		c, err := p.signedNumber()
		if err != nil {
			return nil, err
		}
		d, err := p.mdEncodedNumber()
		if err != nil {
			return nil, err
		}
		leaf = fmt.Sprintf("`RTTI Base Class Descriptor at (%d,%d,%d,%d)'", a, b, c, d)
	case '2':
		leaf = "`RTTI Base Class Array'"
	case '3':
		leaf = "`RTTI Class Hierarchy Descriptor'"
	case '4':
		return p.vtable("`RTTI_Complete_Object_Locator'", '6')
	default:
		return nil, errMsvc
	}
	outer, err := p.optionalQualifiedName()
	if err != nil {
		return nil, err
	}
	if !p.take('8') {
		return nil, errMsvc
	}
	name := strings.ReplaceAll(leaf, " ", "_")
	full := name
	if len(outer.parts) > 0 {
		full = outer.String() + "::" + name
	}
	return &Demangled{Scheme: Msvc, Namespace: outer.outermost(), Name: name, Full: full}, nil
}

// signedNumber is MDSignedEncodedNumber: an optional '?' negates the number.
func (p *msvcParser) signedNumber() (int, error) {
	neg := p.take('?')
	v, err := p.mdEncodedNumber()
	if neg {
		v = -v
	}
	return v, err
}

// optionalQualifiedName is a qualified name that may be empty: a lone '@'.
func (p *msvcParser) optionalQualifiedName() (msvcName, error) {
	if p.take('@') {
		return msvcName{}, nil
	}
	return p.mdQualifiedName()
}
