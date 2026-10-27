package demangle

import "strings"

// msvcOperators are the operator names of MDSpecialName, by the character after
// "??". Ghidra's 'B' (type cast) needs the cast type and is not ported.
var msvcOperators = map[byte]string{
	'2': "operator new", '3': "operator delete", '4': "operator=", '5': "operator>>",
	'6': "operator<<", '7': "operator!", '8': "operator==", '9': "operator!=",
	'A': "operator[]", 'C': "operator->", 'D': "operator*", 'E': "operator++",
	'F': "operator--", 'G': "operator-", 'H': "operator+", 'I': "operator&",
	'J': "operator->*", 'K': "operator/", 'L': "operator%", 'M': "operator<",
	'N': "operator<=", 'O': "operator>", 'P': "operator>=", 'Q': "operator,",
	'R': "operator()", 'S': "operator~", 'T': "operator^", 'U': "operator|",
	'V': "operator&&", 'W': "operator||", 'X': "operator*=", 'Y': "operator+=",
	'Z': "operator-=",
}

// operator parses an operator name: "??<code> class <function>". A member
// takes the class as its namespace; a global operator (an empty qualified name)
// has none. Ghidra names it with the spaces as underscores.
func (p *msvcParser) operator(code byte) (*Demangled, error) {
	text, ok := msvcOperators[code]
	if !ok {
		return nil, errMsvc
	}
	return p.namedOperator(text)
}

// msvcUnderscoreOperators are the operators written "??_" and a character.
var msvcUnderscoreOperators = map[byte]string{
	'0': "operator/=", '1': "operator%=", '2': "operator>>=", '3': "operator<<=",
	'4': "operator&=", '5': "operator|=", '6': "operator^=", 'U': "operator new[]",
	'V': "operator delete[]",
}

// namedOperator parses the function encoding of an operator with the given text.
func (p *msvcParser) namedOperator(text string) (*Demangled, error) {
	cls, err := p.optionalQualifiedName()
	if err != nil {
		return nil, err
	}
	d := &Demangled{Scheme: Msvc, Name: text}
	kind := p.next()
	switch {
	case len(cls.parts) == 0 && kind == 'Y':
		d.IsFunction = true
		res, err := p.functionResult(d, 'Y', false, false)
		return finishOperator(res, err)
	case len(cls.parts) > 0 && (hasThis(kind) || kind == 'S'):
		d.Namespace = cls.outermost()
		d.IsFunction = true
		res, err := p.functionResult(d, kind, false, false)
		return finishOperator(res, err)
	}
	return nil, errMsvc
}

// finishOperator sets the Ghidra name: the operator text with spaces as underscores.
func finishOperator(d *Demangled, err error) (*Demangled, error) {
	if err != nil || d == nil {
		return d, err
	}
	d.Name = strings.ReplaceAll(d.Name, " ", "_")
	return d, nil
}
