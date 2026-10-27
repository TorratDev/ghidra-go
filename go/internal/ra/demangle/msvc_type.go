package demangle

import (
	"fmt"
	"strings"
)

// msvcBasicTypes are the single-letter basic types, spelled as MDMang prints
// them.
var msvcBasicTypes = map[byte]string{
	'C': "signed char", 'D': "char", 'E': "unsigned char",
	'F': "short", 'G': "unsigned short", 'H': "int", 'I': "unsigned int",
	'J': "long", 'K': "unsigned long", 'M': "float", 'N': "double",
	'O': "long double", 'X': "void",
}

// msvcUnderscoreTypes are the basic types written as '_' and a letter.
var msvcUnderscoreTypes = map[byte]string{
	'J': "__int64", 'K': "unsigned __int64", 'N': "bool", 'W': "wchar_t",
}

// msvcCallingConventions are the calling conventions MDMang prints.
var msvcCallingConventions = map[byte]string{
	'A': "__cdecl", 'B': "__cdecl", 'C': "__pascal", 'E': "__thiscall",
	'G': "__stdcall", 'I': "__fastcall",
}

// msvcCVQualifiers are the qualifiers on a pointee, written after its type.
var msvcCVQualifiers = map[byte]string{
	'A': "", 'B': " const", 'C': " volatile", 'D': " const volatile",
}

// mdDataTypeParser ports MDDataTypeParser: it parses one type and returns its
// MDMang spelling, such as "int", "unsigned char const *" or "class std::foo".
// A digit 0-9 refers to the type table that mdArgumentsList fills.
func (p *msvcParser) mdDataTypeParser() (string, error) {
	if p.positionStartsWith("$$BY") {
		p.i += len("$$BY")
		return p.mdArray()
	}
	c := p.next()
	if isDigit(c) {
		idx := int(c - '0')
		if idx >= len(p.types) {
			return "", errMsvc
		}
		return p.types[idx], nil
	}
	if t, ok := msvcBasicTypes[c]; ok {
		return t, nil
	}
	switch c {
	case 'Y':
		return p.mdArray()
	case '_':
		if t, ok := msvcUnderscoreTypes[p.next()]; ok {
			return t, nil
		}
	case 'P', 'Q', 'R', 'A':
		return p.mdPointer(c)
	case 'T':
		return p.mdNamedType("union")
	case 'U':
		return p.mdNamedType("struct")
	case 'V':
		return p.mdNamedType("class")
	case 'W':
		if p.next() == '4' {
			return p.mdNamedType("enum")
		}
	case '6':
		return p.mdFunctionType()
	}
	return "", errMsvc
}

// mdPointer parses a pointer or reference. The letter gives the kind (P plain,
// Q const, R volatile, A reference), then comes the pointee's cv qualifier and
// the pointee. A pointer to a function has no cv letter: "P6". The 64-bit
// marker 'E' renders as " __ptr64".
func (p *msvcParser) mdPointer(kind byte) (string, error) {
	ptr64 := p.take('E')
	if kind == 'P' && !ptr64 && p.take('6') {
		return p.mdFunctionType()
	}
	qual, ok := msvcCVQualifiers[p.next()]
	if !ok {
		return "", errMsvc
	}
	pointee, err := p.mdDataTypeParser()
	if err != nil {
		return "", err
	}
	// The const and volatile of a 'Q' or 'R' pointer print on the pointee.
	suffix := map[byte]string{'P': " *", 'Q': " const *", 'R': " volatile *", 'A': " &"}[kind]
	text := pointee + qual + suffix
	if ptr64 {
		text += " __ptr64"
	}
	return text, nil
}

// mdNamedType parses a class, struct, union or enum name after its keyword.
func (p *msvcParser) mdNamedType(keyword string) (string, error) {
	name, err := p.mdQualifiedName()
	if err != nil {
		return "", err
	}
	return keyword + " " + name.String(), nil
}

// mdArray parses an array after its 'Y' or "$$BY": the dimension count, each
// dimension, and the element type. It is spelled "elem [d1] [d2]".
func (p *msvcParser) mdArray() (string, error) {
	count, err := p.mdEncodedNumber()
	if err != nil {
		return "", err
	}
	if count > 16 {
		return "", errMsvc
	}
	dims := make([]int, count)
	for i := range dims {
		if dims[i], err = p.mdEncodedNumber(); err != nil {
			return "", err
		}
	}
	elem, err := p.mdDataTypeParser()
	if err != nil {
		return "", err
	}
	text := elem
	for _, d := range dims {
		text += fmt.Sprintf(" [%d]", d)
	}
	return text, nil
}

// mdFunctionType parses a function type after its '6' marker and returns its
// spelling as a pointer to the function: "int (__cdecl*)(int)".
func (p *msvcParser) mdFunctionType() (string, error) {
	cc, ok := msvcCallingConventions[p.next()]
	if !ok {
		return "", errMsvc
	}
	ret, err := p.returnType()
	if err != nil {
		return "", err
	}
	args, err := p.mdArgumentsList()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%s (%s *)(%s)", ret, cc, strings.Join(args, ",")), nil
}

// returnType parses a return type and returns its spelling. '@' stands for
// void, which is how constructors and destructors are encoded.
func (p *msvcParser) returnType() (string, error) {
	if p.take('@') {
		return "void", nil
	}
	return p.mdDataTypeParser()
}
