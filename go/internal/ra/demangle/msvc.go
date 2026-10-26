package demangle

import (
	"errors"
	"strings"
)

// DemangleMsvc is stage 1 of the MicrosoftDemangler (MDMang) port. It parses
// the MSVC symbol grammar subset that names come from: qualified names with
// name backreferences, constructors and destructors, global, member and static
// functions, static data, and basic, pointer, reference, array, class and
// function types. It returns nil for any other encoding (templates, operators,
// '$' modifiers, member pointers, thunks) rather than guessing a name.
func DemangleMsvc(mangled string) *Demangled {
	p := &msvcParser{s: mangled}
	d, err := p.symbol()
	if err != nil || p.i != len(p.s) {
		return nil
	}
	return d
}

var errMsvc = errors.New("msvc: unsupported encoding")

// msvcParser is the MDMang driver state: the input and the position in it,
// and the two tables that backreferences index.
type msvcParser struct {
	s string
	i int
	// names is the name table for backreferences 0-9 in qualified names.
	names []string
	// types is the type table for backreferences 0-9 in types, filled by
	// mdArgumentsList with the top-level argument types.
	types []string
}

func (p *msvcParser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

func (p *msvcParser) next() byte {
	c := p.peek()
	p.i++
	return c
}

func (p *msvcParser) take(c byte) bool {
	if p.peek() == c {
		p.i++
		return true
	}
	return false
}

func (p *msvcParser) positionStartsWith(s string) bool {
	return p.i <= len(p.s) && strings.HasPrefix(p.s[p.i:], s)
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// symbol parses the whole symbol. Constructors and destructors come in as
// "??0" and "??1"; their namespace keeps the class name as the last element.
func (p *msvcParser) symbol() (*Demangled, error) {
	if !p.take('?') || p.peek() == '$' {
		return nil, errMsvc
	}
	xtor := byte(0)
	if p.take('?') {
		xtor = p.next()
		if xtor != '0' && xtor != '1' {
			return nil, errMsvc
		}
	}
	name, err := p.mdQualifiedName()
	if err != nil {
		return nil, err
	}
	scope := name.parts // innermost first; the leaf is scope[0]
	d := &Demangled{Scheme: Msvc, Name: scope[0]}
	kind := p.next()
	switch {
	case xtor != 0 && (hasThis(kind) || kind == 'S'):
		// A constructor or destructor is named after its class, and the
		// namespace keeps the class as its last element.
		d.Namespace = name.outermost()
		if xtor == '1' {
			d.Name = "~" + scope[0]
		}
		d.IsFunction = true
		return d, p.function(kind)
	case xtor != 0:
		return nil, errMsvc
	case kind == 'Y' && len(scope) == 1:
		d.IsFunction = true
		return d, p.function('Y')
	case (hasThis(kind) || kind == 'S') && len(scope) > 1:
		d.Namespace = name.outermost()[:len(scope)-1]
		d.IsFunction = true
		return d, p.function(kind)
	case kind == '3' && len(scope) == 1:
		if _, err := p.mdDataTypeParser(); err != nil {
			return nil, err
		}
		if !p.take('A') && !p.take('B') {
			return nil, errMsvc
		}
		return d, nil
	}
	return nil, errMsvc
}

// hasThis reports whether a function kind is a non-static member, which takes
// a this pointer: 'Q' public, 'A' private, 'U' virtual.
func hasThis(kind byte) bool {
	return kind == 'Q' || kind == 'A' || kind == 'U'
}

// function parses the encoding after a function's kind character: an optional
// this-pointer modifier for non-static member functions, the calling
// convention, the return type, the arguments, and the throw-specification
// terminator 'Z'. Kind 'Y' is a global function, 'S' is static.
func (p *msvcParser) function(kind byte) error {
	if hasThis(kind) {
		p.take('E') // 64-bit this pointer
		if !strings.ContainsRune("ABCD", rune(p.next())) {
			return errMsvc
		}
	}
	if !strings.ContainsRune("ABCEGI", rune(p.next())) {
		return errMsvc
	}
	if _, err := p.returnType(); err != nil {
		return err
	}
	_, err := p.mdArgumentsList()
	return err
}
