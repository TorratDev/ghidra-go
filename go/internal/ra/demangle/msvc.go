package demangle

import (
	"errors"
	"strings"
)

// DemangleMsvc is stage 1 of the MicrosoftDemangler (MDMang) port. It parses
// the MSVC symbol grammar subset that names come from: qualified names with
// name backreferences, constructors and destructors, global and member
// functions, static data, and basic, pointer, reference, array and class
// types. It returns nil for any other encoding (templates, operators, '$'
// modifiers, member pointers, thunks) rather than guessing a name.
func DemangleMsvc(mangled string) *Demangled {
	p := &msvcParser{s: mangled}
	d, err := p.symbol()
	if err != nil || p.i != len(p.s) {
		return nil
	}
	return d
}

var errMsvc = errors.New("msvc: unsupported encoding")

// msvcParser is the MDMang driver state: the input and the position in it.
// names is the name table that backreferences 0-9 index: each new name
// component is appended in the order it is parsed, innermost first.
type msvcParser struct {
	s     string
	i     int
	names []string
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
	scope, err := p.qualifiedName()
	if err != nil {
		return nil, err
	}
	// scope is innermost first; the leaf is scope[0].
	d := &Demangled{Scheme: Msvc, Name: scope[0]}
	kind := p.next()
	switch {
	case xtor != 0 && (hasThis(kind) || kind == 'S'):
		// A constructor or destructor is named after its class, and the
		// namespace keeps the class as its last element.
		d.Namespace = reverse(scope)
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
		d.Namespace = reverse(scope[1:])
		d.IsFunction = true
		return d, p.function(kind)
	case kind == '3' && len(scope) == 1:
		if err := p.typ(); err != nil {
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
	if err := p.returnType(); err != nil {
		return err
	}
	return p.args()
}

// returnType parses a return type, where '@' stands for void (constructors and
// destructors are encoded that way).
func (p *msvcParser) returnType() error {
	if p.take('@') {
		return nil
	}
	return p.typ()
}

// args parses the parameter list and its 'Z' terminator. A lone 'X' is the
// void list; otherwise '@' ends the list.
func (p *msvcParser) args() error {
	if p.take('X') {
		if !p.take('Z') {
			return errMsvc
		}
		return nil
	}
	for {
		switch p.peek() {
		case '@':
			p.i++
			if !p.take('Z') {
				return errMsvc
			}
			return nil
		case 'Z':
			p.i++
			return nil
		}
		if err := p.typ(); err != nil {
			return err
		}
	}
}

// qualifiedName parses name components up to the empty component that closes
// the list. A simple name is closed by '@'; a backreference stands alone. It
// returns the components innermost first.
func (p *msvcParser) qualifiedName() ([]string, error) {
	var scope []string
	for !p.take('@') {
		backref := p.peek() >= '0' && p.peek() <= '9'
		name, err := p.component()
		if err != nil {
			return nil, err
		}
		if !backref && !p.take('@') {
			return nil, errMsvc
		}
		scope = append(scope, name)
	}
	if len(scope) == 0 {
		return nil, errMsvc
	}
	return scope, nil
}

// component parses one name: a backreference to the name table, or a plain
// identifier that is then added to the table.
func (p *msvcParser) component() (string, error) {
	c := p.peek()
	if c >= '0' && c <= '9' {
		p.i++
		idx := int(c - '0')
		if idx >= len(p.names) {
			return "", errMsvc
		}
		return p.names[idx], nil
	}
	start := p.i
	for isIdent(p.peek()) {
		p.i++
	}
	if p.i == start || !isIdentStart(p.s[start]) {
		return "", errMsvc
	}
	name := p.s[start:p.i]
	if len(p.names) < 10 {
		p.names = append(p.names, name)
	}
	return name, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdent(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9'
}

func reverse(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[len(in)-1-i] = s
	}
	return out
}
