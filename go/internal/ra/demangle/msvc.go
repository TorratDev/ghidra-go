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
		if p.peek() == '_' {
			return p.special()
		}
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
		return p.functionResult(d, kind, xtor != 0)
	case xtor != 0:
		return nil, errMsvc
	case kind == 'Y' && len(scope) == 1:
		d.IsFunction = true
		return p.functionResult(d, 'Y', false)
	case (hasThis(kind) || kind == 'S') && len(scope) > 1:
		d.Namespace = name.outermost()[:len(scope)-1]
		d.IsFunction = true
		return p.functionResult(d, kind, false)
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

// fnSig is a parsed function encoding. exact is false when the encoding has
// a feature Full does not render yet (64-bit this, a cv-qualified this).
type fnSig struct {
	ret, cc string
	noRet   bool // the encoding has no return type ('@'), as for "__cdecl f(int)"
	args    []string
	exact   bool
}

// function parses the encoding after a function's kind character: an optional
// this-pointer modifier for non-static member functions, the calling
// convention, the return type, the arguments, and the throw-specification
// terminator 'Z'. Kind 'Y' is a global function, 'S' is static.
func (p *msvcParser) function(kind byte) (fnSig, error) {
	sig := fnSig{exact: true}
	if hasThis(kind) {
		if p.take('E') { // 64-bit this pointer
			sig.exact = false
		}
		cv := p.next()
		if !strings.ContainsRune("ABCD", rune(cv)) {
			return sig, errMsvc
		}
		sig.exact = sig.exact && cv == 'A'
	}
	cc := p.next()
	if !strings.ContainsRune("ABCEGI", rune(cc)) {
		return sig, errMsvc
	}
	sig.cc = msvcCallingConventions[cc]
	// shortcut: a member with calling convention 'A' prints __thiscall in Ghidra; Full stays empty for it until that is ported.
	sig.exact = sig.exact && !(hasThis(kind) && cc == 'A')
	sig.noRet = p.peek() == '@'
	ret, err := p.returnType()
	if err != nil {
		return sig, err
	}
	sig.ret = ret
	sig.args, err = p.mdArgumentsList()
	return sig, err
}

// fnAccess is the MDMang prefix for each function kind.
var fnAccess = map[byte]string{
	'Y': "", 'Q': "public ", 'A': "private ", 'S': "public static ", 'U': "public virtual ",
}

// functionResult parses the function encoding and sets Full from the
// rendered text: access, return type (none for constructors and destructors),
// calling convention, qualified name, argument list.
func (p *msvcParser) functionResult(d *Demangled, kind byte, xtor bool) (*Demangled, error) {
	sig, err := p.function(kind)
	if err != nil {
		return nil, err
	}
	// shortcut: a function-pointer return type, a doubled const on a pointee, and
	// a 64-bit pointer inside a function-pointer argument are not spelled as
	// Ghidra does (it writes the return type inside-out and drops the outer
	// __ptr64 there), so Full stays empty for them; upgrade when the pointer rules are ported.
	if !sig.exact || strings.Contains(sig.ret, "(") || strings.Contains(strings.Join(sig.args, ","), "const const") || argPtr64InFnPtr(sig.args) {
		return d, nil
	}
	qual := d.Name
	if len(d.Namespace) > 0 {
		qual = strings.Join(append(append([]string{}, d.Namespace...), d.Name), "::")
	}
	full := fnAccess[kind]
	if !xtor && !sig.noRet {
		full += sig.ret + " "
	}
	d.Full = full + sig.cc + " " + qual + "(" + strings.Join(sig.args, ",") + ") "
	return d, nil
}

// argPtr64InFnPtr reports a 64-bit pointer inside a function-pointer argument.
func argPtr64InFnPtr(args []string) bool {
	for _, a := range args {
		if strings.Contains(a, "(") && strings.Contains(a, "__ptr64") {
			return true
		}
	}
	return false
}
