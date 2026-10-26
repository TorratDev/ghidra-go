package demangle

import "strings"

// typ parses one type: a basic type, a pointer or reference with its
// modifiers, an array, a class, struct, union or enum name, or a function
// pointer. Type backreferences (digits) consume one character; the type table
// they index is only needed for rendering argument types, which names do not
// use.
func (p *msvcParser) typ() error {
	if p.positionStartsWith("$$BY") {
		p.i += len("$$BY")
		return p.array()
	}
	c := p.next()
	switch {
	case c >= '0' && c <= '9', strings.IndexByte("CDEFGHIJKLMNX", c) >= 0:
		return nil
	case c == 'Y':
		return p.array()
	case c == '_':
		if strings.IndexByte("JKNW", p.next()) < 0 {
			return errMsvc
		}
		return nil
	case c == 'P' || c == 'Q' || c == 'R' || c == 'A':
		p.take('E') // 64-bit pointer
		if !strings.ContainsRune("ABCD", rune(p.next())) {
			return errMsvc
		}
		return p.typ()
	case c == 'V' || c == 'U' || c == 'T':
		_, err := p.qualifiedName()
		return err
	case c == 'W':
		if p.next() != '4' {
			return errMsvc
		}
		_, err := p.qualifiedName()
		return err
	case c == '6':
		return p.functionType()
	}
	return errMsvc
}

// functionType parses a function type after its '6' marker: the calling
// convention, the return type, and the arguments.
func (p *msvcParser) functionType() error {
	if !strings.ContainsRune("ABCEGI", rune(p.next())) {
		return errMsvc
	}
	if err := p.returnType(); err != nil {
		return err
	}
	return p.args()
}

// array parses an array type after its 'Y' or "$$BY": the dimension count, each
// dimension, and the element type.
func (p *msvcParser) array() error {
	dims, err := p.number()
	if err != nil {
		return err
	}
	if dims > 16 {
		return errMsvc
	}
	for ; dims > 0; dims-- {
		if _, err := p.number(); err != nil {
			return err
		}
	}
	return p.typ()
}

// number parses an MSVC number: a digit is its value plus one, and 'A'-'P'
// digits followed by '@' spell a hexadecimal value.
func (p *msvcParser) number() (int, error) {
	c := p.next()
	if c >= '0' && c <= '9' {
		return int(c-'0') + 1, nil
	}
	if c < 'A' || c > 'P' {
		return 0, errMsvc
	}
	v := int(c - 'A')
	for {
		c = p.next()
		if c == '@' {
			return v, nil
		}
		if c < 'A' || c > 'P' || v > 1<<20 {
			return 0, errMsvc
		}
		v = v*16 + int(c-'A')
	}
}

func (p *msvcParser) positionStartsWith(s string) bool {
	return p.i <= len(p.s) && strings.HasPrefix(p.s[p.i:], s)
}
