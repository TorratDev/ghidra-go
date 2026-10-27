package demangle

import "strings"

// msvcName is a qualified name. parts holds the components innermost first,
// as they are parsed.
type msvcName struct {
	parts []string
}

// outermost returns the components outermost first, the order a namespace
// path is written in.
func (n msvcName) outermost() []string {
	out := make([]string, len(n.parts))
	for i, s := range n.parts {
		out[len(n.parts)-1-i] = s
	}
	return out
}

// String renders the qualified name the way MDMang prints it: "a::b".
func (n msvcName) String() string {
	return strings.Join(n.outermost(), "::")
}

// mdQualifiedName ports MDQualifiedName: it parses name components up to the
// empty component that closes the list. A simple name is closed by '@'; a
// backreference stands alone. Each new simple name joins the name table.
func (p *msvcParser) mdQualifiedName() (msvcName, error) {
	var n msvcName
	for !p.take('@') {
		if p.positionStartsWith("?$") {
			// The template's arguments end with their own '@'; the loop's '@' closes the list.
			t, _, err := p.templateName(false)
			if err != nil {
				return msvcName{}, err
			}
			n.parts = append(n.parts, t)
			continue
		}
		backref := isDigit(p.peek())
		name, err := p.component()
		if err != nil {
			return msvcName{}, err
		}
		if !backref && !p.take('@') {
			return msvcName{}, errMsvc
		}
		n.parts = append(n.parts, name)
	}
	if len(n.parts) == 0 {
		return msvcName{}, errMsvc
	}
	return n, nil
}

// component parses one name: a backreference to the name table, or a plain
// identifier that is then added to the table.
func (p *msvcParser) component() (string, error) {
	c := p.peek()
	if isDigit(c) {
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
	return isIdentStart(c) || isDigit(c)
}
