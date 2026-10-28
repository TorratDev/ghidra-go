package demangle

import (
	"fmt"
	"strconv"
	"strings"
)

// msvcName is a qualified name. parts holds the components innermost first,
// as they are parsed.
type msvcName struct {
	parts []string
	// local is set when a local scope ("?<n>??f") is one of the components.
	local bool
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
	n, err := p.qualifiedNameFrom(msvcName{})
	if err != nil {
		return msvcName{}, err
	}
	if len(n.parts) == 0 {
		return msvcName{}, errMsvc
	}
	return n, nil
}

// qualifiedNameFrom continues a qualified name after the components in n, up to
// the '@' that closes the list.
func (p *msvcParser) qualifiedNameFrom(n msvcName) (msvcName, error) {
	for !p.take('@') {
		if p.peek() == '?' && isDigit(p.peek1()) {
			scope, err := p.localScope()
			if err != nil {
				return msvcName{}, err
			}
			n.parts = append(n.parts, scope...)
			n.local = true
			continue
		}
		if p.positionStartsWith("?A") {
			a, err := p.anonymous()
			if err != nil {
				return msvcName{}, err
			}
			n.parts = append(n.parts, a)
			continue
		}
		if p.positionStartsWith("?$") {
			// The template's arguments end with their own '@'; the loop's '@' closes the list.
			t, _, err := p.templateName(false)
			if err != nil {
				return msvcName{}, err
			}
			n.parts = append(n.parts, t)
			// The whole "name<args>" is a name for later backreferences (MDReusableName).
			p.addName(t)
			continue
		}
		backref := isDigit(p.peek())
		if backref {
			p.backrefs++
		}
		name, err := p.component()
		if err != nil {
			return msvcName{}, err
		}
		if !backref && !p.take('@') {
			return msvcName{}, errMsvc
		}
		n.parts = append(n.parts, name)
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
	name, err := p.identifier()
	if err != nil {
		return "", err
	}
	p.addName(name)
	return name, nil
}

// identifier reads a plain identifier at the position.
func (p *msvcParser) identifier() (string, error) {
	start := p.i
	for isIdent(p.peek()) {
		p.i++
	}
	if p.i == start || !isIdentStart(p.s[start]) {
		return "", errMsvc
	}
	return p.s[start:p.i], nil
}

// anonymous parses a "?A" qualifier, which Ghidra's MDQualifier keeps as the
// fragment "A...": "?A0x<hex>@" is an anonymous namespace, named "_anon_" and
// the number as 8 uppercase hex digits (MDMangUtils.createStandardAnonymousNamespaceNode).
// Any other "?Aname@" is the name "Aname". It joins the name table either way.
func (p *msvcParser) anonymous() (string, error) {
	p.i++ // the '?'; the 'A' stays part of the fragment
	raw, err := p.identifier()
	if err != nil || !p.take('@') {
		return "", errMsvc
	}
	name := raw
	if hex, ok := strings.CutPrefix(raw, "A0x"); ok {
		v, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return "", errMsvc
		}
		name = fmt.Sprintf("_anon_%08X", v)
	}
	p.addName(name)
	return name, nil
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdent(c byte) bool {
	return isIdentStart(c) || isDigit(c)
}

// addName adds a name to the name table for backreferences, up to ten entries.
func (p *msvcParser) addName(name string) {
	if len(p.names) < 10 {
		p.names = append(p.names, name)
	}
}
