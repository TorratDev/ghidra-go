package demangle

import "strings"

// argBackrefKinds are the first characters of the top-level argument types
// that mdArgumentsList adds to the type table: pointers and references, and
// class, struct, union and enum names. Basic types, arrays, 'X' and 'Z' are
// not added.
const argBackrefKinds = "PQRAVUTW"

// mdArgumentsList ports MDArgumentsList: it parses the parameters and their
// 'Z' terminator, and returns their spellings. A lone 'X' is the void list;
// otherwise '@' ends the list before the 'Z'. Each top-level argument of a
// backreferenced kind joins the type table, so a later digit can refer to it.
func (p *msvcParser) mdArgumentsList() ([]string, error) {
	if p.take('X') {
		if !p.take('Z') {
			return nil, errMsvc
		}
		return []string{"void"}, nil
	}
	args := []string{}
	for {
		switch p.peek() {
		case '@':
			p.i++
			if !p.take('Z') {
				return nil, errMsvc
			}
			return args, nil
		case 'Z':
			p.i++
			return args, nil
		}
		kind := p.peek()
		arg, err := p.mdDataTypeParser()
		if err != nil {
			return nil, err
		}
		if strings.IndexByte(argBackrefKinds, kind) >= 0 {
			p.types = append(p.types, arg)
		}
		args = append(args, arg)
	}
}
