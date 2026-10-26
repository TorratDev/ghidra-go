package demangle

// mdArgumentsList ports MDArgumentsList: it parses the parameters and their
// 'Z' terminator, and returns their spellings. A lone 'X' is the void list;
// otherwise '@' ends the list before the 'Z'.
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
		arg, err := p.mdDataTypeParser()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
	}
}
