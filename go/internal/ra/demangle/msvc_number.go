package demangle

// mdEncodedNumber ports MDEncodedNumber: a digit is its value plus one, and
// 'A'-'P' digits followed by '@' spell a hexadecimal value.
func (p *msvcParser) mdEncodedNumber() (int, error) {
	c := p.next()
	if isDigit(c) {
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
