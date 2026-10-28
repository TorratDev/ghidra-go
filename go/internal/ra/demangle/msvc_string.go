package demangle

import (
	"unicode"
	"unicode/utf8"
)

// msvcStringPunct are the characters a "?<digit>" escape stands for in a string
// literal, as MDString.parseByte maps them.
var msvcStringPunct = map[byte]byte{
	'0': ',', '1': '/', '2': '\\', '3': ':', '4': '.', '5': ' ', '6': '\n',
	'7': '\t', '8': '\'', '9': '-',
}

// stringLiteral ports MDString: "??_C@_<char type><length><crc>@<bytes>@" and an
// optional address after it. The char type is '0' for char and '1' for wchar_t.
// Ghidra names every literal "`string'" with no namespace. Full is the text
// when every character is printable, and empty otherwise.
func (p *msvcParser) stringLiteral() (*Demangled, error) {
	if !p.take('@') || !p.take('_') {
		return nil, errMsvc
	}
	charType := p.next()
	if charType != '0' && charType != '1' {
		return nil, errMsvc
	}
	length, err := p.mdEncodedNumber()
	if err != nil {
		return nil, err
	}
	// The CRC is not checked.
	if err := p.skipHexNibbles(); err != nil {
		return nil, err
	}
	raw, err := p.stringBytes(length)
	if err != nil {
		return nil, err
	}
	if !p.take('@') {
		return nil, errMsvc
	}
	// The address after the bytes, which Ghidra's name does not use, is hex.
	if p.i < len(p.s) {
		if err := p.skipHexNibbles(); err != nil || p.i != len(p.s) {
			return nil, errMsvc
		}
	}
	return &Demangled{Scheme: Msvc, Name: "`string'", Full: stringText(raw, charType)}, nil
}

// skipHexNibbles consumes hex nibbles, each 'A'-'P', and the '@' that ends them.
// A string's CRC and address are written this way, and their values are not used.
func (p *msvcParser) skipHexNibbles() error {
	for p.peek() != '@' {
		if c := p.next(); c < 'A' || c > 'P' {
			return errMsvc
		}
	}
	p.i++
	return nil
}

// stringBytes parses up to n bytes of a string literal, each a plain character
// or a "?" escape. Like MDString, it stops at the '@' even short of n: the
// missing bytes are NULs, which the text drops.
func (p *msvcParser) stringBytes(n int) ([]byte, error) {
	var out []byte
	for len(out) < n && p.peek() != '@' {
		if p.i >= len(p.s) {
			return nil, errMsvc
		}
		b, err := p.stringByte()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// stringByte is MDString.parseByte: a letter, digit, '_' or '$' stands for
// itself; "?" starts an escape for a letter, a punctuation digit, or two hex
// nibbles after '$'.
func (p *msvcParser) stringByte() (byte, error) {
	c := p.next()
	if isIdent(c) || c == '$' {
		return c, nil
	}
	if c != '?' || p.i >= len(p.s) {
		return 0, errMsvc
	}
	c = p.next()
	switch {
	case c >= 'a' && c <= 'z':
		return c - 'a' + 0xe1, nil
	case c >= 'A' && c <= 'Z':
		return c - 'A' + 0xc1, nil
	case c == '$':
		hi, lo := p.next(), p.next()
		if hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P' {
			return 0, errMsvc
		}
		return (hi-'A')<<4 | (lo - 'A'), nil
	}
	if b, ok := msvcStringPunct[c]; ok {
		return b, nil
	}
	return 0, errMsvc
}

// stringText decodes a literal's bytes up to the first NUL: UTF-16 big-endian
// for wchar_t, as Ghidra's "UTF-16" decoding reads it. It is empty unless every
// character is printable, since Ghidra's text for other bytes is not ported.
func stringText(raw []byte, charType byte) string {
	var runes []rune
	if charType == '1' {
		if len(raw)%2 != 0 {
			return ""
		}
		for i := 0; i < len(raw); i += 2 {
			runes = append(runes, rune(raw[i])<<8|rune(raw[i+1]))
		}
	} else {
		if !utf8.Valid(raw) {
			return ""
		}
		runes = []rune(string(raw))
	}
	var s []rune
	for _, r := range runes {
		if r == 0 {
			break
		}
		if !unicode.IsPrint(r) {
			return ""
		}
		s = append(s, r)
	}
	return string(s)
}
