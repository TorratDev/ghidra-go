package demangle

// Port of RustDemanglerV0 (Ghidra 12.1.4): a rustc-demangle style printer for
// Rust v0 symbols. A parse failure unwinds with a panic of type v0Error,
// which demangleV0 turns into the results Java returns.

import (
	"math/bits"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	v0MaxDepth       = 500
	v0RecursionLimit = "{recursion limit reached}"
	// shortcut: Java loops once per bound lifetime, so a huge count hangs;
	// reject counts above this, raise it if a real symbol needs more.
	v0MaxBinderLifetimes = 1 << 16
)

type v0Error struct{ tooDeep bool }

func v0Invalid() { panic(v0Error{}) }

// v0Try runs f and returns the parse error it unwound with, if any.
func v0Try(f func()) (err *v0Error) {
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(v0Error)
			if !ok {
				panic(r)
			}
			err = &e
		}
	}()
	f()
	return nil
}

func upperPath(c int) bool { return c >= 'A' && c <= 'Z' }

// demangleV0 is RustDemanglerV0.demangle; false means Java returns null.
func demangleV0(symbol string) (string, bool) {
	var inner string
	switch {
	case len(symbol) > 2 && strings.HasPrefix(symbol, "_R"):
		inner = symbol[2:]
	case len(symbol) > 1 && strings.HasPrefix(symbol, "R"):
		inner = symbol[1:]
	case len(symbol) > 3 && strings.HasPrefix(symbol, "__R"):
		inner = symbol[3:]
	}
	if inner == "" {
		return "", false
	}
	for i := 0; i < len(inner); i++ {
		if inner[i] >= 0x80 {
			return "", false
		}
	}
	if !upperPath(int(inner[0])) {
		return "", false
	}
	// Dry runs validate the first path and, when one follows, a second.
	if v0Try(func() {
		after := v0DryRun(&v0Parser{sym: inner})
		if upperPath(after.peek()) {
			v0DryRun(after)
		}
	}) != nil {
		return "", false
	}
	var out strings.Builder
	p := &v0Printer{parser: &v0Parser{sym: inner}, out: &out}
	if e := v0Try(func() { p.printPath(true) }); e != nil {
		if e.tooDeep {
			return v0RecursionLimit, true
		}
		return "", false
	}
	suffix := p.parser.remaining()
	// Keep dotted suffixes (".1", ".cold"), drop ".llvm…" and "@@…".
	if strings.HasPrefix(suffix, ".") && !strings.HasPrefix(suffix, ".llvm") && !strings.HasPrefix(suffix, "@@") {
		return out.String() + suffix, true
	}
	return out.String(), true
}

func v0DryRun(p *v0Parser) *v0Parser {
	pr := &v0Printer{parser: p}
	pr.printPath(false)
	return pr.parser
}

type v0Parser struct {
	sym   string
	next  int
	depth int
}

func (p *v0Parser) remaining() string { return p.sym[min(p.next, len(p.sym)):] }

func (p *v0Parser) peek() int {
	if p.next >= len(p.sym) {
		return -1
	}
	return int(p.sym[p.next])
}

func (p *v0Parser) eat(c byte) bool {
	if p.peek() == int(c) {
		p.next++
		return true
	}
	return false
}

func (p *v0Parser) nextChar() byte {
	if p.next >= len(p.sym) {
		v0Invalid()
	}
	p.next++
	return p.sym[p.next-1]
}

func (p *v0Parser) pushDepth() {
	p.depth++
	if p.depth > v0MaxDepth {
		panic(v0Error{tooDeep: true})
	}
}

func (p *v0Parser) popDepth() { p.depth-- }

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func (p *v0Parser) hexNibbles() v0Hex {
	start := p.next
	for {
		c := p.nextChar()
		if isHex(c) {
			continue
		}
		if c == '_' {
			break
		}
		v0Invalid()
	}
	return v0Hex(p.sym[start : p.next-1])
}

func (p *v0Parser) digit10() int {
	if c := p.peek(); c >= '0' && c <= '9' {
		p.next++
		return c - '0'
	}
	v0Invalid()
	return 0
}

func (p *v0Parser) digit62() uint64 {
	c := p.peek()
	switch {
	case c >= '0' && c <= '9':
		p.next++
		return uint64(c - '0')
	case c >= 'a' && c <= 'z':
		p.next++
		return uint64(10 + c - 'a')
	case c >= 'A' && c <= 'Z':
		p.next++
		return uint64(36 + c - 'A')
	}
	v0Invalid()
	return 0
}

func addExact(a, b uint64) uint64 {
	s, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		v0Invalid()
	}
	return s
}

func mulExact(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		v0Invalid()
	}
	return lo
}

func (p *v0Parser) integer62() uint64 {
	if p.eat('_') {
		return 0
	}
	var v uint64
	for !p.eat('_') {
		v = addExact(mulExact(v, 62), p.digit62())
	}
	return addExact(v, 1)
}

func (p *v0Parser) optInteger62(tag byte) uint64 {
	if !p.eat(tag) {
		return 0
	}
	return addExact(p.integer62(), 1)
}

func (p *v0Parser) disambiguator() uint64 { return p.optInteger62('s') }

// namespace returns the uppercase namespace tag, or 0 for a lowercase one.
func (p *v0Parser) namespace() byte {
	c := p.nextChar()
	switch {
	case c >= 'A' && c <= 'Z':
		return c
	case c >= 'a' && c <= 'z':
		return 0
	}
	v0Invalid()
	return 0
}

func (p *v0Parser) backref() *v0Parser {
	start := p.next - 1
	off := p.integer62()
	// Deviation: Java compares signed longs, so an offset above MaxInt64 passes
	// the check and its (int) cast wraps to a possibly valid index. Rejecting any
	// offset >= start (unsigned) avoids decoding from a wrapped, meaningless position.
	if off >= uint64(start) {
		v0Invalid()
	}
	q := &v0Parser{sym: p.sym, next: int(off), depth: p.depth}
	q.pushDepth()
	return q
}

type v0Ident struct{ ascii, punycode string }

func (p *v0Parser) ident() v0Ident {
	puny := p.eat('u')
	n := p.digit10()
	if n != 0 {
		for {
			c := p.peek()
			if c < '0' || c > '9' {
				break
			}
			p.next++
			if n > (1<<31-1)/10 {
				v0Invalid()
			}
			n *= 10
			if n > 1<<31-1-(c-'0') {
				v0Invalid()
			}
			n += c - '0'
		}
	}
	p.eat('_')
	if p.next+n > len(p.sym) {
		v0Invalid()
	}
	raw := p.sym[p.next : p.next+n]
	p.next += n
	if !puny {
		return v0Ident{ascii: raw}
	}
	ascii, punycode := "", raw
	if sep := strings.LastIndexByte(raw, '_'); sep >= 0 {
		ascii, punycode = raw[:sep], raw[sep+1:]
	}
	if punycode == "" {
		v0Invalid()
	}
	return v0Ident{ascii, punycode}
}

func (i v0Ident) isEmpty() bool { return i.ascii == "" && i.punycode == "" }

func (i v0Ident) render() string {
	if i.punycode == "" {
		return i.ascii
	}
	dec, ok := i.decodePunycode()
	if !ok {
		s := "punycode{"
		if i.ascii != "" {
			s += i.ascii + "-"
		}
		return s + i.punycode + "}"
	}
	return string(dec)
}

// decodePunycode is the RFC 3492 decoder with overflow checks as in Java.
func (id v0Ident) decodePunycode() ([]rune, bool) {
	out := []rune(id.ascii)
	const base, tMin, tMax, skew = 36, 1, 26, 38
	damp, bias := uint64(700), 72
	var i, n uint64 = 0, 0x80
	idx := 0
	pc := id.punycode
	for idx < len(pc) {
		var delta, w uint64 = 0, 1
		k := base
		for {
			if idx >= len(pc) {
				return nil, false
			}
			c := pc[idx]
			idx++
			var digit uint64
			switch {
			case c >= 'a' && c <= 'z':
				digit = uint64(c - 'a')
			case c >= '0' && c <= '9':
				digit = uint64(26 + c - '0')
			default:
				return nil, false
			}
			hi, lo := bits.Mul64(w, digit)
			sum, carry := bits.Add64(delta, lo, 0)
			if hi != 0 || carry != 0 {
				return nil, false
			}
			delta = sum
			t := min(max(k-bias, tMin), tMax)
			if digit < uint64(t) {
				break
			}
			hi, lo = bits.Mul64(w, uint64(base-t))
			if hi != 0 {
				return nil, false
			}
			w = lo
			k += base
		}
		outLen := uint64(len(out) + 1)
		var carry uint64
		i, carry = bits.Add64(i, delta, 0)
		if carry != 0 {
			return nil, false
		}
		n, carry = bits.Add64(n, i/outLen, 0)
		if carry != 0 {
			return nil, false
		}
		i %= outLen
		if n > 0x10FFFF {
			return nil, false
		}
		out = append(out, 0)
		copy(out[i+1:], out[i:])
		out[i] = rune(n)
		i++
		delta /= damp
		damp = 2
		delta += delta / outLen
		kAdjust := 0
		for delta > uint64((base-tMin)*tMax)/2 {
			delta /= base - tMin
			kAdjust += base
		}
		bias = kAdjust + int(uint64(base-tMin+1)*delta/(delta+skew))
	}
	return out, true
}

type v0Hex string

// uint is tryParseUInt: nil when more than 16 significant digits.
func (h v0Hex) uint() (uint64, bool) {
	t := strings.TrimLeft(string(h), "0")
	if len(t) > 16 {
		return 0, false
	}
	var v uint64
	for i := 0; i < len(t); i++ {
		d, _ := strconv.ParseUint(t[i:i+1], 16, 8)
		v = v<<4 | d
	}
	return v, true
}

// str is tryParseStr: the nibbles as UTF-8 bytes.
func (h v0Hex) str() (string, bool) {
	if len(h)&1 != 0 {
		return "", false
	}
	b := make([]byte, len(h)/2)
	for i := range b {
		v, _ := strconv.ParseUint(string(h[2*i:2*i+2]), 16, 8)
		b[i] = byte(v)
	}
	if !utf8.Valid(b) {
		return "", false
	}
	return string(b), true
}

var v0Basic = map[byte]string{
	'a': "i8", 'b': "bool", 'c': "char", 'd': "f64", 'e': "str", 'f': "f32", 'h': "u8",
	'i': "isize", 'j': "usize", 'l': "i32", 'm': "u32", 'n': "i128", 'o': "u128", 'p': "_",
	's': "i16", 't': "u16", 'u': "()", 'v': "...", 'x': "i64", 'y': "u64", 'z': "!",
}

// v0Printer prints to out; a nil out is a dry run that only parses.
type v0Printer struct {
	parser             *v0Parser
	out                *strings.Builder
	boundLifetimeDepth int
}

func (p *v0Printer) print(s string) {
	if p.out != nil {
		p.out.WriteString(s)
	}
}

func (p *v0Printer) printByte(c byte) {
	if p.out != nil {
		p.out.WriteByte(c)
	}
}

func (p *v0Printer) printInt(v uint64) { p.print(strconv.FormatInt(int64(v), 10)) } // Java prints longs signed

func (p *v0Printer) printPath(inValue bool) {
	p.parser.pushDepth()
	switch tag := p.parser.nextChar(); tag {
	case 'C':
		dis := p.parser.disambiguator()
		p.print(p.parser.ident().render())
		if dis != 0 {
			p.print("[" + strconv.FormatUint(dis, 16) + "]")
		}
	case 'N':
		ns := p.parser.namespace()
		p.printPath(inValue)
		dis := p.parser.disambiguator()
		name := p.parser.ident()
		if ns != 0 {
			p.print("::{")
			switch ns {
			case 'C':
				p.print("closure")
			case 'S':
				p.print("shim")
			default:
				p.printByte(ns)
			}
			if !name.isEmpty() {
				p.printByte(':')
				p.print(name.render())
			}
			p.printByte('#')
			p.printInt(dis)
			p.printByte('}')
		} else if !name.isEmpty() {
			p.print("::")
			p.print(name.render())
		}
	case 'M', 'X', 'Y':
		if tag != 'Y' {
			p.parser.disambiguator()
			p.skipping(func() { p.printPath(false) })
		}
		p.printByte('<')
		p.printType()
		if tag != 'M' {
			p.print(" as ")
			p.printPath(false)
		}
		p.printByte('>')
	case 'I':
		p.printPath(inValue)
		if inValue {
			p.print("::")
		}
		p.printByte('<')
		p.sepList(p.printGenericArg, ", ")
		p.printByte('>')
	case 'B':
		p.backref(func() { p.printPath(inValue) })
	default:
		v0Invalid()
	}
	p.parser.popDepth()
}

func (p *v0Printer) printGenericArg() {
	switch {
	case p.parser.eat('L'):
		p.lifetime(p.parser.integer62())
	case p.parser.eat('K'):
		p.printConst(false)
	default:
		p.printType()
	}
}

func (p *v0Printer) printType() {
	tag := p.parser.nextChar()
	if b, ok := v0Basic[tag]; ok {
		p.print(b)
		return
	}
	p.parser.pushDepth()
	switch tag {
	case 'R', 'Q':
		p.printByte('&')
		if p.parser.eat('L') {
			if lt := p.parser.integer62(); lt != 0 {
				p.lifetime(lt)
				p.printByte(' ')
			}
		}
		if tag != 'R' {
			p.print("mut ")
		}
		p.printType()
	case 'P', 'O':
		p.printByte('*')
		if tag == 'P' {
			p.print("const ")
		} else {
			p.print("mut ")
		}
		p.printType()
	case 'A', 'S':
		p.printByte('[')
		p.printType()
		if tag == 'A' {
			p.print("; ")
			p.printConst(true)
		}
		p.printByte(']')
	case 'T':
		p.printByte('(')
		if p.sepList(p.printType, ", ") == 1 {
			p.printByte(',')
		}
		p.printByte(')')
	case 'F':
		p.inBinder(func() {
			unsafe := p.parser.eat('U')
			abi, hasABI := "", false
			if p.parser.eat('K') {
				hasABI = true
				if p.parser.eat('C') {
					abi = "C"
				} else {
					id := p.parser.ident()
					if id.punycode != "" || id.ascii == "" {
						v0Invalid()
					}
					abi = id.ascii
				}
			}
			if unsafe {
				p.print("unsafe ")
			}
			if hasABI {
				p.print(`extern "`)
				parts := strings.Split(abi, "_")
				for len(parts) > 0 && parts[len(parts)-1] == "" { // Java's split drops trailing empties
					parts = parts[:len(parts)-1]
				}
				p.print(strings.Join(parts, "-"))
				p.print(`" `)
			}
			p.print("fn(")
			p.sepList(p.printType, ", ")
			p.printByte(')')
			if !p.parser.eat('u') {
				p.print(" -> ")
				p.printType()
			}
		})
	case 'D':
		p.print("dyn ")
		p.inBinder(func() { p.sepList(p.printDynTrait, " + ") })
		if !p.parser.eat('L') {
			v0Invalid()
		}
		if lt := p.parser.integer62(); lt != 0 {
			p.print(" + ")
			p.lifetime(lt)
		}
	case 'B':
		p.backref(p.printType)
	case 'W':
		p.printType()
		p.print(" is ")
		p.printPat()
	default:
		p.parser.next-- // rewind for path parsing
		p.printPath(false)
	}
	p.parser.popDepth()
}

func (p *v0Printer) printPathMaybeOpenGenerics() bool {
	if p.parser.eat('B') {
		open := false
		p.backref(func() { open = p.printPathMaybeOpenGenerics() })
		return open
	}
	if p.parser.eat('I') {
		p.printPath(false)
		p.printByte('<')
		p.sepList(p.printGenericArg, ", ")
		return true
	}
	p.printPath(false)
	return false
}

func (p *v0Printer) printDynTrait() {
	open := p.printPathMaybeOpenGenerics()
	for p.parser.eat('p') {
		if !open {
			p.printByte('<')
			open = true
		} else {
			p.print(", ")
		}
		p.print(p.parser.ident().render())
		p.print(" = ")
		p.printType()
	}
	if open {
		p.printByte('>')
	}
}

func (p *v0Printer) printPat() {
	switch p.parser.nextChar() {
	case 'R':
		p.printConst(false)
		p.print("..=")
		p.printConst(false)
	case 'O':
		p.parser.pushDepth()
		p.printPat()
		for !p.parser.eat('E') {
			p.print(" | ")
			p.printPat()
		}
		p.parser.popDepth()
	case 'N':
		p.print("!null")
	default:
		v0Invalid()
	}
}

func (p *v0Printer) printConst(inValue bool) {
	tag := p.parser.nextChar()
	p.parser.pushDepth()
	opened := false
	wrap := func() {
		if !inValue {
			opened = true
			p.printByte('{')
		}
	}
	switch tag {
	case 'p':
		p.printByte('_')
	case 'h', 't', 'm', 'y', 'o', 'j':
		p.printConstUint(tag)
	case 'a', 's', 'l', 'x', 'n', 'i':
		if p.parser.eat('n') {
			p.printByte('-')
		}
		p.printConstUint(tag)
	case 'b':
		v, ok := p.parser.hexNibbles().uint()
		if !ok {
			v0Invalid()
		}
		switch v {
		case 0:
			p.print("false")
		case 1:
			p.print("true")
		default:
			v0Invalid()
		}
	case 'c':
		v, ok := p.parser.hexNibbles().uint()
		if !ok || v > 0x10FFFF {
			v0Invalid()
		}
		p.quoted('\'', string(rune(v)))
	case 'e':
		wrap()
		p.printByte('*')
		p.printConstStr()
	case 'R', 'Q':
		if tag == 'R' && p.parser.eat('e') {
			p.printConstStr()
		} else {
			wrap()
			p.printByte('&')
			if tag != 'R' {
				p.print("mut ")
			}
			p.printConst(true)
		}
	case 'A':
		wrap()
		p.printByte('[')
		p.sepList(func() { p.printConst(true) }, ", ")
		p.printByte(']')
	case 'T':
		wrap()
		p.printByte('(')
		if p.sepList(func() { p.printConst(true) }, ", ") == 1 {
			p.printByte(',')
		}
		p.printByte(')')
	case 'V':
		wrap()
		p.printPath(true)
		switch p.parser.nextChar() {
		case 'U':
		case 'T':
			p.printByte('(')
			p.sepList(func() { p.printConst(true) }, ", ")
			p.printByte(')')
		case 'S':
			p.print(" { ")
			p.sepList(func() {
				p.parser.disambiguator()
				p.print(p.parser.ident().render())
				p.print(": ")
				p.printConst(true)
			}, ", ")
			p.print(" }")
		default:
			v0Invalid()
		}
	case 'B':
		p.backref(func() { p.printConst(inValue) })
	default:
		v0Invalid()
	}
	if opened {
		p.printByte('}')
	}
	p.parser.popDepth()
}

func (p *v0Printer) printConstStr() {
	s, ok := p.parser.hexNibbles().str()
	if !ok {
		v0Invalid()
	}
	p.quoted('"', s)
}

func (p *v0Printer) printConstUint(tag byte) {
	hex := p.parser.hexNibbles()
	if v, ok := hex.uint(); ok {
		p.printInt(v)
	} else {
		p.print("0x" + string(hex))
	}
	p.print(v0Basic[tag])
}

func (p *v0Printer) backref(f func()) {
	b := p.parser.backref()
	if p.out == nil {
		return
	}
	saved := p.parser
	p.parser = b
	f()
	p.parser = saved
}

func (p *v0Printer) inBinder(f func()) {
	count := p.parser.optInteger62('G')
	if p.out == nil {
		f()
		return
	}
	if count > v0MaxBinderLifetimes {
		v0Invalid()
	}
	if count > 0 {
		p.print("for<")
		for i := uint64(0); i < count; i++ {
			if i != 0 {
				p.print(", ")
			}
			p.boundLifetimeDepth++
			p.lifetime(1)
		}
		p.print("> ")
	}
	f()
	p.boundLifetimeDepth -= int(count)
}

func (p *v0Printer) sepList(f func(), sep string) int {
	n := 0
	for !p.parser.eat('E') {
		if n != 0 {
			p.print(sep)
		}
		f()
		n++
	}
	return n
}

func (p *v0Printer) lifetime(lt uint64) {
	if p.out == nil {
		return
	}
	p.printByte('\'')
	if lt == 0 {
		p.printByte('_')
		return
	}
	depth := int64(p.boundLifetimeDepth) - int64(lt)
	if depth < 0 {
		v0Invalid()
	}
	if depth < 26 {
		p.printByte(byte('a' + depth))
	} else {
		p.printByte('_')
		p.print(strconv.FormatInt(depth, 10))
	}
}

func (p *v0Printer) skipping(f func()) {
	saved := p.out
	p.out = nil
	f()
	p.out = saved
}

func (p *v0Printer) quoted(quote rune, data string) {
	if p.out == nil {
		return
	}
	p.out.WriteRune(quote)
	for _, cp := range data {
		switch {
		case quote == '\'' && cp == '"', quote == '"' && cp == '\'':
			p.out.WriteRune(cp)
		case cp == '\\':
			p.print(`\\`)
		case cp == '\n':
			p.print(`\n`)
		case cp == '\r':
			p.print(`\r`)
		case cp == '\t':
			p.print(`\t`)
		case cp == 0:
			p.print(`\0`)
		case cp == '"' || cp == '\'':
			if cp == quote {
				p.printByte('\\')
			}
			p.out.WriteRune(cp)
		case cp < 0x20 || cp == 0x7f:
			p.print(`\x` + string("0123456789abcdef"[cp>>4]) + string("0123456789abcdef"[cp&15]))
		default:
			p.out.WriteRune(cp)
		}
	}
	p.out.WriteRune(quote)
}
