package proto

import (
	"errors"
	"fmt"
)

// Packed record headers and type codes (marshal.hh PackedFormat).
const (
	pkHeaderMask   = 0xc0
	pkElementStart = 0x40
	pkElementEnd   = 0x80
	pkAttribute    = 0xc0
	pkExtend       = 0x20
	pkIDMask       = 0x1f
	pkRawMask      = 0x7f

	tcBoolean      = 1
	tcSignedPos    = 2
	tcSignedNeg    = 3
	tcUnsigned     = 4
	tcAddrSpace    = 5
	tcSpecialSpace = 6
	tcString       = 7
)

// AttrKind says how an attribute value was encoded.
type AttrKind uint8

const (
	KindBool AttrKind = iota + 1
	KindInt           // signed; Num holds the value
	KindUint
	KindSpace        // address space index
	KindSpecialSpace // stack, join, fspec, iop, spacebase code
	KindString
)

// Attr is one decoded attribute.
type Attr struct {
	ID   uint32
	Kind AttrKind
	Num  uint64 // Int holds two's complement; Bool holds 0 or 1
	Str  string
}

// Int returns the value as a signed integer.
func (a Attr) Int() int64 { return int64(a.Num) }

// Element is a decoded packed element.
type Element struct {
	ID       uint32
	Attrs    []Attr
	Children []*Element
}

// Attr finds an attribute by id.
func (e *Element) Attr(id uint32) (Attr, bool) {
	for _, a := range e.Attrs {
		if a.ID == id {
			return a, true
		}
	}
	return Attr{}, false
}

// Child returns the first child with the given id.
func (e *Element) Child(id uint32) *Element {
	for _, c := range e.Children {
		if c.ID == id {
			return c
		}
	}
	return nil
}

var errPackedEOF = errors.New("proto: truncated packed data")

// DecodePacked decodes one top-level packed element tree.
func DecodePacked(b []byte) (*Element, error) {
	var root *Element
	var stack []*Element
	i := 0
	next := func() (byte, error) {
		if i >= len(b) {
			return 0, errPackedEOF
		}
		c := b[i]
		i++
		return c, nil
	}
	readID := func(h byte) (uint32, error) {
		id := uint32(h & pkIDMask)
		if h&pkExtend != 0 {
			c, err := next()
			if err != nil {
				return 0, err
			}
			id = id<<7 | uint32(c&pkRawMask)
		}
		return id, nil
	}
	readInt := func(n int) (uint64, error) {
		var v uint64
		for ; n > 0; n-- {
			c, err := next()
			if err != nil {
				return 0, err
			}
			v = v<<7 | uint64(c&pkRawMask)
		}
		return v, nil
	}
	for i < len(b) {
		h, _ := next()
		id, err := readID(h)
		if err != nil {
			return nil, err
		}
		switch h & pkHeaderMask {
		case pkElementStart:
			e := &Element{ID: id}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.Children = append(p.Children, e)
			} else if root != nil {
				return nil, errors.New("proto: more than one top-level packed element")
			} else {
				root = e
			}
			stack = append(stack, e)
		case pkElementEnd:
			if len(stack) == 0 || stack[len(stack)-1].ID != id {
				return nil, fmt.Errorf("proto: unmatched packed element end %d", id)
			}
			stack = stack[:len(stack)-1]
		case pkAttribute:
			if len(stack) == 0 {
				return nil, errors.New("proto: packed attribute outside an element")
			}
			t, err := next()
			if err != nil {
				return nil, err
			}
			a := Attr{ID: id}
			code, length := t>>4, int(t&0xf)
			switch code {
			case tcBoolean:
				a.Kind, a.Num = KindBool, uint64(length)
			case tcSignedPos, tcSignedNeg, tcUnsigned, tcAddrSpace:
				a.Kind = map[byte]AttrKind{tcSignedPos: KindInt, tcSignedNeg: KindInt, tcUnsigned: KindUint, tcAddrSpace: KindSpace}[code]
				if a.Num, err = readInt(length); err != nil {
					return nil, err
				}
				if code == tcSignedNeg {
					a.Num = -a.Num
				}
			case tcSpecialSpace:
				a.Kind, a.Num = KindSpecialSpace, uint64(length)
			case tcString:
				n, err := readInt(length)
				if err != nil {
					return nil, err
				}
				if n > uint64(len(b)-i) {
					return nil, errPackedEOF
				}
				a.Kind, a.Str = KindString, string(b[i:i+int(n)])
				i += int(n)
			default:
				return nil, fmt.Errorf("proto: unknown packed type code %d", code)
			}
			top := stack[len(stack)-1]
			top.Attrs = append(top.Attrs, a)
		default:
			return nil, fmt.Errorf("proto: bad packed header %#02x", h)
		}
	}
	if root == nil || len(stack) != 0 {
		return nil, errPackedEOF
	}
	return root, nil
}
