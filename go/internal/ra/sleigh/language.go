package sleigh

import (
	"errors"
	"fmt"
)

// Varnode is a SLEIGH storage location: a register (or other space) range.
type Varnode struct {
	Space  string `json:"space"`
	Offset uint64 `json:"offset"`
	Size   uint32 `json:"size"`
}

// Language is what the bridge reports about a loaded SLEIGH language.
type Language struct {
	ID        string `json:"id"`
	BigEndian bool   `json:"big_endian"`
	// AddressSize is the pointer size in bytes.
	AddressSize uint32 `json:"address_size"`
	// InitialContext is the context register value at an address with no
	// recorded context.
	InitialContext uint64  `json:"initial_context"`
	PC             Varnode `json:"pc"`
	SP             Varnode `json:"sp"`
	// IntArgs are the integer parameter registers of the default calling
	// convention, in order.
	IntArgs []Varnode `json:"int_args"`
}

var languageShape = func() *shape {
	s := obj("id", "big_endian", "address_size", "initial_context", "pc", "sp", "int_args")
	vn := obj("space", "offset", "size")
	s.keys["pc"], s.keys["sp"], s.keys["int_args"] = vn, vn, &shape{elem: vn}
	return s
}()

type varnodeWire struct {
	Space  *string `json:"space"`
	Offset *uint64 `json:"offset"`
	Size   *uint32 `json:"size"`
}

func (w varnodeWire) valid(what string) (Varnode, error) {
	if err := missing(map[string]bool{"space": w.Space != nil, "offset": w.Offset != nil, "size": w.Size != nil}, "space", "offset", "size"); err != nil {
		return Varnode{}, fmt.Errorf("%s: %w", what, err)
	}
	if *w.Space == "" || *w.Size == 0 {
		return Varnode{}, fmt.Errorf("%s: space must be non-empty and size positive", what)
	}
	return Varnode{*w.Space, *w.Offset, *w.Size}, nil
}

type languageWire struct {
	ID             *string        `json:"id"`
	BigEndian      *bool          `json:"big_endian"`
	AddressSize    *uint32        `json:"address_size"`
	InitialContext *uint64        `json:"initial_context"`
	PC             *varnodeWire   `json:"pc"`
	SP             *varnodeWire   `json:"sp"`
	IntArgs        *[]varnodeWire `json:"int_args"`
}

// ParseLanguage decodes and validates a language record. Every field is
// required (int_args may be an empty list); unknown fields are rejected.
func ParseLanguage(data []byte) (*Language, error) {
	var w languageWire
	if err := decodeStrict(data, languageShape, &w); err != nil {
		return nil, fmt.Errorf("language: %w", err)
	}
	if err := missing(map[string]bool{
		"id": w.ID != nil, "big_endian": w.BigEndian != nil, "address_size": w.AddressSize != nil,
		"initial_context": w.InitialContext != nil, "pc": w.PC != nil, "sp": w.SP != nil, "int_args": w.IntArgs != nil,
	}, "id", "big_endian", "address_size", "initial_context", "pc", "sp", "int_args"); err != nil {
		return nil, fmt.Errorf("language: %w", err)
	}
	if *w.ID == "" {
		return nil, errors.New(`language: field "id" is empty`)
	}
	switch *w.AddressSize {
	case 1, 2, 4, 8:
	default:
		return nil, fmt.Errorf(`language: field "address_size" must be 1, 2, 4 or 8, got %d`, *w.AddressSize)
	}
	l := &Language{ID: *w.ID, BigEndian: *w.BigEndian, AddressSize: *w.AddressSize, InitialContext: *w.InitialContext, IntArgs: []Varnode{}}
	var err error
	if l.PC, err = w.PC.valid(`language: field "pc"`); err != nil {
		return nil, err
	}
	if l.SP, err = w.SP.valid(`language: field "sp"`); err != nil {
		return nil, err
	}
	for i, a := range *w.IntArgs {
		v, err := a.valid(fmt.Sprintf(`language: field "int_args"[%d]`, i))
		if err != nil {
			return nil, err
		}
		l.IntArgs = append(l.IntArgs, v)
	}
	return l, nil
}
