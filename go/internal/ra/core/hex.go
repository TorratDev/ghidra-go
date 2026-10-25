// Package core is the Go port of rust-analysis/crates/ra-core: the loaded
// memory image and the normalized analysis report schema.
package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Addr is a 64-bit address encoded in JSON as a lowercase "0x…" string so
// values survive consumers that only have doubles. Zero is "0x0".
type Addr uint64

// ParseHex parses an address with an optional 0x/0X prefix.
func ParseHex(s string) (uint64, error) {
	t := strings.TrimSpace(s)
	if p, ok := strings.CutPrefix(t, "0x"); ok {
		t = p
	} else if p, ok := strings.CutPrefix(t, "0X"); ok {
		t = p
	}
	v, err := strconv.ParseUint(t, 16, 64)
	if err != nil {
		return 0, fmt.Errorf("bad hex address %q: %w", s, err)
	}
	return v, nil
}

func (a Addr) MarshalJSON() ([]byte, error) {
	return []byte(`"0x` + strconv.FormatUint(uint64(a), 16) + `"`), nil
}

// UnmarshalJSON accepts a hex string or a bare non-negative integer.
func (a *Addr) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		v, err := ParseHex(s)
		*a = Addr(v)
		return err
	}
	v, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		return fmt.Errorf("bad address %s: %w", b, err)
	}
	*a = Addr(v)
	return nil
}

// AddrPair is a half-open range [start, end) encoded as ["0x…","0x…"].
type AddrPair [2]Addr

func (p *AddrPair) UnmarshalJSON(b []byte) error {
	var a []Addr
	if err := json.Unmarshal(b, &a); err != nil {
		return err
	}
	if len(a) != 2 {
		return fmt.Errorf("address pair needs 2 elements, got %d", len(a))
	}
	*p = AddrPair{a[0], a[1]}
	return nil
}
