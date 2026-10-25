package loader

import (
	"debug/elf"
	"encoding/binary"
	"errors"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

// ehFrameStarts returns the FDE start addresses of .eh_frame (Ghidra's
// GccExceptionAnalyzer creates functions at every FDE pc_begin). Seeds are
// FDEs with a non-zero length whose start is executable.
func ehFrameStarts(f *elf.File, mem *core.MemoryMap, bias uint64) []uint64 {
	sec := f.Section(".eh_frame")
	if sec == nil || sec.Type == elf.SHT_NOBITS {
		return nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil
	}
	eh := ehFrame{data: data, bo: f.ByteOrder, base: sec.Addr + bias, addrSize: 4}
	if f.Class == elf.ELFCLASS64 {
		eh.addrSize = 8
	}
	if s := f.Section(".text"); s != nil {
		a := s.Addr + bias
		eh.text = &a
	}
	if s := f.Section(".got"); s != nil {
		a := s.Addr + bias
		eh.got = &a
	}
	var out []uint64
	for _, fde := range eh.fdes() {
		if fde.length > 0 && mem.IsExecutable(fde.start) {
			out = append(out, fde.start)
		}
	}
	return out
}

type fde struct{ start, length uint64 }

// ehFrame parses .eh_frame like gimli's EhFrame, except that an entry that
// fails to parse is skipped (its length frames it) instead of ending the walk.
type ehFrame struct {
	data      []byte
	bo        binary.ByteOrder
	base      uint64 // address of the section
	text, got *uint64
	addrSize  int
}

var errEH = errors.New("bad .eh_frame entry")

// cie is the part of a CIE that decides how its FDEs are read.
type cie struct {
	hasAug  bool
	fdeEnc  byte
	hasFDE  bool
	lsdaEnc byte
	hasLSDA bool
}

func (e *ehFrame) fdes() []fde {
	var out []fde
	cies := map[int]*cie{}
	for off := 0; ; {
		hdr, length, ok := e.entryLength(off)
		if !ok {
			break // end of section, terminator, or a length that cannot be framed
		}
		idPos := off + hdr
		end := idPos + length
		next := end
		off = next
		if length < 4 {
			continue
		}
		id := int(e.bo.Uint32(e.data[idPos:]))
		if id == 0 {
			continue // a CIE is parsed when an FDE refers to it
		}
		if id > idPos {
			continue
		}
		cieOff := idPos - id
		c, seen := cies[cieOff]
		if !seen {
			var err error
			if c, err = e.parseCIE(cieOff); err != nil {
				c = nil
			}
			cies[cieOff] = c
		}
		if c == nil {
			continue
		}
		r := &ehReader{data: e.data, bo: e.bo, pos: idPos + 4, end: end}
		if v, err := e.parseFDE(c, r); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// entryLength reads the initial length at off. ok is false at the end of the
// section, at a zero terminator, or when the entry does not fit.
func (e *ehFrame) entryLength(off int) (hdr, length int, ok bool) {
	if off < 0 || off+4 > len(e.data) {
		return 0, 0, false
	}
	l := uint64(e.bo.Uint32(e.data[off:]))
	hdr = 4
	switch {
	case l == 0xffffffff:
		if off+12 > len(e.data) {
			return 0, 0, false
		}
		l, hdr = e.bo.Uint64(e.data[off+4:]), 12
	case l >= 0xfffffff0:
		return 0, 0, false
	}
	if l == 0 || l > uint64(len(e.data)-off-hdr) {
		return 0, 0, false
	}
	return hdr, int(l), true
}

func (e *ehFrame) parseCIE(off int) (*cie, error) {
	hdr, length, ok := e.entryLength(off)
	if !ok || length < 4 {
		return nil, errEH
	}
	idPos := off + hdr
	if e.bo.Uint32(e.data[idPos:]) != 0 {
		return nil, errEH // not a CIE
	}
	r := &ehReader{data: e.data, bo: e.bo, pos: idPos + 4, end: idPos + length}
	switch r.u8() {
	case 1, 3, 4:
	default:
		return nil, errEH
	}
	var aug []byte
	for {
		c := r.u8()
		if r.err != nil {
			return nil, errEH
		}
		if c == 0 {
			break
		}
		aug = append(aug, c)
	}
	r.uleb()
	r.sleb()
	if e.data[idPos+4] == 1 { // version 1 has a one byte return register
		r.u8()
	} else {
		r.uleb()
	}
	if r.err != nil {
		return nil, errEH
	}
	c := &cie{}
	if len(aug) == 0 {
		return c, nil
	}
	c.hasAug = true
	var rest *ehReader
	for i, ch := range aug {
		switch {
		case ch == 'z' && i == 0:
			n := r.uleb()
			if r.err != nil || n > uint64(r.end-r.pos) {
				return nil, errEH
			}
			rest = &ehReader{data: e.data, bo: e.bo, pos: r.pos, end: r.pos + int(n)}
			r.pos += int(n)
		case ch == 'L' && rest != nil:
			c.lsdaEnc, c.hasLSDA = rest.encoding(), true
		case ch == 'R' && rest != nil:
			c.fdeEnc, c.hasFDE = rest.encoding(), true
		case ch == 'P' && rest != nil:
			enc := rest.encoding()
			if _, err := e.pointer(enc, rest, nil); err != nil {
				return nil, err
			}
		case ch == 'S':
		default:
			return nil, errEH
		}
		if rest != nil && rest.err != nil {
			return nil, errEH
		}
	}
	return c, nil
}

func (e *ehFrame) parseFDE(c *cie, r *ehReader) (fde, error) {
	var start, length uint64
	if c.hasFDE {
		var err error
		if start, err = e.pointer(c.fdeEnc, r, nil); err != nil {
			return fde{}, err
		}
		if length, err = e.value(c.fdeEnc, r); err != nil {
			return fde{}, err
		}
	} else {
		start, length = r.address(e.addrSize), r.address(e.addrSize)
	}
	if r.err != nil {
		return fde{}, errEH
	}
	if c.hasAug {
		n := r.uleb()
		if r.err != nil || n > uint64(r.end-r.pos) {
			return fde{}, errEH
		}
		aug := &ehReader{data: e.data, bo: e.bo, pos: r.pos, end: r.pos + int(n)}
		if c.hasLSDA {
			if _, err := e.pointer(c.lsdaEnc, aug, &start); err != nil {
				return fde{}, err
			}
		}
	}
	return fde{start, length}, nil
}

const ehPEOmit = 0xff

// pointer reads a DW_EH_PE encoded pointer and applies its base.
func (e *ehFrame) pointer(enc byte, r *ehReader, funcBase *uint64) (uint64, error) {
	if !validEncoding(enc) || enc == ehPEOmit {
		return 0, errEH
	}
	var base uint64
	switch enc & 0x70 {
	case 0x00:
	case 0x10:
		base = e.wrapAdd(e.base, uint64(r.pos))
	case 0x20:
		if e.text == nil {
			return 0, errEH
		}
		base = *e.text
	case 0x30:
		if e.got == nil {
			return 0, errEH
		}
		base = *e.got
	case 0x40:
		if funcBase == nil {
			return 0, errEH
		}
		base = *funcBase
	default: // aligned
		return 0, errEH
	}
	v, err := e.value(enc, r)
	if err != nil {
		return 0, err
	}
	return e.wrapAdd(base, v), nil
}

func validEncoding(enc byte) bool {
	if enc == ehPEOmit {
		return true
	}
	switch enc & 0x0f {
	case 0x00, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0a, 0x0b, 0x0c:
	default:
		return false
	}
	switch enc & 0x70 {
	case 0x00, 0x10, 0x20, 0x30, 0x40, 0x50:
		return true
	}
	return false
}

// value reads the value in an encoding's format; signed formats are sign
// extended so that wrapping addition does the right thing.
func (e *ehFrame) value(enc byte, r *ehReader) (uint64, error) {
	var v uint64
	switch enc & 0x0f {
	case 0x00:
		v = r.address(e.addrSize)
	case 0x01:
		v = r.uleb()
	case 0x02:
		v = uint64(r.u16())
	case 0x03:
		v = uint64(r.u32())
	case 0x04:
		v = r.u64()
	case 0x09:
		v = uint64(r.sleb())
	case 0x0a:
		v = uint64(int64(int16(r.u16())))
	case 0x0b:
		v = uint64(int64(int32(r.u32())))
	case 0x0c:
		v = r.u64()
	default:
		return 0, errEH
	}
	if r.err != nil {
		return 0, errEH
	}
	return v, nil
}

// wrapAdd adds modulo the address size.
func (e *ehFrame) wrapAdd(a, b uint64) uint64 {
	if e.addrSize == 4 {
		return uint64(uint32(a) + uint32(b))
	}
	return a + b
}

type ehReader struct {
	data     []byte
	bo       binary.ByteOrder
	pos, end int
	err      error
}

func (r *ehReader) take(n int) []byte {
	if r.err != nil || n < 0 || r.pos+n > r.end {
		r.err = errEH
		return nil
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b
}

func (r *ehReader) u8() byte {
	if b := r.take(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *ehReader) u16() uint16 {
	if b := r.take(2); b != nil {
		return r.bo.Uint16(b)
	}
	return 0
}

func (r *ehReader) u32() uint32 {
	if b := r.take(4); b != nil {
		return r.bo.Uint32(b)
	}
	return 0
}

func (r *ehReader) u64() uint64 {
	if b := r.take(8); b != nil {
		return r.bo.Uint64(b)
	}
	return 0
}

func (r *ehReader) address(size int) uint64 {
	if size == 4 {
		return uint64(r.u32())
	}
	return r.u64()
}

func (r *ehReader) uleb() uint64 {
	var v uint64
	for shift := uint(0); ; shift += 7 {
		b := r.u8()
		if r.err != nil {
			return 0
		}
		if shift < 64 {
			v |= uint64(b&0x7f) << shift
		}
		if b&0x80 == 0 {
			return v
		}
		if shift > 63 {
			r.err = errEH
			return 0
		}
	}
}

func (r *ehReader) sleb() int64 {
	var v int64
	for shift := uint(0); ; shift += 7 {
		b := r.u8()
		if r.err != nil {
			return 0
		}
		if shift < 64 {
			v |= int64(b&0x7f) << shift
		}
		if b&0x80 == 0 {
			if shift < 57 && b&0x40 != 0 {
				v |= -1 << (shift + 7)
			}
			return v
		}
		if shift > 63 {
			r.err = errEH
			return 0
		}
	}
}

// encoding reads a pointer encoding byte and rejects unknown ones.
func (r *ehReader) encoding() byte {
	b := r.u8()
	if r.err == nil && !validEncoding(b) {
		r.err = errEH
	}
	return b
}
