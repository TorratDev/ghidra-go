package proto

import (
	"bufio"
	"errors"
	"fmt"
	"io"
)

// MaxPayload bounds the data of one string so a corrupt stream cannot exhaust memory.
const MaxPayload = 64 << 20

// Token is either a marker or a run of payload bytes between two markers.
type Token struct {
	Marker Marker // zero when the token is data
	Data   []byte
}

func (t Token) IsMarker() bool { return t.Marker != 0 }

// Reader splits a byte stream into markers and payload data.
type Reader struct {
	br      *bufio.Reader
	pending Marker // marker found right after a data run
}

func NewReader(r io.Reader) *Reader { return &Reader{br: bufio.NewReaderSize(r, 64<<10)} }

// Next returns the next token. At a clean boundary the stream end is io.EOF; inside a
// payload or marker it is io.ErrUnexpectedEOF.
//
// A burst is one or more zero bytes, then 0x01, then a non-zero type byte (ghidra_arch.cc
// readToAnyBurst, DecompileProcess.readToBurst). The golden transcripts only show exactly
// two zeros, but both implementations accept any run, so this reader does too. A zero run
// not followed by 0x01 and a type byte is payload.
func (r *Reader) Next() (Token, error) {
	if r.pending != 0 {
		m := r.pending
		r.pending = 0
		return Token{Marker: m}, nil
	}
	var data []byte
	for {
		b, err := r.br.ReadByte()
		if err != nil {
			return r.fail(data, err)
		}
		if b != 0 {
			data = append(data, b)
			if len(data) > MaxPayload {
				return Token{}, fmt.Errorf("proto: payload exceeds %d bytes", MaxPayload)
			}
			continue
		}
		zeros := 1
		var c byte
		for {
			if c, err = r.br.ReadByte(); err != nil {
				return r.fail([]byte{0}, err) // mid-burst
			}
			if c != 0 {
				break
			}
			zeros++
		}
		if c == 1 {
			t, err := r.br.ReadByte()
			if err != nil {
				return r.fail([]byte{0}, err)
			}
			if t != 0 {
				if len(data) > 0 {
					r.pending = Marker(t)
					return Token{Data: data}, nil
				}
				return Token{Marker: Marker(t)}, nil
			}
			// 00 01 00: not a burst; the 00 starts a new zero run.
			r.br.UnreadByte()
		}
		for i := 0; i < zeros; i++ {
			data = append(data, 0)
		}
		data = append(data, c)
	}
}

func (r *Reader) fail(data []byte, err error) (Token, error) {
	if errors.Is(err, io.EOF) && len(data) > 0 {
		return Token{}, io.ErrUnexpectedEOF
	}
	return Token{}, err
}

// Expect reads one token and requires it to be the given marker.
func (r *Reader) Expect(m Marker) error {
	t, err := r.Next()
	if err != nil {
		return err
	}
	if t.Marker != m {
		return fmt.Errorf("proto: expected marker %#02x, got %s", byte(m), t)
	}
	return nil
}

// ReadUntil reads the payload up to the end marker (an empty payload yields nil data)
// and consumes the end marker. It is for flat payloads: raw error/warning text and
// string frames that cannot contain queries.
func (r *Reader) ReadUntil(end Marker) ([]byte, error) {
	t, err := r.Next()
	if err != nil {
		return nil, err
	}
	var data []byte
	if !t.IsMarker() {
		data = t.Data
		if t, err = r.Next(); err != nil {
			return nil, err
		}
	}
	if t.Marker != end {
		return nil, fmt.Errorf("proto: expected end marker %#02x, got %s", byte(end), t)
	}
	return data, nil
}

func (t Token) String() string {
	if t.IsMarker() {
		return fmt.Sprintf("marker %#02x", byte(t.Marker))
	}
	return fmt.Sprintf("%d data bytes", len(t.Data))
}
