package proto

import (
	"bufio"
	"io"
)

// Writer writes markers and payload to the native process.
type Writer struct{ bw *bufio.Writer }

func NewWriter(w io.Writer) *Writer { return &Writer{bw: bufio.NewWriterSize(w, 64<<10)} }

func (w *Writer) Marker(m Marker) { w.bw.Write([]byte{0, 0, 1, byte(m)}) }

// String writes data inside a string frame.
func (w *Writer) String(data []byte) {
	w.Marker(StringStart)
	w.bw.Write(data)
	w.Marker(StringEnd)
}

// Command writes a command frame: name, then each argument as a string.
func (w *Writer) Command(name string, args ...[]byte) {
	w.Marker(CmdStart)
	w.String([]byte(name))
	for _, a := range args {
		w.String(a)
	}
	w.Marker(CmdEnd)
}

// Flush sends buffered bytes. Write errors (including a closed process) surface here.
func (w *Writer) Flush() error { return w.bw.Flush() }
