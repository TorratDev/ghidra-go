package proto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"testing"
	"time"
)

// Hash of the decompile binary the golden transcripts were recorded with (testdata/golden/README.md).
const goldenDecompileSHA256 = "deff417328db63659ad1498bbf85ea9148fc541200e5c0ab1d3f2bf389b5cc77"

// recorded plays back the Java side of a transcript: the commands to send and the answer to
// each query, in order.
type recorded struct {
	cmds    [][][]byte // per command: name, args...
	answers []Reply
	next    int
	t       *testing.T
}

func parseIn(t *testing.T, in []byte) *recorded {
	rec := &recorded{t: t}
	ts := tokens(t, in)
	for i := 0; i < len(ts); i++ {
		switch ts[i].Marker {
		case CmdStart:
			var c [][]byte
			for i++; ts[i].Marker != CmdEnd; i++ {
				if !ts[i].IsMarker() {
					c = append(c, ts[i].Data)
				}
			}
			rec.cmds = append(rec.cmds, c)
		case QueryRespStart:
			rep := Reply{}
			for i++; ts[i].Marker != QueryRespEnd; i++ {
				if ts[i].Marker == StringStart {
					rep = String([]byte{})
				} else if !ts[i].IsMarker() {
					rep.Data = ts[i].Data
				}
			}
			rec.answers = append(rec.answers, rep)
		}
	}
	return rec
}

func (r *recorded) do(q *Element) (Reply, error) {
	if r.next >= len(r.answers) {
		return Reply{}, fmt.Errorf("query %d (id %d) has no recorded answer", r.next+1, q.ID)
	}
	r.next++
	return r.answers[r.next-1], nil
}

func (r *recorded) IsNameUsed(q *Element) (Reply, error)          { return r.do(q) }
func (r *recorded) GetBytes(q *Element) (Reply, error)            { return r.do(q) }
func (r *recorded) GetCallFixup(q *Element) (Reply, error)        { return r.do(q) }
func (r *recorded) GetCallMech(q *Element) (Reply, error)         { return r.do(q) }
func (r *recorded) GetCallOtherFixup(q *Element) (Reply, error)   { return r.do(q) }
func (r *recorded) GetCodeLabel(q *Element) (Reply, error)        { return r.do(q) }
func (r *recorded) GetComments(q *Element) (Reply, error)         { return r.do(q) }
func (r *recorded) GetCPoolRef(q *Element) (Reply, error)         { return r.do(q) }
func (r *recorded) GetDataType(q *Element) (Reply, error)         { return r.do(q) }
func (r *recorded) GetExternalRef(q *Element) (Reply, error)      { return r.do(q) }
func (r *recorded) GetMappedSymbols(q *Element) (Reply, error)    { return r.do(q) }
func (r *recorded) GetNamespacePath(q *Element) (Reply, error)    { return r.do(q) }
func (r *recorded) GetPcode(q *Element) (Reply, error)            { return r.do(q) }
func (r *recorded) GetPcodeExecutable(q *Element) (Reply, error)  { return r.do(q) }
func (r *recorded) GetRegister(q *Element) (Reply, error)         { return r.do(q) }
func (r *recorded) GetRegisterName(q *Element) (Reply, error)     { return r.do(q) }
func (r *recorded) GetStringData(q *Element) (Reply, error)       { return r.do(q) }
func (r *recorded) GetTrackedRegisters(q *Element) (Reply, error) { return r.do(q) }
func (r *recorded) GetUserOpName(q *Element) (Reply, error)       { return r.do(q) }

// decompileBin finds the real binary from $DECOMPILE_BIN. The test is skipped when it is
// unset; when set, the binary must match the recorded hash unless $DECOMPILE_SKIP_HASH=1.
func decompileBin(t *testing.T) string {
	path := os.Getenv("DECOMPILE_BIN")
	if path == "" {
		t.Skip("DECOMPILE_BIN not set: point it at the Ghidra 11.4.3 os/linux_x86_64/decompile binary to run the replay")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("DECOMPILE_BIN: %v", err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != goldenDecompileSHA256 && os.Getenv("DECOMPILE_SKIP_HASH") != "1" {
		t.Fatalf("DECOMPILE_BIN %s has sha256 %s, but the transcripts were recorded with %s (set DECOMPILE_SKIP_HASH=1 to replay anyway)", path, got, goldenDecompileSHA256)
	}
	return path
}

func TestReplayGolden(t *testing.T) {
	bin := decompileBin(t)
	for _, fn := range golden {
		t.Run(fn, func(t *testing.T) {
			wantIn, wantOut := load(t, fn, "in"), load(t, fn, "out")
			rec := parseIn(t, wantIn)
			var gotIn, gotOut bytes.Buffer
			p, err := StartCmdTrace(exec.Command(bin), rec, &gotIn, &gotOut)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			for _, c := range rec.cmds {
				if _, err := p.Run(ctx, string(c[0]), c[1:]...); err != nil {
					t.Fatalf("%s: %v", c[0], err)
				}
			}
			if err := p.Close(); err != nil {
				t.Fatalf("close: %v", err)
			}
			if rec.next != len(rec.answers) {
				t.Errorf("used %d of %d recorded answers", rec.next, len(rec.answers))
			}
			if msg := firstDiff("native output (out.hex)", gotOut.Bytes(), wantOut); msg != "" {
				t.Error(msg)
			}
			if msg := firstDiff("client input (in.hex)", gotIn.Bytes(), wantIn); msg != "" {
				t.Error(msg)
			}
		})
	}
}

// firstDiff returns "" when got equals want, else a message with the first differing offset,
// the frame it is in, and a hex window of both sides.
func firstDiff(what string, got, want []byte) string {
	n := min(len(got), len(want))
	off := 0
	for off < n && got[off] == want[off] {
		off++
	}
	if off == n && len(got) == len(want) {
		return ""
	}
	msg := fmt.Sprintf("%s differs at byte offset %d (hex file line %d); got %d bytes, want %d\n", what, off, off/30+1, len(got), len(want))
	msg += "  in frame: " + frameAt(want, off) + "\n"
	lo, hi := max(off-16, 0), off+16
	win := func(b []byte) string {
		h := min(hi, len(b))
		if lo >= h {
			return "(past end)"
		}
		return hex.EncodeToString(b[lo:off]) + "[" + hex.EncodeToString(b[off:min(off+1, len(b))]) + "]" + hex.EncodeToString(b[min(off+1, h):h])
	}
	return msg + fmt.Sprintf("  got  %s\n  want %s (window starts at byte %d, [] marks the differing byte)", win(got), win(want), lo)
}

// frameAt describes the marker/data token of the recording that contains byte off.
func frameAt(b []byte, off int) string {
	r := NewReader(bytes.NewReader(b))
	pos, idx := 0, 0
	var last Marker
	for {
		t, err := r.Next()
		if err != nil {
			return "past the last complete frame"
		}
		n := len(t.Data)
		if t.IsMarker() {
			n, last = 4, t.Marker
		}
		if off < pos+n {
			if t.IsMarker() {
				return fmt.Sprintf("marker %#02x, token %d (starts at byte %d)", byte(t.Marker), idx, pos)
			}
			return fmt.Sprintf("%d payload bytes after marker %#02x, token %d (bytes %d-%d)", n, byte(last), idx, pos, pos+n-1)
		}
		pos += n
		idx++
	}
}

func TestFirstDiffMessage(t *testing.T) {
	want := []byte{0, 0, 1, 0x0e, 'a', 'b', 'c', 0, 0, 1, 0x0f}
	if firstDiff("x", want, want) != "" {
		t.Fatal("equal inputs reported different")
	}
	got := append([]byte(nil), want...)
	got[5] = 'X'
	msg := firstDiff("x", got, want)
	for _, s := range []string{"offset 5", "3 payload bytes after marker 0x0e", "got  ", "[58]", "[62]"} {
		if !bytes.Contains([]byte(msg), []byte(s)) {
			t.Errorf("message lacks %q:\n%s", s, msg)
		}
	}
}
