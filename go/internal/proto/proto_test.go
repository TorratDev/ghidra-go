package proto

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var golden = []string{"02000d6c", "02018c80"}

func load(t *testing.T, fn, dir string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "golden", fn, dir+".hex"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := hex.DecodeString(strings.Join(strings.Fields(string(b)), ""))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func tokens(t *testing.T, b []byte) []Token {
	t.Helper()
	r := NewReader(bytes.NewReader(b))
	var ts []Token
	for {
		tok, err := r.Next()
		if err == io.EOF {
			return ts
		}
		if err != nil {
			t.Fatal(err)
		}
		ts = append(ts, tok)
	}
}

func count(ts []Token) map[Marker]int {
	c := map[Marker]int{}
	for _, t := range ts {
		if t.IsMarker() {
			c[t.Marker]++
		}
	}
	return c
}

// Marker counts from docs/re/decompiler-protocol.md ("Frame sequence per transcript").
func TestReaderGoldenCounts(t *testing.T) {
	want := map[string]struct{ in, out map[Marker]int }{
		"02000d6c": {
			map[Marker]int{CmdStart: 4, CmdEnd: 4, QueryRespStart: 179, QueryRespEnd: 179},
			map[Marker]int{QueryStart: 179, QueryEnd: 179, RespStart: 4, RespEnd: 4, ErrorStart: 3, ErrorEnd: 3},
		},
		"02018c80": {
			map[Marker]int{CmdStart: 4, CmdEnd: 4, QueryRespStart: 182, QueryRespEnd: 182},
			map[Marker]int{QueryStart: 182, QueryEnd: 182, RespStart: 4, RespEnd: 4, ErrorStart: 3, ErrorEnd: 3},
		},
	}
	for _, fn := range golden {
		for dir, w := range map[string]map[Marker]int{"in": want[fn].in, "out": want[fn].out} {
			b := load(t, fn, dir)
			c := count(tokens(t, b))
			for m, n := range w {
				if c[m] != n {
					t.Errorf("%s %s: marker %#02x count %d, want %d", fn, dir, byte(m), c[m], n)
				}
			}
			// The only markers present are the ones listed (string markers aside).
			for m := range c {
				if _, ok := w[m]; !ok && m != StringStart && m != StringEnd {
					t.Errorf("%s %s: unexpected marker %#02x", fn, dir, byte(m))
				}
			}
			if c[StringStart] != c[StringEnd] {
				t.Errorf("%s %s: unbalanced strings", fn, dir)
			}
		}
	}
}

// Rewriting the commands with Writer reproduces the recorded command bytes exactly.
func TestWriterCommandsMatchGolden(t *testing.T) {
	for _, fn := range golden {
		in := load(t, fn, "in")
		ts := tokens(t, in)
		var got []byte
		for i := 0; i < len(ts); i++ {
			if ts[i].Marker != CmdStart {
				continue
			}
			var strs [][]byte
			for j := i + 1; ts[j].Marker != CmdEnd; j++ {
				if !ts[j].IsMarker() {
					strs = append(strs, ts[j].Data)
				}
			}
			var buf bytes.Buffer
			w := NewWriter(&buf)
			w.Command(string(strs[0]), strs[1:]...)
			w.Flush()
			got = append(got, buf.Bytes()...)
		}
		// Every command byte of the recording, i.e. the transcript minus the 08..09 answers.
		var want []byte
		answering := false
		off := 0
		for _, tk := range ts {
			n := len(tk.Data)
			if tk.IsMarker() {
				n = 4
			}
			switch {
			case tk.Marker == QueryRespStart:
				answering = true
			case tk.Marker == QueryRespEnd:
				answering = false
			case !answering:
				want = append(want, in[off:off+n]...)
			}
			off += n
			if tk.Marker == QueryRespEnd {
				continue
			}
		}
		// The 08/09 marker bytes themselves are skipped above only for 08; drop the 09s too.
		want = bytes.ReplaceAll(want, []byte{0, 0, 1, 9}, nil)
		if !bytes.Equal(got, want) {
			t.Errorf("%s: rewritten commands differ from recording (%d vs %d bytes)", fn, len(got), len(want))
		}
	}
}

func TestReaderBurstEdgeCases(t *testing.T) {
	// Extra leading zeros belong to the burst (ghidra_arch.cc readToAnyBurst).
	ts := tokens(t, []byte{0, 0, 0, 0, 1, 0x0e, 'x', 0, 0, 0, 1, 0x0f})
	if len(ts) != 3 || ts[0].Marker != StringStart || string(ts[1].Data) != "x" || ts[2].Marker != StringEnd {
		t.Fatalf("zero run: %+v", ts)
	}
	// Zeros not followed by 01 <type> are data.
	ts = tokens(t, []byte{'a', 0, 2, 0, 1, 0, 'b', 0, 0, 1, 0x0f})
	if len(ts) != 2 || !bytes.Equal(ts[0].Data, []byte{'a', 0, 2, 0, 1, 0, 'b'}) {
		t.Fatalf("data zeros: %+v", ts)
	}
	// Truncated inside a marker or payload.
	for _, b := range [][]byte{{0, 0, 1}, {'a'}, {'a', 0, 0}} {
		r := NewReader(bytes.NewReader(b))
		if _, err := r.Next(); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("%v: err %v", b, err)
		}
	}
}

func TestDecodePackedGoldenQueries(t *testing.T) {
	for _, fn := range golden {
		ts := tokens(t, load(t, fn, "out"))
		ids := map[uint32]int{}
		for i, tk := range ts {
			if tk.Marker != QueryStart {
				continue
			}
			q, err := DecodePacked(ts[i+2].Data)
			if err != nil {
				t.Fatalf("%s query %d: %v", fn, i, err)
			}
			ids[q.ID]++
			if q.ID == QueryGetUserOpName {
				if a, _ := q.Attr(AttrIndex); a.Int() != int64(ids[q.ID]-1) {
					t.Errorf("useropname index %d at position %d", a.Int(), ids[q.ID])
				}
			}
			if q.ID == QueryGetComments {
				a := q.Child(ElemAddr)
				off, _ := a.Attr(AttrOffset)
				typ, _ := q.Attr(AttrType)
				sp, _ := a.Attr(AttrSpace)
				if typ.Int() != 58 || sp.Kind != KindSpace || sp.Num != 3 || off.Num != map[string]uint64{"02000d6c": 0x02000d6c, "02018c80": 0x02018c80}[fn] {
					t.Errorf("%s getcomments: %+v", fn, q)
				}
			}
		}
		w := map[string]map[uint32]int{
			"02000d6c": {QueryGetUserOpName: 169, QueryGetRegister: 1, QueryGetMappedSymbols: 2, QueryGetPcode: 4, QueryGetCallOtherFixup: 1, QueryGetTrackedRegisters: 1, QueryGetComments: 1},
			"02018c80": {QueryGetUserOpName: 169, QueryGetRegister: 1, QueryGetMappedSymbols: 3, QueryGetPcode: 6, QueryGetCallOtherFixup: 1, QueryGetTrackedRegisters: 1, QueryGetComments: 1},
		}[fn]
		for id, n := range w {
			if ids[id] != n {
				t.Errorf("%s: query %d count %d, want %d", fn, id, ids[id], n)
			}
		}
	}
}

// recorder answers queries and records them.
type recorder struct {
	seen []uint32
	fail bool
}

func (h *recorder) do(q *Element) (Reply, error) {
	h.seen = append(h.seen, q.ID)
	if h.fail {
		return Reply{}, errors.New("boom")
	}
	return String([]byte("ok")), nil
}
func (h *recorder) IsNameUsed(q *Element) (Reply, error)          { return h.do(q) }
func (h *recorder) GetBytes(q *Element) (Reply, error)            { return h.do(q) }
func (h *recorder) GetCallFixup(q *Element) (Reply, error)        { return h.do(q) }
func (h *recorder) GetCallMech(q *Element) (Reply, error)         { return h.do(q) }
func (h *recorder) GetCallOtherFixup(q *Element) (Reply, error)   { return h.do(q) }
func (h *recorder) GetCodeLabel(q *Element) (Reply, error)        { return h.do(q) }
func (h *recorder) GetComments(q *Element) (Reply, error)         { return h.do(q) }
func (h *recorder) GetCPoolRef(q *Element) (Reply, error)         { return h.do(q) }
func (h *recorder) GetDataType(q *Element) (Reply, error)         { return h.do(q) }
func (h *recorder) GetExternalRef(q *Element) (Reply, error)      { return h.do(q) }
func (h *recorder) GetMappedSymbols(q *Element) (Reply, error)    { return h.do(q) }
func (h *recorder) GetNamespacePath(q *Element) (Reply, error)    { return h.do(q) }
func (h *recorder) GetPcode(q *Element) (Reply, error)            { return h.do(q) }
func (h *recorder) GetPcodeExecutable(q *Element) (Reply, error)  { return h.do(q) }
func (h *recorder) GetRegister(q *Element) (Reply, error)         { return h.do(q) }
func (h *recorder) GetRegisterName(q *Element) (Reply, error)     { return h.do(q) }
func (h *recorder) GetStringData(q *Element) (Reply, error)       { return h.do(q) }
func (h *recorder) GetTrackedRegisters(q *Element) (Reply, error) { return h.do(q) }
func (h *recorder) GetUserOpName(q *Element) (Reply, error)       { return h.do(q) }

// TestHelperProcess is a fake decompile: it plays a recorded stdout and drains stdin.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("PROTO_FAKE")
	if mode == "" {
		t.Skip("helper process")
	}
	switch mode {
	case "sleep":
		time.Sleep(time.Minute)
	case "exit":
		os.Exit(3)
	default:
		b, err := os.ReadFile(mode)
		if err != nil {
			os.Exit(2)
		}
		if n := os.Getenv("PROTO_TRUNC"); n != "" {
			var k int
			for _, c := range n {
				k = k*10 + int(c-'0')
			}
			b = b[:k]
		}
		os.Stdout.Write(b)
		if os.Getenv("PROTO_TRUNC") != "" {
			os.Exit(0) // dies mid-response
		}
		io.Copy(io.Discard, os.Stdin)
	}
	os.Exit(0)
}

func fake(t *testing.T, mode string, h Handler, env ...string) *Process {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$")
	cmd.Env = append(os.Environ(), append([]string{"PROTO_FAKE=" + mode}, env...)...)
	p, err := StartCmd(cmd, h)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Plays a golden out.hex through the process layer: 4 commands, answers every query,
// and gets the result strings back with the nested query removed from the doc.
func TestProcessGolden(t *testing.T) {
	for _, fn := range golden {
		raw := filepath.Join(t.TempDir(), "out.bin")
		os.WriteFile(raw, load(t, fn, "out"), 0o644)
		h := &recorder{}
		p := fake(t, raw, h)
		ctx := context.Background()
		var results []*Result
		var queries []int
		for _, c := range []string{CmdRegisterProgram, CmdDecompileAt, CmdFlushNative, CmdDeregisterProgram} {
			r, err := p.Run(ctx, c, []byte("arg"))
			if err != nil {
				t.Fatalf("%s %s: %v", fn, c, err)
			}
			results = append(results, r)
			queries = append(queries, len(h.seen))
		}
		if err := p.Close(); err != nil {
			t.Errorf("%s close: %v", fn, err)
		}
		total := map[string]int{"02000d6c": 179, "02018c80": 182}[fn]
		if len(h.seen) != total {
			t.Errorf("%s: %d queries, want %d", fn, len(h.seen), total)
		}
		if queries[0] != 170 || queries[2] != total || queries[3] != total {
			t.Errorf("%s: cumulative queries %v", fn, queries)
		}
		for i, want := range []string{"0", "", "0", "1"} {
			r := results[i]
			if len(r.Strings) != 1 || r.Error != "" {
				t.Fatalf("%s result %d: %+v", fn, i, r)
			}
			if want != "" && string(r.Strings[0]) != want {
				t.Errorf("%s result %d = %q, want %q", fn, i, r.Strings[0], want)
			}
		}
		// The decompileAt doc is the recorded string with the nested getcomments query cut out.
		doc := results[1].Strings[0]
		if e, err := DecodePacked(doc); err != nil || e.ID != ElemDoc {
			t.Errorf("%s: doc does not decode as <doc>: %v %+v", fn, err, e)
		}
	}
}

// query frames in, answer frames out, checked byte for byte.
func TestQueryAnswerFraming(t *testing.T) {
	var q bytes.Buffer
	qw := NewWriter(&q)
	qw.String([]byte{0x62, 0x81, 0xca, 0x20, 0xa2, 0x81}) // getuseropname index=0
	qw.Marker(QueryEnd)
	qw.Flush()
	frame := func(m Marker, data string) []byte {
		return append(append([]byte{0, 0, 1, byte(m)}, data...), 0, 0, 1, byte(m+1))
	}
	cat := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	cases := []struct {
		name string
		h    func(*Element) (Reply, error)
		want []byte
	}{
		{"string", func(*Element) (Reply, error) { return String([]byte("ok")), nil },
			cat([]byte{0, 0, 1, 8}, frame(StringStart, "ok"), []byte{0, 0, 1, 9})},
		{"empty string", func(*Element) (Reply, error) { return String([]byte{}), nil },
			cat([]byte{0, 0, 1, 8}, frame(StringStart, ""), []byte{0, 0, 1, 9})},
		{"none", func(*Element) (Reply, error) { return Reply{}, nil }, []byte{0, 0, 1, 8, 0, 0, 1, 9}},
		{"bytes", func(*Element) (Reply, error) { return HexBytes([]byte{0x1f, 0xa0}), nil },
			cat([]byte{0, 0, 1, 8}, frame(BytesStart, "BPKA"), []byte{0, 0, 1, 9})},
		{"no bytes", func(*Element) (Reply, error) { return HexBytes(nil), nil }, []byte{0, 0, 1, 8, 0, 0, 1, 9}},
		{"error", func(*Element) (Reply, error) { return Reply{}, errors.New("boom") },
			cat([]byte{0, 0, 1, 0x0a}, frame(StringStart, "go.*errors.errorString"), frame(StringStart, "boom"), []byte{0, 0, 1, 0x0b})},
	}
	for _, c := range cases {
		var out bytes.Buffer
		p := &Process{r: NewReader(bytes.NewReader(q.Bytes())), w: NewWriter(&out), h: funcHandler{c.h}}
		if err := p.query(); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if !bytes.Equal(out.Bytes(), c.want) {
			t.Errorf("%s: wrote %x, want %x", c.name, out.Bytes(), c.want)
		}
	}
}

// funcHandler sends getuseropname to f; the other queries answer nothing.
type funcHandler struct{ f func(*Element) (Reply, error) }

func (h funcHandler) GetUserOpName(q *Element) (Reply, error) { return h.f(q) }
func (funcHandler) IsNameUsed(*Element) (Reply, error)        { return Reply{}, nil }
func (funcHandler) GetBytes(*Element) (Reply, error)          { return Reply{}, nil }
func (funcHandler) GetCallFixup(*Element) (Reply, error)      { return Reply{}, nil }
func (funcHandler) GetCallMech(*Element) (Reply, error)       { return Reply{}, nil }
func (funcHandler) GetCallOtherFixup(*Element) (Reply, error) { return Reply{}, nil }
func (funcHandler) GetCodeLabel(*Element) (Reply, error)      { return Reply{}, nil }
func (funcHandler) GetComments(*Element) (Reply, error)       { return Reply{}, nil }
func (funcHandler) GetCPoolRef(*Element) (Reply, error)       { return Reply{}, nil }
func (funcHandler) GetDataType(*Element) (Reply, error)       { return Reply{}, nil }
func (funcHandler) GetExternalRef(*Element) (Reply, error)    { return Reply{}, nil }
func (funcHandler) GetMappedSymbols(*Element) (Reply, error)  { return Reply{}, nil }
func (funcHandler) GetNamespacePath(*Element) (Reply, error)  { return Reply{}, nil }
func (funcHandler) GetPcode(*Element) (Reply, error)          { return Reply{}, nil }
func (funcHandler) GetPcodeExecutable(*Element) (Reply, error) {
	return Reply{}, nil
}
func (funcHandler) GetRegister(*Element) (Reply, error)         { return Reply{}, nil }
func (funcHandler) GetRegisterName(*Element) (Reply, error)     { return Reply{}, nil }
func (funcHandler) GetStringData(*Element) (Reply, error)       { return Reply{}, nil }
func (funcHandler) GetTrackedRegisters(*Element) (Reply, error) { return Reply{}, nil }

func TestProcessTruncatedOutputErrors(t *testing.T) {
	raw := filepath.Join(t.TempDir(), "out.bin")
	os.WriteFile(raw, load(t, golden[0], "out"), 0o644)
	p := fake(t, raw, &recorder{}, "PROTO_TRUNC=1000")
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := p.Run(ctx, CmdRegisterProgram); err == nil || ctx.Err() != nil {
		t.Fatal("want error for truncated response")
	}
}

func TestProcessExitedErrors(t *testing.T) {
	p := fake(t, "exit", &recorder{})
	defer p.Close()
	done := make(chan error, 1)
	go func() { _, err := p.Run(context.Background(), CmdFlushNative); done <- err }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "exit status 3") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run hung on an exited process")
	}
	if _, err := p.Run(context.Background(), CmdFlushNative); err == nil {
		t.Fatal("want error on closed process")
	}
}

func TestProcessContextCancelKills(t *testing.T) {
	p := fake(t, "sleep", &recorder{})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := p.Run(ctx, CmdFlushNative); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	p.Close()
}

func TestStartMissingBinary(t *testing.T) {
	if _, err := Start("/nonexistent/decompile", &recorder{}); err == nil {
		t.Fatal("want error")
	}
}
