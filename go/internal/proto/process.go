package proto

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"
)

var errUnsupported = errors.New("Unsupported decompiler query")

// Result is what one command produced.
type Result struct {
	Strings  [][]byte // result string frames, in order (nested queries removed)
	Error    string   // native error text; empty means success
	Warnings []string
}

// ExceptionError is an exception frame sent by the native side. Unverified in the
// golden transcripts.
type ExceptionError struct{ Type, Message string }

func (e *ExceptionError) Error() string { return "decompile exception " + e.Type + ": " + e.Message }

// Process is a running decompile process. Run is not safe for concurrent use.
type Process struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *os.File
	r      *Reader
	w      *Writer
	h      Handler
	stderr *bytes.Buffer
	once   sync.Once
	done   chan struct{}
	werr   error
}

// Start runs the decompile binary at path (no shell) and attaches handler h.
func Start(path string, h Handler) (*Process, error) { return StartCmd(exec.Command(path), h) }

// StartCmd is Start for a caller-configured command. It must not have Stdin, Stdout or Stderr set.
func StartCmd(cmd *exec.Cmd, h Handler) (*Process, error) { return StartCmdTrace(cmd, h, nil, nil) }

// StartCmdTrace is StartCmd that also copies every byte sent to the process to tx and every
// byte read from it to rx (either may be nil). It is for recording and replay tests.
func StartCmdTrace(cmd *exec.Cmd, h Handler, tx, rx io.Writer) (*Process, error) {
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	// An os.Pipe, not StdoutPipe: Wait closes StdoutPipe on exit, which would drop output
	// the child wrote just before exiting that we have not read yet.
	out, outw, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	cmd.Stdout = outw
	var stdin io.Writer = in
	var stdout io.Reader = out
	if tx != nil {
		stdin = io.MultiWriter(in, tx)
	}
	if rx != nil {
		stdout = io.TeeReader(out, rx)
	}
	p := &Process{cmd: cmd, in: in, out: out, r: NewReader(stdout), w: NewWriter(stdin), h: h, stderr: &bytes.Buffer{}, done: make(chan struct{})}
	cmd.Stderr = &limitedWriter{b: p.stderr, n: 4096}
	err = cmd.Start()
	outw.Close()
	if err != nil {
		out.Close()
		return nil, err
	}
	// Reap the process as soon as it exits so a dead child is noticed and never leaks.
	go func() {
		p.werr = cmd.Wait()
		close(p.done)
	}()
	return p, nil
}

// Run sends one command and reads its response, answering queries through the handler.
// Cancelling ctx kills the process, so ctx should carry a deadline. A dead or closed
// process returns an error.
//
// shortcut: a live child that never answers blocks Run until ctx is done; callers must pass a ctx with a deadline, upgrade to a per-read timeout if needed
func (p *Process) Run(ctx context.Context, name string, args ...[]byte) (*Result, error) {
	stop := context.AfterFunc(ctx, func() { p.cmd.Process.Kill() })
	defer stop()
	res, err := p.run(name, args)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return nil, cerr
		}
		return nil, fmt.Errorf("decompile %s: %w%s", name, err, p.tail())
	}
	return res, nil
}

// tail adds the child's stderr and exit status when it has already exited.
func (p *Process) tail() string {
	select {
	case <-p.done:
	case <-time.After(100 * time.Millisecond):
		return ""
	}
	s := fmt.Sprintf(" (process exited: %v", p.werr)
	if p.stderr.Len() > 0 {
		s += "; stderr: " + p.stderr.String()
	}
	return s + ")"
}

func (p *Process) run(name string, args [][]byte) (*Result, error) {
	p.w.Command(name, args...)
	if err := p.w.Flush(); err != nil {
		return nil, err
	}
	// Skip stray end markers before the header, as DecompileProcess.readToResponse does.
	var t Token
	var err error
	for {
		if t, err = p.r.Next(); err != nil {
			return nil, err
		}
		if t.IsMarker() && t.Marker&1 == 1 {
			continue
		}
		break
	}
	if t.Marker == ExceptionStart {
		return nil, p.readException()
	}
	if t.Marker != RespStart {
		return nil, fmt.Errorf("alignment error: expected response header, got %s", t)
	}
	res := &Result{}
	var cur []byte // open result string, nil when none
	open := false
	for {
		if t, err = p.r.Next(); err != nil {
			return nil, err
		}
		if !t.IsMarker() {
			if !open {
				return nil, fmt.Errorf("alignment error: %s outside a string", t)
			}
			cur = append(cur, t.Data...)
			continue
		}
		switch t.Marker {
		case RespEnd:
			if open {
				return nil, errors.New("alignment error: response ended inside a string")
			}
			return res, nil
		case StringStart:
			if open {
				return nil, errors.New("alignment error: nested result string")
			}
			open, cur = true, nil
		case StringEnd:
			if !open {
				return nil, errors.New("alignment error: mismatched string end")
			}
			res.Strings = append(res.Strings, cur)
			open = false
		case QueryStart:
			// May occur inside an open result string; cur is left untouched.
			if err := p.query(); err != nil {
				return nil, err
			}
		case ErrorStart:
			b, err := p.r.ReadUntil(ErrorEnd)
			if err != nil {
				return nil, err
			}
			res.Error = string(b)
			open = false // the native side drops the main response after an error
		case WarningStart:
			b, err := p.r.ReadUntil(WarningEnd)
			if err != nil {
				return nil, err
			}
			res.Warnings = append(res.Warnings, string(b))
		case ExceptionStart:
			return nil, p.readException()
		default:
			return nil, fmt.Errorf("alignment error: unexpected %s", t)
		}
	}
}

func (p *Process) readException() error {
	var s [2]string
	for i := range s {
		if err := p.r.Expect(StringStart); err != nil {
			return err
		}
		b, err := p.r.ReadUntil(StringEnd)
		if err != nil {
			return err
		}
		s[i] = string(b)
	}
	if err := p.r.Expect(ExceptionEnd); err != nil {
		return err
	}
	return &ExceptionError{s[0], s[1]}
}

// query reads one query (after its start marker), calls the handler and writes the answer.
func (p *Process) query() error {
	if err := p.r.Expect(StringStart); err != nil {
		return err
	}
	body, err := p.r.ReadUntil(StringEnd)
	if err != nil {
		return err
	}
	if err := p.r.Expect(QueryEnd); err != nil {
		return err
	}
	var rep Reply
	q, err := DecodePacked(body)
	if err == nil {
		rep, err = dispatch(p.h, q)
	}
	if err != nil {
		// Java reports any handler failure to the native side as an exception frame.
		p.w.Marker(ExceptionStart)
		p.w.String([]byte("go." + errType(err)))
		p.w.String([]byte(err.Error()))
		p.w.Marker(ExceptionEnd)
		return p.w.Flush()
	}
	p.w.Marker(QueryRespStart)
	switch rep.Kind {
	case ReplyString:
		p.w.String(rep.Data)
	case ReplyBytes:
		p.w.Marker(BytesStart)
		p.w.bw.Write(rep.Data)
		p.w.Marker(BytesEnd)
	}
	p.w.Marker(QueryRespEnd)
	return p.w.Flush()
}

func errType(err error) string {
	if err == errUnsupported {
		return "Exception"
	}
	return fmt.Sprintf("%T", err)
}

// Close closes stdin, which makes the native process exit, and waits for it. It kills
// the process if it has not exited after a few seconds. It returns the exit error, if any.
func (p *Process) Close() error {
	p.once.Do(func() { p.in.Close() })
	select {
	case <-p.done:
	case <-time.After(5 * time.Second):
		p.cmd.Process.Kill()
		<-p.done
	}
	p.out.Close()
	return p.werr
}

// limitedWriter keeps the first n bytes written to it.
type limitedWriter struct {
	b *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.n - l.b.Len(); room > 0 {
		l.b.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}
