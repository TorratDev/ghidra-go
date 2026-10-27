package sleigh

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

// The bridge is driven with JSON lines over its stdin and stdout. One request
// line carries a batch of instructions to decode:
//
//	{"language":"x86:LE:64:default","batch":[{"addr":"0x1000","bytes":"e805000000","context":"0x0"}]}
//
// and the bridge answers with one line per batch entry, in order: either the
// facts for the instruction,
//
//	{"addr":"0x1000","len":5,"mnemonic":"CALL","text":"CALL 0x100a","flow":"UNCONDITIONAL_CALL",
//	 "has_fallthrough":true,"targets":["0x100a"],"indirect":false,"context":"0x0"}
//
// or {"error":"message"} when it cannot decode that entry. The bridge always
// answers every entry of a batch, so an error never leaves the batch short.
// Both sides reject unknown, missing, duplicate and differently-cased fields.
// Four more facts are optional on the wire (the bridge always writes them,
// a reader may leave them out): indirect_via (hex address or null),
// data_refs ([{"addr":"0x..","access":"read|write|address"}]), addends (hex
// addresses) and indexed_load (bool); see Decoded.
// Addresses and contexts are "0x..." hex strings.
//
// Register state is optional on both sides: a request entry may carry "state",
// the register constants known before the instruction
// ([{"space":"register","offset":16,"size":8,"value":"0x.."}]), and the response
// carries the constants still known after it, in the same shape; see Register.

// Context is a SLEIGH context register value. On the wire it is a "0x..."
// hex string, like an address, and a bare JSON number is rejected: a Java long
// of 2^64-1 prints as -1 and must not turn into a value unnoticed.
type Context uint64

func (c Context) MarshalJSON() ([]byte, error) { return core.Addr(c).MarshalJSON() }

func (c *Context) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || b[0] != '"' {
		return fmt.Errorf("context must be a hex string like \"0x0\", got %s", b)
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := core.ParseHex(s)
	*c = Context(v)
	return err
}

// Insn is one batch entry: where the bytes are and the SLEIGH context value
// (context register bits) to decode them with.
type Insn struct {
	Addr    core.Addr
	Bytes   []byte
	Context Context
}

// Register is a varnode with a constant value: the state the bridge is seeded
// with, and the state it reports after the instruction.
type Register struct {
	Varnode
	Value uint64
}

type Request struct {
	Language string
	Batch    []Insn
	// State, when not nil, holds the register constants for each entry of
	// Batch: State[i] seeds Batch[i] (nil for none). Its length is len(Batch).
	State [][]Register
}

type insnWire struct {
	Addr    *core.Addr     `json:"addr"`
	Bytes   *string        `json:"bytes"`
	Context *Context       `json:"context"`
	State   []registerWire `json:"state"`
}

type registerWire struct {
	Space  *string  `json:"space"`
	Offset *uint64  `json:"offset"`
	Size   *uint32  `json:"size"`
	Value  *Context `json:"value"`
}

// registers converts the wire form, naming the first entry with a missing field.
func registers(ws []registerWire) ([]Register, error) {
	var out []Register
	for i, w := range ws {
		if w.Space == nil || w.Offset == nil || w.Size == nil || w.Value == nil {
			return nil, fmt.Errorf(`state[%d]: missing required field "space", "offset", "size" or "value"`, i)
		}
		out = append(out, Register{Varnode{*w.Space, *w.Offset, *w.Size}, uint64(*w.Value)})
	}
	return out, nil
}

func (r Register) wire() registerWire {
	space, offset, size, value := r.Space, r.Offset, r.Size, Context(r.Value)
	return registerWire{&space, &offset, &size, &value}
}

type requestWire struct {
	Language *string     `json:"language"`
	Batch    *[]insnWire `json:"batch"`
}

// missing names the nil (absent or null) fields, in order.
func missing(fields map[string]bool, order ...string) error {
	var names []string
	for _, n := range order {
		if !fields[n] {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return fmt.Errorf("missing required field %q", strings.Join(names, `", "`))
}

// shape describes the object keys a JSON value may have: keys for an object,
// elem for an array. A nil shape accepts any value.
type shape struct {
	keys map[string]*shape
	elem *shape
}

func obj(keys ...string) *shape {
	s := &shape{keys: map[string]*shape{}}
	for _, k := range keys {
		s.keys[k] = nil
	}
	return s
}

// checkKeys walks data and rejects a key that is not in the shape, a key that
// is repeated, and a key that only matches a field in a different case:
// encoding/json would accept the last two silently.
func checkKeys(data []byte, s *shape) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	var walk func(*shape) error
	walk = func(s *shape) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				k := kt.(string)
				if seen[k] {
					return fmt.Errorf("duplicate field %q", k)
				}
				seen[k] = true
				var child *shape
				if s != nil {
					c, ok := s.keys[k]
					if !ok {
						for known := range s.keys {
							if strings.EqualFold(known, k) {
								return fmt.Errorf("unknown field %q (field names are case-sensitive, did you mean %q?)", k, known)
							}
						}
						return fmt.Errorf("unknown field %q", k)
					}
					child = c
				}
				if err := walk(child); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		case json.Delim('['):
			var elem *shape
			if s != nil {
				elem = s.elem
			}
			for dec.More() {
				if err := walk(elem); err != nil {
					return err
				}
			}
			_, err := dec.Token()
			return err
		}
		return nil
	}
	return walk(s)
}

// decodeStrict decodes exactly one JSON value into v after checking its keys
// against s; unknown fields and trailing data are errors.
func decodeStrict(data []byte, s *shape, v any) error {
	if err := checkKeys(data, s); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after the JSON value")
	}
	return nil
}

func (r Request) MarshalJSON() ([]byte, error) {
	w := struct {
		Language string     `json:"language"`
		Batch    []insnJSON `json:"batch"`
	}{r.Language, make([]insnJSON, len(r.Batch))}
	for i, in := range r.Batch {
		w.Batch[i] = insnJSON{in.Addr, hex.EncodeToString(in.Bytes), in.Context, nil}
		if r.State != nil {
			w.Batch[i].State = wireRegisters(r.State[i])
		}
	}
	return json.Marshal(w)
}

type insnJSON struct {
	Addr    core.Addr      `json:"addr"`
	Bytes   string         `json:"bytes"`
	Context Context        `json:"context"`
	State   []registerWire `json:"state,omitempty"`
}

func wireRegisters(rs []Register) []registerWire {
	out := make([]registerWire, len(rs))
	for i, r := range rs {
		out[i] = r.wire()
	}
	return out
}

// registerShape is the object shape of one register state entry.
func registerShape() *shape { return obj("space", "offset", "size", "value") }

var (
	requestShape = func() *shape {
		s := obj("language", "batch")
		e := obj("addr", "bytes", "context", "state")
		e.keys["state"] = &shape{elem: registerShape()}
		s.keys["batch"] = &shape{elem: e}
		return s
	}()
	responseShape = func() *shape {
		s := obj("addr", "len", "mnemonic", "text", "flow", "has_fallthrough", "targets", "indirect", "context",
			"indirect_via", "data_refs", "addends", "indexed_load", "state")
		s.keys["data_refs"] = &shape{elem: obj("addr", "access")}
		s.keys["state"] = &shape{elem: registerShape()}
		return s
	}()
	errorShape = obj("error")
)

// ParseRequest decodes and validates a request line.
func ParseRequest(line []byte) (*Request, error) {
	var w requestWire
	if err := decodeStrict(line, requestShape, &w); err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	if err := missing(map[string]bool{"language": w.Language != nil, "batch": w.Batch != nil}, "language", "batch"); err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	if *w.Language == "" {
		return nil, errors.New(`request: field "language" is empty`)
	}
	if len(*w.Batch) == 0 {
		return nil, errors.New(`request: field "batch" is empty`)
	}
	req := &Request{Language: *w.Language}
	for i, e := range *w.Batch {
		if err := missing(map[string]bool{"addr": e.Addr != nil, "bytes": e.Bytes != nil, "context": e.Context != nil}, "addr", "bytes", "context"); err != nil {
			return nil, fmt.Errorf("request: batch[%d]: %w", i, err)
		}
		b, err := hex.DecodeString(*e.Bytes)
		if err != nil || len(b) == 0 {
			return nil, fmt.Errorf(`request: batch[%d]: field "bytes" must be non-empty hex`, i)
		}
		st, err := registers(e.State)
		if err != nil {
			return nil, fmt.Errorf("request: batch[%d]: %w", i, err)
		}
		req.Batch = append(req.Batch, Insn{*e.Addr, b, *e.Context})
		if len(st) > 0 && req.State == nil {
			req.State = make([][]Register, len(*w.Batch))
		}
		if req.State != nil {
			req.State[i] = st
		}
	}
	return req, nil
}

// WriteRequest writes the request as one JSON line.
func WriteRequest(w io.Writer, r Request) error {
	if len(r.Batch) == 0 || r.Language == "" {
		return errors.New("request needs a language and a non-empty batch")
	}
	if r.State != nil && len(r.State) != len(r.Batch) {
		return errors.New("request state needs one entry per batch entry")
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// Decoded is what the bridge reports for one instruction: Ghidra's facts, not
// ra's analysis. Field names and JSON tags are the Rust ra-sleigh ones.
// IndirectVia, Addends and IndexedLoad are the p-code-derived facts of Rust's
// ra-sleigh, computed within the one instruction. DataRefs also count the
// accesses through the register state the entry was decoded with (a LEA
// before the load), and State is the register state after the instruction.
type Decoded struct {
	Addr     core.Addr `json:"addr"`
	Len      uint32    `json:"len"`
	Mnemonic string    `json:"mnemonic"`
	Text     string    `json:"text"`
	// Flow is the FlowType name on the wire ("flow") and its kind here.
	Flow           FlowKind    `json:"-"`
	HasFallthrough bool        `json:"has_fallthrough"`
	Targets        []core.Addr `json:"targets"` // direct branch/call targets
	// Indirect is set for a branch or call whose target is computed at run time.
	Indirect bool `json:"indirect"`
	// Context is the context value the bridge decoded the instruction with.
	Context Context `json:"context"`

	// IndirectVia is the constant address an indirect jump or call loads its
	// target from (JMP [0x1234]).
	IndirectVia *core.Addr
	// DataRefs are the constant addresses the instruction reads, writes or
	// computes.
	DataRefs []DataRef
	// Addends are constants (>= 0x100) added to a run-time value: the table
	// base of JMP [T+idx*S].
	Addends []core.Addr
	// IndexedLoad is a load from a run-time computed address.
	IndexedLoad bool
	// State is the register constants known after the instruction (the
	// seeded ones it did not overwrite, and those it materialized).
	State []Register
}

// Access is how an instruction touches a constant address.
type Access string

const (
	AccessRead    Access = "read"
	AccessWrite   Access = "write"
	AccessAddress Access = "address" // computed, not dereferenced here
)

type DataRef struct {
	Addr   core.Addr `json:"addr"`
	Access Access    `json:"access"`
}

type decodedWire struct {
	Addr           *core.Addr   `json:"addr"`
	Len            *uint32      `json:"len"`
	Mnemonic       *string      `json:"mnemonic"`
	Text           *string      `json:"text"`
	Flow           *string      `json:"flow"`
	HasFallthrough *bool        `json:"has_fallthrough"`
	Targets        *[]core.Addr `json:"targets"`
	Indirect       *bool        `json:"indirect"`
	Context        *Context     `json:"context"`

	IndirectVia *core.Addr     `json:"indirect_via,omitempty"`
	DataRefs    []dataRefWire  `json:"data_refs,omitempty"`
	Addends     []core.Addr    `json:"addends,omitempty"`
	IndexedLoad bool           `json:"indexed_load,omitempty"`
	State       []registerWire `json:"state,omitempty"`
}

type dataRefWire struct {
	Addr   *core.Addr `json:"addr"`
	Access *string    `json:"access"`
}

// BridgeError is an error object from the bridge.
type BridgeError struct{ Message string }

func (e *BridgeError) Error() string { return "sleigh bridge: " + e.Message }

// ParseResponse decodes one response line. A bridge error object comes back
// as a *BridgeError; anything that is neither a valid Decoded nor an error
// object is an error that names the offending field.
func ParseResponse(line []byte) (*Decoded, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(line, &probe); err != nil {
		return nil, fmt.Errorf("response: %w", err)
	}
	if raw, isErr := probe["error"]; isErr {
		var e struct {
			Error *string `json:"error"`
		}
		if err := decodeStrict(line, errorShape, &e); err != nil {
			return nil, fmt.Errorf("response: error object: %w", err)
		}
		if e.Error == nil || *e.Error == "" {
			return nil, fmt.Errorf("response: field \"error\" must be a non-empty string, got %s", raw)
		}
		return nil, &BridgeError{*e.Error}
	}
	var w decodedWire
	if err := decodeStrict(line, responseShape, &w); err != nil {
		return nil, fmt.Errorf("response: %w", err)
	}
	if err := missing(map[string]bool{
		"addr": w.Addr != nil, "len": w.Len != nil, "mnemonic": w.Mnemonic != nil, "text": w.Text != nil,
		"flow": w.Flow != nil, "has_fallthrough": w.HasFallthrough != nil, "targets": w.Targets != nil,
		"indirect": w.Indirect != nil, "context": w.Context != nil,
	}, "addr", "len", "mnemonic", "text", "flow", "has_fallthrough", "targets", "indirect", "context"); err != nil {
		return nil, fmt.Errorf("response: %w", err)
	}
	if *w.Len == 0 {
		return nil, errors.New(`response: field "len" must be positive`)
	}
	if *w.Mnemonic == "" {
		return nil, errors.New(`response: field "mnemonic" is empty`)
	}
	flow, err := FlowFromGhidra(*w.Flow)
	if err != nil {
		return nil, fmt.Errorf(`response: field "flow": %w`, err)
	}
	d := &Decoded{
		Addr: *w.Addr, Len: *w.Len, Mnemonic: *w.Mnemonic, Text: *w.Text, Flow: flow,
		HasFallthrough: *w.HasFallthrough, Targets: *w.Targets, Indirect: *w.Indirect, Context: *w.Context,
		IndirectVia: w.IndirectVia, Addends: w.Addends, IndexedLoad: w.IndexedLoad,
	}
	for i, r := range w.DataRefs {
		if r.Addr == nil || r.Access == nil {
			return nil, fmt.Errorf(`response: data_refs[%d]: missing required field "addr" or "access"`, i)
		}
		switch a := Access(*r.Access); a {
		case AccessRead, AccessWrite, AccessAddress:
			d.DataRefs = append(d.DataRefs, DataRef{*r.Addr, a})
		default:
			return nil, fmt.Errorf(`response: data_refs[%d]: unknown access %q`, i, *r.Access)
		}
	}
	d.State, err = registers(w.State)
	if err != nil {
		return nil, fmt.Errorf("response: %w", err)
	}
	return d, nil
}

// MarshalJSON writes the wire form, with the FlowType name for flow.
func (d Decoded) MarshalJSON() ([]byte, error) {
	if d.Flow < 0 || int(d.Flow) >= len(flowRows) {
		return nil, fmt.Errorf("invalid flow kind %d", int(d.Flow))
	}
	targets := d.Targets
	if targets == nil {
		targets = []core.Addr{}
	}
	name := d.Flow.GhidraName()
	refs := make([]dataRefWire, len(d.DataRefs))
	for i, r := range d.DataRefs {
		a := string(r.Access)
		refs[i] = dataRefWire{&d.DataRefs[i].Addr, &a}
	}
	addends := d.Addends
	if addends == nil {
		addends = []core.Addr{}
	}
	return json.Marshal(decodedWire{&d.Addr, &d.Len, &d.Mnemonic, &d.Text, &name, &d.HasFallthrough, &targets, &d.Indirect, &d.Context,
		d.IndirectVia, refs, addends, d.IndexedLoad, wireRegisters(d.State)})
}

// Result is the answer for one batch entry: Decoded, or the error that
// replaced it (a *BridgeError, a malformed line, or an address mismatch).
type Result struct {
	Decoded *Decoded
	Err     error
}

// AddrMismatchError means the bridge answered an entry with another
// instruction's address: the request and response lines are out of step.
type AddrMismatchError struct {
	Entry     int
	Got, Want core.Addr
}

func (e *AddrMismatchError) Error() string {
	return fmt.Sprintf("entry %d: response addr %#x does not match request addr %#x", e.Entry, uint64(e.Got), uint64(e.Want))
}

// ReadResponses reads exactly len(batch) response lines, one per entry, and
// returns one Result for each, so an error on one entry never leaves the rest
// of the batch unread in the pipe. A decoded response must carry its entry's
// address. The returned error is for the stream itself (a short read) or, when
// an address mismatches, *AddrMismatchError after the whole batch was read; it
// names the first such entry and the stream cannot be trusted afterwards. Per
// entry errors are in the Results only.
func ReadResponses(r *bufio.Reader, batch []Insn) ([]Result, error) {
	out := make([]Result, 0, len(batch))
	var hard error
	for i, want := range batch {
		line, err := r.ReadBytes('\n')
		if err != nil && len(bytes.TrimSpace(line)) == 0 {
			return out, fmt.Errorf("entry %d: reading response: %w", i, err)
		}
		d, perr := ParseResponse(bytes.TrimSpace(line))
		if perr != nil {
			out = append(out, Result{Err: fmt.Errorf("entry %d: %w", i, perr)})
			continue
		}
		if d.Addr != want.Addr {
			mm := &AddrMismatchError{i, d.Addr, want.Addr}
			if hard == nil {
				hard = mm
			}
			out = append(out, Result{Err: mm})
			continue
		}
		out = append(out, Result{Decoded: d})
	}
	return out, hard
}
