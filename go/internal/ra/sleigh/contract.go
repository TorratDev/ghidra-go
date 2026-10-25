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
//	{"language":"x86:LE:64:default","batch":[{"addr":"0x1000","bytes":"e805000000","context":0}]}
//
// and the bridge answers with one line per batch entry, in order: either the
// facts for the instruction,
//
//	{"addr":"0x1000","len":5,"mnemonic":"CALL","text":"CALL 0x100a","flow":"UNCONDITIONAL_CALL",
//	 "has_fallthrough":true,"targets":["0x100a"],"indirect":false,"context":0}
//
// or {"error":"message"} when it cannot decode that entry. Both sides reject
// unknown and missing fields.

// Insn is one batch entry: where the bytes are and the SLEIGH context value
// (context register bits) to decode them with.
type Insn struct {
	Addr    core.Addr
	Bytes   []byte
	Context uint64
}

type Request struct {
	Language string
	Batch    []Insn
}

type insnWire struct {
	Addr    *core.Addr `json:"addr"`
	Bytes   *string    `json:"bytes"`
	Context *uint64    `json:"context"`
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

// decodeStrict decodes exactly one JSON value, rejecting unknown fields and
// trailing data.
func decodeStrict(data []byte, v any) error {
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
		w.Batch[i] = insnJSON{in.Addr, hex.EncodeToString(in.Bytes), in.Context}
	}
	return json.Marshal(w)
}

type insnJSON struct {
	Addr    core.Addr `json:"addr"`
	Bytes   string    `json:"bytes"`
	Context uint64    `json:"context"`
}

// ParseRequest decodes and validates a request line.
func ParseRequest(line []byte) (*Request, error) {
	var w requestWire
	if err := decodeStrict(line, &w); err != nil {
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
		req.Batch = append(req.Batch, Insn{*e.Addr, b, *e.Context})
	}
	return req, nil
}

// WriteRequest writes the request as one JSON line.
func WriteRequest(w io.Writer, r Request) error {
	if len(r.Batch) == 0 || r.Language == "" {
		return errors.New("request needs a language and a non-empty batch")
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
// Rust's indirect_via, data_refs, addends and indexed_load are not produced
// by the bridge (data references need analysis, which compare reports as
// missing; the addend heuristics are dropped, see #10).
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
	Context uint64 `json:"context"`
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
	Context        *uint64      `json:"context"`
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
		if err := decodeStrict(line, &e); err != nil {
			return nil, fmt.Errorf("response: error object: %w", err)
		}
		if e.Error == nil || *e.Error == "" {
			return nil, fmt.Errorf("response: field \"error\" must be a non-empty string, got %s", raw)
		}
		return nil, &BridgeError{*e.Error}
	}
	var w decodedWire
	if err := decodeStrict(line, &w); err != nil {
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
	return &Decoded{
		Addr: *w.Addr, Len: *w.Len, Mnemonic: *w.Mnemonic, Text: *w.Text, Flow: flow,
		HasFallthrough: *w.HasFallthrough, Targets: *w.Targets, Indirect: *w.Indirect, Context: *w.Context,
	}, nil
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
	return json.Marshal(decodedWire{&d.Addr, &d.Len, &d.Mnemonic, &d.Text, &name, &d.HasFallthrough, &targets, &d.Indirect, &d.Context})
}

// ReadResponses reads exactly n response lines, one per batch entry. The
// first bridge error, malformed line or early end of input stops the read and
// is returned with the index of the entry it answers; the responses decoded so
// far are returned too.
func ReadResponses(r *bufio.Reader, n int) ([]Decoded, error) {
	var out []Decoded
	for len(out) < n {
		line, err := r.ReadBytes('\n')
		if err != nil && len(bytes.TrimSpace(line)) == 0 {
			return out, fmt.Errorf("entry %d: reading response: %w", len(out), err)
		}
		d, perr := ParseResponse(bytes.TrimSpace(line))
		if perr != nil {
			return out, fmt.Errorf("entry %d: %w", len(out), perr)
		}
		out = append(out, *d)
	}
	return out, nil
}
