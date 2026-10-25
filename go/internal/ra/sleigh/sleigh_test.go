package sleigh

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

// Every row of the issue's table: the Rust kind and its Ghidra FlowType name.
func TestFlowMappingRows(t *testing.T) {
	rows := []struct {
		kind   FlowKind
		rust   string
		ghidra string
	}{
		{FlowFallthrough, "Fallthrough", "FALL_THROUGH"},
		{FlowJump, "Jump", "UNCONDITIONAL_JUMP"},
		{FlowCondJump, "CondJump", "CONDITIONAL_JUMP"},
		{FlowCall, "Call", "UNCONDITIONAL_CALL"},
		{FlowCondCall, "CondCall", "CONDITIONAL_CALL"},
		{FlowReturn, "Return", "TERMINATOR"},
		{FlowCondReturn, "CondReturn", "CONDITIONAL_TERMINATOR"},
		{FlowTerminator, "Terminator", "TERMINATOR"},
	}
	for _, r := range rows {
		if r.kind.String() != r.rust || r.kind.GhidraName() != r.ghidra {
			t.Errorf("%v: %q %q", r.kind, r.kind.String(), r.kind.GhidraName())
		}
		got, err := FlowFromGhidra(r.ghidra)
		if err != nil {
			t.Errorf("%s: %v", r.ghidra, err)
		}
		// TERMINATOR is both Return and Terminator; the name maps to Return
		if want := r.kind; r.kind != FlowTerminator && got != want {
			t.Errorf("%s -> %v, want %v", r.ghidra, got, want)
		}
	}
	if k, _ := FlowFromGhidra("TERMINATOR"); k != FlowReturn {
		t.Errorf("TERMINATOR -> %v", k)
	}
	if FlowKind(99).GhidraName() != "" || FlowKind(-1).String() != "FlowKind(-1)" {
		t.Error("out of range kinds")
	}
}

func TestUnknownFlowNamesAreErrors(t *testing.T) {
	// Ghidra FlowTypes the table does not list, a case slip and an empty name
	for _, n := range []string{"COMPUTED_JUMP", "COMPUTED_CALL", "CONDITIONAL_COMPUTED_JUMP",
		"INDIRECTION", "fall_through", "Fallthrough", "FALL THROUGH", "", "TERMINATOR "} {
		if k, err := FlowFromGhidra(n); err == nil {
			t.Errorf("%q accepted as %v", n, k)
		} else if !strings.Contains(err.Error(), "unknown FlowType name") {
			t.Errorf("%q: %v", n, err)
		}
	}
}

const (
	callLine = `{"addr":"0x1000","len":5,"mnemonic":"CALL","text":"CALL 0x100a","flow":"UNCONDITIONAL_CALL","has_fallthrough":true,"targets":["0x100a"],"indirect":false,"context":"0x0"}`
	jeLine   = `{"addr":"0x1005","len":2,"mnemonic":"JZ","text":"JZ 0x1009","flow":"CONDITIONAL_JUMP","has_fallthrough":true,"targets":["0x1009"],"indirect":false,"context":"0x0"}`
	retLine  = `{"addr":"0x1007","len":1,"mnemonic":"RET","text":"RET","flow":"TERMINATOR","has_fallthrough":false,"targets":[],"indirect":false,"context":"0x0"}`
)

func TestFixtureBatch(t *testing.T) {
	req := Request{Language: "x86:LE:64:default", Batch: []Insn{
		{0x1000, []byte{0xe8, 5, 0, 0, 0}, 0},
		{0x1005, []byte{0x74, 2}, 0},
		{0x1007, []byte{0xc3}, 0},
	}}
	var out bytes.Buffer
	if err := WriteRequest(&out, req); err != nil {
		t.Fatal(err)
	}
	const want = `{"language":"x86:LE:64:default","batch":[{"addr":"0x1000","bytes":"e805000000","context":"0x0"},{"addr":"0x1005","bytes":"7402","context":"0x0"},{"addr":"0x1007","bytes":"c3","context":"0x0"}]}` + "\n"
	if out.String() != want {
		t.Errorf("request line:\n%s\nwant:\n%s", out.String(), want)
	}
	back, err := ParseRequest(out.Bytes())
	if err != nil || back.Language != req.Language || len(back.Batch) != 3 || !bytes.Equal(back.Batch[0].Bytes, req.Batch[0].Bytes) || back.Batch[1].Addr != 0x1005 {
		t.Fatalf("%v %+v", err, back)
	}

	res, err := ReadResponses(bufio.NewReader(strings.NewReader(callLine+"\n"+jeLine+"\n"+retLine+"\n")), req.Batch)
	if err != nil {
		t.Fatal(err)
	}
	var got []*Decoded
	for i, r := range res {
		if r.Err != nil {
			t.Fatalf("entry %d: %v", i, r.Err)
		}
		got = append(got, r.Decoded)
	}
	if got[0].Flow != FlowCall || got[0].Mnemonic != "CALL" || got[0].Len != 5 || !got[0].HasFallthrough || !slices.Equal(got[0].Targets, []core.Addr{0x100a}) {
		t.Errorf("call %+v", got[0])
	}
	if got[1].Flow != FlowCondJump || got[1].Addr != 0x1005 || !got[1].HasFallthrough || !slices.Equal(got[1].Targets, []core.Addr{0x1009}) {
		t.Errorf("conditional jump %+v", got[1])
	}
	if got[2].Flow != FlowReturn || got[2].HasFallthrough || len(got[2].Targets) != 0 || got[2].Targets == nil || got[2].Indirect {
		t.Errorf("return %+v", got[2])
	}
	// the wire form round trips
	for i, line := range []string{callLine, jeLine, retLine} {
		b, err := json.Marshal(got[i])
		if err != nil || string(b) != line {
			t.Errorf("marshal %d: %v\n%s\n%s", i, err, b, line)
		}
	}
}

func TestContextIsCarriedPerAddress(t *testing.T) {
	req, err := ParseRequest([]byte(`{"language":"ARM:LE:32:v8","batch":[{"addr":"0x100","bytes":"00f020e3","context":"0x0"},{"addr":"0x104","bytes":"00f020e3","context":"0x1"},{"addr":"0x108","bytes":"00f020e3","context":"0xffffffffffffffff"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if req.Batch[0].Context != 0 || req.Batch[1].Context != 1 || req.Batch[2].Context != 1<<64-1 {
		t.Errorf("request contexts %+v", req.Batch)
	}
	// the bridge reports the context it used for each instruction
	lines := ""
	for i, c := range []string{"0x0", "0x1", "0xffffffffffffffff"} {
		l := strings.Replace(callLine, `"context":"0x0"`, `"context":"`+c+`"`, 1)
		lines += strings.Replace(l, `"0x1000"`, []string{`"0x100"`, `"0x104"`, `"0x108"`}[i], 1) + "\n"
	}
	res, err := ReadResponses(bufio.NewReader(strings.NewReader(lines)), req.Batch)
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Decoded.Context != 0 || res[1].Decoded.Context != 1 || res[2].Decoded.Context != 1<<64-1 || res[1].Decoded.Addr != 0x104 {
		t.Errorf("%+v", res)
	}
	b, _ := json.Marshal(res[2].Decoded)
	if !strings.Contains(string(b), `"context":"0xffffffffffffffff"`) {
		t.Errorf("marshalled %s", b)
	}
}

// A bare number, a negative number and non-hex text are not contexts.
func TestContextMustBeAHexString(t *testing.T) {
	for _, c := range []string{`0`, `1`, `-1`, `18446744073709551615`, `1.5`, `true`, `null`, `"-1"`, `"zz"`, `""`, `"0x"`, `"0x10000000000000000"`} {
		req := `{"language":"x","batch":[{"addr":"0x1","bytes":"90","context":` + c + `}]}`
		if _, err := ParseRequest([]byte(req)); err == nil {
			t.Errorf("request context %s accepted", c)
		}
		resp := strings.Replace(callLine, `"context":"0x0"`, `"context":`+c, 1)
		if _, err := ParseResponse([]byte(resp)); err == nil {
			t.Errorf("response context %s accepted", c)
		}
	}
	for _, c := range []string{`"0x0"`, `"0X1F"`, `"0xdeadbeef"`} {
		if _, err := ParseRequest([]byte(`{"language":"x","batch":[{"addr":"0x1","bytes":"90","context":` + c + `}]}`)); err != nil {
			t.Errorf("context %s: %v", c, err)
		}
	}
}

func TestParseResponseRejects(t *testing.T) {
	good := map[string]string{
		"addr": `"0x1000"`, "len": `5`, "mnemonic": `"CALL"`, "text": `"CALL 0x100a"`, "flow": `"UNCONDITIONAL_CALL"`,
		"has_fallthrough": `true`, "targets": `["0x100a"]`, "indirect": `false`, "context": `"0x0"`,
	}
	order := []string{"addr", "len", "mnemonic", "text", "flow", "has_fallthrough", "targets", "indirect", "context"}
	build := func(mod func(m map[string]string)) string {
		m := map[string]string{}
		for k, v := range good {
			m[k] = v
		}
		mod(m)
		var parts []string
		for _, k := range order {
			if v, ok := m[k]; ok {
				parts = append(parts, `"`+k+`":`+v)
			}
		}
		for _, k := range []string{"extra", "indirect_via"} { // fields that are not part of the contract
			if v, ok := m[k]; ok {
				parts = append(parts, `"`+k+`":`+v)
			}
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	if _, err := ParseResponse([]byte(build(func(map[string]string) {}))); err != nil {
		t.Fatalf("good response: %v", err)
	}
	for _, f := range order {
		line := build(func(m map[string]string) { delete(m, f) })
		if _, err := ParseResponse([]byte(line)); err == nil || !strings.Contains(err.Error(), `missing required field "`+f+`"`) {
			t.Errorf("without %s: %v", f, err)
		}
		line = build(func(m map[string]string) { m[f] = "null" })
		if _, err := ParseResponse([]byte(line)); err == nil || !strings.Contains(err.Error(), f) {
			t.Errorf("%s null: %v", f, err)
		}
	}
	for name, c := range map[string]struct {
		mod  func(m map[string]string)
		want string
	}{
		"unknown field":   {func(m map[string]string) { m["extra"] = "1" }, `unknown field "extra"`},
		"dropped field":   {func(m map[string]string) { m["indirect_via"] = "null" }, `unknown field "indirect_via"`},
		"unknown flow":    {func(m map[string]string) { m["flow"] = `"COMPUTED_CALL"` }, `unknown FlowType name "COMPUTED_CALL"`},
		"empty flow":      {func(m map[string]string) { m["flow"] = `""` }, `unknown FlowType name ""`},
		"zero length":     {func(m map[string]string) { m["len"] = `0` }, `"len" must be positive`},
		"negative length": {func(m map[string]string) { m["len"] = `-1` }, `len`},
		"empty mnemonic":  {func(m map[string]string) { m["mnemonic"] = `""` }, `"mnemonic" is empty`},
		"bad address":     {func(m map[string]string) { m["addr"] = `"0xZZ"` }, `bad hex address`},
		"flow not string": {func(m map[string]string) { m["flow"] = `3` }, `flow`},
		"targets entry":   {func(m map[string]string) { m["targets"] = `["nope"]` }, `bad hex address`},
		"numeric ctx":     {func(m map[string]string) { m["context"] = `0` }, `context must be a hex string`},
		"negative ctx":    {func(m map[string]string) { m["context"] = `-1` }, `context must be a hex string`},
	} {
		if _, err := ParseResponse([]byte(build(c.mod))); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want it to contain %q", name, err, c.want)
		}
	}
	for name, line := range map[string]string{
		"not json":      `CALL`,
		"not an object": `[1]`,
		"trailing data": callLine + ` {}`,
		"empty":         ``,
	} {
		if _, err := ParseResponse([]byte(line)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func batchOf(addrs ...core.Addr) []Insn {
	var b []Insn
	for _, a := range addrs {
		b = append(b, Insn{Addr: a, Bytes: []byte{0x90}})
	}
	return b
}

func TestBridgeErrorObject(t *testing.T) {
	_, err := ParseResponse([]byte(`{"error":"no instruction at 0x1000"}`))
	var be *BridgeError
	if !errors.As(err, &be) || be.Message != "no instruction at 0x1000" {
		t.Fatalf("%v", err)
	}
	for _, line := range []string{`{"error":""}`, `{"error":3}`, `{"error":"x","addr":"0x1"}`, `{"error":null}`, `{"Error":"x"}`} {
		if _, err := ParseResponse([]byte(line)); err == nil || errors.As(err, &be) {
			t.Errorf("%s: %v (want a malformed-response error, not a bridge error)", line, err)
		}
	}
}

// An error on one entry must not leave the rest of the batch in the pipe: the
// next read has to start at the next batch.
func TestErrorEntryDoesNotDesyncTheStream(t *testing.T) {
	second := strings.Replace(retLine, `"0x1007"`, `"0x2000"`, 1)
	stream := bufio.NewReader(strings.NewReader(callLine + "\n" + `{"error":"bad bytes"}` + "\n" + retLine + "\n" + second + "\n"))
	res, err := ReadResponses(stream, batchOf(0x1000, 0x1005, 0x1007))
	if err != nil || len(res) != 3 {
		t.Fatalf("%d results, %v", len(res), err)
	}
	var be *BridgeError
	if res[0].Err != nil || res[0].Decoded.Addr != 0x1000 {
		t.Errorf("entry 0 %+v", res[0])
	}
	if res[1].Decoded != nil || !errors.As(res[1].Err, &be) || be.Message != "bad bytes" || !strings.Contains(res[1].Err.Error(), "entry 1") {
		t.Errorf("entry 1 %+v", res[1])
	}
	if res[2].Err != nil || res[2].Decoded.Addr != 0x1007 {
		t.Errorf("entry 2 %+v", res[2])
	}
	next, err := ReadResponses(stream, batchOf(0x2000))
	if err != nil || len(next) != 1 || next[0].Err != nil || next[0].Decoded.Addr != 0x2000 {
		t.Errorf("second batch: %v %+v", err, next)
	}
	// a malformed line is an entry error too, and the batch is still read in full
	stream = bufio.NewReader(strings.NewReader("not json\n" + retLine + "\n"))
	res, err = ReadResponses(stream, batchOf(0x1000, 0x1007))
	if err != nil || res[0].Err == nil || res[1].Err != nil {
		t.Errorf("malformed line: %v %+v", err, res)
	}
}

func TestAddrMismatchIsAHardError(t *testing.T) {
	// entry 1 is answered with the response for 0x1007
	stream := bufio.NewReader(strings.NewReader(callLine + "\n" + retLine + "\n" + retLine + "\n"))
	res, err := ReadResponses(stream, batchOf(0x1000, 0x1005, 0x1007))
	var mm *AddrMismatchError
	if !errors.As(err, &mm) || mm.Entry != 1 || mm.Got != 0x1007 || mm.Want != 0x1005 || !strings.Contains(err.Error(), "entry 1") {
		t.Fatalf("error %v", err)
	}
	if len(res) != 3 || res[0].Err != nil || res[1].Err == nil || res[1].Decoded != nil || res[2].Err != nil {
		t.Errorf("results %+v", res)
	}
}

func TestShortStreamIsAStreamError(t *testing.T) {
	res, err := ReadResponses(bufio.NewReader(strings.NewReader(callLine+"\n")), batchOf(0x1000, 0x1005))
	if err == nil || !strings.Contains(err.Error(), "entry 1") || len(res) != 1 || res[0].Err != nil {
		t.Errorf("short output: %v %+v", err, res)
	}
	// a last line without a newline still counts
	if res, err := ReadResponses(bufio.NewReader(strings.NewReader(retLine)), batchOf(0x1007)); err != nil || len(res) != 1 || res[0].Err != nil {
		t.Errorf("no trailing newline: %v", err)
	}
}

func TestDuplicateAndCaseVariantKeysAreRejected(t *testing.T) {
	// encoding/json takes the last duplicate and matches keys case-insensitively
	for name, c := range map[string]struct{ line, want string }{
		"duplicate key":      {strings.Replace(callLine, `"len":5,`, `"len":5,"len":6,`, 1), `duplicate field "len"`},
		"duplicate addr":     {strings.Replace(callLine, `{"addr"`, `{"addr":"0x1","addr"`, 1), `duplicate field "addr"`},
		"case variant":       {strings.Replace(callLine, `"mnemonic"`, `"Mnemonic"`, 1), `unknown field "Mnemonic"`},
		"case variant twin":  {strings.Replace(callLine, `"len":5,`, `"len":5,"LEN":6,`, 1), `unknown field "LEN"`},
		"upper case flow":    {strings.Replace(callLine, `"flow"`, `"FLOW"`, 1), `unknown field "FLOW"`},
		"nested duplicate":   {`{"language":"x","batch":[{"addr":"0x1","addr":"0x2","bytes":"90","context":"0x0"}]}`, `duplicate field "addr"`},
		"nested case":        {`{"language":"x","batch":[{"Addr":"0x1","bytes":"90","context":"0x0"}]}`, `unknown field "Addr"`},
		"request case":       {`{"Language":"x","batch":[{"addr":"0x1","bytes":"90","context":"0x0"}]}`, `unknown field "Language"`},
		"language duplicate": {strings.Replace(goodLanguage, `"id":`, `"id":"a","id":`, 1), `duplicate field "id"`},
		"varnode case":       {strings.Replace(goodLanguage, `"space":"register","offset":128`, `"Space":"register","offset":128`, 1), `unknown field "Space"`},
		"error duplicate":    {`{"error":"a","error":"b"}`, `duplicate field "error"`},
	} {
		var err error
		switch {
		case strings.HasPrefix(c.line, `{"language"`), strings.HasPrefix(c.line, `{"Language"`):
			_, err = ParseRequest([]byte(c.line))
		case strings.HasPrefix(c.line, `{"id"`):
			_, err = ParseLanguage([]byte(c.line))
		default:
			_, err = ParseResponse([]byte(c.line))
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want it to contain %q", name, err, c.want)
		}
	}
}

func TestBridgeRuleFlowNames(t *testing.T) {
	for _, n := range []string{"CALL_TERMINATOR", "JUMP_TERMINATOR", "CALLOTHER_OVERRIDE_CALL", "CALLOTHER_OVERRIDE_JUMP", "CALLOTHER_OVERRIDE_X"} {
		_, err := FlowFromGhidra(n)
		if err == nil || !strings.Contains(err.Error(), "bridge rule") || !strings.Contains(err.Error(), n) {
			t.Errorf("%s: %v", n, err)
		}
		line := strings.Replace(callLine, `"UNCONDITIONAL_CALL"`, `"`+n+`"`, 1)
		if _, err := ParseResponse([]byte(line)); err == nil || !strings.Contains(err.Error(), "bridge rule") {
			t.Errorf("response with %s: %v", n, err)
		}
	}
	// names that are merely unknown do not claim a bridge rule
	if _, err := FlowFromGhidra("CALLOTHER_OVERRIDE"); err == nil || strings.Contains(err.Error(), "bridge rule") {
		t.Errorf("CALLOTHER_OVERRIDE without the suffix: %v", err)
	}
}

func TestParseRequestRejects(t *testing.T) {
	const entry = `{"addr":"0x1","bytes":"90","context":"0x0"}`
	for name, c := range map[string]struct{ line, want string }{
		"no language":    {`{"batch":[` + entry + `]}`, `missing required field "language"`},
		"no batch":       {`{"language":"x"}`, `missing required field "batch"`},
		"unknown field":  {`{"language":"x","batch":[` + entry + `],"opts":1}`, `unknown field "opts"`},
		"empty language": {`{"language":"","batch":[` + entry + `]}`, `"language" is empty`},
		"empty batch":    {`{"language":"x","batch":[]}`, `"batch" is empty`},
		"no addr":        {`{"language":"x","batch":[{"bytes":"90","context":"0x0"}]}`, `batch[0]: missing required field "addr"`},
		"no bytes":       {`{"language":"x","batch":[{"addr":"0x1","context":"0x0"}]}`, `missing required field "bytes"`},
		"no context":     {`{"language":"x","batch":[` + entry + `,{"addr":"0x1","bytes":"90"}]}`, `batch[1]: missing required field "context"`},
		"unknown insn":   {`{"language":"x","batch":[{"addr":"0x1","bytes":"90","context":0,"mode":1}]}`, `unknown field "mode"`},
		"odd hex":        {`{"language":"x","batch":[{"addr":"0x1","bytes":"9","context":"0x0"}]}`, `"bytes" must be non-empty hex`},
		"not hex":        {`{"language":"x","batch":[{"addr":"0x1","bytes":"zz","context":"0x0"}]}`, `"bytes" must be non-empty hex`},
		"empty bytes":    {`{"language":"x","batch":[{"addr":"0x1","bytes":"","context":"0x0"}]}`, `"bytes" must be non-empty hex`},
		"trailing":       {`{"language":"x","batch":[` + entry + `]} x`, `trailing data`},
	} {
		if _, err := ParseRequest([]byte(c.line)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want it to contain %q", name, err, c.want)
		}
	}
	var sink bytes.Buffer
	if err := WriteRequest(&sink, Request{Language: "x"}); err == nil || sink.Len() != 0 {
		t.Error("empty batch written")
	}
}

const goodLanguage = `{"id":"x86:LE:64:default","big_endian":false,"address_size":8,"initial_context":0,` +
	`"pc":{"space":"register","offset":128,"size":8},"sp":{"space":"register","offset":32,"size":8},` +
	`"int_args":[{"space":"register","offset":56,"size":8},{"space":"register","offset":48,"size":8}]}`

func TestParseLanguage(t *testing.T) {
	l, err := ParseLanguage([]byte(goodLanguage))
	if err != nil {
		t.Fatal(err)
	}
	if l.ID != "x86:LE:64:default" || l.BigEndian || l.AddressSize != 8 || l.InitialContext != 0 ||
		l.PC != (Varnode{"register", 128, 8}) || l.SP != (Varnode{"register", 32, 8}) ||
		len(l.IntArgs) != 2 || l.IntArgs[1] != (Varnode{"register", 48, 8}) {
		t.Errorf("%+v", l)
	}
	// no integer argument registers is valid, but the list must be there
	empty := strings.Replace(goodLanguage, `"int_args":[{"space":"register","offset":56,"size":8},{"space":"register","offset":48,"size":8}]`, `"int_args":[]`, 1)
	if l, err := ParseLanguage([]byte(empty)); err != nil || l.IntArgs == nil || len(l.IntArgs) != 0 {
		t.Errorf("empty int_args: %v %+v", err, l)
	}
}

func TestParseLanguageRejects(t *testing.T) {
	for _, f := range []string{"id", "big_endian", "address_size", "initial_context", "pc", "sp", "int_args"} {
		var m map[string]json.RawMessage
		json.Unmarshal([]byte(goodLanguage), &m)
		delete(m, f)
		b, _ := json.Marshal(m)
		if _, err := ParseLanguage(b); err == nil || !strings.Contains(err.Error(), `missing required field "`+f+`"`) {
			t.Errorf("without %s: %v", f, err)
		}
	}
	rep := func(old, new string) string { return strings.Replace(goodLanguage, old, new, 1) }
	for name, c := range map[string]struct{ in, want string }{
		"unknown field":        {rep(`"id"`, `"name":"x","id"`), `unknown field "name"`},
		"empty id":             {rep(`"x86:LE:64:default"`, `""`), `"id" is empty`},
		"address size 3":       {rep(`"address_size":8`, `"address_size":3`), `"address_size" must be 1, 2, 4 or 8, got 3`},
		"address size 0":       {rep(`"address_size":8`, `"address_size":0`), `"address_size"`},
		"pc without offset":    {rep(`"pc":{"space":"register","offset":128,"size":8}`, `"pc":{"space":"register","size":8}`), `"pc": missing required field "offset"`},
		"sp without space":     {rep(`"sp":{"space":"register",`, `"sp":{`), `"sp": missing required field "space"`},
		"sp zero size":         {rep(`"sp":{"space":"register","offset":32,"size":8}`, `"sp":{"space":"register","offset":32,"size":0}`), `"sp": space must be non-empty and size positive`},
		"pc empty space":       {rep(`"pc":{"space":"register"`, `"pc":{"space":""`), `"pc"`},
		"arg unknown field":    {rep(`"offset":56,"size":8}`, `"offset":56,"size":8,"name":"RDI"}`), `unknown field "name"`},
		"arg missing size":     {rep(`{"space":"register","offset":48,"size":8}`, `{"space":"register","offset":48}`), `"int_args"[1]: missing required field "size"`},
		"int_args null":        {rep(`"int_args":[`, `"int_args":null,"x":[`), `x`},
		"initial_context text": {rep(`"initial_context":0`, `"initial_context":"0"`), `initial_context`},
		"trailing":             {goodLanguage + `{}`, `trailing data`},
	} {
		if _, err := ParseLanguage([]byte(c.in)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want it to contain %q", name, err, c.want)
		}
	}
}
