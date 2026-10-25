// Package sleigh is the Go side of the SLEIGH bridge: the JSON-lines contract
// with the temporary Java helper that decodes through Ghidra's own SLEIGH
// engine (the native Go port is #19), the Ghidra FlowType name mapping and
// the language record. The Java bridge itself is not written yet.
package sleigh

import (
	"fmt"
	"strings"
)

// FlowKind is the coarse flow classification (Ghidra FlowType) the analyzers
// use; it has the eight kinds of the Rust ra-sleigh crate.
type FlowKind int

const (
	FlowFallthrough FlowKind = iota
	FlowJump
	FlowCondJump
	FlowCall
	FlowCondCall
	FlowReturn
	FlowCondReturn
	// FlowTerminator is an instruction with no fallthrough and no known
	// successor (HLT, UD2). Ghidra reports it as TERMINATOR, like a return,
	// so the name mapping never produces it; see FlowFromGhidra.
	FlowTerminator
)

// flowRows is the Rust-kind to Ghidra FlowType table from the issue.
var flowRows = []struct {
	Kind   FlowKind
	Rust   string
	Ghidra string
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

func (k FlowKind) String() string {
	if k < 0 || int(k) >= len(flowRows) {
		return fmt.Sprintf("FlowKind(%d)", int(k))
	}
	return flowRows[k].Rust
}

// GhidraName is the FlowType name for k.
func (k FlowKind) GhidraName() string {
	if k < 0 || int(k) >= len(flowRows) {
		return ""
	}
	return flowRows[k].Ghidra
}

// FlowFromGhidra maps a Ghidra FlowType name to a FlowKind. Only the names of
// the issue's table are known; any other name (COMPUTED_JUMP, a typo) is an
// error, never a guess. TERMINATOR is both Return and Terminator in the
// table; Ghidra cannot tell them apart, so it maps to FlowReturn.
//
// Bridge rule for the FlowTypes that look like part of the table but are not:
// CALL_TERMINATOR, JUMP_TERMINATOR and CALLOTHER_OVERRIDE_* (a CALLOTHER
// instruction whose flow a language overrides) have no mapping in the
// contract, and the bridge must not emit them. They are rejected with an
// error that names this rule so a bridge that forwards them fails loudly
// instead of being mapped by guesswork; give them rows in the table first.
func FlowFromGhidra(name string) (FlowKind, error) {
	for _, r := range flowRows {
		if r.Ghidra == name {
			return r.Kind, nil
		}
	}
	if name == "CALL_TERMINATOR" || name == "JUMP_TERMINATOR" || strings.HasPrefix(name, "CALLOTHER_OVERRIDE_") {
		return 0, fmt.Errorf("FlowType %q has no mapping in the contract (bridge rule: CALL_TERMINATOR, JUMP_TERMINATOR and CALLOTHER_OVERRIDE_* must not be emitted)", name)
	}
	return 0, fmt.Errorf("unknown FlowType name %q", name)
}
