// Package demangle is the Go port of the GNU and Rust parts of
// rust-analysis/crates/ra-demangle: demanglers with Ghidra 12.1.4's naming
// rules. Each scheme yields what Ghidra's demangler of the same name yields,
// a leaf name and a namespace path. MSVC is a partial port of Ghidra's
// MicrosoftDemangler (MDMang), see msvc.go.
package demangle

import "strings"

type Scheme int

const (
	Gnu Scheme = iota
	Rust
	Msvc
)

// GhidraClass is the Ghidra demangler class a scheme mirrors.
func (s Scheme) GhidraClass() string {
	switch s {
	case Rust:
		return "RustDemangler"
	case Msvc:
		return "MicrosoftDemangler"
	}
	return "GnuDemangler"
}

type Demangled struct {
	Scheme Scheme
	// Namespace holds the parent namespaces, outermost first.
	Namespace []string
	// Name is the leaf name as Ghidra applies it (area, ~Rect, operator.new).
	Name       string
	IsFunction bool
	// Full is the demangled text the name was derived from.
	Full string
}

// NamespaceString returns "a::b", or nil for the global namespace.
func (d *Demangled) NamespaceString() *string {
	if len(d.Namespace) == 0 {
		return nil
	}
	s := strings.Join(d.Namespace, "::")
	return &s
}

// Demangle demangles with the scheme Ghidra would pick: Rust first when
// rustProgram is set (RustDemanglerAnalyzer only runs on Rust programs),
// MSVC for "?" symbols, otherwise GNU.
func Demangle(mangled string, rustProgram bool) *Demangled {
	if rustProgram {
		if d := DemangleRust(mangled); d != nil {
			return d
		}
	}
	if strings.HasPrefix(mangled, "?") {
		return DemangleMsvc(mangled)
	}
	return DemangleGnu(mangled)
}

// DemangleWith runs one specific scheme, like calling one Ghidra demangler class.
func DemangleWith(s Scheme, mangled string) *Demangled {
	switch s {
	case Rust:
		return DemangleRust(mangled)
	case Msvc:
		return DemangleMsvc(mangled)
	}
	return DemangleGnu(mangled)
}
