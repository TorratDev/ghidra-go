package analysis

import (
	_ "embed"
	"strings"
)

// The name lists are copies of Ghidra/Features/Base/data/*FunctionsThatDoNotReturn
// (go:embed cannot reach outside the module).

//go:embed data/ElfFunctionsThatDoNotReturn
var elfNoReturn string

//go:embed data/PEFunctionsThatDoNotReturn
var peNoReturn string

//go:embed data/MachOFunctionsThatDoNotReturn
var machoNoReturn string

// noReturnNames is Ghidra's NoReturnFunctionAnalyzer name list for a format.
type noReturnNames map[string]bool

func noReturnNamesFor(format string) noReturnNames {
	text := elfNoReturn
	switch format {
	case "PE":
		text = peNoReturn
	case "MachO":
		text = machoNoReturn
	}
	names := noReturnNames{}
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			names[strings.TrimLeft(l, "_")] = true
		}
	}
	return names
}

// contains ignores leading underscores and a @version suffix, as Ghidra does.
func (n noReturnNames) contains(name string) bool {
	base, _, _ := strings.Cut(name, "@")
	return n[strings.TrimLeft(base, "_")]
}
