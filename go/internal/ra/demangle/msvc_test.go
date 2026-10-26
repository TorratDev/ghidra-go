package demangle

import "testing"

// Expected values are the MicrosoftDemangler results recorded in
// rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcNaming(t *testing.T) {
	for _, c := range []struct{ name, mangled, ns, leaf string }{
		{"global function", "?FnName@@YAXAAH@Z", "", "FnName"},
		{"static member", "?Bar3@Foo2b@@SAHXZ", "Foo2b", "Bar3"},
		{"constructor keeps the class in the namespace", "??0Base2@BN2@@QEAA@AEBV01@@Z", "BN2::Base2", "Base2"},
		{"destructor", "??1Rect@geo@@UEAA@XZ", "geo::Rect", "~Rect"},
		{"global data with an array type", "?FirstRxPacket@@3PAY0IA@EA", "", "FirstRxPacket"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := DemangleMsvc(c.mangled)
			if d == nil {
				t.Fatalf("%s: no result", c.mangled)
			}
			if d.Name != c.leaf || ns(d) != c.ns {
				t.Errorf("%s: got %q in %q, want %q in %q", c.mangled, d.Name, ns(d), c.leaf, c.ns)
			}
		})
	}
}

// Encodings outside the stage-1 subset must give no name rather than a guess.
// Ghidra gives no name for the first; templates are not ported yet.
func TestMsvcRejects(t *testing.T) {
	for _, mangled := range []string{
		"?fn@@YAHX@Z",
		"?$S1@HH",
		"?AAA@@QAA@P8BBB@@AAPAVCCC@@XZ@Z",
		"?FnName@@YAXAAH@Z trailing",
	} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}
