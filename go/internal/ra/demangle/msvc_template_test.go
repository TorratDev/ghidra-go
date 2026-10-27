package demangle

import "testing"

// Template names. Expected names, namespaces and Full are the Ghidra 12.1.4
// MicrosoftDemangler results in rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcTemplateNames(t *testing.T) {
	for _, c := range []struct{ mangled, name, ns, full string }{
		{"?$S1@HH", "S1<int,int>", "", "S1<int,int>"},
		{"?$Tc@H", "Tc<int>", "", "Tc<int>"},
		{"?$template@H", "template<int>", "", "template<int>"},
	} {
		t.Run(c.mangled, func(t *testing.T) {
			d := DemangleMsvc(c.mangled)
			if d == nil {
				t.Fatalf("%s: no result", c.mangled)
			}
			if d.Name != c.name || ns(d) != c.ns || d.Full != c.full {
				t.Errorf("got name %q ns %q full %q; want %q %q %q", d.Name, ns(d), d.Full, c.name, c.ns, c.full)
			}
		})
	}
}

// Pointers to member functions are not ported, so the template constructors that
// take them give no result.
func TestMsvcTemplateRejects(t *testing.T) {
	for _, mangled := range []string{
		"??0?$AAA@@@QEAA@P8BBB@@EAAPEAVCCC@@XZ@Z",
		"??0?$AAA@VBBB@@VCCC@@@@QEAA@P8BBB@@EAAPEAVCCC@@XZ@Z",
	} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}
