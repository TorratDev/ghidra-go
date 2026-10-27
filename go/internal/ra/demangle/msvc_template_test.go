package demangle

import (
	"strings"
	"testing"
)

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

// A template's arguments have their own name table, and the whole template is a
// name for later backreferences in the outer qualified name (MDContext, MDReusableName).
func TestMsvcTemplateBackrefs(t *testing.T) {
	for _, c := range []struct{ mangled, ns, full string }{
		{"?g@?$AAA@VBBB@@@1@QAEXXZ", "AAA<BBB>::AAA<BBB>", ""},
		{"?g@?$AAA@V0@@@QAEXXZ", "AAA<AAA>", ""},
		{"?g@?$AAA@VBBB@@@@QAEXV1@@Z", "AAA<BBB>", "(class AAA<BBB>)"},
	} {
		t.Run(c.mangled, func(t *testing.T) {
			d := DemangleMsvc(c.mangled)
			if d == nil {
				t.Fatalf("%s: no result", c.mangled)
			}
			if d.Name != "g" || ns(d) != c.ns {
				t.Errorf("got name %q ns %q; want g in %q", d.Name, ns(d), c.ns)
			}
			if c.full != "" && !strings.Contains(d.Full, c.full) {
				t.Errorf("full %q lacks %q", d.Full, c.full)
			}
		})
	}
}

// Template arguments of the forms added with the constants and handles. Expected
// name, namespace and Full are the Ghidra 12.1.4 MicrosoftDemangler results.
func TestMsvcTemplateArgForms(t *testing.T) {
	for _, c := range []struct{ mangled, name, ns, full string }{
		{"?$name1@P$AAVname2@name3@@", "name1<name3::name2_^>", "", "name1<name3::name2_^>"},
		{"??0?$name0@$$BY02Uname1@@@name2@@QEAA@XZ", "name0<struct_name1_[3]>", "name2::name0<struct_name1_[3]>", ""},
	} {
		t.Run(c.mangled, func(t *testing.T) {
			d := DemangleMsvc(c.mangled)
			if d == nil {
				t.Fatalf("%s: no result", c.mangled)
			}
			if d.Name != c.name || ns(d) != c.ns {
				t.Errorf("got name %q ns %q; want %q %q", d.Name, ns(d), c.name, c.ns)
			}
			if c.full != "" && d.Full != c.full {
				t.Errorf("full %q, want %q", d.Full, c.full)
			}
		})
	}
}
