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
// Ghidra gives no name for the first three; templates are not ported yet.
func TestMsvcRejects(t *testing.T) {
	for _, mangled := range []string{
		"?fn@@YAHX@Z",
		"?fn@@3PE6AHH@ZA",
		"?fn@@3AE6AHH@ZA",
		"?$S1@HH",
		"?FnName@@YAXAAH@Z trailing",
	} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}

// mdDataTypeParser must return the MDMang spelling, which stage 2 embeds in
// template arguments.
func TestMsvcTypeSpelling(t *testing.T) {
	for _, c := range []struct{ name, mangled, want string }{
		{"basic", "H", "int"},
		{"pointer", "PAH", "int *"},
		{"pointer to const", "PBE", "unsigned char const *"},
		{"reference", "AAH", "int &"},
		{"class in a namespace", "VFoo@Ns@@", "class Ns::Foo"},
		{"bool", "_N", "bool"},
		{"array", "$$BY0IA@H", "int [128]"},
		{"pointer to function", "P6AHH@Z", "int (__cdecl*)(int)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := &msvcParser{s: c.mangled}
			got, err := p.mdDataTypeParser()
			if err != nil || got != c.want {
				t.Errorf("%s: got %q (%v), want %q", c.mangled, got, err, c.want)
			}
		})
	}
}

// A digit in a type refers to the type table filled by earlier types; $0-$9
// refer to the template argument table, which only a template fills.
func TestMsvcBackreferences(t *testing.T) {
	p := &msvcParser{s: "PAH0"}
	if _, err := p.mdDataTypeParser(); err != nil {
		t.Fatal(err)
	}
	if got, err := p.mdDataTypeParser(); err != nil || got != "int *" {
		t.Errorf("type backref 0: got %q (%v), want %q", got, err, "int *")
	}

	p = &msvcParser{s: "$1", templateArgs: []string{"int", "char"}}
	if got, err := p.mdDataTypeParser(); err != nil || got != "char" {
		t.Errorf("template backref $1: got %q (%v), want %q", got, err, "char")
	}

	p = &msvcParser{s: "$0"}
	if _, err := p.mdDataTypeParser(); err == nil {
		t.Error("template backref $0 outside a template: want an error")
	}
}
