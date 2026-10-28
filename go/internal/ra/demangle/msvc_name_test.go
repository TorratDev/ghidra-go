package demangle

import "testing"

// Expected values are the MicrosoftDemangler results recorded in
// rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcAnonymousNamespaces(t *testing.T) {
	for _, c := range []struct{ mangled, ns, leaf, full string }{
		// "?A0x" is an anonymous namespace, named by its zero-padded number.
		{"??_7a@?A0xfedcba98@b@@6B@", "b::_anon_FEDCBA98::a", "`vftable'", "const b::_anon_FEDCBA98::a::`vftable'"},
		// "?Aname" keeps its 'A' as the name of the namespace.
		{"?var@abc@?Axyz@1@3HA", "abc::Axyz::abc", "var", ""},
		{"?var@abc@?Axyz@2@3HA", "Axyz::Axyz::abc", "var", ""},
		{"??_7name0@?Aname1@@6Bname2@1@@", "Aname1::name0", "`vftable'{for_`Aname1::name2'}", "const Aname1::name0::`vftable'{for_`Aname1::name2'}"},
	} {
		d := DemangleMsvc(c.mangled)
		if d == nil {
			t.Fatalf("%s: no result", c.mangled)
		}
		if d.Name != c.leaf || ns(d) != c.ns || d.Full != c.full {
			t.Errorf("%s: got %q in %q with Full %q, want %q in %q with Full %q", c.mangled, d.Name, ns(d), d.Full, c.leaf, c.ns, c.full)
		}
	}
}

// A function in an anonymous namespace keeps its name and namespace, with Full
// empty: the oracle spells that Full only for CLR names.
func TestMsvcAnonymousFunctionFull(t *testing.T) {
	d := DemangleMsvc("?f@?A0x1@@YAXXZ")
	if d == nil || d.Name != "f" || ns(d) != "_anon_00000001" || d.Full != "" {
		t.Errorf("got %+v, want f in _anon_00000001 with empty Full", d)
	}
}

// A code view ("?@") names the symbol it precedes. The rest of the oracle's
// code-view names are not ported (bare templates and constructor data).
func TestMsvcCodeViews(t *testing.T) {
	d := DemangleMsvc("?@?var@@3HA")
	if d == nil || d.Name != "var" || ns(d) != "" || d.Full != "" {
		t.Errorf("got %+v, want var with empty Full", d)
	}
	for _, mangled := range []string{"?@?$template@H", "?@?@?var@@3HA"} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}
