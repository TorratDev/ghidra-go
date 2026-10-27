package demangle

import "testing"

// Operator, dynamic initializer and iterator names. Expected name, namespace and
// Full are the Ghidra 12.1.4 MicrosoftDemangler results in
// rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcOperatorNames(t *testing.T) {
	for _, c := range []struct{ mangled, name, ns, full string }{
		{"??2@YAPAXI@Z", "operator_new", "", "void * __cdecl operator new(unsigned int) "},
		{"??8@YAHAEBVname0@@0@Z", "operator==", "", "int __cdecl operator==(class name0 const & __ptr64,class name0 const & __ptr64) "},
		{"??9type_info@@QBEHABV0@@Z", "operator!=", "type_info", ""},
		{"??__Evar@@YMXXZ", "`dynamic_initializer_for_'var''", "", "void __clrcall `dynamic initializer for 'var''(void) "},
		{"??__AtestAccessLevel@@$BA@AA", "`managed_vector_constructor_iterator'{0,{flat}}'_}'", "testAccessLevel", "[thunk]:__thiscall testAccessLevel::`managed vector constructor iterator'{0,{flat}}' }'(void)"},
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

// Type casts, atexit destructors and guards are not ported: no result.
func TestMsvcOperatorRejects(t *testing.T) {
	for _, mangled := range []string{
		"??Bvar@@3$$A6AH$$A6AH@Z@ZA",
		"??__Fname0@@YAXXZ",
		"??__JtestAccessLevel@@$BA@AA",
	} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}
