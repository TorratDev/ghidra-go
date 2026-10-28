package demangle

import "testing"

// Expected values are the MicrosoftDemangler results recorded in
// rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcLocalScopes(t *testing.T) {
	const fnName = "`protected:_static_int___cdecl_name2::name1::name0(unsigned_short_const*___ptr64,unsigned_short&___ptr64)'::__l2"
	for _, c := range []struct{ name, mangled, ns, leaf string }{
		{"guard of a static local", "??_B?1??name0@name1@name2@@KAHPEBGAEAG@Z@51", fnName, "`local_static_guard'{2}'"},
		{"reference temporary", "?$RT1@?1??name0@name1@name2@@KAHPEBGAEAG@Z@4HA", fnName, "`reference_temporary{1}'"},
		{"nonvisible static guard", "?$S1@?1??name0@name1@name2@@KAHPEBGAEAG@Z@4HA", fnName, "`nonvisible_static_guard{1}'"},
		{"thread-safe static guard", "?$TSS0@?1??GetCategoryMap@CDynamicRegistrationInfoSource@XPerfAddIn@@SAPEBU_ATL_CATMAP_ENTRY@ATL@@XZ@4HA", "`public:_static_struct_ATL::_ATL_CATMAP_ENTRY_const*___ptr64___cdecl_XPerfAddIn::CDynamicRegistrationInfoSource::GetCategoryMap(void)'::__l2", "`thread_safe_static_guard{0}'"},
		{"static local in a static function", "?name0@?1??name1@name2@name3@@SGPBUname4@name5@@XZ@4QBU45@B", "`public:_static_struct_name5::name4_const*___stdcall_name3::name2::name1(void)'::__l2", "name0"},
		{"scope number and its own namespace", "?name0@?2??name1@name2@name3@3@KGPAUname4@@PAG@Z@4QBUname5@233@B", "`protected:_static_struct_name4*___stdcall_name3::name3::name2::name1(unsigned_short*)'::__l3", "name0"},
		{"scope of a function with no encoding", "?name0@?1??name1@@9@4Uname2@@A", "`name1'::__l2", "name0"},
		{"function pointer data in a scope", "?name0@?1??name1@@9@4P6AHPEAUname2@@@ZEA", "`name1'::__l2", "name0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := DemangleMsvc(c.mangled)
			if d == nil {
				t.Fatalf("%s: no result", c.mangled)
			}
			if d.Name != c.leaf || ns(d) != c.ns {
				t.Errorf("%s: got %q in %q, want %q in %q", c.mangled, d.Name, ns(d), c.leaf, c.ns)
			}
			if d.Full != "" {
				t.Errorf("%s: Full %q, want empty for a scope", c.mangled, d.Full)
			}
		})
	}
}

// A scope whose function is not ported gives no name rather than a guess: a
// member function, a missing guard number, and a function inside a scope.
func TestMsvcLocalScopeRejects(t *testing.T) {
	for _, mangled := range []string{
		"??_B?1??name0@name1@name2@@KAHPEBGAEAG@Z@5",
		"??_B?1??name0@name1@name2@@KAHPEBGAEAG@Z@51X",
		"??_B?1??name0@name1@name2@@QEAAHXZ@51",
		"?fn2@Bar1@?6??Bar3@Foo6@@SAHXZ@SAHXZ",
	} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}
