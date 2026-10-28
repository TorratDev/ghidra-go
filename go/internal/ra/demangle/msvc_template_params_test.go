package demangle

import "testing"

// Template-parameter, float, tuple and function-template names. Expected name,
// namespace and Full are the Ghidra 12.1.4 MicrosoftDemangler results in
// rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcTemplateParamForms(t *testing.T) {
	for _, c := range []struct{ mangled, name, ns, full string }{
		{"??$F@$2?B@B@@@QAE@@Z", "F<-1.e1>", "", "public __thiscall F<-1.e1>(void) "},
		{"??$F@$G?A@?A@?A@@@QAE@@Z", "F<{-0,-0,-0}>", "", "public __thiscall F<{-0,-0,-0}>(void) "},
		{"??$largest@H@geo@@YAHPBHH@Z", "largest<int>", "geo", "int __cdecl geo::largest<int>(int const *,int) "},
		{"??$name0@D@name1@@YAIPAD0PBD1PBUname2@@@Z", "name0<char>", "name1", "unsigned int __cdecl name1::name0<char>(char *,char *,char const *,char const *,struct name2 const *) "},
		{"??0?$name0@?0Uname1@@@name2@@QEAA@XZ", "name0<`template-parameter-1',name1>", "name2::name0<`template-parameter-1',name1>", ""},
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
