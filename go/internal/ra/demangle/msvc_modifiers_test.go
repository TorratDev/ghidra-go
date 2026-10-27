package demangle

import (
	"strings"
	"testing"
)

// The "$$" modifiers. Expected name, namespace and Full are the Ghidra 12.1.4
// MicrosoftDemangler results in rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcModifiers(t *testing.T) {
	for _, c := range []struct{ mangled, name, ns, full string }{
		{"??0Array@@$$FQAE@XZ", "public:___thiscall_Array::Array(void)", "", "public: __thiscall Array::Array(void)"},
		{"??1Array@@$$FQAE@XZ", "public:___thiscall_Array::~Array(void)", "", "public: __thiscall Array::~Array(void)"},
		{"?name0@@$$FYMXXZ", "void___clrcall_name0(void)", "", "void __clrcall name0(void)"},
		{"??0C@@$$FQE$AAM@XZ", "public:___clrcall_C::C(void)___ptr64", "", "public: __clrcall C::C(void) __ptr64"},
		{"?fn@@YAH$$QAH@Z", "fn", "", "int __cdecl fn(int &&) "},
		{"?fn@@YAH$$QDH@Z", "fn", "", "int __cdecl fn(int const volatile &&) "},
		{"?fn@@YAH$$RAH@Z", "fn", "", "int __cdecl fn(int volatile &&) "},
		{"?fn@@YAH$$T@Z", "fn", "", "int __cdecl fn(std::nullptr_t) "},
		{"?abort@@$$J0YAXXZ", "abort", "", `extern "C" void __cdecl abort(void) `},
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

// A "$$BY" argument joins the type table, so a later digit can name it.
func TestMsvcArrayArgBackref(t *testing.T) {
	p := &msvcParser{s: "$$BY01HPAH0@Z"}
	args, err := p.mdArgumentsList()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"int [2]", "int *", "int [2]"}; strings.Join(args, ",") != strings.Join(want, ",") {
		t.Errorf("got %q, want %q", args, want)
	}
	if d := DemangleMsvc("?f@@YAX$$BY01HPAH0@Z"); d == nil || d.Full != "void __cdecl f(int [2],int *,int [2]) " {
		t.Errorf("full %q, want the array backref rendered", fullOf(d))
	}
}

// Ghidra names some $$ names by their type or leaves them unparsed; those give
// no result rather than a guess.
func TestMsvcModifierRejects(t *testing.T) {
	for _, mangled := range []string{
		"?Name@@3$$TA",               // data of type nullptr_t: Ghidra names it by the type
		"?name0@@2$$A6A$$A6AXXZXZEA", // function-pointer modifiers are not ported
		"?fn@@3$$Q6AHH@ZA",           // rvalue reference to a function
	} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}
