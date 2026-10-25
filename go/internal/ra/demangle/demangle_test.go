package demangle

import (
	"strings"
	"testing"
)

func ns(d *Demangled) string {
	if s := d.NamespaceString(); s != nil {
		return *s
	}
	return ""
}

// Expected values for oracle names come from Ghidra 12.1.4
// (rust-analysis/compare/expected/demangle/ghidra.json.gz).
func TestGnuNamingRules(t *testing.T) {
	for _, c := range []struct{ name, mangled, ns, leaf string }{
		{"leaf and namespace", "_ZNK5Shape4nameEv", "Shape", "name"},
		{"clone suffix and .cold are not a label in 12.1.4", "_Z5maxofIiET_RKSt6vectorIS0_SaIS0_EE.isra.0.cold", "", "maxof<int>"},
		{".cold on a method", "_ZN6ghidra15ContextInternal9FreeArrayaSERKS1_.cold", "ghidra::ContextInternal::FreeArray", "operator="},
		{"operator()", "_ZN10OpTestTypeclEf", "OpTestType", "operator()"},
		{"operator() on a lambda template argument",
			"_ZN12LayerDetails15RandomProviderTIZNKS_9LayerBase10initRandomEllEUlRljE_EclIiLm2EEET_RAT0__KS6_",
			"LayerDetails::RandomProviderT<LayerDetails::LayerBase::initRandom(long,long)const::{lambda(long&,unsigned_int)#1}>", "operator()"},
		{"lambda is a namespace without its parameter list",
			"_ZZN12GrGLFunctionIFPKhjEEC1IZN13skia_bindings28CreateGLES2InterfaceBindingsEPN3gpu5gles214GLES2InterfaceEPNS6_14ContextSupportEE3$_0EET_ENUlPKvjE_8__invokeESF_j",
			"GrGLFunction<unsigned_char_const*(unsigned_int)>::GrGLFunction<skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*,gpu::ContextSupport*)::$_0>(skia_bindings::CreateGLES2InterfaceBindings(gpu::gles2::GLES2Interface*,gpu::ContextSupport*)::$_0)::{lambda(void_const*,unsigned_int)#1}",
			"__invoke"},
		{"conversion operator", "_ZN10OpTestTypecvPKcEv", "OpTestType", "operator.cast.to.char*"},
		{"operator new", "_Znwm", "", "operator.new"},
		{"_ZZ local entity", "_ZZ18__gthread_active_pvE20__gthread_active_ptr", "__gthread_active_p()", "__gthread_active_ptr"},
		{"item in namespace, local", "_ZGVZN10KDirLister11emitChangesEvE3dot", "KDirLister::emitChanges()", "dot"},
		{"item in namespace, global", "_ZGV17globalVariableFoo", "", "globalVariableFoo"},
		{"address table", "_ZTV4Rect", "Rect", "vtable"},
		{"typeinfo name", "_ZTS5Shape", "Shape", "typeinfo-name"},
		{"thunk", "_ZThn8_N14nsPrintSession6AddRefEv", "nsPrintSession", "AddRef"},
		{"std replacement", "_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev", "std::__cxx11::string", "~string"},
		{"rust legacy through the GNU path", "_ZN3std2io4Read11read_to_end17hb85a0f6802e14499E", "std::io::Read", "read_to_end"},
		{"global init keeps the raw prefix", "_GLOBAL__sub_I__ZN3FooC2Ev", "Foo", "_GLOBAL__sub_I_Foo"},
		{"global dtor keeps the raw prefix", "_GLOBAL__sub_D__ZN3FooC2Ev", "Foo", "_GLOBAL__sub_D_Foo"},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := DemangleGnu(c.mangled)
			if d == nil {
				t.Fatal("did not demangle")
			}
			if ns(d) != c.ns || d.Name != c.leaf {
				t.Errorf("got %q | %q, want %q | %q", ns(d), d.Name, c.ns, c.leaf)
			}
		})
	}
}

func TestGnuSkipRules(t *testing.T) {
	for _, m := range []string{"_ZTISt13runtime_error@GLIBCXX_3.4", "___x", "main", "DW.ref._ZTI3Foo"} {
		if DemangleGnu(m) != nil {
			t.Errorf("%s demangled with only-known-patterns", m)
		}
	}
	// the analyzer passes everything, but versioned and ___ names stay skipped
	if d := DemangleGnuOpts("DW.ref._ZTI3Foo", false); d == nil || ns(d) != "Foo" || d.Name != "typeinfo" {
		t.Errorf("DW.ref.: %+v", d)
	}
	if DemangleGnuOpts("_ZTISt13runtime_error@GLIBCXX_3.4", false) != nil || DemangleGnuOpts("___x", false) != nil {
		t.Error("always-skipped names demangled")
	}
	if skip("foo", true) != true || skip("foo", false) != false {
		t.Error("skip: unknown pattern")
	}
	for _, m := range []string{"_GLOBAL_.I.foo", "_GLOBAL_.D.foo", "_GLOBAL__I__Zfoo", "_GLOBAL__D__Zfoo", "h__foo", "?foo", "__Zfoo"} {
		if skip(m, true) {
			t.Errorf("skip(%q) = true", m)
		}
	}
	if !isGnu2Or3Pattern("_GLOBAL__D__Zx") || isGnu2Or3Pattern("_GLOBAL__sub_I_x") {
		t.Error("isGnu2Or3Pattern")
	}
	if !invalidDoubleUnderscore("text__more", "text(int)") || invalidDoubleUnderscore("text__more", "other") || invalidDoubleUnderscore("plain", "plain") {
		t.Error("invalidDoubleUnderscore")
	}
}

func TestFindNamespaceStartShortCircuit(t *testing.T) {
	// A '<' seen while inside parentheses must not change the template depth,
	// so the later '>' leaves the scan nested and no namespace start is found.
	if got := findNamespaceStart("p::q>f(<)", 8, 0); got != -1 {
		t.Errorf("got %d", got)
	}
	if got := findNamespaceStart("ns::name", 7, 0); got != 4 {
		t.Errorf("got %d", got)
	}
	if got := findNamespaceStart("plain", 4, 0); got != -1 {
		t.Errorf("got %d", got)
	}
}

func TestReplacements(t *testing.T) {
	r := replacements()
	if len(r) < 50 {
		t.Fatalf("only %d replacements", len(r))
	}
	d := parse("_Zx", "std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >::~basic_string()")
	if d == nil || d.name != "~string" {
		t.Errorf("%+v", d)
	}
}

func TestRustLegacy(t *testing.T) {
	d := DemangleRust("_ZN64_$LT$rustlib..shapes..Rect$u20$as$u20$rustlib..shapes..Shape$GT$4area17hdd6d4cd2f1383c34E")
	if d == nil || d.Name != "area" || ns(d) != "<rustlib::shapes::Rect_as_rustlib::shapes::Shape>" {
		t.Fatalf("%+v", d)
	}
	if s, ok := rustLegacy("_ZN3foo17hdd6d4cd2f1383c34E"); !ok || s != "foo" {
		t.Errorf("hash not dropped: %q", s)
	}
	if s, ok := rustLegacy("_ZN17hdd6d4cd2f1383c34E"); !ok || s != "hdd6d4cd2f1383c34" {
		t.Errorf("sole hash element dropped: %q", s)
	}
	if DemangleRust("main") != nil || DemangleRust("_ZN3fooE") == nil {
		t.Error("detection")
	}
}

func TestRustUnicodeEscapes(t *testing.T) {
	// (char) cast keeps the low 16 bits, as in Java.
	if got, err := unescapeU("a$u1f600$b"); err != nil || got != "ab" {
		t.Errorf("got %q, %v", got, err)
	}
	if got, err := unescapeU("x$u20$y"); err != nil || got != "x y" {
		t.Errorf("got %q, %v", got, err)
	}
	// Integer.parseInt accepts a sign.
	if got, err := unescapeU("$u-1$"); err != nil || got != "￿" {
		t.Errorf("got %q, %v", got, err)
	}
	for _, bad := range []string{"a$u1", "a$uzz$b", "$u$", "$u80000000$", "$"} {
		if _, err := unescapeU(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// malformed escapes leave the symbol undemangled
	for _, m := range []string{"_ZN7a$uzz$b3barE", "_ZN4a$u13barE"} {
		if _, ok := rustLegacy(m); ok {
			t.Errorf("%s demangled", m)
		}
	}
	// Java restarts the search at the closing '$', so a leftover odd '$' throws.
	if _, err := unescapeU("a$foo$b"); err == nil {
		t.Error("a$foo$b accepted")
	}
}

func TestRustV0(t *testing.T) {
	const crate = "rustlib[5c719a9850234f19]::math::largest"
	d := DemangleRust("_RNvXNtCs7W4I7ebKKSb_7rustlib6shapesNtB2_4RectNtB2_5Shape4area")
	if d == nil || d.Name != "area" ||
		d.Full != "<rustlib[5c719a9850234f19]::shapes::Rect as rustlib[5c719a9850234f19]::shapes::Shape>::area" {
		t.Fatalf("%+v", d)
	}
	// The oracle has no __R names or dotted suffixes; these follow the Java logic.
	for m, want := range map[string]string{
		"_RNvNtCs7W4I7ebKKSb_7rustlib4math7largest":                         crate,
		"__RNvNtCs7W4I7ebKKSb_7rustlib4math7largest":                        crate,
		"RNvNtCs7W4I7ebKKSb_7rustlib4math7largest":                          crate,
		"_RNvNtCs7W4I7ebKKSb_7rustlib4math7largest.1":                       crate + ".1",
		"_RNvNtCs7W4I7ebKKSb_7rustlib4math7largest.cold":                    crate + ".cold",
		"_RNvNtCs7W4I7ebKKSb_7rustlib4math7largest.llvm.12345":              crate,
		"_RNvNtCs7W4I7ebKKSb_7rustlib4math7largest@@VERS":                   crate,
		"_RNvNtCs7W4I7ebKKSb_7rustlib4math7largestxyz":                      crate,
		"_RNqCs4fqI2P2rA04_11utf8_identsu30____7hkackfecea1cbdathfdh9hlq6y": "utf8_idents[317d481089b8c8fe]::საჭმელად_გემრიელი_სადილი",
	} {
		if got, ok := demangleV0(m); !ok || got != want {
			t.Errorf("%s: got %q %v, want %q", m, got, ok, want)
		}
	}
	// The path must start with an uppercase tag; prefix and ASCII gates.
	for _, m := range []string{"_R", "_Rn", "_Rfoo", "_RNvC", "main", "_RNvCs1_4cr\xc3\xa9", "_R" + strings.Repeat("I", 600)} {
		if got, ok := demangleV0(m); ok {
			t.Errorf("%q demangled to %q", m, got)
		}
	}
	// DemangleRust only accepts the known prefixes.
	if DemangleRust("RNvNtCs7W4I7ebKKSb_7rustlib4math7largest") != nil {
		t.Error("bare R prefix accepted")
	}
	if d := DemangleRust("__RNvNtCs7W4I7ebKKSb_7rustlib4math7largest"); d == nil || d.Name != "largest" {
		t.Errorf("%+v", d)
	}
}

func TestCondenseAndSanitize(t *testing.T) {
	for in, want := range map[string]string{
		"std::vector<int, std::allocator<int> >": "std::vector<int,std::allocator<int>>",
		"foo<unsigned long>":                     "foo<unsigned_long>",
		"{unnamed type#1}":                       "{unnamed_type#1}",
		"f<é b>":                                 "f<é_b>",
		"f<² b>":                                 "f<²b>", // ² is not a letter or digit, as in Java
		"  x  ":                                  "x",
	} {
		if got := condense(in, true); got != want {
			t.Errorf("condense(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeName("operator new"); got != "operator_new" {
		t.Error(got)
	}
	if got := sanitizeName("f(int, char *)"); got != "f(int,char*)" {
		t.Error(got)
	}
}

func TestSymbolPath(t *testing.T) {
	for in, want := range map[string]string{
		"a::b<c::d>::e": "a|b<c::d>|e",
		"f(x::y)::z":    "f(x::y)|z",
		"plain":         "plain",
		"a<b::c":        "a<b|c",
	} {
		if got := join(symbolPath(in)); got != want {
			t.Errorf("symbolPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func join(s []string) string {
	out := ""
	for i, x := range s {
		if i > 0 {
			out += "|"
		}
		out += x
	}
	return out
}
