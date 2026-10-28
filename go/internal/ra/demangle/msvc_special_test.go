package demangle

import (
	"reflect"
	"testing"
)

// The '_' argument kind joins the type table, so a digit can name a bool.
func TestMsvcUnderscoreBackref(t *testing.T) {
	p := &msvcParser{s: "_NPAH0@Z"}
	args, err := p.mdArgumentsList()
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bool", "int *", "bool"}; !reflect.DeepEqual(args, want) {
		t.Errorf("got %q, want %q", args, want)
	}
}

// Expected leaf, namespace and full text are the Ghidra 12.1.4 MicrosoftDemangler
// results recorded in rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcSpecialNames(t *testing.T) {
	for _, c := range []struct{ mangled, name, ns, full string }{
		{"??_7A@@6B@", "`vftable'", "A", "const A::`vftable'"},
		{"??_7C@@6BA@@@", "`vftable'{for_`A'}", "C", "const C::`vftable'{for_`A'}"},
		{"??_7a@b@@6Bc@d@e@@f@g@h@@i@j@k@@@", "`vftable'{for_`e::d::c's_`h::g::f's_`k::j::i'}", "b::a", "const b::a::`vftable'{for_`e::d::c's_`h::g::f's_`k::j::i'}"},
		{"??_8CWebDVDComp@@7B@", "`vbtable'", "CWebDVDComp", "const CWebDVDComp::`vbtable'"},
		{"??_8CGWTelMenuData@@7BCGWTelSelectionData@@@", "`vbtable'{for_`CGWTelSelectionData'}", "CGWTelMenuData", "const CGWTelMenuData::`vbtable'{for_`CGWTelSelectionData'}"},
		{"??_R0?AVA@@@8", "class_A_`RTTI_Type_Descriptor'", "", "class_A_`RTTI_Type_Descriptor'"},
		{"??_R0?AVBase2@BN2@@@8", "class_BN2::Base2_`RTTI_Type_Descriptor'", "", "class_BN2::Base2_`RTTI_Type_Descriptor'"},
		{"??_R17?0A@EA@name0@@8", "`RTTI_Base_Class_Descriptor_at_(8,-1,0,64)'", "name0", "name0::`RTTI_Base_Class_Descriptor_at_(8,-1,0,64)'"},
		{"??_R1A@?0A@A@CEnumUnknown@@8", "`RTTI_Base_Class_Descriptor_at_(0,-1,0,0)'", "CEnumUnknown", "CEnumUnknown::`RTTI_Base_Class_Descriptor_at_(0,-1,0,0)'"},
		{"??_9name0@@$BBII@BA", "`vcall'", "name0", "[thunk]:__thiscall name0::`vcall'(void)"},
		{"??_9testAccessLevel@@$BA@AA", "`vcall'{0,{flat}}'_}'", "testAccessLevel", "[thunk]:__thiscall testAccessLevel::`vcall'{0,{flat}}' }'(void)"},
		{"??_R2A@@8", "`RTTI_Base_Class_Array'", "A", "A::`RTTI_Base_Class_Array'"},
		{"??_R3_AFX_THREAD_STATE@@8", "`RTTI_Class_Hierarchy_Descriptor'", "_AFX_THREAD_STATE", "_AFX_THREAD_STATE::`RTTI_Class_Hierarchy_Descriptor'"},
		{"??_R4C@@6BB@@@", "`RTTI_Complete_Object_Locator'{for_`B'}", "C", "const C::`RTTI_Complete_Object_Locator'{for_`B'}"},
		{"??_R1ABCP@?0FGHJKL@A@_AFX_CTL3D_STATE@@8", "`RTTI_Base_Class_Descriptor_at_(303,-1,5667243,0)'", "_AFX_CTL3D_STATE", "_AFX_CTL3D_STATE::`RTTI_Base_Class_Descriptor_at_(303,-1,5667243,0)'"},
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

// Vcall thunks with a longer tail, and guards without a local scope, are not ported: no result, not a guess.
func TestMsvcSpecialRejects(t *testing.T) {
	for _, mangled := range []string{
		"??_9name0@@$BBII@I0A",
		"??_7name0@name1@@6B",
	} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}

// Full is the rendered MDMang text; these match the oracle signatures exactly.
// A 64-bit pointer inside a function-pointer argument is not rendered as Ghidra
// does, so its Full stays empty while the name still resolves.
func TestMsvcFullText(t *testing.T) {
	if d := DemangleMsvc("?name0@@YAXP6AJPEAPEAVname1@@@ZP6AJPEAVname2@@PEAPEAUname3@@@ZP6AJ3@Z@Z"); d == nil || d.Name != "name0" || d.Full != "" {
		t.Errorf("64-bit function-pointer argument: got %+v, want name0 with empty Full", d)
	}
	for _, c := range []struct{ mangled, full string }{
		{"?FnName@@YAXAAH@Z", "void __cdecl FnName(int &) "},
		{"?Bar3@Foo2b@@SAHXZ", "public static int __cdecl Foo2b::Bar3(void) "},
		{"??0Rect@geo@@QAE@HH@Z", "public __thiscall geo::Rect::Rect(int,int) "},
		{"?FnName@@YAXQAH@Z", "void __cdecl FnName(int const *) "},
	} {
		if d := DemangleMsvc(c.mangled); d == nil || d.Full != c.full {
			t.Errorf("%s: full %q, want %q", c.mangled, fullOf(d), c.full)
		}
	}
}

func fullOf(d *Demangled) string {
	if d == nil {
		return "<nil>"
	}
	return d.Full
}
