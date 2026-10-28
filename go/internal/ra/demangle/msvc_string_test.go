package demangle

import "testing"

// Expected values are the MicrosoftDemangler results recorded in
// rust-analysis/compare/expected/demangle/ghidra.json.gz.
func TestMsvcStringLiterals(t *testing.T) {
	for _, c := range []struct{ mangled, full string }{
		{"??_C@_07CBCILOAJ@FaxTask?$AA@FNODOBFM@", "FaxTask"},
		{"??_C@_0M@IDPNJOFL@TlsGetValue?$AA@", "TlsGetValue"},
		{"??_C@_1BA@KFOBIOMM@?$AAT?$AAY?$AAP?$AAE?$AAL?$AAI?$AAB?$AA?$AA@", "TYPELIB"},
		{"??_C@_13BDBHJCJN@u?3?$AA?$AA@", "町"},
		{"??_C@_1EK@KFPEBLPK@?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AA0?$AA1?$AA2?$AA3?$AA4?$AA5?$AA6?$AA7?$AA8?$AA9?$AAA?$AAB@", "012345678901234567890123456789AB"},
		// A byte that is not printable (here 0xe8) has no Full text.
		{"??_C@_01CIIBJEOE@?h?$AA@", ""},
	} {
		d := DemangleMsvc(c.mangled)
		if d == nil {
			t.Fatalf("%s: no result", c.mangled)
		}
		if d.Name != "`string'" || ns(d) != "" || d.Full != c.full {
			t.Errorf("%s: got %q in %q with Full %q, want `string' with Full %q", c.mangled, d.Name, ns(d), d.Full, c.full)
		}
	}
}

// A string literal's encoding that is not certain gives no result: a char type
// other than 0 or 1, a missing '@' after the bytes, and an address that is not hex.
func TestMsvcStringRejects(t *testing.T) {
	for _, mangled := range []string{
		"??_C@_21CBCILOAJ@FaxTask?$AA@",
		"??_C@_07CBCILOAJ@FaxTask?$AA",
		"??_C@_07CBCILOAJ@FaxTask?$AA@FNODOBFM@X",
	} {
		if d := DemangleMsvc(mangled); d != nil {
			t.Errorf("%s: got %q, want no result", mangled, d.Name)
		}
	}
}
