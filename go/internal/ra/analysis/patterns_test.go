package analysis

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/loader"
)

func TestParseBytePattern(t *testing.T) {
	p, ok := parseBytePattern("0x55 0x48 0x89 0xe5")
	if !ok || !p.matches([]byte{0x55, 0x48, 0x89, 0xe5, 0}) || p.matches([]byte{0x55, 0x48}) {
		t.Error("plain hex")
	}
	p, _ = parseBytePattern("0xe9........")
	if len(p) != 5 || !p.matches([]byte{0xe9, 1, 2, 3, 4}) {
		t.Error("wildcard nibbles")
	}
	p, _ = parseBytePattern("0x41 010111.. 0xc3")
	if !p.matches([]byte{0x41, 0x5f, 0xc3}) || p.matches([]byte{0x41, 0x50, 0xc3}) {
		t.Error("bit pattern")
	}
	p, _ = parseBytePattern("0x1.")
	if !p.matches([]byte{0x1f}) || p.matches([]byte{0x2f}) {
		t.Error("half-wildcard byte")
	}
	for _, bad := range []string{"0x1", "", "0xzz", "0101", "01x10101"} {
		if _, ok := parseBytePattern(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParsePatternFileAndConstraints(t *testing.T) {
	rules := parsePatternFile(`<patternlist>
	  <patternpairs totalbits="32" postbits="16">
	    <prepatterns><data>0xc3</data><data>0x90 0x90</data></prepatterns>
	    <postpatterns><data>0x55 0x48 0x89 0xe5</data><funcstart/></postpatterns>
	  </patternpairs>
	  <pattern><data>0xf3 0x0f 0x1e 0xfa</data><funcstart after="defined" validcode="5"/></pattern>
	  <pattern><data>0x90</data><funcstart after="data" validcode="function"/><align mark="0" bits="4"/></pattern>
	</patternlist>`)
	if len(rules) != 3 || len(rules[0].pre) != 2 || rules[0].actions[0] != actFuncStart {
		t.Fatalf("%+v", rules)
	}
	if !rules[1].c.afterDefined || rules[1].c.validCode != 5 {
		t.Errorf("%+v", rules[1].c)
	}
	if !rules[2].c.afterData || !rules[2].c.existingFunction || !rules[2].hasAlign || rules[2].alignBits != 4 {
		t.Errorf("%+v", rules[2])
	}
	files := patternFiles(`<patternconstraints>
	  <language id="x86:LE:64:*"><compiler id="gcc"><patternfile>gcc.xml</patternfile></compiler>
	    <compiler id="windows"><patternfile>win.xml</patternfile></compiler><patternfile>all.xml</patternfile></language>
	  <language id="ARM:LE:32:v8"><patternfile>arm.xml</patternfile></language>
	</patternconstraints>`, "x86:LE:64:default", "gcc")
	if !slices.Equal(files, []string{"gcc.xml", "all.xml"}) {
		t.Errorf("files %v", files)
	}
}

// writePatterns makes a patterns directory for x86:LE:64:default / gcc.
func writePatterns(t *testing.T, patternXML string) string {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "patternconstraints.xml"), []byte(`<patternconstraints><language id="x86:LE:64:default"><compiler id="gcc"><patternfile>p.xml</patternfile></compiler></language></patternconstraints>`), 0o644)
	os.WriteFile(filepath.Join(dir, "p.xml"), []byte(patternXML), 0o644)
	return dir
}

func patternRun(t *testing.T, xml string, mark func(*loader.Program), d fake) *Analysis {
	t.Helper()
	p := newProg(0x1000, 0x400, seeds(0x1000))
	mark(p)
	lang := testLang()
	lang.PatternsDir = writePatterns(t, xml)
	return Analyze(p, lang, d, Options{Patterns: true})
}

// 5. Each rule applies its own validcode to its own match. The Rust version
// took the maximum over all rules, so a validcode="5" rule elsewhere in the
// file made a validcode="1" match fail.
func TestPatternUsesItsOwnValidCode(t *testing.T) {
	xml := `<patternlist>
	  <pattern><data>0x55</data><funcstart validcode="1"/></pattern>
	  <pattern><data>0xaa</data><funcstart validcode="5"/></pattern>
	</patternlist>`
	mark := func(p *loader.Program) {
		p.Memory.Write(0x1100, []byte{0x55}) // rule A: one decodable instruction is enough
		p.Memory.Write(0x1200, []byte{0xaa}) // rule B: five are needed, the second does not decode
	}
	d := fake{}.add(ins(0x1000, 1, "RET", ret), ins(0x1100, 1, "PUSH", fall), ins(0x1200, 1, "PUSH", fall))
	a := patternRun(t, xml, mark, d)
	wantFuncs(t, a, 0x1000, 0x1100)
	if a.Functions[0x1100].Source != SourcePattern {
		t.Errorf("source %v", a.Functions[0x1100].Source)
	}
	// with enough code behind it, rule B's match is accepted too
	d = d.add(ins(0x1201, 1, "NOP", fall), ins(0x1202, 1, "NOP", fall), ins(0x1203, 1, "NOP", fall), ins(0x1204, 1, "RET", ret))
	wantFuncs(t, patternRun(t, xml, mark, d), 0x1000, 0x1100, 0x1200)
}

func TestPatternConstraints(t *testing.T) {
	xml := `<patternlist>
	  <pattern><data>0x55</data><funcstart after="defined"/></pattern>
	  <pattern><data>0x56</data><funcstart after="data"/></pattern>
	  <pattern><data>0x57</data><funcstart validcode="function"/></pattern>
	  <pattern><data>0x58</data><codeboundary/><align mark="0" bits="4"/></pattern>
	  <patternpairs><prepatterns><data>0xc3</data></prepatterns><postpatterns><data>0x59</data><funcstart/></postpatterns></patternpairs>
	</patternlist>`
	mark := func(p *loader.Program) {
		p.Memory.Write(0x1100, []byte{0xc3, 0x59}) // pre-pattern 0xc3 then the post pattern at 0x1101
		p.Memory.Write(0x1101, []byte{0x59})
		p.Memory.Write(0x1110, []byte{0x55}) // after="defined": byte before is undefined
		p.Memory.Write(0x1120, []byte{0x56}) // after="data" is a known gap: never matches past the block start
		p.Memory.Write(0x1130, []byte{0x57}) // validcode="function" never discovers a function
		p.Memory.Write(0x1141, []byte{0x58}) // misaligned code boundary
		p.Memory.Write(0x1140, []byte{0x58}) // aligned code boundary
	}
	d := fake{}.add(ins(0x1000, 1, "RET", ret), ins(0x1101, 1, "NOP", fall), ins(0x1102, 1, "RET", ret),
		ins(0x1110, 1, "RET", ret), ins(0x1120, 1, "RET", ret), ins(0x1130, 1, "RET", ret),
		ins(0x1140, 1, "RET", ret), ins(0x1141, 1, "RET", ret))
	a := patternRun(t, xml, mark, d)
	wantFuncs(t, a, 0x1000, 0x1101)
	if a.Insns[0x1140] == nil || a.Insns[0x1141] != nil {
		t.Error("code boundary: only the aligned one starts code")
	}
}
