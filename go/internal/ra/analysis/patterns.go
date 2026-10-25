package analysis

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Function start byte patterns (Ghidra FunctionStartAnalyzer, pattern files
// Ghidra/Processors/*/data/patterns/*.xml).

// bytePattern is a mask and a value per byte.
type bytePattern []struct{ mask, val byte }

// parseBytePattern parses Ghidra's pattern syntax: whitespace separated
// tokens, each either 0x followed by hex nibbles ('.' is a wildcard nibble) or
// a string of bits ('.' is a wildcard bit), 8 bits per byte.
func parseBytePattern(text string) (bytePattern, bool) {
	var out bytePattern
	for _, tok := range strings.Fields(text) {
		if hex, ok := strings.CutPrefix(strings.Replace(tok, "0X", "0x", 1), "0x"); ok {
			if len(hex)%2 != 0 {
				return nil, false
			}
			for i := 0; i < len(hex); i += 2 {
				var mask, val byte
				for _, c := range hex[i : i+2] {
					mask, val = mask<<4, val<<4
					if c != '.' {
						n, err := strconv.ParseUint(string(c), 16, 8)
						if err != nil {
							return nil, false
						}
						mask |= 0xf
						val |= byte(n)
					}
				}
				out = append(out, struct{ mask, val byte }{mask, val})
			}
			continue
		}
		if len(tok)%8 != 0 {
			return nil, false
		}
		for i := 0; i < len(tok); i += 8 {
			var mask, val byte
			for _, c := range tok[i : i+8] {
				mask, val = mask<<1, val<<1
				switch c {
				case '0':
					mask |= 1
				case '1':
					mask |= 1
					val |= 1
				case '.':
				default:
					return nil, false
				}
			}
			out = append(out, struct{ mask, val byte }{mask, val})
		}
	}
	return out, len(out) > 0
}

func (p bytePattern) matches(b []byte) bool {
	if len(b) < len(p) {
		return false
	}
	for i, e := range p {
		if b[i]&e.mask != e.val {
			return false
		}
	}
	return true
}

type patternAction int

const (
	actFuncStart patternAction = iota
	actPossibleFuncStart
	actCodeBoundary
)

type constraints struct {
	// afterDefined: after="defined", the preceding byte must be defined.
	afterDefined bool
	// validCode: validcode="N", N instructions must decode by straight-line flow.
	validCode uint32
	// existingFunction: validcode="function", the rule only applies at an
	// existing function (it labels or marks functions, it never discovers one).
	existingFunction bool
	// afterData: after="data". Known gap: needs defined data before the match,
	// and the analysis defines no data, so such a rule only matches at the
	// start of a block. Not measured against Ghidra.
	afterData bool
}

type patternRule struct {
	pre, post []bytePattern
	actions   []patternAction
	c         constraints
	// align: <align mark bits>, the address low `bits` bits must equal mark.
	hasAlign  bool
	alignMark uint64
	alignBits uint32
}

type patternSet struct{ rules []patternRule }

// loadPatternSet loads the pattern files patternconstraints.xml assigns to
// langID and compiler from dir (a processor's data/patterns directory).
func loadPatternSet(dir, langID, compiler string) patternSet {
	var set patternSet
	if dir == "" {
		return set
	}
	cons, err := os.ReadFile(filepath.Join(dir, "patternconstraints.xml"))
	if err != nil {
		return set
	}
	for _, f := range patternFiles(string(cons), langID, compiler) {
		if text, err := os.ReadFile(filepath.Join(dir, f)); err == nil {
			set.rules = append(set.rules, parsePatternFile(string(text))...)
		}
	}
	return set
}

func langMatches(pattern, id string) bool {
	p, i := strings.Split(pattern, ":"), strings.Split(id, ":")
	if len(p) != len(i) {
		return false
	}
	for k := range p {
		if p[k] != "*" && p[k] != i[k] {
			return false
		}
	}
	return true
}

func attr(e xml.StartElement, name string) (string, bool) {
	for _, a := range e.Attr {
		if a.Name.Local == name {
			return a.Value, true
		}
	}
	return "", false
}

// patternFiles lists the pattern file names for a language and compiler.
// Files listed directly under <language> apply to every compiler.
func patternFiles(xmlText, langID, compiler string) []string {
	d := xml.NewDecoder(strings.NewReader(xmlText))
	var out []string
	inLang, compilerOK, inFile := false, true, false
	for {
		tok, err := d.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "language":
				id, ok := attr(t, "id")
				inLang = ok && langMatches(id, langID)
			case "compiler":
				id, ok := attr(t, "id")
				compilerOK = ok && id == compiler
			case "patternfile":
				inFile = true
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "language":
				inLang = false
			case "compiler":
				compilerOK = true
			case "patternfile":
				inFile = false
			}
		case xml.CharData:
			if inFile && inLang && compilerOK {
				name := strings.TrimSpace(string(t))
				if name != "" && !contains(out, name) {
					out = append(out, name)
				}
			}
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func parsePatternFile(xmlText string) []patternRule {
	const (
		secNone = iota
		secPre
		secPost
		secSingle
	)
	d := xml.NewDecoder(strings.NewReader(xmlText))
	var rules []patternRule
	sec := secNone
	var cur *patternRule
	inData := false
	var data strings.Builder

	tag := func(e xml.StartElement) {
		if cur == nil {
			return
		}
		var act patternAction
		switch e.Name.Local {
		case "funcstart":
			act = actFuncStart
		case "possiblefuncstart":
			act = actPossibleFuncStart
		case "codeboundary":
			act = actCodeBoundary
		case "align":
			m, _ := attr(e, "mark")
			b, _ := attr(e, "bits")
			mark, _ := strconv.ParseUint(m, 10, 64)
			bits, _ := strconv.ParseUint(b, 10, 32)
			cur.hasAlign, cur.alignMark, cur.alignBits = true, mark, uint32(bits)
			return
		default:
			return
		}
		if a, _ := attr(e, "after"); a == "defined" {
			cur.c.afterDefined = true
		} else if a == "data" {
			cur.c.afterData = true
		}
		if v, ok := attr(e, "validcode"); ok {
			if v == "function" {
				cur.c.existingFunction = true
			} else if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				cur.c.validCode = uint32(n)
			}
		}
		cur.actions = append(cur.actions, act)
	}

	for {
		tok, err := d.Token()
		if err != nil {
			return rules
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "patternpairs":
				cur = &patternRule{}
			case "pattern":
				cur = &patternRule{}
				sec = secSingle
			case "prepatterns":
				sec = secPre
			case "postpatterns":
				sec = secPost
			case "data":
				inData = true
				data.Reset()
			default:
				tag(t)
			}
			// self-closing elements arrive as Start immediately followed by End
		case xml.CharData:
			if inData {
				data.Write(t)
			}
		case xml.EndElement:
			switch t.Name.Local {
			case "data":
				inData = false
				if p, ok := parseBytePattern(data.String()); ok && cur != nil {
					switch sec {
					case secPre:
						cur.pre = append(cur.pre, p)
					case secPost, secSingle:
						cur.post = append(cur.post, p)
					}
				}
			case "patternpairs", "pattern":
				if cur != nil && len(cur.post) > 0 && len(cur.actions) > 0 {
					rules = append(rules, *cur)
				}
				cur = nil
				sec = secNone
			case "prepatterns", "postpatterns":
				if cur != nil {
					sec = secNone
				}
			}
		}
	}
}
