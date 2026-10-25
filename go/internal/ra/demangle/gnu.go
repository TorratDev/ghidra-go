package demangle

// GNU / Itanium demangling: GnuDemangler + GnuDemanglerParser (Ghidra
// 12.1.4). Ghidra runs the bundled binutils demangler and parses its text
// output. The library renders the same libiberty text; the parser below ports
// the parts of GnuDemanglerParser that decide the applied name and namespace
// (the data-type and parameter parsing that only feeds signatures is not
// ported).

import (
	_ "embed"
	"regexp"
	"strings"
	"sync"

	lib "github.com/ianlancetaylor/demangle"
)

// replacements.txt is a copy of Ghidra/Features/GnuDemangler/data/
// default.gnu.demangler.replacements.txt (go:embed cannot reach outside the
// module).
//
//go:embed replacements.txt
var replacementsFile string

// obj is the intermediate parse result (Ghidra DemangledObject).
type obj struct {
	name       string // sanitized leaf name
	namespace  []string
	isFunction bool
	// params is the raw parameter text when this is a function; it is part of
	// the name when the object is used as a namespace.
	params *string
	// lambda objects (DemangledLambda) leave their parameters out of the
	// namespace name.
	lambda bool
}

// asNamespace is createNamespaceDemangledType / getNamespaceName: functions
// contribute name(params).
func (o *obj) asNamespace() []string {
	leaf := o.name
	if o.params != nil && !o.lambda {
		leaf += "(" + renderParams(*o.params) + ")"
	}
	return append(append([]string(nil), o.namespace...), condense(leaf, true))
}

// renderParams approximates DemangledFunction.getParameterString: top-level
// comma-separated parameters, trimmed.
func renderParams(p string) string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(p); i++ {
		switch p[i] {
		case '<', '(', '[':
			depth++
		case '>', ')', ']':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(p[start:i]))
				start = i + 1
			}
		}
	}
	if last := strings.TrimSpace(p[start:]); last != "" {
		parts = append(parts, last)
	}
	return strings.Join(parts, ",")
}

type replacement struct{ find, replace string }

var (
	reDescriptivePrefix = regexp.MustCompile(`^((.+ )(for|to) )(.+)$`)
	reGlobalCtorDtor    = regexp.MustCompile(`^(global (constructors|destructors) keyed to )(.+)$`)
	reArrayData         = regexp.MustCompile(`^(.+)\{(.+)\[\d*\]\{.*\}\}$`)
	reConversion        = regexp.MustCompile(`^(.*operator) (.*)\(\).*$`)
	reNewDelete         = regexp.MustCompile(`^(.*operator) (new|delete)(\[\])?\((.*)\).*$`)
	reLambda            = regexp.MustCompile(`^.*(\{lambda\((.*)\)(#\d+)\})(.*)$`)
	reRustLegacySuffix  = regexp.MustCompile(`^(.*)::h[0-9a-f]{16}$`)
	reOverload          = sync.OnceValue(func() *regexp.Regexp {
		ops := []string{"++", "--", ">>=", "<<=", "->*", "->", "==", "!=", ">=", "<=", "&&", "||", ">>", "<<",
			"+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "+", "-", "*", "/", "%", "~", "^", "&",
			"|", "!", "<", ">", "=", ",", "()"}
		alt := make([]string, 0, len(ops)+1)
		for _, o := range ops {
			alt = append(alt, regexp.QuoteMeta(o))
		}
		alt = append(alt, `""\s_.+`) // user defined literal
		return regexp.MustCompile(`^(.*operator(` + strings.Join(alt, "|") + `)\s*(<.+>){0,1})\s*(\(.*\))(.*)$`)
	})
	replacements = sync.OnceValue(loadReplacements)
)

// loadReplacements is loadStandardReplacements / parseReplacement /
// createAlternateReplacement.
func loadReplacements() []replacement {
	var out []replacement
	for _, line := range strings.Split(replacementsFile, "\n") {
		if strings.HasPrefix(line, "//") || strings.TrimSpace(line) == "" {
			continue
		}
		line = strings.TrimSpace(line)
		i := strings.IndexAny(line, " \t\r\f\v")
		if i < 0 {
			continue
		}
		repl := strings.TrimSpace(line[:i])
		if repl == `""` {
			repl = ""
		}
		find := strings.TrimSpace(line[i:])
		out = append(out, replacement{find, repl})
		if strings.HasPrefix(find, "std::") && strings.HasPrefix(repl, "std::") {
			for _, alt := range []string{"std::__cxx11::", "__gnu_cxx::"} {
				out = append(out, replacement{strings.Replace(find, "std::", alt, 1), strings.Replace(repl, "std::", alt, 1)})
			}
		}
	}
	return out
}

var addressTablePrefixes = []string{
	"construction vtable for ", "VTT for ", "vtable for ", "typeinfo fn for ", "typeinfo for ",
}

const (
	typeinfoNameFor = "typeinfo name for "
	tlsInitFor      = "TLS init function for "
)

// DemangleGnu is GnuDemangler.demangleInternal with default options
// (demangleOnlyKnownPatterns = true, standard replacements), as used by
// DemanglerUtil.
func DemangleGnu(mangled string) *Demangled { return DemangleGnuOpts(mangled, true) }

// DemangleGnuOpts is GnuDemangler.demangleInternal; GnuDemanglerAnalyzer runs
// with onlyKnownPatterns = false, passing every symbol to the demangler.
func DemangleGnuOpts(mangled string, onlyKnownPatterns bool) *Demangled {
	if skip(mangled, onlyKnownPatterns) {
		return nil
	}
	original, m := mangled, mangled
	globalPrefix := ""
	if strings.HasPrefix(m, "_GLOBAL_") {
		if i := strings.Index(m, "_Z"); i > 0 {
			globalPrefix, m = m[:i], m[i:]
		}
	} else if strings.HasPrefix(m, "__Z") {
		m = m[1:]
	}
	m = strings.TrimPrefix(m, "DW.ref.")
	text, ok := LibibertyText(m)
	if !ok {
		return nil
	}
	text = strings.TrimSpace(text)
	if text == "" || text == m {
		return nil
	}
	if onlyKnownPatterns && invalidDoubleUnderscore(original, text) {
		return nil
	}
	o := parse(original, text)
	if o == nil {
		return nil
	}
	if globalPrefix != "" {
		// 12.1.4 keeps the raw global prefix (newer versions translate it).
		o = &obj{name: sanitizeName(globalPrefix + o.name), namespace: o.namespace, isFunction: true, params: o.params}
	}
	return &Demangled{Scheme: Gnu, Namespace: o.namespace, Name: o.name, IsFunction: o.isFunction, Full: text}
}

// LibibertyText is the demangled text in binutils' format, which is what
// Ghidra parses. Rust symbols go through the library's Rust decoders, as
// binutils' rust-demangle does.
func LibibertyText(m string) (string, bool) {
	s, err := lib.ToString(m)
	return s, err == nil
}

// skip is GnuDemangler.skip.
func skip(m string, onlyKnownPatterns bool) bool {
	if i := strings.Index(m, "@"); i > 0 || strings.HasPrefix(m, "___") {
		return true
	}
	if !onlyKnownPatterns {
		return false
	}
	if strings.HasPrefix(m, "_GLOBAL_") && strings.Index(m, "_Z") > 0 {
		return false
	}
	return !(strings.HasPrefix(m, "_Z") || strings.HasPrefix(m, "__Z") || strings.HasPrefix(m, "h__") ||
		strings.HasPrefix(m, "?") || isGnu2Or3Pattern(m))
}

func isGnu2Or3Pattern(m string) bool {
	for _, p := range []string{"_GLOBAL_.I.", "_GLOBAL_.D.", "_GLOBAL__I__Z", "_GLOBAL__D__Z"} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

// invalidDoubleUnderscore is isInvalidDoubleUnderscoreString.
func invalidDoubleUnderscore(mangled, demangled string) bool {
	i := strings.Index(mangled, "__")
	return i >= 0 && strings.Contains(demangled, mangled[:i])
}

// parse is GnuDemanglerParser.parse(mangled, demangled, simplify = true).
func parse(mangled, demangled string) *obj {
	d := demangled
	if c := reRustLegacySuffix.FindStringSubmatch(d); c != nil {
		d = c[1]
	}
	for _, r := range replacements() {
		if r.find != "" {
			d = strings.ReplaceAll(d, r.find, r.replace)
		}
	}
	if o, ok := specialPrefix(d); ok {
		return o
	}
	if o, ok := operator(d); ok {
		return o
	}
	if strings.HasPrefix(mangled, "_ZZ") || strings.HasPrefix(mangled, "__ZZ") {
		parsed := parseFunctionOrVariable(d)
		if parsed == nil {
			return nil
		}
		if item := parseItemInNamespace(d); item != nil {
			return item
		}
		return parsed
	}
	return parseFunctionOrVariable(d)
}

// specialPrefix is getSpecialPrefixHandler; ok reports whether a handler
// applied (its result may still be nil when parsing fails).
func specialPrefix(d string) (*obj, bool) {
	c := reDescriptivePrefix.FindStringSubmatch(d)
	if c == nil {
		return nil, false
	}
	prefix, typ := c[1], c[4]
	if strings.Contains(prefix, "thunk") {
		// DemangledThunk wraps the function it thunks to.
		return parseFunctionOrVariable(typ), true
	}
	for _, p := range addressTablePrefixes {
		if prefix == p {
			ns := parseFunctionOrVariable(typ)
			if ns == nil {
				return nil, true
			}
			trimmed := strings.TrimSpace(prefix)
			pos := strings.LastIndexByte(trimmed, ' ')
			if pos < 0 {
				pos = len(trimmed)
			}
			return &obj{name: sanitizeName(strings.ReplaceAll(prefix[:pos], " ", "-")), namespace: ns.asNamespace()}, true
		}
	}
	if strings.HasPrefix(prefix, typeinfoNameFor) {
		classname := strings.TrimSpace(d[len(typeinfoNameFor):])
		var ns []string
		for _, n := range symbolPath(condense(classname, true)) {
			ns = append(ns, nsElem(n))
		}
		return &obj{name: "typeinfo-name", namespace: ns}, true
	}
	if strings.HasPrefix(prefix, tlsInitFor) {
		ns := parseFunctionOrVariable(typ)
		if ns == nil {
			return nil, true
		}
		return &obj{name: "__tls_init", namespace: ns.asNamespace(), isFunction: true}, true
	}
	if a := reArrayData.FindStringSubmatch(typ); a != nil {
		if parseFunctionOrVariable(typ) == nil {
			return nil, true
		}
		return parseItemInNamespace(a[1]), true
	}
	if g := reGlobalCtorDtor.FindStringSubmatch(d); g != nil {
		f := g[3]
		if !strings.Contains(f, "(") {
			f += "()"
		}
		o := parseFunctionOrVariable(f)
		if o == nil {
			return nil, true
		}
		gp := strings.Join(strings.Fields(g[1]), ".") + "."
		cp := *o
		cp.name = sanitizeName(gp + o.name)
		return &cp, true
	}
	parsed := parseFunctionOrVariable(typ)
	if item := parseItemInNamespace(typ); item != nil {
		return item, true
	}
	return parsed, true
}

// operator is getOperatorHandler.
func operator(d string) (*obj, bool) {
	if c := reOverload().FindStringSubmatchIndex(d); c != nil {
		opStart, opEnd := c[4], c[5]
		leafStart := findNamespaceStart(d, len(d)-1, opStart)
		if leafStart <= opStart { // else the operator is inside a non-leaf namespace entry
			chars := d[opStart:opEnd]
			end := opEnd + len(templatesAt(d, opEnd))
			base := "operator" + d[opStart:end]
			fixed := strings.ReplaceAll(d, base, "TEMPNAMEPLACEHOLDERVALUE")
			f := parseFunctionOrVariable(fixed)
			if f == nil {
				return nil, true
			}
			cp := *f
			cp.name, cp.isFunction = sanitizeName("operator"+chars), true
			return &cp, true
		}
	}
	if c := reConversion.FindStringSubmatch(d); c != nil {
		fullName, ret := c[1], c[2]
		ret = strings.ReplaceAll(ret, " const", "")
		op := strings.LastIndex(fullName, "::operator")
		if op < 0 {
			return nil, true
		}
		path := symbolPath(stripTemplates(ret))
		short := path[len(path)-1]
		if strings.Contains(short, "(") {
			short = "function.pointer"
		}
		var ns []string
		for _, n := range symbolPath(stripTemplates(fullName[:op])) {
			ns = append(ns, nsElem(n))
		}
		empty := ""
		return &obj{name: sanitizeName("operator.cast.to." + short), namespace: ns, isFunction: true, params: &empty}, true
	}
	if c := reNewDelete.FindStringSubmatch(d); c != nil {
		name := c[2]
		if c[3] != "" {
			name += "[]"
		}
		path := symbolPath(c[1])
		var ns []string
		for _, n := range path[:len(path)-1] {
			ns = append(ns, nsElem(n))
		}
		params := c[4]
		return &obj{name: sanitizeName("operator." + name), namespace: ns, isFunction: true, params: &params}, true
	}
	return nil, false
}

// parseItemInNamespace is parseItemInNamespace; nil when there is no "::".
func parseItemInNamespace(text string) *obj {
	pos := strings.LastIndex(text, "::")
	if pos < 0 {
		return nil
	}
	parent := parseFunctionOrVariable(text[:pos])
	if parent == nil {
		return nil
	}
	item := parseFunctionOrVariable(text[pos+2:])
	if item == nil {
		return nil
	}
	cp := *item
	cp.namespace = parent.asNamespace()
	return &cp
}

func nsElem(raw string) string { return sanitizeName(condense(raw, true)) }

// parseFunctionOrVariable is parseFunctionOrVariable.
func parseFunctionOrVariable(d string) *obj {
	ps, pe, ok := locateParameters(d)
	if !ok {
		// parseVariable
		name := strings.TrimSpace(condense(d, true))
		if name == "" {
			return nil
		}
		return nameAndNamespace(name, false, nil)
	}
	rawPrefix := strings.TrimSpace(d[:ps])
	prefix := condense(rawPrefix, true)
	nameStart := max(0, strings.LastIndexByte(prefix, ' '))
	simple := strings.TrimSpace(prefix[nameStart:])
	isLambda := strings.HasSuffix(simple, "{lambda")
	if isLambda {
		if full, ok := lambdaName(d[len(rawPrefix)-len("{lambda"):]); ok {
			simple = strings.Replace(simple, "{lambda", condense(full, true), 1)
		}
	}
	if simple == "" {
		return nil
	}
	params := strings.TrimSpace(d[ps+1 : pe])
	o := nameAndNamespace(simple, true, &params)
	o.lambda = isLambda
	return o
}

// nameAndNamespace is setNameAndNamespace.
func nameAndNamespace(name string, isFunction bool, params *string) *obj {
	names := symbolPath(name)
	o := &obj{name: sanitizeName(names[len(names)-1]), isFunction: isFunction, params: params}
	for _, n := range names[:len(names)-1] {
		o.namespace = append(o.namespace, nsElem(n))
	}
	return o
}

// lambdaName is getLambdaName: the full {lambda(...)#N} text at the start of name.
func lambdaName(name string) (string, bool) {
	if !strings.HasPrefix(name, "{") {
		return "", false
	}
	// LambdaReplacedString: hide every "lambda" word but the first from the regex.
	const ph = "LAMBDAREPLACEDSTRINGREPLACEDSTRINGTEMPNAMEPLACEHOLDERVALUE"
	i := strings.Index(name, "lambda")
	modified := name
	if i >= 0 {
		modified = name[:i+len("lambda")] + strings.ReplaceAll(name[i+len("lambda"):], "lambda", ph)
	}
	c := reLambda.FindStringSubmatch(modified)
	if c == nil {
		return "", false
	}
	return strings.ReplaceAll(c[1], ph, "lambda"), true
}

// locateParameters is ParameterLocator: the outer parameter list.
func locateParameters(text string) (start, end int, ok bool) {
	end = strings.LastIndexByte(text, ')')
	if end < 0 {
		return 0, 0, false
	}
	if end+1 < len(text) && text[end+1] == ':' {
		return 0, 0, false // contained within a namespace
	}
	start = -1
	depth := 0
	for i := end - 1; i >= 0; i-- {
		c := text[i]
		if c == '(' && depth == 0 {
			start = i
			break
		} else if c == '>' || c == ')' {
			depth++
		} else if c == '<' || c == '(' {
			depth--
		}
	}
	if start < 0 {
		return 0, 0, false
	}
	tEnd := balancedEnd(text, 0, '<', '>')
	tStart := -1
	if tEnd != -1 {
		tStart = balancedStart(text, tEnd, '<', '>')
	}
	if start > tStart && start < tEnd {
		return 0, 0, false
	}
	return start, end, true
}

func balancedEnd(s string, start int, open, close byte) int {
	found, depth := false, 0
	for i := start; i < len(s); i++ {
		if s[i] == open {
			depth++
			found = true
		} else if s[i] == close {
			depth--
		}
		if found && depth == 0 {
			return i
		}
	}
	return -1
}

func balancedStart(s string, start int, open, close byte) int {
	found, depth := false, 0
	for i := min(start, len(s)-1); i >= 0; i-- {
		if s[i] == open {
			depth--
		} else if s[i] == close {
			depth++
			found = true
		}
		if found && depth == 0 {
			return i
		}
	}
	return -1
}

// templatesAt returns the template arguments directly following an operator
// (operator<< <T>).
func templatesAt(d string, start int) string {
	if !strings.HasPrefix(strings.TrimLeft(d[start:], " "), "<") {
		return ""
	}
	if e := balancedEnd(d, start, '<', '>'); e >= 0 {
		return d[start : e+1]
	}
	return ""
}

// findNamespaceStart is findNamespaceStart: the start of the leaf name,
// scanning backwards from start down to stop, or -1. The Java code mutates
// each depth only when the checks before it in the || chain are false; this
// keeps that short-circuit order.
func findNamespaceStart(text string, start, stop int) int {
	if !strings.Contains(text, "::") {
		return -1
	}
	colons, paren, tpl, brace := 0, 0, 0, 0
	nested := false
	for i := start; i >= stop; i-- {
		switch text[i] {
		case ':':
			colons++
			if colons == 2 {
				if !nested {
					return i + 2
				}
				colons = 0
			}
		case ' ':
			if !nested {
				return -1 // a space implies a return type when not nested
			}
		case '(':
			paren--
			nested = paren > 0 || tpl > 0 || brace > 0
		case ')':
			paren++
			nested = paren > 0 || tpl > 0 || brace > 0
		case '<':
			if nested = paren > 0; !nested {
				tpl--
				nested = tpl > 0 || brace > 0
			}
		case '>':
			if nested = paren > 0; !nested {
				tpl++
				nested = tpl > 0 || brace > 0
			}
		case '{':
			if nested = paren > 0 || tpl > 0; !nested {
				brace--
				nested = brace > 0
			}
		case '}':
			if nested = paren > 0 || tpl > 0; !nested {
				brace++
				nested = brace > 0
			}
		}
	}
	return -1
}

// stripTemplates is stripOffTemplates.
func stripTemplates(s string) string {
	var out strings.Builder
	depth := 0
	for _, c := range s {
		switch {
		case c == '<':
			depth++
		case c == '>':
			depth--
		case depth == 0:
			out.WriteRune(c)
		}
	}
	return out.String()
}
