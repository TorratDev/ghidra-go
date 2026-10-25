package demangle

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// DemangleRust is RustDemangler.demangle with the AUTO format and known
// patterns only: legacy symbols use a port of RustDemanglerLegacy, v0 symbols
// use the RustDemanglerV0 port, then RustDemanglerParser splits the path.
func DemangleRust(mangled string) *Demangled {
	if !IsRustMangled(mangled) {
		return nil
	}
	text, ok := rustLegacy(mangled)
	if !ok {
		if text, ok = demangleV0(mangled); !ok {
			return nil
		}
	}
	// RustDemanglerParser.parseNext
	path := symbolPath(condense(text, false))
	leaf, ns := path[len(path)-1], path[:len(path)-1]
	d := &Demangled{Scheme: Rust, Name: sanitizeName(leaf), IsFunction: true, Full: text}
	for _, n := range ns {
		d.Namespace = append(d.Namespace, sanitizeName(condense(n, false)))
	}
	return d
}

// IsRustMangled is RustDemangler.isRustMangled.
func IsRustMangled(m string) bool {
	for _, p := range []string{"_ZN", "__ZN", "_R", "__R"} {
		if strings.HasPrefix(m, p) {
			return true
		}
	}
	return false
}

var errMalformedEscape = errors.New("malformed $u escape")

// rustLegacy is RustDemanglerLegacy.demangle. A malformed $…$ escape makes
// Java throw; here it reports false so the symbol stays undemangled.
func rustLegacy(symbol string) (string, bool) {
	var s string
	switch {
	case strings.HasPrefix(symbol, "_ZN"):
		s = symbol[3:]
	case strings.HasPrefix(symbol, "ZN"):
		s = symbol[2:]
	case strings.HasPrefix(symbol, "__ZN"):
		s = symbol[4:]
	default:
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return "", false
		}
	}
	var elements []string
	i := 0
	for i < len(s) && s[i] != 'E' {
		if s[i] < '0' || s[i] > '9' {
			return "", false
		}
		start := i
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i >= len(s) {
			return "", false
		}
		n, err := strconv.ParseInt(s[start:i], 10, 32)
		if err != nil || i+int(n) > len(s) {
			return "", false
		}
		e := s[i : i+int(n)]
		if strings.HasPrefix(e, "_$") {
			e = e[1:]
		}
		elements = append(elements, e)
		i += int(n)
	}
	if i >= len(s) || s[i] != 'E' {
		return "", false
	}
	for j, e := range elements {
		for _, r := range [][2]string{{"$SP$", "@"}, {"$BP$", "*"}, {"$RF$", "&"}, {"$LT$", "<"},
			{"$GT$", ">"}, {"$LP$", "("}, {"$RP$", ")"}, {"$C$", ","}, {"..", "::"}} {
			e = strings.ReplaceAll(e, r[0], r[1])
		}
		e, err := unescapeU(e)
		if err != nil {
			return "", false
		}
		elements[j] = e
	}
	if len(elements) > 1 && isLegacyHash(elements[len(elements)-1]) {
		elements = elements[:len(elements)-1]
	}
	return strings.Join(elements, "::"), true
}

// unescapeU mirrors the Java loop: at each '$' find the next '$' and, if the
// span starts with "$u", replace it with (char) Integer.parseInt(hex, 16),
// which truncates to 16 bits. The cursor advances one char either way.
func unescapeU(e string) (string, error) {
	for k := 0; k < len(e); k++ {
		if e[k] != '$' {
			continue
		}
		l := strings.IndexByte(e[k+1:], '$')
		if l < 0 {
			return "", errMalformedEscape
		}
		l += k + 2
		if strings.HasPrefix(e[k:l], "$u") {
			n, err := javaParseHex(e[k+2 : l-1])
			if err != nil {
				return "", err
			}
			e = e[:k] + string(rune(uint16(n))) + e[l:]
		}
	}
	return e, nil
}

// javaParseHex is Integer.parseInt(s, 16): optional sign, hex digits, int32 range.
func javaParseHex(s string) (int32, error) {
	if s == "" || s == "+" || s == "-" {
		return 0, errMalformedEscape
	}
	for _, c := range s[1:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return 0, errMalformedEscape
		}
	}
	n, err := strconv.ParseInt(s, 16, 32)
	if err != nil {
		return 0, errMalformedEscape
	}
	return int32(n), nil
}

var legacyHash = regexp.MustCompile(`^h[0-9a-f]{16}$`)

// isLegacyHash is RustDemanglerLegacy.isUID.
func isLegacyHash(s string) bool { return legacyHash.MatchString(strings.TrimSpace(s)) }
