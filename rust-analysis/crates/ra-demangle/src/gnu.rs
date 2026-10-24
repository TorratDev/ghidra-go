//! GNU / Itanium demangling: `GnuDemangler` + `GnuDemanglerParser` (Ghidra
//! 12.1.4).
//!
//! Ghidra runs the bundled binutils demangler and parses its text output.
//! `cpp_demangle` renders the same libiberty-compatible text; the parser
//! below ports the parts of `GnuDemanglerParser` that decide the applied
//! name and namespace (the data-type and parameter parsing that only feeds
//! function signatures is not ported).

use std::sync::OnceLock;

use regex::Regex;

use crate::util::{condense, sanitize_name, symbol_path};
use crate::{Demangled, Scheme};

const REPLACEMENTS_FILE: &str = include_str!(
    "../../../../Ghidra/Features/GnuDemangler/data/default.gnu.demangler.replacements.txt"
);

/// Intermediate parse result (Ghidra `DemangledObject`).
#[derive(Debug, Clone)]
struct Obj {
    /// Sanitized leaf name.
    name: String,
    namespace: Vec<String>,
    is_function: bool,
    /// Raw parameter text when this is a function (for use as a namespace).
    params: Option<String>,
}

impl Obj {
    /// `createNamespaceDemangledType` / `getNamespaceName`: this object as a
    /// namespace (functions contribute `name(params)`).
    fn as_namespace(&self) -> Vec<String> {
        let mut ns = self.namespace.clone();
        let leaf = match &self.params {
            Some(p) => format!("{}({})", self.name, render_params(p)),
            None => self.name.clone(),
        };
        ns.push(condense(&leaf, true));
        ns
    }
}

/// Approximates `DemangledFunction.getParameterString`: top-level
/// comma-separated parameters, condensed.
fn render_params(p: &str) -> String {
    let mut parts = vec![];
    let (mut depth, mut start) = (0i32, 0usize);
    for (i, c) in p.char_indices() {
        match c {
            '<' | '(' | '[' => depth += 1,
            '>' | ')' | ']' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(p[start..i].trim().to_string());
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = p[start..].trim();
    if !last.is_empty() {
        parts.push(last.to_string());
    }
    parts.join(",")
}

struct Re {
    descriptive_prefix: Regex,
    global_ctor_dtor: Regex,
    array_data: Regex,
    overload_operator: Regex,
    conversion_operator: Regex,
    new_delete_operator: Regex,
    lambda: Regex,
    rust_legacy_suffix: Regex,
    replacements: Vec<(String, String)>,
}

fn re() -> &'static Re {
    static RE: OnceLock<Re> = OnceLock::new();
    RE.get_or_init(|| {
        let ops = [
            "++", "--", ">>=", "<<=", "->*", "->", "==", "!=", ">=", "<=", "&&", "||", ">>", "<<",
            "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "+", "-", "*", "/", "%", "~", "^", "&",
            "|", "!", "<", ">", "=", ",", "()",
        ];
        let mut alternated: Vec<String> = ops.iter().map(|o| regex::escape(o)).collect();
        alternated.push("\"\"\\s_.+".into()); // user defined literal
        let overload = format!(
            r"^(.*operator({})\s*(<.+>){{0,1}})\s*(\(.*\))(.*)$",
            alternated.join("|")
        );
        Re {
            descriptive_prefix: Regex::new(r"^((.+ )(for|to) )(.+)$").unwrap(),
            global_ctor_dtor: Regex::new(r"^(global (constructors|destructors) keyed to )(.+)$")
                .unwrap(),
            array_data: Regex::new(r"^(.+)\{(.+)\[\d*\]\{.*\}\}$").unwrap(),
            overload_operator: Regex::new(&overload).unwrap(),
            conversion_operator: Regex::new(r"^(.*operator) (.*)\(\).*$").unwrap(),
            new_delete_operator: Regex::new(r"^(.*operator) (new|delete)(\[\])?\((.*)\).*$")
                .unwrap(),
            lambda: Regex::new(r"^.*(\{lambda\((.*)\)(#\d+)\})(.*)$").unwrap(),
            rust_legacy_suffix: Regex::new(r"^(.*)::h[0-9a-f]{16}$").unwrap(),
            replacements: load_replacements(),
        }
    })
}

/// `loadStandardReplacements` / `parseReplacement` / `createAlternateReplacement`.
fn load_replacements() -> Vec<(String, String)> {
    let mut out = vec![];
    for line in REPLACEMENTS_FILE.lines() {
        if line.starts_with("//") || line.trim().is_empty() {
            continue;
        }
        let line = line.trim();
        let Some(i) = line.find(char::is_whitespace) else {
            continue;
        };
        let mut replace = line[..i].trim().to_string();
        if replace == "\"\"" {
            replace.clear();
        }
        let find = line[i..].trim().to_string();
        let std_pair = find.starts_with("std::") && replace.starts_with("std::");
        out.push((find.clone(), replace.clone()));
        if std_pair {
            for alt in ["std::__cxx11::", "__gnu_cxx::"] {
                out.push((
                    find.replacen("std::", alt, 1),
                    replace.replacen("std::", alt, 1),
                ));
            }
        }
    }
    out
}

const ADDRESS_TABLE_PREFIXES: [&str; 5] = [
    "construction vtable for ",
    "VTT for ",
    "vtable for ",
    "typeinfo fn for ",
    "typeinfo for ",
];
const TYPEINFO_NAME_FOR: &str = "typeinfo name for ";
const TLS_INIT_FOR: &str = "TLS init function for ";

/// `GnuDemangler.demangleInternal` with default `DemanglerOptions`
/// (`demangleOnlyKnownPatterns = true`, standard replacements), as used by
/// `DemanglerUtil`.
pub fn demangle(mangled: &str) -> Option<Demangled> {
    demangle_opts(mangled, true)
}

/// `GnuDemangler.demangleInternal`; `GnuDemanglerAnalyzer` runs with
/// `only_known_patterns = false`, passing every symbol to the demangler.
pub fn demangle_opts(mangled: &str, only_known_patterns: bool) -> Option<Demangled> {
    if skip(mangled, only_known_patterns) {
        return None;
    }
    let original = mangled;
    let mut m = mangled;
    let mut global_prefix = None;
    if m.starts_with("_GLOBAL_") {
        if let Some(i) = m.find("_Z").filter(|&i| i > 0) {
            global_prefix = Some(&m[..i]);
            m = &m[i..];
        }
    } else if m.starts_with("__Z") {
        m = &m[1..];
    }
    let is_dwarf = m.starts_with("DW.ref.");
    if is_dwarf {
        m = &m["DW.ref.".len()..];
    }
    let demangled = libiberty_text(m)?;
    let demangled = demangled.trim();
    if demangled.is_empty() || demangled == m {
        return None;
    }
    if only_known_patterns && invalid_double_underscore(original, demangled) {
        return None;
    }
    let mut obj = parse(original, demangled)?;
    if let Some(prefix) = global_prefix {
        // 12.1.4 keeps the raw global prefix (newer versions translate it).
        obj = Obj {
            name: sanitize_name(&format!("{prefix}{}", obj.name)),
            is_function: true,
            ..obj
        };
    }
    Some(Demangled {
        scheme: Scheme::Gnu,
        namespace: obj.namespace,
        name: obj.name,
        is_function: obj.is_function,
        full: demangled.to_string(),
    })
}

/// Demangled text in binutils' (libiberty `cplus_demangle`) format, which is
/// what Ghidra parses. `cpp_demangle` matches it except for a few special
/// names it renders as `{vtable(..)}` / `{virtual override thunk(..)}`;
/// those are rendered here the way libiberty does.
pub fn libiberty_text(m: &str) -> Option<String> {
    // binutils decodes Rust symbols itself (rust-demangle.c): legacy
    // `_ZN...17h<hash>E` and v0 `_R...`.
    if crate::rust::is_legacy_rust(m) {
        return crate::rust::legacy(m);
    }
    if m.starts_with("_R") {
        return rustc_demangle::try_demangle(m).ok().map(|d| format!("{d}"));
    }
    // Return types are omitted: libiberty does not print them for function
    // encodings nested in local names, and the leaf name never depends on
    // the top-level one.
    let opts = cpp_demangle::DemangleOptions::new().no_return_type();
    let plain = |s: &str| {
        let d = cpp_demangle::Symbol::new(s.as_bytes())
            .ok()?
            .demangle_with_options(&opts)
            .ok()?;
        Some(libiberty_literals(&d))
    };
    let ty = |rest: &str| plain(&format!("_Z{rest}"));
    if let Some(rest) = m.strip_prefix("_ZTV") {
        return Some(format!("vtable for {}", ty(rest)?));
    }
    if let Some(rest) = m.strip_prefix("_ZTT") {
        return Some(format!("VTT for {}", ty(rest)?));
    }
    if let Some(rest) = m.strip_prefix("_ZTh") {
        return Some(format!(
            "non-virtual thunk to {}",
            ty(skip_call_offset(rest, 1)?)?
        ));
    }
    if let Some(rest) = m.strip_prefix("_ZTv") {
        return Some(format!(
            "virtual thunk to {}",
            ty(skip_call_offset(rest, 2)?)?
        ));
    }
    if let Some(rest) = m.strip_prefix("_ZTC") {
        // libiberty: "construction vtable for <base>-in-<derived>";
        // cpp_demangle prints the two types the other way round.
        let text = plain(m).or_else(|| plain(&format!("_ZTC{rest}")))?;
        let body = text.strip_prefix("construction vtable for ")?;
        let (a, b) = body.split_once("-in-")?;
        return Some(format!("construction vtable for {b}-in-{a}"));
    }
    if let Some(rest) = m.strip_prefix("_ZGR") {
        // reference temporary for a (usually local) name; seq-id optional.
        let without_seq = rest
            .strip_suffix('_')
            .map(|r| r.trim_end_matches(|c: char| c.is_ascii_digit() || c.is_ascii_uppercase()));
        let inner = ty(rest).or_else(|| without_seq.and_then(ty))?;
        return Some(format!("reference temporary #0 for {inner}"));
    }
    if let Some(rest) = m.strip_prefix("_Zli") {
        // user-defined literal operator: operator"" <id>(params)
        let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
        let len: usize = rest[..digits].parse().ok()?;
        let id = rest.get(digits..digits + len)?;
        let params = plain(&format!("_Z1x{}", &rest[digits + len..]))?;
        return Some(format!("operator\"\" {id}{}", params.strip_prefix('x')?));
    }
    if let Some(rest) = m.strip_prefix("_ZTc") {
        // two <call-offset>s, each h<n>_ or v<n>_<n>_
        let mut r = rest;
        for _ in 0..2 {
            r = match r.as_bytes().first()? {
                b'h' => skip_call_offset(&r[1..], 1)?,
                b'v' => skip_call_offset(&r[1..], 2)?,
                _ => return None,
            };
        }
        return Some(format!("covariant return thunk to {}", ty(r)?));
    }
    plain(m)
}

/// libiberty prints integer literals of builtin types with a suffix
/// (`64u`, `-1l`, `3ul`) and booleans as `true`/`false`, where
/// `cpp_demangle` prints a cast (`(unsigned int)64`).
fn libiberty_literals(s: &str) -> String {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| {
        Regex::new(
            r"\((int|unsigned int|long|unsigned long|long long|unsigned long long|bool)\)(-?\d+)",
        )
        .unwrap()
    });
    re.replace_all(s, |c: &regex::Captures| {
        let n = &c[2];
        match &c[1] {
            "int" => n.to_string(),
            "unsigned int" => format!("{n}u"),
            "long" => format!("{n}l"),
            "unsigned long" => format!("{n}ul"),
            "long long" => format!("{n}ll"),
            "unsigned long long" => format!("{n}ull"),
            _ => (if n == "0" { "false" } else { "true" }).to_string(),
        }
    })
    .into_owned()
}

/// Skips `count` `[n]<digits>_` offset numbers.
fn skip_call_offset(s: &str, count: usize) -> Option<&str> {
    let mut r = s;
    for _ in 0..count {
        r = r.strip_prefix('n').unwrap_or(r);
        let digits = r.bytes().take_while(u8::is_ascii_digit).count();
        if digits == 0 {
            return None;
        }
        r = r[digits..].strip_prefix('_')?;
    }
    Some(r)
}

/// `GnuDemangler.skip`.
fn skip(m: &str, only_known_patterns: bool) -> bool {
    if m.find('@').is_some_and(|i| i > 0) || m.starts_with("___") {
        return true;
    }
    if !only_known_patterns {
        return false;
    }
    if m.starts_with("_GLOBAL_") && m.find("_Z").is_some_and(|i| i > 0) {
        return false;
    }
    let gnu23 = [
        "_GLOBAL_.I.",
        "_GLOBAL_.D.",
        "_GLOBAL__I__Z",
        "_GLOBAL__D__Z",
    ];
    !(m.starts_with("_Z")
        || m.starts_with("__Z")
        || m.starts_with("h__")
        || m.starts_with('?')
        || gnu23.iter().any(|p| m.starts_with(p)))
}

/// `isInvalidDoubleUnderscoreString`.
fn invalid_double_underscore(mangled: &str, demangled: &str) -> bool {
    match mangled.find("__") {
        None => false,
        Some(i) => demangled.contains(&mangled[..i]),
    }
}

/// `GnuDemanglerParser.parse(mangled, demangled, simplify = true)`.
fn parse(mangled: &str, demangled: &str) -> Option<Obj> {
    let r = re();
    let mut d = demangled.to_string();
    if let Some(c) = r.rust_legacy_suffix.captures(&d) {
        d = c[1].to_string();
    }
    for (find, replace) in &r.replacements {
        if !find.is_empty() {
            d = d.replace(find.as_str(), replace);
        }
    }
    if let Some(o) = special_prefix(&d) {
        return o;
    }
    if let Some(o) = operator(&d) {
        return o;
    }
    if mangled.starts_with("_ZZ") || mangled.starts_with("__ZZ") {
        let parsed = parse_function_or_variable(&d)?;
        return Some(parse_item_in_namespace(&d).unwrap_or(parsed));
    }
    parse_function_or_variable(&d)
}

/// `getSpecialPrefixHandler`. Outer `None`: not a special prefix.
fn special_prefix(d: &str) -> Option<Option<Obj>> {
    let r = re();
    let c = r.descriptive_prefix.captures(d)?;
    let prefix = c[1].to_string();
    let ty = c[4].to_string();
    if prefix.contains("thunk") {
        // DemangledThunk wraps the function it thunks to.
        return Some(parse_function_or_variable(&ty));
    }
    if ADDRESS_TABLE_PREFIXES.contains(&prefix.as_str()) {
        let trimmed = prefix.trim();
        let pos = trimmed.rfind(' ').unwrap_or(trimmed.len());
        let name = prefix[..pos].replace(' ', "-");
        return Some(parse_function_or_variable(&ty).map(|ns| Obj {
            name: sanitize_name(&name),
            namespace: ns.as_namespace(),
            is_function: false,
            params: None,
        }));
    }
    if prefix.starts_with(TYPEINFO_NAME_FOR) {
        let classname = d[TYPEINFO_NAME_FOR.len()..].trim();
        let ns = symbol_path(&condense(classname, true))
            .iter()
            .map(|n| ns_elem(n))
            .collect();
        return Some(Some(Obj {
            name: "typeinfo-name".into(),
            namespace: ns,
            is_function: false,
            params: None,
        }));
    }
    if prefix.starts_with(TLS_INIT_FOR) {
        return Some(parse_function_or_variable(&ty).map(|ns| Obj {
            name: "__tls_init".into(),
            namespace: ns.as_namespace(),
            is_function: true,
            params: None,
        }));
    }
    if let Some(a) = r.array_data.captures(&ty) {
        let inner = a[1].to_string();
        return Some(parse_function_or_variable(&ty).and_then(|_| parse_item_in_namespace(&inner)));
    }
    if let Some(g) = r.global_ctor_dtor.captures(d) {
        let gp = g[1].to_string();
        let mut f = g[3].to_string();
        if !f.contains('(') {
            f.push_str("()");
        }
        return Some(parse_function_or_variable(&f).map(|o| Obj {
            name: sanitize_name(&format!(
                "{}{}",
                gp.split_whitespace().collect::<Vec<_>>().join(".") + ".",
                o.name
            )),
            ..o
        }));
    }
    let parsed = parse_function_or_variable(&ty);
    Some(parse_item_in_namespace(&ty).or(parsed))
}

/// `getOperatorHandler`.
fn operator(d: &str) -> Option<Option<Obj>> {
    let r = re();
    if let Some(c) = r.overload_operator.captures(d) {
        let g2 = c.get(2).unwrap();
        let leaf_start = find_namespace_start(d, d.len().saturating_sub(1), g2.start());
        if leaf_start.is_none_or(|l| l <= g2.start()) {
            let chars = g2.as_str();
            let mut end = g2.end();
            let templates = templates_at(d, end);
            end += templates.len();
            let base = format!("operator{}", &d[g2.start()..end]);
            let fixed = d.replace(&base, "TEMPNAMEPLACEHOLDERVALUE");
            return Some(parse_function_or_variable(&fixed).map(|f| Obj {
                name: sanitize_name(&format!("operator{chars}")),
                is_function: true,
                ..f
            }));
        }
    }
    if let Some(c) = r.conversion_operator.captures(d) {
        let full_name = c[1].to_string();
        let mut ret = c[2].to_string();
        if ret.contains(" const") {
            ret = ret.replace(" const", "");
        }
        let Some(op) = full_name.rfind("::operator") else {
            return Some(None);
        };
        let ns = strip_templates(&full_name[..op]);
        let path = symbol_path(&strip_templates(&ret));
        let mut short = path.last().cloned().unwrap_or_default();
        if short.contains('(') {
            short = "function.pointer".into();
        }
        return Some(Some(Obj {
            name: sanitize_name(&format!("operator.cast.to.{short}")),
            namespace: symbol_path(&ns).iter().map(|n| ns_elem(n)).collect(),
            is_function: true,
            params: Some(String::new()),
        }));
    }
    if let Some(c) = r.new_delete_operator.captures(d) {
        let op_text = c[1].to_string();
        let mut name = c[2].to_string();
        if c.get(3).is_some() {
            name.push_str("[]");
        }
        let path = symbol_path(&op_text);
        let namespace = path[..path.len() - 1].iter().map(|n| ns_elem(n)).collect();
        return Some(Some(Obj {
            name: sanitize_name(&format!("operator.{name}")),
            namespace,
            is_function: true,
            params: Some(c[4].to_string()),
        }));
    }
    None
}

/// `parseItemInNamespace`.
fn parse_item_in_namespace(text: &str) -> Option<Obj> {
    let pos = text.rfind("::")?;
    let parent = parse_function_or_variable(&text[..pos])?;
    let mut item = parse_function_or_variable(&text[pos + 2..])?;
    item.namespace = parent.as_namespace();
    Some(item)
}

fn ns_elem(raw: &str) -> String {
    sanitize_name(&condense(raw, true))
}

/// `parseFunctionOrVariable`.
fn parse_function_or_variable(d: &str) -> Option<Obj> {
    let Some((param_start, param_end)) = locate_parameters(d) else {
        // parseVariable
        let name = condense(d, true);
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        return Some(name_and_namespace(name, false, None));
    };
    let raw_prefix = d[..param_start].trim();
    let prefix = condense(raw_prefix, true);
    let name_start = prefix.rfind(' ').unwrap_or(0);
    let mut simple = prefix[name_start..].trim().to_string();
    if simple.ends_with("{lambda") {
        let lambda_start = raw_prefix.len() - "{lambda".len();
        if let Some(full) = lambda_name(&d[lambda_start..]) {
            simple = simple.replace("{lambda", &condense(&full, true));
        }
    }
    if simple.is_empty() {
        return None;
    }
    let params = d[param_start + 1..param_end].trim().to_string();
    Some(name_and_namespace(&simple, true, Some(params)))
}

/// `setNameAndNamespace`.
fn name_and_namespace(name: &str, is_function: bool, params: Option<String>) -> Obj {
    let names = symbol_path(name);
    let (leaf, ns) = names.split_last().unwrap();
    Obj {
        name: sanitize_name(leaf),
        namespace: ns.iter().map(|n| ns_elem(n)).collect(),
        is_function,
        params,
    }
}

/// `getLambdaName`: the full `{lambda(...)#N}` text at the start of `name`.
fn lambda_name(name: &str) -> Option<String> {
    if !name.starts_with('{') {
        return None;
    }
    // LambdaReplacedString: hide nested `lambda` words from the regex.
    const PH: &str = "LAMBDAREPLACEDSTRINGREPLACEDSTRINGTEMPNAMEPLACEHOLDERVALUE";
    let mut modified = String::new();
    let mut first = true;
    let mut rest = name;
    while let Some(i) = rest.find("lambda") {
        modified.push_str(&rest[..i]);
        modified.push_str(if first { "lambda" } else { PH });
        first = false;
        rest = &rest[i + "lambda".len()..];
    }
    modified.push_str(rest);
    let c = re().lambda.captures(&modified)?;
    Some(c[1].replace(PH, "lambda"))
}

/// `ParameterLocator`: (start, end) of the outer parameter list.
fn locate_parameters(text: &str) -> Option<(usize, usize)> {
    let b = text.as_bytes();
    let end = text.rfind(')')?;
    if end + 1 < b.len() && b[end + 1] == b':' {
        return None; // contained within a namespace
    }
    let mut depth = 0i32;
    let mut start = None;
    for i in (0..end).rev() {
        match b[i] {
            b'(' if depth == 0 => {
                start = Some(i);
                break;
            }
            b'>' | b')' => depth += 1,
            b'<' | b'(' => depth -= 1,
            _ => {}
        }
    }
    let start = start?;
    if let Some(t_end) = balanced_end(text, 0, b'<', b'>') {
        let t_start = balanced_start(text, t_end, b'<', b'>');
        if t_start.is_some_and(|ts| start > ts && start < t_end) {
            return None;
        }
    }
    Some((start, end))
}

fn balanced_end(s: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let mut found = false;
    let mut depth = 0i32;
    for (i, &c) in s.as_bytes().iter().enumerate().skip(start) {
        if c == open {
            depth += 1;
            found = true;
        } else if c == close {
            depth -= 1;
        }
        if found && depth == 0 {
            return Some(i);
        }
    }
    None
}

fn balanced_start(s: &str, start: usize, open: u8, close: u8) -> Option<usize> {
    let b = s.as_bytes();
    let mut found = false;
    let mut depth = 0i32;
    for i in (0..=start.min(b.len().saturating_sub(1))).rev() {
        if b[i] == open {
            depth -= 1;
        } else if b[i] == close {
            depth += 1;
            found = true;
        }
        if found && depth == 0 {
            return Some(i);
        }
    }
    None
}

/// Template arguments directly following an operator (`operator<< <T>`).
fn templates_at(d: &str, start: usize) -> &str {
    let rest = &d[start..];
    if !rest.trim_start_matches(' ').starts_with('<') {
        return "";
    }
    match balanced_end(d, start, b'<', b'>') {
        Some(e) => &d[start..=e],
        None => "",
    }
}

/// `findNamespaceStart`: start of the leaf name scanning backwards from
/// `start` to `stop`.
fn find_namespace_start(text: &str, start: usize, stop: usize) -> Option<usize> {
    if !text.contains("::") {
        return None;
    }
    let b = text.as_bytes();
    let (mut colons, mut paren, mut tpl, mut brace) = (0, 0i32, 0i32, 0i32);
    let mut nested = false;
    let mut i = start as isize;
    while i >= stop as isize {
        let c = b[i as usize];
        match c {
            b':' => {
                colons += 1;
                if colons == 2 {
                    if !nested {
                        return Some(i as usize + 2);
                    }
                    colons = 0;
                }
            }
            b' ' => {
                if !nested {
                    return None;
                }
            }
            b'(' => {
                paren -= 1;
                nested = paren > 0 || tpl > 0 || brace > 0;
            }
            b')' => {
                paren += 1;
                nested = paren > 0 || tpl > 0 || brace > 0;
            }
            b'<' => {
                tpl -= 1;
                nested = paren > 0 || tpl > 0 || brace > 0;
            }
            b'>' => {
                tpl += 1;
                nested = paren > 0 || tpl > 0 || brace > 0;
            }
            b'{' => {
                brace -= 1;
                nested = paren > 0 || tpl > 0 || brace > 0;
            }
            b'}' => {
                brace += 1;
                nested = paren > 0 || tpl > 0 || brace > 0;
            }
            _ => {}
        }
        i -= 1;
    }
    None
}

/// `stripOffTemplates`.
fn strip_templates(s: &str) -> String {
    let mut out = String::new();
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '<' => depth += 1,
            '>' => depth -= 1,
            _ if depth == 0 => out.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::demangle;

    fn nn(m: &str) -> (Option<String>, String) {
        let d = demangle(m).unwrap_or_else(|| panic!("{m} did not demangle"));
        (d.namespace_string(), d.name)
    }

    #[test]
    fn ghidra_naming_rules() {
        // Values from Ghidra 12.1.4 (compare/expected/demangle/ghidra.json.gz).
        assert_eq!(
            nn("_ZNK5Shape4nameEv"),
            (Some("Shape".into()), "name".into())
        );
        assert_eq!(
            nn("_Z5maxofIiET_RKSt6vectorIS0_SaIS0_EE.isra.0"),
            (None, "maxof<int>".into())
        );
        assert_eq!(
            nn("_ZN6CircleD0Ev"),
            (Some("Circle".into()), "~Circle".into())
        );
        assert_eq!(nn("_Znwm"), (None, "operator.new".into()));
        assert_eq!(
            nn("_ZTS5Shape"),
            (Some("Shape".into()), "typeinfo-name".into())
        );
        assert_eq!(nn("_ZTV4Rect"), (Some("Rect".into()), "vtable".into()));
        assert_eq!(
            nn("_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEED1Ev"),
            (Some("std::__cxx11::string".into()), "~string".into())
        );
        assert!(demangle("_ZTISt13runtime_error@GLIBCXX_3.4").is_none());
        assert!(demangle("main").is_none());
    }
}
