//! MSVC demangling: `MicrosoftDemangler` (MDMang, Ghidra 12.1.4).
//!
//! `msvc-demangler` renders the qualified name (undname `NAME_ONLY` style
//! with `__ptr64`); the text is then adjusted to MDMang's spelling and split
//! into namespace and leaf as Ghidra's `processNamespace` does:
//! - template arguments carry no `class`/`struct`/`union`/`enum` keyword
//! - no space between a calling convention and a parameter list
//! - templated constructors/destructors are named after their class

use std::sync::OnceLock;

use msvc_demangler::{DemangleFlags, Name, Operator};
use regex::Regex;

use crate::util::sanitize_name;
use crate::{Demangled, Scheme};

pub fn demangle(mangled: &str) -> Option<Demangled> {
    if !mangled.starts_with('?') {
        return None;
    }
    let parsed = msvc_demangler::parse(mangled).ok()?;
    let is_function = matches!(
        parsed.symbol_type,
        msvc_demangler::Type::MemberFunction(..) | msvc_demangler::Type::NonMemberFunction(..)
    );
    let qualified = msvc_demangler::demangle(
        mangled,
        DemangleFlags::NAME_ONLY | DemangleFlags::WITH_PTR64,
    )
    .ok()?;
    let full = msvc_demangler::demangle(mangled, DemangleFlags::COMPLETE)
        .unwrap_or_else(|_| qualified.clone());
    let mut text = mdmang_spelling(&qualified);
    if is_64bit(mangled) {
        text = add_ptr64(&text);
    }
    let path = split_path(&text);
    let (leaf, ns) = path.split_last()?;
    let mut leaf = leaf.clone();
    // Templated ctor/dtor: undname prints `ctor<T>`; MDMang uses the class name.
    if let Name::Template(inner, _) = &parsed.symbol.name {
        if let (Name::Operator(op @ (Operator::Ctor | Operator::Dtor)), Some(class)) =
            (inner.as_ref(), ns.last())
        {
            let args = leaf.find('<').map(|i| &leaf[i..]).unwrap_or("");
            let tilde = if matches!(op, Operator::Dtor) {
                "~"
            } else {
                ""
            };
            leaf = format!("{tilde}{class}{args}");
        }
    }
    Some(Demangled {
        scheme: Scheme::Msvc,
        namespace: ns.iter().map(|n| sanitize_name(n)).collect(),
        name: sanitize_name(&leaf),
        is_function,
        full,
    })
}

/// 64-bit mangled names mark pointers/references with the `E` (`__ptr64`)
/// modifier, which MDMang prints and `msvc-demangler` omits.
fn is_64bit(m: &str) -> bool {
    [
        "PEA", "PEB", "PEC", "PED", "QEA", "QEB", "AEA", "AEB", "$$QEA", "$$QEB",
    ]
    .iter()
    .any(|p| m.contains(p))
}

/// Adds ` __ptr64` after data pointer/reference declarators (not function
/// pointer declarators `(__cdecl *)` and not `&&`).
fn add_ptr64(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len() + 16);
    for (i, c) in s.char_indices() {
        out.push(c);
        let next = b.get(i + 1).copied();
        let prev_is_cc = s[..i].trim_end().ends_with("__cdecl")
            || s[..i].trim_end().ends_with("__stdcall")
            || s[..i].trim_end().ends_with("__thiscall")
            || s[..i].trim_end().ends_with("__fastcall");
        if (c == '*' || c == '&')
            && next != Some(b'&')
            && !(i > 0 && b[i - 1] == b'&')
            && !prev_is_cc
            && !s[..i].ends_with("operator")
        {
            out.push_str(" __ptr64");
        }
    }
    out
}

fn mdmang_spelling(s: &str) -> String {
    static RE: OnceLock<(Regex, Regex, Regex)> = OnceLock::new();
    let (kw, cc, cv) = RE.get_or_init(|| {
        (
            Regex::new(r"\b(class|struct|union|enum) ").unwrap(),
            Regex::new(
                r"(__cdecl|__stdcall|__thiscall|__fastcall|__clrcall|__vectorcall|__pascal) \(",
            )
            .unwrap(),
            // msvc-demangler drops the space in `T const*` after a name
            Regex::new(r"([A-Za-z0-9_>])(const|volatile)([*&])").unwrap(),
        )
    });
    let s = kw.replace_all(s, "");
    let s = cc.replace_all(&s, "$1(");
    cv.replace_all(&s, "$1 $2$3").into_owned()
}

/// Overloadable operator spellings, longest first.
const OPERATOR_TOKENS: [&str; 40] = [
    "()", "[]", "->*", "->", "<<=", ">>=", "<<", ">>", "<=", ">=", "==", "!=", "&&", "||", "++",
    "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<", ">", "=", "!", "+", "-", "*", "/",
    "%", "^", "&", "|", "~", ",", " new", " delete",
];

/// Splits at top-level `::`; operator tokens (`operator<=`, `operator>>`)
/// do not count as template brackets.
fn split_path(s: &str) -> Vec<String> {
    let b = s.as_bytes();
    let mut out = vec![];
    let (mut depth, mut paren, mut start, mut i) = (0i32, 0i32, 0usize, 0usize);
    while i < b.len() {
        if s[i..].starts_with("operator") {
            i += "operator".len();
            if let Some(tok) = OPERATOR_TOKENS.iter().find(|t| s[i..].starts_with(*t)) {
                i += tok.len();
            }
            continue;
        }
        match b[i] {
            b'<' => depth += 1,
            b'>' => depth -= 1,
            b'(' => paren += 1,
            b')' => paren -= 1,
            b'`' => {
                // `vftable'-style quoted names may contain anything
                if let Some(e) = s[i + 1..].find('\'') {
                    i += e + 2;
                    continue;
                }
            }
            b':' if depth == 0 && paren == 0 && b.get(i + 1) == Some(&b':') => {
                if i > start {
                    out.push(s[start..i].to_string());
                }
                start = i + 2;
                i += 2;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    out.push(s[start..].to_string());
    out
}

#[cfg(test)]
mod tests {
    use super::{demangle, split_path};

    #[test]
    fn ctor_vftable_operator() {
        let d = demangle("??0Rect@geo@@QEAA@HH@Z").unwrap();
        assert_eq!(
            (
                d.namespace_string().as_deref(),
                d.name.as_str(),
                d.is_function
            ),
            (Some("geo::Rect"), "Rect", true)
        );
        let d = demangle("??_7Rect@geo@@6B@").unwrap();
        assert_eq!(
            (d.namespace_string().as_deref(), d.name.as_str()),
            (Some("geo::Rect"), "`vftable'")
        );
        let d = demangle("??8Rect@geo@@QEBA_NAEBU01@@Z").unwrap();
        assert_eq!(d.name, "operator==");
    }

    #[test]
    fn operator_aware_split() {
        assert_eq!(
            split_path("std::operator<=<char,std::traits<char> >"),
            vec!["std", "operator<=<char,std::traits<char> >"]
        );
        assert_eq!(split_path("a::b<c::d>::e"), vec!["a", "b<c::d>", "e"]);
    }
}
