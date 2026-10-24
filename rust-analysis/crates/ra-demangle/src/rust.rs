//! Rust demangling: `RustDemangler` (Ghidra 12.1.4).
//!
//! Legacy symbols use a port of `RustDemanglerLegacy`; v0 symbols use
//! `rustc-demangle`, whose (non-alternate) output matches Ghidra's
//! `RustDemanglerV0`. `RustDemanglerParser` then splits the path.

use crate::util::{condense, sanitize_name, symbol_path};
use crate::{Demangled, Scheme};

/// `RustDemangler.demangle` with `AUTO` format and known patterns only.
pub fn demangle(mangled: &str) -> Option<Demangled> {
    if !is_rust_mangled(mangled) {
        return None;
    }
    let text = legacy(mangled).or_else(|| v0(mangled))?;
    // RustDemanglerParser.parseNext
    let path = symbol_path(&condense(&text, false));
    let (leaf, ns) = path.split_last()?;
    Some(Demangled {
        scheme: Scheme::Rust,
        namespace: ns
            .iter()
            .map(|n| sanitize_name(&condense(n, false)))
            .collect(),
        name: sanitize_name(leaf),
        is_function: true,
        full: text,
    })
}

/// `RustDemangler.isRustMangled`.
pub fn is_rust_mangled(m: &str) -> bool {
    ["_ZN", "__ZN", "_R", "__R"]
        .iter()
        .any(|p| m.starts_with(p))
}

fn v0(m: &str) -> Option<String> {
    let m = m
        .strip_prefix('_')
        .filter(|r| r.starts_with("_R"))
        .unwrap_or(m);
    if !m.starts_with("_R") {
        return None;
    }
    let d = rustc_demangle::try_demangle(m).ok()?;
    Some(format!("{d}"))
}

/// Port of `RustDemanglerLegacy.demangle`.
pub fn legacy(symbol: &str) -> Option<String> {
    let s = symbol
        .strip_prefix("_ZN")
        .or_else(|| symbol.strip_prefix("ZN"))
        .or_else(|| symbol.strip_prefix("__ZN"))?;
    if !s.is_ascii() {
        return None;
    }
    let b = s.as_bytes();
    let mut elements: Vec<String> = vec![];
    let mut i = 0;
    while i < b.len() && b[i] != b'E' {
        if !b[i].is_ascii_digit() {
            return None;
        }
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i >= b.len() {
            return None;
        }
        let len: usize = s[start..i].parse().ok()?;
        if i + len > b.len() {
            return None;
        }
        let mut e = &s[i..i + len];
        if e.starts_with("_$") {
            e = &e[1..];
        }
        elements.push(e.to_string());
        i += len;
    }
    if i >= b.len() || b[i] != b'E' {
        return None;
    }
    for e in &mut elements {
        let mut x = e
            .replace("$SP$", "@")
            .replace("$BP$", "*")
            .replace("$RF$", "&")
            .replace("$LT$", "<")
            .replace("$GT$", ">")
            .replace("$LP$", "(")
            .replace("$RP$", ")")
            .replace("$C$", ",")
            .replace("..", "::");
        // $uXX$ escapes
        let mut k = 0;
        while let Some(rel) = x[k..].find('$') {
            let start = k + rel;
            let Some(end_rel) = x[start + 1..].find('$') else {
                break;
            };
            let end = start + 1 + end_rel + 1;
            let inner = &x[start..end];
            if let Some(hex) = inner.strip_prefix("$u").and_then(|h| h.strip_suffix('$')) {
                if let Some(ch) = u32::from_str_radix(hex, 16).ok().and_then(char::from_u32) {
                    x = format!("{}{}{}", &x[..start], ch, &x[end..]);
                    k = start + ch.len_utf8();
                    continue;
                }
            }
            k = start + 1;
        }
        *e = x;
    }
    if elements.len() > 1 && is_hash(elements.last().unwrap()) {
        elements.pop();
    }
    Some(elements.join("::"))
}

/// Legacy Rust symbol: `_ZN...17h<16 hex>E` (as binutils' `rust_is_mangled`).
pub fn is_legacy_rust(m: &str) -> bool {
    let core = m.strip_prefix("__ZN").or_else(|| m.strip_prefix("_ZN"));
    let Some(core) = core.and_then(|c| c.strip_suffix('E')) else {
        return false;
    };
    core.len() > 19 && core.ends_with(|_: char| true) && {
        let tail = &core[core.len() - 19..];
        tail.starts_with("17") && is_hash(&tail[2..])
    }
}

fn is_hash(s: &str) -> bool {
    let s = s.trim();
    s.len() == 17
        && s.starts_with('h')
        && s[1..]
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_and_v0() {
        let d = demangle("_ZN64_$LT$rustlib..shapes..Rect$u20$as$u20$rustlib..shapes..Shape$GT$4area17hdd6d4cd2f1383c34E").unwrap();
        assert_eq!(d.name, "area");
        assert_eq!(
            d.namespace_string().unwrap(),
            "<rustlib::shapes::Rect_as_rustlib::shapes::Shape>"
        );
        let d = demangle("_RNvXNtCs7W4I7ebKKSb_7rustlib6shapesNtB2_4RectNtB2_5Shape4area").unwrap();
        assert_eq!(d.name, "area");
        assert_eq!(
            d.namespace_string().unwrap(),
            "<rustlib[5c719a9850234f19]::shapes::Rect_as_rustlib[5c719a9850234f19]::shapes::Shape>"
        );
    }
}
