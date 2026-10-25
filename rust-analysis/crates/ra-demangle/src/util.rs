//! Helpers shared by the demanglers, ported from Ghidra.

/// `SymbolPathParser.parse(name, false)`: splits at `::` outside templates
/// and parentheses; if those are unbalanced, splits at every `::`.
pub fn symbol_path(name: &str) -> Vec<String> {
    if !name.contains("::") {
        return vec![name.to_string()];
    }
    let b = name.as_bytes();
    let split = |balanced: bool| {
        let mut out = vec![];
        let (mut tpl, mut paren, mut start) = (0i32, 0i32, 0usize);
        let mut i = 0;
        while i < b.len() {
            if b[i] == b':' && i + 1 < b.len() && b[i + 1] == b':' {
                if (!balanced || (tpl == 0 && paren == 0)) && i > start {
                    out.push(name[start..i].to_string());
                    start = i + 2;
                    i += 1;
                }
            } else if balanced {
                match b[i] {
                    b'<' => tpl += 1,
                    b'>' => tpl -= 1,
                    b'(' => paren += 1,
                    b')' => paren -= 1,
                    _ => {}
                }
            }
            i += 1;
        }
        out.push(name[start..].to_string());
        (out, tpl == 0 && paren == 0)
    };
    let (out, ok) = split(true);
    if ok {
        out
    } else {
        split(false).0
    }
}

/// `CondensedString`: inside `<>`/`()` a space between two alphanumerics
/// becomes `_`, other spaces are dropped.
pub fn condense(input: &str, fix_unnamed: bool) -> String {
    let fixed = if fix_unnamed {
        fixup_unnamed_types(input)
    } else {
        input.to_string()
    };
    let chars: Vec<char> = fixed.chars().collect();
    let mut out = String::with_capacity(fixed.len());
    let mut depth = 0i32;
    let mut last = '\0';
    for i in 0..chars.len() {
        let ch = chars[i];
        if ch == '<' || ch == '(' {
            depth += 1;
        } else if (ch == '>' || ch == ')') && depth != 0 {
            depth -= 1;
        }
        if depth > 0 && ch == ' ' {
            let next = chars.get(i + 1).copied().unwrap_or('\0');
            if last != '\0' && next != '\0' && last.is_alphanumeric() && next.is_alphanumeric() {
                out.push('_');
            }
        } else {
            out.push(ch);
        }
        last = ch;
    }
    out.trim().to_string()
}

/// `{unnamed type#1}` -> `{unnamed_type#1}`.
fn fixup_unnamed_types(s: &str) -> String {
    let re = regex::Regex::new(r"\{unnamed type#\d+\}").unwrap();
    re.replace_all(s, |c: &regex::Captures| c[0].replacen(' ', "_", 1))
        .into_owned()
}

/// `DemangledObject.setName`: `stripSuperfluousSignatureSpaces`, trim, and
/// spaces to `_`.
pub fn sanitize_name(name: &str) -> String {
    let lead = regex::Regex::new(r" ([*&)])").unwrap();
    let trail = regex::Regex::new(r"([(,]) ").unwrap();
    let s = lead.replace_all(name, "$1");
    let s = trail.replace_all(&s, "$1");
    s.trim().replace(' ', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_path_respects_templates() {
        assert_eq!(symbol_path("a::b<c::d>::e"), vec!["a", "b<c::d>", "e"]);
        assert_eq!(symbol_path("f(x::y)::z"), vec!["f(x::y)", "z"]);
        assert_eq!(symbol_path("plain"), vec!["plain"]);
        assert_eq!(symbol_path("a<b::c"), vec!["a<b", "c"]);
    }

    #[test]
    fn condense_and_sanitize() {
        assert_eq!(
            condense("std::vector<int, std::allocator<int> >", true),
            "std::vector<int,std::allocator<int>>"
        );
        assert_eq!(condense("foo<unsigned long>", true), "foo<unsigned_long>");
        assert_eq!(sanitize_name("operator new"), "operator_new");
        assert_eq!(sanitize_name("f(int, char *)"), "f(int,char*)");
    }
}
