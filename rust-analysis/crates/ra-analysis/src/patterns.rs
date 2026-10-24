//! Function start byte patterns (Ghidra `FunctionStartAnalyzer`, pattern files
//! `Ghidra/Processors/*/data/patterns/*.xml`).

use std::path::{Path, PathBuf};

use quick_xml::{events::Event, Reader};

/// One byte pattern: `(mask, value)` per byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BytePattern(pub Vec<(u8, u8)>);

impl BytePattern {
    /// Parses Ghidra's pattern syntax: whitespace separated tokens, each
    /// either `0x` followed by hex nibbles (`.` = wildcard nibble) or a
    /// string of bits (`.` = wildcard bit), 8 bits per byte.
    pub fn parse(text: &str) -> Option<Self> {
        let mut bytes = vec![];
        for tok in text.split_whitespace() {
            if let Some(hex) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
                if hex.len() % 2 != 0 {
                    return None;
                }
                let chars: Vec<char> = hex.chars().collect();
                for pair in chars.chunks(2) {
                    let mut mask = 0u8;
                    let mut val = 0u8;
                    for c in pair {
                        mask <<= 4;
                        val <<= 4;
                        if *c != '.' {
                            mask |= 0xf;
                            val |= c.to_digit(16)? as u8;
                        }
                    }
                    bytes.push((mask, val));
                }
            } else {
                if tok.len() % 8 != 0 {
                    return None;
                }
                let chars: Vec<char> = tok.chars().collect();
                for byte in chars.chunks(8) {
                    let mut mask = 0u8;
                    let mut val = 0u8;
                    for c in byte {
                        mask <<= 1;
                        val <<= 1;
                        match c {
                            '0' => mask |= 1,
                            '1' => {
                                mask |= 1;
                                val |= 1
                            }
                            '.' => {}
                            _ => return None,
                        }
                    }
                    bytes.push((mask, val));
                }
            }
        }
        (!bytes.is_empty()).then_some(Self(bytes))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes.len() >= self.0.len() && self.0.iter().zip(bytes).all(|((m, v), b)| b & m == *v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    FuncStart,
    PossibleFuncStart,
    CodeBoundary,
}

#[derive(Debug, Clone, Default)]
pub struct Constraints {
    /// `after="defined"`: the preceding byte must be defined (code or the
    /// start of a block).
    pub after_defined: bool,
    /// `validcode="N"`: N instructions must decode by straight-line flow.
    pub valid_code: u32,
    /// `validcode="function"`: only applies at an existing function (it
    /// labels or marks functions, it never discovers them).
    pub existing_function: bool,
    /// `after="data"`: defined data (or no memory) must precede the match.
    pub after_data: bool,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub pre: Vec<BytePattern>,
    pub post: Vec<BytePattern>,
    pub actions: Vec<Action>,
    pub constraints: Constraints,
    /// `<align mark=".." bits=".."/>`: address low `bits` bits must equal `mark`.
    pub align: Option<(u64, u32)>,
}

#[derive(Debug, Clone, Default)]
pub struct PatternSet {
    pub rules: Vec<Rule>,
}

impl PatternSet {
    /// Loads the pattern files that `patternconstraints.xml` assigns to
    /// `lang_id` / `compiler` in the processor owning `ldefs`.
    pub fn for_language(ldefs: &Path, lang_id: &str, compiler: &str) -> Self {
        let Some(dir) = ldefs
            .parent()
            .and_then(Path::parent)
            .map(|d| d.join("patterns"))
        else {
            return Self::default();
        };
        let Ok(constraints) = std::fs::read_to_string(dir.join("patternconstraints.xml")) else {
            return Self::default();
        };
        let mut set = Self::default();
        for file in pattern_files(&constraints, lang_id, compiler) {
            if let Ok(text) = std::fs::read_to_string(dir.join(&file)) {
                set.rules.extend(parse_pattern_file(&text));
            }
        }
        set
    }
}

fn lang_matches(pattern: &str, id: &str) -> bool {
    let p: Vec<&str> = pattern.split(':').collect();
    let i: Vec<&str> = id.split(':').collect();
    p.len() == i.len() && p.iter().zip(&i).all(|(a, b)| *a == "*" || a == b)
}

fn attr(e: &quick_xml::events::BytesStart, name: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == name.as_bytes())
        .and_then(|a| a.unescape_value().ok().map(|v| v.into_owned()))
}

/// Pattern file names for a language/compiler from `patternconstraints.xml`.
/// Files listed directly under `<language>` apply to every compiler.
pub fn pattern_files(xml: &str, lang_id: &str, compiler: &str) -> Vec<PathBuf> {
    let mut r = Reader::from_str(xml);
    let mut out = vec![];
    let mut in_lang = false;
    let mut compiler_ok = true;
    let mut in_file = false;
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"language" => {
                    in_lang = attr(&e, "id").is_some_and(|id| lang_matches(&id, lang_id))
                }
                b"compiler" => compiler_ok = attr(&e, "id").is_some_and(|c| c == compiler),
                b"patternfile" => in_file = true,
                _ => {}
            },
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"language" => in_lang = false,
                b"compiler" => compiler_ok = true,
                b"patternfile" => in_file = false,
                _ => {}
            },
            Ok(Event::Text(t)) if in_file && in_lang && compiler_ok => {
                if let Ok(name) = t.unescape() {
                    let name = name.trim();
                    if !name.is_empty() && !out.iter().any(|p: &PathBuf| p == Path::new(name)) {
                        out.push(PathBuf::from(name));
                    }
                }
            }
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    out
}

pub fn parse_pattern_file(xml: &str) -> Vec<Rule> {
    #[derive(PartialEq)]
    enum Sec {
        None,
        Pre,
        Post,
        Single,
    }
    let mut r = Reader::from_str(xml);
    let mut rules = vec![];
    let mut sec = Sec::None;
    let mut cur: Option<Rule> = None;
    let mut in_data = false;
    let mut data_text = String::new();
    let new_rule = || Rule {
        pre: vec![],
        post: vec![],
        actions: vec![],
        constraints: Constraints::default(),
        align: None,
    };

    let handle_tag = |e: &quick_xml::events::BytesStart, cur: &mut Option<Rule>| {
        let Some(rule) = cur.as_mut() else { return };
        let action = match e.name().as_ref() {
            b"funcstart" => Some(Action::FuncStart),
            b"possiblefuncstart" => Some(Action::PossibleFuncStart),
            b"codeboundary" => Some(Action::CodeBoundary),
            b"align" => {
                let mark = attr(e, "mark").and_then(|m| m.parse().ok()).unwrap_or(0);
                let bits = attr(e, "bits").and_then(|m| m.parse().ok()).unwrap_or(0);
                rule.align = Some((mark, bits));
                None
            }
            _ => None,
        };
        if let Some(a) = action {
            match attr(e, "after").as_deref() {
                Some("defined") => rule.constraints.after_defined = true,
                Some("data") => rule.constraints.after_data = true,
                _ => {}
            }
            match attr(e, "validcode") {
                Some(v) if v == "function" => rule.constraints.existing_function = true,
                Some(v) => {
                    if let Ok(n) = v.parse() {
                        rule.constraints.valid_code = n;
                    }
                }
                None => {}
            }
            rule.actions.push(a);
        }
    };

    loop {
        match r.read_event() {
            Ok(Event::Start(e)) => match e.name().as_ref() {
                b"patternpairs" => cur = Some(new_rule()),
                b"pattern" => {
                    cur = Some(new_rule());
                    sec = Sec::Single;
                }
                b"prepatterns" => sec = Sec::Pre,
                b"postpatterns" => sec = Sec::Post,
                b"data" => {
                    in_data = true;
                    data_text.clear();
                }
                _ => handle_tag(&e, &mut cur),
            },
            Ok(Event::Empty(e)) => handle_tag(&e, &mut cur),
            Ok(Event::Text(t)) if in_data => {
                if let Ok(s) = t.unescape() {
                    data_text.push_str(&s);
                }
            }
            Ok(Event::End(e)) => match e.name().as_ref() {
                b"data" => {
                    in_data = false;
                    if let (Some(rule), Some(p)) = (cur.as_mut(), BytePattern::parse(&data_text)) {
                        match sec {
                            Sec::Pre => rule.pre.push(p),
                            Sec::Post | Sec::Single => rule.post.push(p),
                            Sec::None => {}
                        }
                    }
                }
                b"patternpairs" | b"pattern" => {
                    if let Some(rule) = cur.take() {
                        if !rule.post.is_empty() && !rule.actions.is_empty() {
                            rules.push(rule);
                        }
                    }
                    sec = Sec::None;
                }
                b"prepatterns" | b"postpatterns" => {
                    sec = if cur.is_some() { Sec::None } else { sec }
                }
                _ => {}
            },
            Ok(Event::Eof) | Err(_) => break,
            _ => {}
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_bits_and_wildcards() {
        let p = BytePattern::parse("0x55 0x48 0x89 0xe5").unwrap();
        assert!(p.matches(&[0x55, 0x48, 0x89, 0xe5]));
        let p = BytePattern::parse("0xe9........").unwrap();
        assert_eq!(p.len(), 5);
        assert!(p.matches(&[0xe9, 1, 2, 3, 4]));
        let p = BytePattern::parse("0x41 010111.. 0xc3").unwrap();
        assert!(p.matches(&[0x41, 0x5f, 0xc3]));
        assert!(!p.matches(&[0x41, 0x50, 0xc3]));
        let p = BytePattern::parse("0x1.").unwrap();
        assert!(p.matches(&[0x1f]) && !p.matches(&[0x2f]));
        assert!(BytePattern::parse("0x1").is_none());
    }

    #[test]
    fn parses_pattern_file() {
        let xml = r#"<patternlist>
          <patternpairs totalbits="32" postbits="16">
            <prepatterns><data>0xc3</data><data>0x90 0x90</data></prepatterns>
            <postpatterns><data>0x55 0x48 0x89 0xe5</data><funcstart/></postpatterns>
          </patternpairs>
          <pattern><data>0xf3 0x0f 0x1e 0xfa</data><funcstart after="defined" validcode="5"/></pattern>
        </patternlist>"#;
        let rules = parse_pattern_file(xml);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].pre.len(), 2);
        assert_eq!(rules[0].actions, vec![Action::FuncStart]);
        assert!(rules[1].constraints.after_defined);
        assert_eq!(rules[1].constraints.valid_code, 5);
    }

    #[test]
    fn real_x86_64_gcc_patterns_load() {
        let ldefs = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../Ghidra/Processors/x86/data/languages/x86.ldefs");
        let set = PatternSet::for_language(&ldefs, "x86:LE:64:default", "gcc");
        assert!(set.rules.len() > 10, "{}", set.rules.len());
        let aarch = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../Ghidra/Processors/AARCH64/data/languages/AARCH64.ldefs");
        assert!(
            !PatternSet::for_language(&aarch, "AARCH64:LE:64:v8A", "default")
                .rules
                .is_empty()
        );
    }
}
