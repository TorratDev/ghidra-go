//! Shared loader for the Ghidra demangle oracle.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::io::Read;

use ra_demangle::Scheme;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Oracle {
    pub producer: String,
    pub results: Vec<Entry>,
}

#[derive(Deserialize)]
pub struct Entry {
    pub mangled: String,
    pub demanglers: Vec<GhidraResult>,
}

#[derive(Deserialize)]
pub struct GhidraResult {
    pub demangler: String,
    pub name: String,
    pub namespace: Option<String>,
}

pub fn load() -> Oracle {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../compare/expected/demangle/ghidra.json.gz");
    let mut s = String::new();
    flate2::read::GzDecoder::new(std::fs::File::open(&p).expect("oracle"))
        .read_to_string(&mut s)
        .unwrap();
    serde_json::from_str(&s).unwrap()
}

#[derive(Debug, Default, Clone)]
pub struct Score {
    /// Names Ghidra demangled with this scheme.
    pub ghidra: usize,
    /// Names ra demangled with this scheme.
    pub ours: usize,
    /// Both demangled, same namespace and leaf.
    pub matched: usize,
    pub mismatches: Vec<String>,
}

pub fn score() -> BTreeMap<&'static str, Score> {
    let oracle = load();
    let mut out: BTreeMap<&'static str, Score> = BTreeMap::new();
    for scheme in [Scheme::Gnu, Scheme::Rust, Scheme::Msvc] {
        let s = out.entry(scheme.ghidra_class()).or_default();
        for e in &oracle.results {
            let g = e
                .demanglers
                .iter()
                .find(|r| r.demangler == scheme.ghidra_class());
            let ours = ra_demangle::demangle_with(scheme, &e.mangled);
            if g.is_some() {
                s.ghidra += 1;
            }
            if ours.is_some() {
                s.ours += 1;
            }
            match (g, ours) {
                (Some(g), Some(o)) if g.name == o.name && g.namespace == o.namespace_string() => {
                    s.matched += 1
                }
                (g, o) => {
                    if g.is_some() || o.is_some() {
                        s.mismatches.push(format!(
                            "{}\n    ghidra: {:?}\n    ra:     {:?}",
                            e.mangled,
                            g.map(|g| (g.namespace.clone(), g.name.clone())),
                            o.map(|o| (o.namespace_string(), o.name))
                        ));
                    }
                }
            }
        }
    }
    out
}
