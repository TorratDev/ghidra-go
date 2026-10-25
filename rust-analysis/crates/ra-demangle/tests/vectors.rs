//! Test vectors ported from Ghidra's Java tests by
//! `tools/extract_demangler_vectors.py`.

use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    mangled: String,
    #[serde(default)]
    ms_truth: Option<String>,
}

fn load(name: &str) -> Vec<Vector> {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// Number of MDMangBaseTest cases whose full demangled text equals Ghidra's
/// `msTruth` (Microsoft undname output). Ratchet: raise when it improves.
const MSVC_FULL_TEXT_FLOOR: usize = 406;

#[test]
fn msvc_full_text_matches_undname() {
    let v = load("msvc.json");
    let mut pass = 0;
    let mut total = 0;
    for x in &v {
        let Some(truth) = &x.ms_truth else { continue };
        total += 1;
        if ra_demangle::msvc::demangle(&x.mangled).is_some_and(|d| d.full == *truth) {
            pass += 1;
        }
    }
    println!("msvc full text: {pass}/{total}");
    assert!(
        pass >= MSVC_FULL_TEXT_FLOOR,
        "msvc full-text agreement dropped: {pass} < {MSVC_FULL_TEXT_FLOOR}"
    );
}

/// Every ported input must be handled without panicking, by every scheme.
#[test]
fn all_vectors_are_handled() {
    for file in ["msvc.json", "gnu.json", "rust.json"] {
        let v = load(file);
        assert!(!v.is_empty(), "{file} is empty");
        for x in &v {
            for scheme in [
                ra_demangle::Scheme::Gnu,
                ra_demangle::Scheme::Rust,
                ra_demangle::Scheme::Msvc,
            ] {
                let _ = ra_demangle::demangle_with(scheme, &x.mangled);
            }
        }
    }
}
