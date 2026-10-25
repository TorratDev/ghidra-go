//! Differential regression: ra vs Ghidra on the committed corpus.
//!
//! For every binary in `compare/corpus/binaries` this runs `ra`, loads Ghidra's
//! export of the same binary (`compare/expected/<bin>.json`, produced by
//! `compare/ghidra_export.sh` with real Ghidra headless), compares the two
//! category by category and fails if any metric drops below
//! `compare/thresholds.toml`. Run `compare/run.sh` to regenerate the Ghidra
//! side live instead of using the committed exports.

use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn ra_matches_ghidra_within_thresholds() {
    let compare = root().join("compare");
    let out = ra_cli::regress(&ra_cli::RegressConfig {
        corpus: compare.join("corpus/binaries"),
        expected: std::env::var_os("RA_EXPECTED_DIR")
            .map(PathBuf::from)
            .unwrap_or(compare.join("expected")),
        thresholds: compare.join("thresholds.toml"),
        processors: ra_sleigh::default_processors_dir(),
        report_dir: Some(root().join("target/compare-report")),
        update_thresholds: false,
        filter: std::env::var("RA_FILTER").ok(),
    })
    .expect("regression run");
    println!("{}", out.markdown);
    assert!(
        out.missing_expected.is_empty(),
        "corpus binaries without a Ghidra export: {:?}",
        out.missing_expected
    );
    assert!(!out.results.is_empty(), "no binaries compared");
    let msgs: Vec<String> = out.violations.iter().map(|v| v.to_string()).collect();
    assert!(
        msgs.is_empty(),
        "regressions vs Ghidra (see target/compare-report/report.md):\n{}",
        msgs.join("\n")
    );
}

#[test]
fn every_category_is_gated_for_every_binary() {
    let compare = root().join("compare");
    let t = ra_compare::Thresholds::load(&compare.join("thresholds.toml")).unwrap();
    let demangle = t
        .binaries
        .get(ra_cli::DEMANGLE_ORACLE)
        .expect("demangle-oracle has no thresholds");
    for class in ["GnuDemangler", "RustDemangler", "MicrosoftDemangler"] {
        assert!(
            demangle.contains_key(class),
            "demangle-oracle: {class} not gated"
        );
    }
    for e in std::fs::read_dir(compare.join("expected"))
        .unwrap()
        .flatten()
    {
        if e.path().is_dir() {
            continue;
        }
        let name = e
            .file_name()
            .to_string_lossy()
            .trim_end_matches(".gz")
            .trim_end_matches(".json")
            .to_string();
        let gates = t.binaries.get(&name).unwrap_or_else(|| {
            panic!("{name} has no thresholds; run ra regress --update-thresholds")
        });
        for cat in ra_compare::CATEGORIES {
            assert!(gates.contains_key(*cat), "{name}: category {cat} not gated");
        }
    }
}
