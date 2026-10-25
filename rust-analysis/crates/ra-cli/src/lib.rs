//! Library side of the `ra` CLI, shared with the regression tests.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ra_analysis::Options;
use ra_compare::{Comparison, Thresholds, Violation};
use ra_core::AnalysisReport;

/// Loads, analyzes and reports one binary.
pub fn analyze_file(
    path: &Path,
    language: Option<&str>,
    processors: &Path,
    opts: &Options,
) -> Result<AnalysisReport> {
    let prog = ra_loader::load_path(path, language)?;
    let lang = ra_sleigh::Language::load(processors, &prog.language)
        .with_context(|| format!("loading language {}", prog.language))?;
    let analysis = ra_analysis::analyze(&prog, &lang, opts);
    let mut report = ra_analysis::report(&prog, &analysis);
    report.binary.path = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    Ok(report)
}

/// Name of the pseudo-binary under which demangler agreement is reported
/// and gated (categories are Ghidra demangler classes).
pub const DEMANGLE_ORACLE: &str = "demangle-oracle";

/// Compares ra-demangle with Ghidra's demanglers on the oracle written by
/// `compare/ghidra_demangle.sh` (`expected/demangle/ghidra.json.gz`). For
/// each Ghidra demangler class, keys are `mangled => namespace::name`;
/// recall is agreement over the names Ghidra demangled, precision over the
/// names ra demangled.
pub fn demangle_comparison(oracle: &Path) -> Result<Comparison> {
    #[derive(serde::Deserialize)]
    struct Oracle {
        producer: String,
        results: Vec<Entry>,
    }
    #[derive(serde::Deserialize)]
    struct Entry {
        mangled: String,
        demanglers: Vec<R>,
    }
    #[derive(serde::Deserialize)]
    struct R {
        demangler: String,
        name: String,
        namespace: Option<String>,
    }
    let raw = std::fs::read(oracle).with_context(|| format!("reading {}", oracle.display()))?;
    let mut text = String::new();
    std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&raw[..]), &mut text)?;
    let o: Oracle = serde_json::from_str(&text)?;
    let key = |m: &str, ns: Option<&str>, n: &str| match ns {
        Some(ns) => format!("{m} => {ns}::{n}"),
        None => format!("{m} => {n}"),
    };
    let mut categories = vec![];
    for scheme in [
        ra_demangle::Scheme::Gnu,
        ra_demangle::Scheme::Rust,
        ra_demangle::Scheme::Msvc,
    ] {
        let class = scheme.ghidra_class();
        let mut g = std::collections::BTreeSet::new();
        let mut r = std::collections::BTreeSet::new();
        for e in &o.results {
            if let Some(x) = e.demanglers.iter().find(|x| x.demangler == class) {
                g.insert(key(&e.mangled, x.namespace.as_deref(), &x.name));
            }
            if let Some(d) = ra_demangle::demangle_with(scheme, &e.mangled) {
                r.insert(key(&e.mangled, d.namespace_string().as_deref(), &d.name));
            }
        }
        categories.push(ra_compare::CategoryResult::from_sets(class, &g, &r));
    }
    Ok(Comparison {
        binary: DEMANGLE_ORACLE.into(),
        ghidra_producer: o.producer,
        ra_producer: format!("ra {}", env!("CARGO_PKG_VERSION")),
        language: "-".into(),
        bias: 0,
        categories,
    })
}

pub struct RegressConfig {
    pub corpus: PathBuf,
    pub expected: PathBuf,
    pub thresholds: PathBuf,
    pub processors: PathBuf,
    pub report_dir: Option<PathBuf>,
    pub update_thresholds: bool,
    pub filter: Option<String>,
}

pub struct RegressOutcome {
    pub results: Vec<Comparison>,
    pub violations: Vec<Violation>,
    /// Corpus binaries with no Ghidra export to compare against.
    pub missing_expected: Vec<String>,
    pub markdown: String,
}

/// Analyzes every corpus binary that has a Ghidra export, compares the two,
/// and checks (or ratchets) the thresholds.
pub fn regress(cfg: &RegressConfig) -> Result<RegressOutcome> {
    let mut bins: Vec<PathBuf> = std::fs::read_dir(&cfg.corpus)
        .with_context(|| format!("reading corpus {}", cfg.corpus.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_none_or(|e| e != "log"))
        .collect();
    bins.sort();
    let mut results = vec![];
    let mut missing_expected = vec![];
    for bin in bins {
        let name = bin.file_name().unwrap().to_string_lossy().into_owned();
        if cfg
            .filter
            .as_ref()
            .is_some_and(|f| !name.contains(f.as_str()))
        {
            continue;
        }
        let Some(expected) = ra_compare::expected_path(&cfg.expected, &name) else {
            missing_expected.push(name);
            continue;
        };
        let ghidra = ra_compare::load_report(&expected)?;
        let ours = analyze_file(&bin, None, &cfg.processors, &Options::default())
            .with_context(|| format!("analyzing {name}"))?;
        if let Some(dir) = &cfg.report_dir {
            std::fs::create_dir_all(dir)?;
            std::fs::write(
                dir.join(format!("{name}.ra.json")),
                serde_json::to_string_pretty(&ours)?,
            )?;
        }
        results.push(ra_compare::compare(&name, &ghidra, &ours));
    }
    let oracle = cfg.expected.join("demangle/ghidra.json.gz");
    if oracle.exists()
        && cfg
            .filter
            .as_ref()
            .is_none_or(|f| DEMANGLE_ORACLE.contains(f.as_str()))
    {
        results.push(demangle_comparison(&oracle)?);
    }
    let mut thresholds = Thresholds::load(&cfg.thresholds)?;
    if cfg.update_thresholds {
        for c in &results {
            thresholds.ratchet(c);
        }
        thresholds.save(&cfg.thresholds)?;
    }
    let violations: Vec<Violation> = results.iter().flat_map(|c| thresholds.check(c)).collect();
    let markdown = ra_compare::markdown(&results, &violations);
    if let Some(dir) = &cfg.report_dir {
        std::fs::write(dir.join("report.md"), &markdown)?;
        std::fs::write(
            dir.join("report.json"),
            serde_json::to_string_pretty(&results)?,
        )?;
    }
    Ok(RegressOutcome {
        results,
        violations,
        missing_expected,
        markdown,
    })
}
