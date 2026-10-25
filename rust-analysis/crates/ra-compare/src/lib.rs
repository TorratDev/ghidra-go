//! Differential comparison between a Ghidra export (the oracle) and an `ra`
//! report for the same binary.
//!
//! Every category is compared as a set of keys. Keys present in both are
//! true positives; Ghidra-only keys are misses (they lower recall); ra-only
//! keys are extras (they lower precision).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use anyhow::{Context, Result};
use ra_core::{AnalysisReport, SymbolSource, XrefKind};
use serde::{Deserialize, Serialize};

/// Max mismatch samples kept per category and side.
pub const SAMPLES: usize = 25;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CategoryResult {
    pub name: String,
    pub matched: usize,
    pub ghidra_only: usize,
    pub ra_only: usize,
    pub precision: f64,
    pub recall: f64,
    pub ghidra_only_samples: Vec<String>,
    pub ra_only_samples: Vec<String>,
}

impl CategoryResult {
    pub fn from_sets(name: &str, ghidra: &BTreeSet<String>, ra: &BTreeSet<String>) -> Self {
        let matched = ghidra.intersection(ra).count();
        let g_only: Vec<_> = ghidra.difference(ra).cloned().collect();
        let r_only: Vec<_> = ra.difference(ghidra).cloned().collect();
        let ratio = |n: usize, d: usize| if d == 0 { 1.0 } else { n as f64 / d as f64 };
        Self {
            name: name.into(),
            matched,
            ghidra_only: g_only.len(),
            ra_only: r_only.len(),
            precision: ratio(matched, matched + r_only.len()),
            recall: ratio(matched, matched + g_only.len()),
            ghidra_only_samples: g_only.into_iter().take(SAMPLES).collect(),
            ra_only_samples: r_only.into_iter().take(SAMPLES).collect(),
        }
    }

    pub fn f1(&self) -> f64 {
        let (p, r) = (self.precision, self.recall);
        if p + r == 0.0 {
            0.0
        } else {
            2.0 * p * r / (p + r)
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Comparison {
    pub binary: String,
    pub ghidra_producer: String,
    pub ra_producer: String,
    pub language: String,
    /// `ghidra_addr = ra_addr + bias`.
    pub bias: i64,
    pub categories: Vec<CategoryResult>,
}

impl Comparison {
    pub fn category(&self, name: &str) -> Option<&CategoryResult> {
        self.categories.iter().find(|c| c.name == name)
    }
}

/// All compared categories, in report order.
pub const CATEGORIES: &[&str] = &[
    "memory_blocks",
    "symbols",
    "imports",
    "exports",
    "functions",
    "function_names",
    "demangled_names",
    "function_bodies",
    "thunks",
    "no_return",
    "instructions",
    "instruction_details",
    "blocks",
    "edges",
    "xrefs_flow",
    "xrefs_data",
    "xrefs_data_kinds",
    "xrefs_from_data",
];

/// Finds the address bias between the two reports by matching memory block
/// names (Ghidra rebases position independent images), falling back to the
/// image base difference.
pub fn detect_bias(ghidra: &AnalysisReport, ra: &AnalysisReport) -> i64 {
    for name in [".text", "__text", ".init", ".plt"] {
        let g = ghidra.memory.iter().find(|m| m.name == name);
        let r = ra.memory.iter().find(|m| m.name == name);
        if let (Some(g), Some(r)) = (g, r) {
            return g.start.wrapping_sub(r.start) as i64;
        }
    }
    let mut votes: BTreeMap<i64, usize> = BTreeMap::new();
    for g in &ghidra.memory {
        if let Some(r) = ra
            .memory
            .iter()
            .find(|r| r.name == g.name && r.end - r.start == g.end - g.start)
        {
            *votes
                .entry(g.start.wrapping_sub(r.start) as i64)
                .or_default() += 1;
        }
    }
    if let Some((b, _)) = votes.into_iter().max_by_key(|(_, n)| *n) {
        return b;
    }
    ghidra.binary.image_base.wrapping_sub(ra.binary.image_base) as i64
}

fn hex(a: u64) -> String {
    format!("{a:#x}")
}

struct View<'a> {
    r: &'a AnalysisReport,
    bias: i64,
    insn_addrs: HashSet<u64>,
}

impl<'a> View<'a> {
    fn new(r: &'a AnalysisReport, bias: i64) -> Self {
        let insn_addrs = r.instructions.iter().map(|i| i.addr).collect();
        Self {
            r,
            bias,
            insn_addrs,
        }
    }

    /// Maps an address into Ghidra's address space.
    fn a(&self, addr: u64) -> u64 {
        addr.wrapping_add(self.bias as u64)
    }

    fn set(&self, cat: &str) -> BTreeSet<String> {
        let r = self.r;
        match cat {
            "memory_blocks" => r
                .memory
                .iter()
                // `tdb` is Ghidra's synthetic Windows thread data block.
                .filter(|m| {
                    !m.name.starts_with("segment_") && m.name != "Headers" && m.name != "tdb"
                })
                .map(|m| {
                    format!(
                        "{} {}-{} {}{}{}",
                        m.name,
                        hex(self.a(m.start)),
                        hex(self.a(m.end)),
                        if m.read { 'r' } else { '-' },
                        if m.write { 'w' } else { '-' },
                        if m.execute { 'x' } else { '-' }
                    )
                })
                .collect(),
            "symbols" => r
                .symbols
                .iter()
                .filter(|s| s.source == SymbolSource::Imported)
                .map(|s| format!("{} {}", hex(self.a(s.addr)), s.name))
                .collect(),
            "imports" => r
                .imports
                .iter()
                .map(|i| strip_version(&i.name).to_string())
                .collect(),
            "exports" => r
                .exports
                .iter()
                .map(|e| format!("{} {}", hex(self.a(e.addr)), e.name))
                .collect(),
            "functions" => r.functions.iter().map(|f| hex(self.a(f.entry))).collect(),
            "function_names" => r
                .functions
                .iter()
                .filter(|f| f.source != SymbolSource::Default)
                .map(|f| format!("{} {}", hex(self.a(f.entry)), f.name))
                .collect(),
            // Names a demangler applied: analysis-source symbols at addresses
            // that also carry a mangled imported symbol.
            "demangled_names" => {
                let mangled: HashSet<u64> = r
                    .symbols
                    .iter()
                    .filter(|s| s.source == SymbolSource::Imported && is_mangled(&s.name))
                    .map(|s| s.addr)
                    .collect();
                r.symbols
                    .iter()
                    .filter(|s| s.source == SymbolSource::Analysis && mangled.contains(&s.addr))
                    .map(|s| match &s.namespace {
                        Some(ns) => format!("{} {ns}::{}", hex(self.a(s.addr)), s.name),
                        None => format!("{} {}", hex(self.a(s.addr)), s.name),
                    })
                    .collect()
            }
            "function_bodies" => r
                .functions
                .iter()
                .map(|f| {
                    let body: Vec<String> = f
                        .body
                        .iter()
                        .map(|(s, e)| format!("{}-{}", hex(self.a(*s)), hex(self.a(*e))))
                        .collect();
                    format!("{} [{}]", hex(self.a(f.entry)), body.join(","))
                })
                .collect(),
            "thunks" => r
                .functions
                .iter()
                .filter(|f| f.thunk)
                .map(|f| hex(self.a(f.entry)))
                .collect(),
            "no_return" => r
                .functions
                .iter()
                .filter(|f| f.no_return)
                .map(|f| hex(self.a(f.entry)))
                .collect(),
            "instructions" => r.instructions.iter().map(|i| hex(self.a(i.addr))).collect(),
            "instruction_details" => r
                .instructions
                .iter()
                .map(|i| format!("{} {} {}", hex(self.a(i.addr)), i.len, i.mnemonic))
                .collect(),
            "blocks" => r
                .blocks
                .iter()
                .map(|b| format!("{}-{}", hex(self.a(b.start)), hex(self.a(b.end))))
                .collect(),
            "edges" => r
                .edges
                .iter()
                .map(|e| {
                    format!(
                        "{}->{} {:?}",
                        hex(self.a(e.from)),
                        hex(self.a(e.to)),
                        e.kind
                    )
                })
                .collect(),
            "xrefs_flow" => r
                .xrefs
                .iter()
                .filter(|x| x.kind.is_flow())
                .map(|x| {
                    format!(
                        "{}->{} {:?}",
                        hex(self.a(x.from)),
                        hex(self.a(x.to)),
                        x.kind
                    )
                })
                .collect(),
            "xrefs_data" => r
                .xrefs
                .iter()
                .filter(|x| !x.kind.is_flow() && self.insn_addrs.contains(&x.from))
                .map(|x| format!("{}->{}", hex(self.a(x.from)), hex(self.a(x.to))))
                .collect(),
            "xrefs_data_kinds" => r
                .xrefs
                .iter()
                .filter(|x| !x.kind.is_flow() && self.insn_addrs.contains(&x.from))
                .map(|x| {
                    format!(
                        "{}->{} {:?}",
                        hex(self.a(x.from)),
                        hex(self.a(x.to)),
                        x.kind
                    )
                })
                .collect(),
            "xrefs_from_data" => r
                .xrefs
                .iter()
                .filter(|x| x.kind == XrefKind::Data && !self.insn_addrs.contains(&x.from))
                .map(|x| format!("{}->{}", hex(self.a(x.from)), hex(self.a(x.to))))
                .collect(),
            _ => BTreeSet::new(),
        }
    }
}

fn is_mangled(name: &str) -> bool {
    ["_Z", "__Z", "_R", "__R", "?"]
        .iter()
        .any(|p| name.starts_with(p))
}

fn strip_version(name: &str) -> &str {
    name.split('@').next().unwrap_or(name)
}

/// Restricts a category to keys whose address part is comparable: for
/// `instruction_details` and `function_bodies`, only entries whose address
/// exists on both sides are compared, so a missing instruction is counted
/// once (under `instructions`/`functions`), not twice.
fn restrict_to_common(g: &mut BTreeSet<String>, r: &mut BTreeSet<String>) {
    let key = |s: &String| s.split(' ').next().unwrap_or("").to_string();
    let gk: HashSet<String> = g.iter().map(key).collect();
    let rk: HashSet<String> = r.iter().map(key).collect();
    g.retain(|s| rk.contains(&key(s)));
    r.retain(|s| gk.contains(&key(s)));
}

pub fn compare(binary: &str, ghidra: &AnalysisReport, ra: &AnalysisReport) -> Comparison {
    let bias = detect_bias(ghidra, ra);
    let gv = View::new(ghidra, 0);
    let rv = View::new(ra, bias);
    let categories = CATEGORIES
        .iter()
        .map(|cat| {
            let mut g = gv.set(cat);
            let mut r = rv.set(cat);
            if matches!(
                *cat,
                "instruction_details" | "function_bodies" | "xrefs_data_kinds"
            ) {
                if *cat == "xrefs_data_kinds" {
                    let key = |s: &String| {
                        s.rsplit_once(' ')
                            .map(|(a, _)| a.to_string())
                            .unwrap_or_default()
                    };
                    let gk: HashSet<String> = g.iter().map(key).collect();
                    let rk: HashSet<String> = r.iter().map(key).collect();
                    g.retain(|s| rk.contains(&key(s)));
                    r.retain(|s| gk.contains(&key(s)));
                } else {
                    restrict_to_common(&mut g, &mut r);
                }
            }
            CategoryResult::from_sets(cat, &g, &r)
        })
        .collect();
    Comparison {
        binary: binary.into(),
        ghidra_producer: ghidra.producer.clone(),
        ra_producer: ra.producer.clone(),
        language: ghidra.binary.language.clone(),
        bias,
        categories,
    }
}

/// Loads a report; `.gz` files are decompressed (large Ghidra exports are
/// committed gzipped).
pub fn load_report(path: &std::path::Path) -> Result<AnalysisReport> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let text = if path.extension().is_some_and(|e| e == "gz") {
        let mut s = String::new();
        std::io::Read::read_to_string(&mut flate2::read::GzDecoder::new(&raw[..]), &mut s)
            .with_context(|| format!("decompressing {}", path.display()))?;
        s
    } else {
        String::from_utf8(raw).with_context(|| format!("{} is not UTF-8", path.display()))?
    };
    let mut r: AnalysisReport =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
    r.normalize();
    Ok(r)
}

/// The Ghidra export for corpus binary `name` in `dir`, gzipped or not.
pub fn expected_path(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
    [format!("{name}.json.gz"), format!("{name}.json")]
        .into_iter()
        .map(|f| dir.join(f))
        .find(|p| p.exists())
}

// ---------------------------------------------------------------------------
// Thresholds (ratchet)

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct Gate {
    pub recall: f64,
    pub precision: f64,
}

/// `thresholds.toml`: `[binaries."<name>"] <category> = { recall, precision }`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Thresholds {
    #[serde(default)]
    pub binaries: BTreeMap<String, BTreeMap<String, Gate>>,
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub binary: String,
    pub category: String,
    pub metric: &'static str,
    pub actual: f64,
    pub required: f64,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} / {}: {} {:.4} < required {:.4}",
            self.binary, self.category, self.metric, self.actual, self.required
        )
    }
}

/// Values are floored to 3 decimals so tiny float noise never trips a gate.
fn floor3(v: f64) -> f64 {
    (v * 1000.0).floor() / 1000.0
}

impl Thresholds {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
    }

    pub fn save(&self, path: &std::path::Path) -> Result<()> {
        let header = "# Minimum precision/recall per binary and category, versus Ghidra.\n\
                      # Ratchet: `ra regress --update-thresholds` only ever raises these.\n\n";
        std::fs::write(path, format!("{header}{}", toml::to_string_pretty(self)?))?;
        Ok(())
    }

    pub fn check(&self, c: &Comparison) -> Vec<Violation> {
        let mut out = vec![];
        let Some(gates) = self.binaries.get(&c.binary) else {
            return out;
        };
        for (cat, gate) in gates {
            let Some(res) = c.category(cat) else { continue };
            for (metric, actual, required) in [
                ("recall", res.recall, gate.recall),
                ("precision", res.precision, gate.precision),
            ] {
                if floor3(actual) < required {
                    out.push(Violation {
                        binary: c.binary.clone(),
                        category: cat.clone(),
                        metric,
                        actual,
                        required,
                    });
                }
            }
        }
        out
    }

    /// Raises gates to the current results (never lowers them).
    pub fn ratchet(&mut self, c: &Comparison) {
        let gates = self.binaries.entry(c.binary.clone()).or_default();
        for res in &c.categories {
            let new = Gate {
                recall: floor3(res.recall),
                precision: floor3(res.precision),
            };
            let g = gates.entry(res.name.clone()).or_insert(new);
            g.recall = g.recall.max(new.recall);
            g.precision = g.precision.max(new.precision);
        }
    }
}

// ---------------------------------------------------------------------------
// Rendering

pub fn markdown(results: &[Comparison], violations: &[Violation]) -> String {
    let mut s = String::new();
    s.push_str("# Ghidra vs ra differential report\n\n");
    if let Some(c) = results.first() {
        s.push_str(&format!(
            "Oracle: `{}` · Implementation: `{}`\n\n",
            c.ghidra_producer, c.ra_producer
        ));
    }
    s.push_str("Values are `recall / precision` against Ghidra (Ghidra = ground truth).\n\n");
    let shown = [
        "functions",
        "function_names",
        "demangled_names",
        "thunks",
        "no_return",
        "instructions",
        "instruction_details",
        "blocks",
        "edges",
        "xrefs_flow",
        "xrefs_data",
        "imports",
        "symbols",
    ];
    s.push_str("| binary |");
    for c in shown {
        s.push_str(&format!(" {c} |"));
    }
    s.push_str("\n|---|");
    for _ in shown {
        s.push_str("---|");
    }
    s.push('\n');
    let (programs, others): (Vec<&Comparison>, Vec<&Comparison>) = results
        .iter()
        .partition(|c| c.category("functions").is_some());
    for c in programs {
        s.push_str(&format!("| {} |", c.binary));
        for name in shown {
            match c.category(name) {
                Some(r) => s.push_str(&format!(" {:.3} / {:.3} |", r.recall, r.precision)),
                None => s.push_str(" - |"),
            }
        }
        s.push('\n');
    }
    s.push('\n');
    // Comparisons that are not whole programs (the demangle oracle) have
    // their own categories.
    for c in others {
        s.push_str(&format!(
            "**{}** (vs `{}`)\n\n| category | matched | ghidra-only | ra-only | recall / precision |\n|---|---|---|---|---|\n",
            c.binary, c.ghidra_producer
        ));
        for r in &c.categories {
            s.push_str(&format!(
                "| {} | {} | {} | {} | {:.3} / {:.3} |\n",
                r.name, r.matched, r.ghidra_only, r.ra_only, r.recall, r.precision
            ));
        }
        s.push('\n');
    }
    if violations.is_empty() {
        s.push_str("**Gates: all passing.**\n\n");
    } else {
        s.push_str("## Gate violations\n\n");
        for v in violations {
            s.push_str(&format!("- {v}\n"));
        }
        s.push('\n');
    }
    s.push_str("## Mismatch samples\n\n");
    for c in results {
        s.push_str(&format!(
            "### {}\n\nlanguage `{}`, bias `{:#x}`\n\n",
            c.binary, c.language, c.bias
        ));
        for r in &c.categories {
            if r.ghidra_only == 0 && r.ra_only == 0 {
                continue;
            }
            s.push_str(&format!(
                "- **{}**: matched {}, ghidra-only {}, ra-only {}\n",
                r.name, r.matched, r.ghidra_only, r.ra_only
            ));
            if !r.ghidra_only_samples.is_empty() {
                s.push_str(&format!(
                    "  - ghidra-only: `{}`\n",
                    r.ghidra_only_samples.join("`, `")
                ));
            }
            if !r.ra_only_samples.is_empty() {
                s.push_str(&format!(
                    "  - ra-only: `{}`\n",
                    r.ra_only_samples.join("`, `")
                ));
            }
        }
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use ra_core::*;

    fn report(base: u64, funcs: &[u64]) -> AnalysisReport {
        AnalysisReport {
            memory: vec![MemoryInfo {
                name: ".text".into(),
                start: base + 0x1000,
                end: base + 0x2000,
                read: true,
                write: false,
                execute: true,
                initialized: true,
            }],
            functions: funcs
                .iter()
                .map(|&f| FunctionInfo {
                    entry: base + f,
                    name: format!("f{f:x}"),
                    namespace: None,
                    source: SymbolSource::Imported,
                    thunk: false,
                    thunk_target: None,
                    no_return: false,
                    body: vec![(base + f, base + f + 4)],
                })
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn bias_and_set_metrics() {
        let g = report(0x100000, &[0x1000, 0x1010, 0x1020, 0x1030]);
        let r = report(0, &[0x1000, 0x1010, 0x1040]);
        let c = compare("t", &g, &r);
        assert_eq!(c.bias, 0x100000);
        let f = c.category("functions").unwrap();
        assert_eq!((f.matched, f.ghidra_only, f.ra_only), (2, 2, 1));
        assert!((f.recall - 0.5).abs() < 1e-9);
        assert!((f.precision - 2.0 / 3.0).abs() < 1e-9);
        // Bodies are only compared for functions present on both sides.
        let b = c.category("function_bodies").unwrap();
        assert_eq!((b.matched, b.ghidra_only, b.ra_only), (2, 0, 0));
    }

    #[test]
    fn ratchet_only_raises() {
        let g = report(0, &[0x1000, 0x1010]);
        let mut r = report(0, &[0x1000]);
        let mut t = Thresholds::default();
        t.ratchet(&compare("t", &g, &r));
        assert_eq!(t.binaries["t"]["functions"].recall, 0.5);
        r = report(0, &[]);
        let worse = compare("t", &g, &r);
        t.ratchet(&worse);
        assert_eq!(t.binaries["t"]["functions"].recall, 0.5);
        let v = t.check(&worse);
        assert!(v
            .iter()
            .any(|v| v.category == "functions" && v.metric == "recall"));
    }
}
