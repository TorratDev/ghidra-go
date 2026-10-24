//! Golden snapshots of ra's own output, to catch unintended changes between
//! Ghidra comparisons. Review changes with `cargo insta review`.

use std::path::PathBuf;

use ra_analysis::Options;
use serde_json::json;

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../compare/corpus/binaries")
        .join(name)
}

fn summary(name: &str) -> serde_json::Value {
    let r = ra_cli::analyze_file(
        &corpus(name),
        None,
        &ra_sleigh::default_processors_dir(),
        &Options::default(),
    )
    .expect("analyze");
    json!({
        "format": r.binary.format,
        "language": r.binary.language,
        "counts": {
            "functions": r.functions.len(),
            "instructions": r.instructions.len(),
            "blocks": r.blocks.len(),
            "edges": r.edges.len(),
            "xrefs": r.xrefs.len(),
            "imports": r.imports.len(),
            "exports": r.exports.len(),
        },
        "functions": r.functions.iter().map(|f| format!(
            "{:#x} {}{}{} [{}]",
            f.entry, f.name,
            if f.thunk { " thunk" } else { "" },
            if f.no_return { " noreturn" } else { "" },
            f.body.iter().map(|(s, e)| format!("{s:#x}-{e:#x}")).collect::<Vec<_>>().join(",")
        )).collect::<Vec<_>>(),
    })
}

#[test]
fn snapshot_basic_gcc_o2_stripped() {
    insta::assert_json_snapshot!(summary("basic-x86_64-gcc-O2-stripped"));
}

#[test]
fn snapshot_freestanding_aarch64() {
    insta::assert_json_snapshot!(summary("freestanding-aarch64-clang-O2"));
}

#[test]
fn snapshot_freestanding_pe() {
    insta::assert_json_snapshot!(summary("freestanding-x86_64-pe-clang-O2.exe"));
}
