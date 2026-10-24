//! PARITY.md must list every analyzer, loader, relocation handler, ELF
//! extension, demangler and file system found in the Java tree.

use std::process::Command;

#[test]
fn parity_matrix_covers_java_tree() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let Ok(out) = Command::new("python3")
        .arg("-I")
        .arg(root.join("tools/gen_parity.py"))
        .arg("--check")
        .output()
    else {
        eprintln!("python3 not available; skipping");
        return;
    };
    assert!(
        out.status.success(),
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}
