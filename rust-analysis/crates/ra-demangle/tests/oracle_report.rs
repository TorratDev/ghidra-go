mod common;

/// Prints per-scheme agreement and mismatches: `cargo test -p ra-demangle --test oracle_report -- --nocapture --ignored`
#[test]
#[ignore]
fn print_oracle_mismatches() {
    for (k, s) in common::score() {
        println!(
            "== {k}: ghidra {} ours {} matched {}",
            s.ghidra, s.ours, s.matched
        );
        for m in s.mismatches.iter().take(
            std::env::var("N")
                .ok()
                .and_then(|n| n.parse().ok())
                .unwrap_or(15),
        ) {
            println!("  {m}");
        }
    }
}
