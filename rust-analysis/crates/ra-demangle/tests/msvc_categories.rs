mod common;

/// MSVC mismatch breakdown: `cargo test -p ra-demangle --test msvc_categories -- --ignored --nocapture`
#[test]
#[ignore]
fn msvc_breakdown() {
    let oracle = common::load();
    let (mut fail, mut differ) = (std::collections::BTreeMap::<String, usize>::new(), vec![]);
    for e in &oracle.results {
        let Some(g) = e
            .demanglers
            .iter()
            .find(|r| r.demangler == "MicrosoftDemangler")
        else {
            continue;
        };
        match ra_demangle::msvc::demangle(&e.mangled) {
            None => *fail.entry(e.mangled.chars().take(3).collect()).or_default() += 1,
            Some(o) if o.name != g.name || o.namespace_string() != g.namespace => {
                differ.push(format!(
                    "{}\n   g: {:?} :: {}\n   r: {:?} :: {}",
                    e.mangled,
                    g.namespace,
                    g.name,
                    o.namespace_string(),
                    o.name
                ))
            }
            _ => {}
        }
    }
    println!("failures by prefix: {fail:?}");
    println!("differ: {}", differ.len());
    for d in differ.iter().take(40) {
        println!("{d}");
    }
}
