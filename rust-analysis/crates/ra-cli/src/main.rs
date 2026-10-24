use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use ra_analysis::Options;

#[derive(Parser)]
#[command(name = "ra", version, about = "Rust port of Ghidra auto-analysis")]
struct Cli {
    /// Ghidra `Processors` directory holding the SLEIGH specs
    /// (default: $RA_PROCESSORS or the repository's Ghidra/Processors).
    #[arg(long, global = true)]
    processors: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze a binary and print the normalized JSON report.
    Analyze {
        binary: PathBuf,
        /// Ghidra language id (required for raw binaries).
        #[arg(long)]
        language: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        no_patterns: bool,
    },
    /// Compare a Ghidra export with an ra report.
    Compare {
        ghidra: PathBuf,
        ra: PathBuf,
        /// Print the full JSON comparison instead of markdown.
        #[arg(long)]
        json: bool,
    },
    /// Run ra and compare against Ghidra exports for a whole corpus.
    Regress {
        #[arg(long, default_value = "compare/corpus/binaries")]
        corpus: PathBuf,
        #[arg(long, default_value = "compare/expected")]
        expected: PathBuf,
        #[arg(long, default_value = "compare/thresholds.toml")]
        thresholds: PathBuf,
        #[arg(long)]
        report_dir: Option<PathBuf>,
        /// Raise thresholds to the current results (ratchet).
        #[arg(long)]
        update_thresholds: bool,
        /// Only binaries whose name contains this string.
        #[arg(long)]
        filter: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let processors = cli
        .processors
        .unwrap_or_else(ra_sleigh::default_processors_dir);
    match cli.cmd {
        Cmd::Analyze {
            binary,
            language,
            output,
            no_patterns,
        } => {
            let opts = Options {
                patterns: !no_patterns,
                ..Options::default()
            };
            let report = ra_cli::analyze_file(&binary, language.as_deref(), &processors, &opts)?;
            let json = serde_json::to_string_pretty(&report)?;
            match output {
                Some(p) => std::fs::write(p, json)?,
                None => println!("{json}"),
            }
        }
        Cmd::Compare { ghidra, ra, json } => {
            let g = ra_compare::load_report(&ghidra)?;
            let r = ra_compare::load_report(&ra)?;
            let name = ghidra
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let c = ra_compare::compare(&name, &g, &r);
            if json {
                println!("{}", serde_json::to_string_pretty(&c)?);
            } else {
                print!("{}", ra_compare::markdown(&[c], &[]));
            }
        }
        Cmd::Regress {
            corpus,
            expected,
            thresholds,
            report_dir,
            update_thresholds,
            filter,
        } => {
            let out = ra_cli::regress(&ra_cli::RegressConfig {
                corpus,
                expected,
                thresholds,
                processors,
                report_dir,
                update_thresholds,
                filter,
            })?;
            print!(
                "{}",
                out.markdown
                    .split("## Mismatch samples")
                    .next()
                    .unwrap_or("")
            );
            for m in &out.missing_expected {
                eprintln!("warning: no Ghidra export for {m}; run compare/ghidra_export.sh");
            }
            if !out.violations.is_empty() {
                bail!("{} gate violation(s)", out.violations.len());
            }
        }
    }
    Ok(())
}
