//! Known non-returning function names (Ghidra `NoReturnFunctionAnalyzer`,
//! data from `Ghidra/Features/Base/data/*FunctionsThatDoNotReturn`).

use std::collections::HashSet;

const ELF: &str = include_str!("../../../../Ghidra/Features/Base/data/ElfFunctionsThatDoNotReturn");
const PE: &str = include_str!("../../../../Ghidra/Features/Base/data/PEFunctionsThatDoNotReturn");
const MACHO: &str =
    include_str!("../../../../Ghidra/Features/Base/data/MachOFunctionsThatDoNotReturn");

pub struct NoReturnNames {
    names: HashSet<String>,
}

impl NoReturnNames {
    /// Name list for an executable format (`noReturnFunctionConstraints.xml`).
    pub fn for_format(format: &str) -> Self {
        let text = match format {
            "PE" => PE,
            "MachO" => MACHO,
            _ => ELF,
        };
        let names = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.trim_start_matches('_').to_string())
            .collect();
        Self { names }
    }

    /// Leading underscores are ignored, as in Ghidra.
    pub fn contains(&self, name: &str) -> bool {
        let base = name.split('@').next().unwrap_or(name);
        self.names.contains(base.trim_start_matches('_'))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn elf_names() {
        let n = super::NoReturnNames::for_format("ELF");
        assert!(n.contains("exit"));
        assert!(n.contains("__assert_fail"));
        assert!(n.contains("abort@GLIBC_2.2.5"));
        assert!(!n.contains("printf"));
    }
}
