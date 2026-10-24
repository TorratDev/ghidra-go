//! Normalized analysis report.
//!
//! This is the interchange format between the Rust analyzer (`ra analyze`)
//! and the Ghidra headless exporter (`compare/ghidra/ExportAnalysis.java`).
//! Both sides emit exactly this schema so `ra compare` can diff them.

use serde::{Deserialize, Serialize};

use crate::hex;

/// 2: `namespace` on symbols, functions and imports.
pub const SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub schema_version: u32,
    /// e.g. `"ra 0.1.0"` or `"ghidra 12.1.4"`.
    pub producer: String,
    pub binary: BinaryInfo,
    #[serde(default)]
    pub memory: Vec<MemoryInfo>,
    #[serde(default)]
    pub symbols: Vec<SymbolInfo>,
    #[serde(default)]
    pub imports: Vec<ImportInfo>,
    #[serde(default)]
    pub exports: Vec<ExportInfo>,
    #[serde(default)]
    pub functions: Vec<FunctionInfo>,
    #[serde(default)]
    pub instructions: Vec<InstructionInfo>,
    #[serde(default)]
    pub blocks: Vec<BlockInfo>,
    #[serde(default)]
    pub edges: Vec<EdgeInfo>,
    #[serde(default)]
    pub xrefs: Vec<XrefInfo>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub path: String,
    #[serde(default)]
    pub sha256: String,
    /// `ELF`, `PE`, `MachO`, `Raw`.
    pub format: String,
    /// Ghidra language id, e.g. `x86:LE:64:default`.
    pub language: String,
    /// All addresses in the report are absolute; comparisons subtract this.
    #[serde(with = "hex")]
    pub image_base: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemoryInfo {
    pub name: String,
    #[serde(with = "hex")]
    pub start: u64,
    /// Exclusive.
    #[serde(with = "hex")]
    pub end: u64,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    pub initialized: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SymbolSource {
    /// From the binary's symbol tables (Ghidra `SourceType.IMPORTED`).
    Imported,
    /// Created by analysis (Ghidra `SourceType.ANALYSIS`).
    Analysis,
    /// Generated default name such as `FUN_00101000` (`SourceType.DEFAULT`).
    Default,
    /// User defined (`SourceType.USER_DEFINED`); not produced by `ra`.
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SymbolInfo {
    #[serde(with = "hex")]
    pub addr: u64,
    pub name: String,
    /// Parent namespace path (`std::vector<int>`), `None` for global.
    #[serde(default)]
    pub namespace: Option<String>,
    /// `function`, `label`, `data`.
    pub kind: String,
    pub source: SymbolSource,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportInfo {
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    #[serde(default)]
    pub library: Option<String>,
    /// Address of the thunk/stub or pointer slot that refers to the import.
    #[serde(default, with = "hex::opt")]
    pub addr: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportInfo {
    #[serde(with = "hex")]
    pub addr: u64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionInfo {
    #[serde(with = "hex")]
    pub entry: u64,
    pub name: String,
    #[serde(default)]
    pub namespace: Option<String>,
    pub source: SymbolSource,
    #[serde(default)]
    pub thunk: bool,
    #[serde(default, with = "hex::opt")]
    pub thunk_target: Option<u64>,
    #[serde(default)]
    pub no_return: bool,
    /// Address ranges `[start, end)` making up the function body.
    #[serde(default, with = "hex::pairs")]
    pub body: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstructionInfo {
    #[serde(with = "hex")]
    pub addr: u64,
    pub len: u32,
    /// Upper-case mnemonic as printed by SLEIGH (`MOV`, `CALL`, ...).
    pub mnemonic: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockInfo {
    #[serde(with = "hex")]
    pub start: u64,
    /// Exclusive.
    #[serde(with = "hex")]
    pub end: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    Fallthrough,
    Jump,
    CondJump,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EdgeInfo {
    /// Start address of the source block.
    #[serde(with = "hex")]
    pub from: u64,
    /// Start address of the destination block.
    #[serde(with = "hex")]
    pub to: u64,
    pub kind: EdgeKind,
}

/// Reference kinds, a coarse projection of Ghidra's `RefType`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum XrefKind {
    Call,
    Jump,
    CondJump,
    Read,
    Write,
    /// Data reference whose access is unknown (address taken, pointer).
    Data,
}

impl XrefKind {
    pub fn is_flow(self) -> bool {
        matches!(self, XrefKind::Call | XrefKind::Jump | XrefKind::CondJump)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct XrefInfo {
    /// Address of the referencing instruction (or data item).
    #[serde(with = "hex")]
    pub from: u64,
    #[serde(with = "hex")]
    pub to: u64,
    pub kind: XrefKind,
}

impl AnalysisReport {
    /// Sorts every list so serialized reports are deterministic.
    pub fn normalize(&mut self) {
        self.memory.sort_by_key(|m| (m.start, m.end));
        self.symbols
            .sort_by(|a, b| (a.addr, &a.name).cmp(&(b.addr, &b.name)));
        self.symbols.dedup();
        self.imports
            .sort_by(|a, b| (&a.name, &a.library, a.addr).cmp(&(&b.name, &b.library, b.addr)));
        self.imports.dedup();
        self.exports
            .sort_by(|a, b| (a.addr, &a.name).cmp(&(b.addr, &b.name)));
        self.exports.dedup();
        self.functions.sort_by_key(|f| f.entry);
        for f in &mut self.functions {
            f.body.sort();
        }
        self.instructions.sort_by_key(|i| i.addr);
        self.blocks.sort_by_key(|b| (b.start, b.end));
        self.blocks.dedup();
        self.edges.sort_by_key(|e| (e.from, e.to, e.kind));
        self.edges.dedup();
        self.xrefs.sort_by_key(|x| (x.from, x.to, x.kind));
        self.xrefs.dedup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_roundtrip_as_hex_strings() {
        let f = FunctionInfo {
            entry: 0xffff_ffff_8000_0000,
            name: "f".into(),
            namespace: None,
            source: SymbolSource::Imported,
            thunk: false,
            thunk_target: Some(0x10),
            no_return: false,
            body: vec![(0x10, 0x20)],
        };
        let s = serde_json::to_string(&f).unwrap();
        assert!(s.contains("\"0xffffffff80000000\""), "{s}");
        assert!(s.contains("[[\"0x10\",\"0x20\"]]"), "{s}");
        let back: FunctionInfo = serde_json::from_str(&s).unwrap();
        assert_eq!(back, f);
    }
}
