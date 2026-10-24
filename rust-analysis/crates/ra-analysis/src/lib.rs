//! Auto-analysis (milestone 1).
//!
//! Java counterparts, in pass order:
//! - `EntryPointAnalyzer`, `ExternalEntryFunctionAnalyzer` – seed functions
//!   from the entry point, exports and symbols (seeds come from `ra-loader`).
//! - `ElfDefaultGotPltMarkup` – disassemble PLT sections, create thunks.
//! - `DisassembleCommand` + `FunctionAnalyzer` (Subroutine References) –
//!   recursive descent; call targets become functions.
//! - `NoReturnFunctionAnalyzer` / `FindNoReturnFunctionsAnalyzer` – known and
//!   discovered non-returning functions, cutting flow after calls to them.
//! - `FunctionStartAnalyzer` – byte-pattern function starts in undefined gaps.
//! - `CreateThunkAnalyzer` – single-jump thunks.
//! - `OperandReferenceAnalyzer` / `DataOperandReferenceAnalyzer` – references.
//! - `BasicBlockModel` – basic blocks and edges.

pub mod noreturn;
pub mod patterns;
pub mod switch;

use std::collections::{BTreeMap, BTreeSet, HashSet};

use ra_core::{
    AnalysisReport, BinaryInfo, BlockInfo, EdgeInfo, EdgeKind, ExportInfo, FunctionInfo,
    ImportInfo, InstructionInfo, MemoryInfo, SymbolInfo, SymbolSource, XrefInfo, XrefKind,
    SCHEMA_VERSION,
};
use ra_loader::{Program, SeedKind};
use ra_sleigh::{Access, Decoded, FlowKind, Language};

use crate::{
    noreturn::NoReturnNames,
    patterns::{Action, PatternSet},
};

#[derive(Debug, Clone)]
pub struct Options {
    /// Run the byte-pattern function start search.
    pub patterns: bool,
    /// Create functions at code addresses referenced by operands or pointers.
    pub pointer_functions: bool,
    /// Compiler id used to select pattern files (`gcc`, `windows`, ...).
    pub compiler: Option<String>,
    /// Resolve `CALL [T + idx*S]` function-pointer tables (Ghidra resolves
    /// most of these through decompiler analysis; this recovers the
    /// absolute-base form).
    pub call_tables: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            patterns: true,
            pointer_functions: true,
            compiler: None,
            call_tables: true,
        }
    }
}

/// Why a function exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FuncSource {
    Seed(SeedKind),
    Plt,
    Call,
    Pattern,
    Pointer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThunkTarget {
    Internal(u64),
    External(String),
}

#[derive(Debug, Clone)]
pub struct Insn {
    pub d: Decoded,
    /// Fallthrough address after no-return call cutting.
    pub ft: Option<u64>,
}

impl Insn {
    fn end(&self) -> u64 {
        self.d.addr + self.d.len as u64
    }
}

#[derive(Debug, Clone)]
pub struct Function {
    pub entry: u64,
    pub source: FuncSource,
    pub thunk: Option<ThunkTarget>,
    pub no_return: bool,
    pub body: Vec<(u64, u64)>,
}

/// Results of analysis, before conversion to the report schema.
pub struct Analysis {
    pub insns: BTreeMap<u64, Insn>,
    pub functions: BTreeMap<u64, Function>,
    /// Indirect jumps/calls whose tables were recovered.
    pub switch_jumps: BTreeSet<u64>,
}

struct Analyzer<'a> {
    prog: &'a Program,
    lang: &'a Language,
    opts: &'a Options,
    names: NoReturnNames,
    patterns: PatternSet,
    insns: BTreeMap<u64, Insn>,
    funcs: BTreeMap<u64, FuncSource>,
    /// Starts found by patterns or pointers; kept across fixpoint rounds.
    extra_funcs: BTreeMap<u64, FuncSource>,
    code_boundaries: BTreeSet<u64>,
    noreturn: HashSet<u64>,
    thunks: BTreeMap<u64, ThunkTarget>,
    /// Recovered jump tables: jump address -> (table start, table end, targets).
    switches: BTreeMap<u64, switch::Table>,
}

pub fn analyze(prog: &Program, lang: &Language, opts: &Options) -> Analysis {
    let compiler = opts
        .compiler
        .clone()
        .unwrap_or_else(|| default_compiler(&prog.format).into());
    let patterns = if opts.patterns {
        PatternSet::for_language(&lang.ldefs, &lang.id, &compiler)
    } else {
        PatternSet::default()
    };
    let mut a = Analyzer {
        prog,
        lang,
        opts,
        names: NoReturnNames::for_format(&prog.format),
        patterns,
        insns: BTreeMap::new(),
        funcs: BTreeMap::new(),
        extra_funcs: BTreeMap::new(),
        code_boundaries: BTreeSet::new(),
        noreturn: HashSet::new(),
        thunks: BTreeMap::new(),
        switches: BTreeMap::new(),
    };
    a.run();
    a.propagate_constants();
    let functions = a.build_functions();
    let switch_jumps = a
        .switches
        .iter()
        .filter(|(j, _)| a.insns.get(j).is_some_and(|i| i.d.flow == FlowKind::Jump))
        .map(|(j, _)| *j)
        .collect();
    Analysis {
        insns: a.insns,
        functions,
        switch_jumps,
    }
}

fn default_compiler(format: &str) -> &'static str {
    match format {
        "PE" => "windows",
        "MachO" => "clang",
        _ => "gcc",
    }
}

impl Analyzer<'_> {
    fn run(&mut self) {
        // Fixpoint over no-return knowledge: flows after calls to no-return
        // functions are cut, which can change everything downstream.
        for _round in 0..8 {
            self.insns.clear();
            self.funcs.clear();
            self.thunks.clear();
            for (&a, &k) in &self.prog.seeds {
                self.funcs.insert(a, FuncSource::Seed(k));
            }
            for (&a, &k) in &self.extra_funcs {
                self.funcs.entry(a).or_insert(k);
            }
            self.markup_plt();
            let starts: Vec<u64> = self
                .funcs
                .keys()
                .copied()
                .chain(self.code_boundaries.iter().copied())
                .collect();
            for s in starts {
                self.disassemble(s);
            }
            for _ in 0..16 {
                let mut changed = self.resolve_switches();
                if self.opts.pointer_functions {
                    changed |= self.pointer_functions();
                }
                if self.opts.patterns {
                    changed |= self.pattern_pass();
                }
                if !changed {
                    break;
                }
            }
            self.detect_thunks();
            let before = self.noreturn.len();
            self.compute_noreturn();
            if self.noreturn.len() == before {
                break;
            }
        }
    }

    fn decode(&self, addr: u64) -> Option<Decoded> {
        if !self.prog.memory.is_executable(addr) {
            return None;
        }
        let bytes = self.prog.memory.bytes_from(addr)?;
        let mut d = self.lang.decoder().decode(addr, bytes)?;
        // Lazy-binding PLT entries jump to PLT0; Ghidra's PLT markup treats
        // that jump as a call that falls through to the next entry.
        if let Some(b) = self.prog.memory.block_at(addr) {
            // The flow type stays JUMP (it still ends the basic block); only
            // the reference becomes a call.
            if self.prog.format == "ELF"
                && b.name == ".plt"
                && d.flow == FlowKind::Jump
                && d.targets == [b.start]
            {
                d.has_fallthrough = true;
            }
        }
        Some(d)
    }

    /// Instruction containing `addr` (not necessarily starting at it).
    fn insn_containing(&self, addr: u64) -> Option<&Insn> {
        let (_, i) = self.insns.range(..=addr).next_back()?;
        (addr < i.end()).then_some(i)
    }

    fn conflicts(&self, addr: u64, len: u32) -> bool {
        self.insn_containing(addr).is_some()
            || self
                .insns
                .range(addr + 1..addr + len as u64)
                .next()
                .is_some()
    }

    fn import_name_of_slot(&self, slot: u64) -> Option<&str> {
        self.prog.import_slots.get(&slot).map(String::as_str)
    }

    fn call_is_noreturn(&self, d: &Decoded) -> bool {
        if !matches!(d.flow, FlowKind::Call) {
            return false;
        }
        if d.targets.iter().any(|t| self.noreturn.contains(t)) {
            return true;
        }
        d.indirect_via
            .and_then(|s| self.import_name_of_slot(s))
            .is_some_and(|n| self.names.contains(n))
    }

    /// Recursive descent from `start`.
    fn disassemble(&mut self, start: u64) {
        let mut work = vec![start];
        while let Some(a) = work.pop() {
            if self.insns.contains_key(&a) {
                continue;
            }
            let Some(mut d) = self.decode(a) else {
                continue;
            };
            if self.conflicts(a, d.len) {
                continue;
            }
            if let Some(t) = self.switches.get(&a) {
                d.targets = t.targets.clone();
            }
            for t in self.switches.values() {
                for &(from, to, acc) in &t.refs {
                    if from == a && !d.data_refs.iter().any(|r| r.0 == to) {
                        d.data_refs.push((to, acc));
                    }
                }
            }
            let next = a + d.len as u64;
            let ft = (d.has_fallthrough && !self.call_is_noreturn(&d)).then_some(next);
            for &t in &d.targets {
                if matches!(d.flow, FlowKind::Call | FlowKind::CondCall)
                    && self.prog.memory.is_executable(t)
                {
                    self.funcs.entry(t).or_insert(FuncSource::Call);
                }
                work.push(t);
            }
            if let Some(f) = ft {
                work.push(f);
            }
            self.insns.insert(a, Insn { d, ft });
        }
    }

    /// PLT-like stub sections: stub starts are found by a linear sweep
    /// (each stub begins after the previous stub's final jump, skipping
    /// padding NOPs) and then disassembled by flow; stubs that jump through
    /// an import slot become thunks (Ghidra `ElfDefaultGotPltMarkup`).
    fn markup_plt(&mut self) {
        if self.prog.format != "ELF" {
            return;
        }
        let plt_blocks: Vec<_> = self
            .prog
            .memory
            .blocks()
            .iter()
            .filter(|b| {
                matches!(b.name.as_str(), ".plt" | ".plt.sec" | ".plt.got" | ".iplt")
                    && b.perms.execute
            })
            .map(|b| (b.name.clone(), b.start, b.end()))
            .collect();
        for (name, start, end) in plt_blocks {
            let mut a = start;
            let mut stubs = vec![];
            let mut prev_terminated = true;
            let mut prev: Option<(u64, String)> = None;
            let mut prev_len = 0u64;
            while a < end {
                let Some(d) = self.decode(a) else {
                    a += 1;
                    continue;
                };
                let is_nop = d.mnemonic.starts_with("NOP");
                if prev_terminated && !is_nop {
                    stubs.push(a);
                    prev_terminated = false;
                }
                if !d.has_fallthrough {
                    prev_terminated = true;
                }
                if let Some(slot) = d.indirect_via.filter(|_| d.flow == FlowKind::Jump) {
                    if let Some(imp) = self.import_name_of_slot(slot).map(str::to_string) {
                        // The thunk starts at the jump, or at the landing pad
                        // (ENDBR64/BTI) immediately before it.
                        let entry = match prev {
                            Some((pa, ref pm)) if is_landing_pad(pm) && pa + prev_len == a => pa,
                            _ => a,
                        };
                        self.funcs.insert(entry, FuncSource::Plt);
                        self.thunks.insert(entry, ThunkTarget::External(imp));
                    }
                }
                prev = Some((a, d.mnemonic.clone()));
                prev_len = d.len as u64;
                a += d.len as u64;
            }
            if name == ".plt" {
                self.funcs.entry(start).or_insert(FuncSource::Plt);
            }
            for stub in stubs {
                self.disassemble(stub);
            }
        }
    }

    /// Creates functions at undefined code addresses referenced by
    /// instruction operands or relocated pointers.
    fn pointer_functions(&mut self) -> bool {
        let mut cands = BTreeSet::new();
        let jump_tables: HashSet<u64> = self
            .insns
            .values()
            .filter(|i| i.d.indirect && i.d.flow == FlowKind::Jump)
            .flat_map(|i| i.d.data_refs.iter().map(|r| r.0))
            .collect();
        for i in self.insns.values() {
            for &(t, acc) in &i.d.data_refs {
                if acc == Access::Address && self.prog.memory.is_executable(t) {
                    cands.insert(t);
                }
            }
        }
        let in_table = |slot: u64| {
            self.switches
                .values()
                .any(|t| slot >= t.start && slot < t.end)
        };
        for (&slot, &t) in &self.prog.pointers {
            if !jump_tables.contains(&slot) && !in_table(slot) && self.prog.memory.is_executable(t)
            {
                cands.insert(t);
            }
        }
        let mut changed = false;
        let code_targets: Vec<u64> = self.prog.code_pointers.values().copied().collect();
        for t in code_targets {
            if self.prog.memory.is_executable(t)
                && !self.insns.contains_key(&t)
                && self.insn_containing(t).is_none()
                && self.valid_code(t, 2)
            {
                self.code_boundaries.insert(t);
                self.disassemble(t);
                changed = true;
            }
        }
        for t in cands {
            if self.insns.contains_key(&t)
                || self.insn_containing(t).is_some()
                || self.funcs.contains_key(&t)
            {
                continue;
            }
            if !self.valid_code(t, 2) {
                continue;
            }
            self.funcs.insert(t, FuncSource::Pointer);
            self.extra_funcs.insert(t, FuncSource::Pointer);
            self.disassemble(t);
            changed = true;
        }
        changed
    }

    /// True if `n` instructions (or fewer ending in a terminator) decode by
    /// straight-line flow from `addr` without running into existing code.
    fn valid_code(&self, addr: u64, n: u32) -> bool {
        let mut a = addr;
        for k in 0..n.max(1) {
            if k > 0 && self.insns.contains_key(&a) {
                return true;
            }
            let Some(d) = self.decode(a) else {
                return false;
            };
            if self.conflicts(a, d.len) {
                return false;
            }
            if !d.has_fallthrough {
                return true;
            }
            a += d.len as u64;
        }
        true
    }

    /// Byte-pattern function start search over undefined executable bytes.
    fn pattern_pass(&mut self) -> bool {
        if self.patterns.rules.is_empty() {
            return false;
        }
        let mut found: Vec<(u64, Action)> = vec![];
        for b in self
            .prog
            .memory
            .blocks()
            .iter()
            .filter(|b| b.perms.execute && b.is_initialized())
        {
            let mut a = b.start;
            while a < b.start + b.data.len() as u64 {
                if let Some(i) = self.insn_containing(a) {
                    a = i.end();
                    continue;
                }
                let off = (a - b.start) as usize;
                let bytes = &b.data[off..];
                'rules: for rule in &self.patterns.rules {
                    if let Some((mark, bits)) = rule.align {
                        if bits > 0 && (a & ((1 << bits) - 1)) != mark {
                            continue;
                        }
                    }
                    if !rule.post.iter().any(|p| p.matches(bytes)) {
                        continue;
                    }
                    if !rule.pre.is_empty() {
                        let ok = rule.pre.iter().any(|p| {
                            let n = p.len();
                            off >= n && p.matches(&b.data[off - n..off])
                        });
                        if !ok {
                            continue;
                        }
                    }
                    if rule.constraints.after_defined
                        && off > 0
                        && self.insn_containing(a - 1).is_none()
                    {
                        continue;
                    }
                    // Rules that only apply at existing functions never
                    // discover one; `after="data"` needs defined data or no
                    // memory before the match (ra defines no data yet).
                    if rule.constraints.existing_function
                        || (rule.constraints.after_data && off > 0)
                    {
                        continue;
                    }
                    // The first action of the first matching rule wins.
                    if let Some(act) = rule.actions.first() {
                        found.push((a, *act));
                        break 'rules;
                    }
                }
                a += 1;
            }
        }
        let mut changed = false;
        for (a, act) in found {
            if self.insns.contains_key(&a) || self.insn_containing(a).is_some() {
                continue;
            }
            let rule_valid = self
                .patterns
                .rules
                .iter()
                .map(|r| r.constraints.valid_code)
                .max()
                .unwrap_or(0)
                .clamp(1, 5);
            if !self.valid_code(a, rule_valid) {
                continue;
            }
            match act {
                Action::FuncStart | Action::PossibleFuncStart => {
                    self.funcs.insert(a, FuncSource::Pattern);
                    self.extra_funcs.insert(a, FuncSource::Pattern);
                }
                Action::CodeBoundary => {
                    self.code_boundaries.insert(a);
                }
            }
            self.disassemble(a);
            changed = true;
        }
        changed
    }

    /// A function whose first real instruction is an unconditional jump to
    /// another function or through an import slot is a thunk.
    fn detect_thunks(&mut self) {
        let entries: Vec<u64> = self.funcs.keys().copied().collect();
        for e in entries {
            if self.thunks.contains_key(&e) {
                continue;
            }
            let mut a = e;
            let mut steps = 0;
            while let Some(i) = self.insns.get(&a) {
                steps += 1;
                if steps > 3 {
                    break;
                }
                if is_marker(&i.d.mnemonic) && i.ft.is_some() {
                    a = i.end();
                    continue;
                }
                // A lone call to a non-returning function acts like a jump
                // (Ghidra makes such stubs, e.g. `main.cold`, thunks).
                if i.d.flow == FlowKind::Call && i.ft.is_none() {
                    if let [t] = i.d.targets[..] {
                        if t != e && self.funcs.contains_key(&t) {
                            self.thunks.insert(e, ThunkTarget::Internal(t));
                        }
                    }
                }
                if i.d.flow == FlowKind::Jump && !i.d.has_fallthrough {
                    if let [t] = i.d.targets[..] {
                        // CreateThunkFunctionCmd creates the thunked function
                        // when it does not exist yet.
                        if t != e && self.insns.contains_key(&t) {
                            self.funcs.entry(t).or_insert(FuncSource::Call);
                            self.thunks.insert(e, ThunkTarget::Internal(t));
                        }
                    } else if let Some(name) =
                        i.d.indirect_via.and_then(|s| self.import_name_of_slot(s))
                    {
                        self.thunks
                            .insert(e, ThunkTarget::External(name.to_string()));
                    }
                }
                break;
            }
        }
    }

    /// Recovers jump tables for unresolved indirect jumps and disassembles
    /// the cases (stand-in for `DecompilerSwitchAnalyzer`).
    fn resolve_switches(&mut self) -> bool {
        let jumps: Vec<u64> = self
            .insns
            .values()
            .filter(|i| {
                i.d.flow == FlowKind::Jump
                    && i.d.indirect
                    && i.d.targets.is_empty()
                    && i.d.indirect_via.is_none()
            })
            .map(|i| i.d.addr)
            .filter(|a| !self.switches.contains_key(a))
            .collect();
        let calls: Vec<u64> = self
            .insns
            .values()
            .filter(|i| {
                self.opts.call_tables
                    && i.d.flow == FlowKind::Call
                    && i.d.indirect
                    && i.d.targets.is_empty()
                    && !i.d.addends.is_empty()
            })
            .map(|i| i.d.addr)
            .filter(|a| !self.switches.contains_key(a))
            .collect();
        let mut changed = false;
        for c in calls {
            let ci = &self.insns[&c];
            let Some(table) = switch::recover_call_table(
                ci,
                &self.prog.memory,
                self.prog.big_endian,
                self.prog.pointer_size,
                |t| {
                    self.insns.contains_key(&t)
                        || (self.insn_containing(t).is_none() && self.valid_code(t, 2))
                },
            ) else {
                continue;
            };
            for &t in &table.targets {
                self.funcs.entry(t).or_insert(FuncSource::Call);
                self.extra_funcs.entry(t).or_insert(FuncSource::Pointer);
            }
            self.apply_table(c, table);
            changed = true;
        }
        for j in jumps {
            let Some(table) = switch::recover(
                j,
                &self.insns,
                &self.prog.memory,
                self.prog.big_endian,
                self.prog.pointer_size,
            ) else {
                continue;
            };
            self.apply_table(j, table);
            changed = true;
        }
        changed
    }

    /// Block-local constant propagation (a reduced `ConstantPropagationAnalyzer`):
    /// re-decodes every instruction with the register constants flowing in
    /// from its basic-block predecessor, so references through registers
    /// (`ADRP`+`LDR`, `LEA`+`MOV [reg]`) land on the instruction that uses them.
    /// State is reset at block starts and after calls.
    fn propagate_constants(&mut self) {
        let mut starts: HashSet<u64> = self.funcs.keys().copied().collect();
        for i in self.insns.values() {
            starts.extend(i.d.targets.iter().copied());
        }
        let args = self.lang.int_args.clone();
        let mut state = ra_sleigh::RegState::default();
        // Register -> instruction that last wrote its constant value.
        let mut writer: Vec<(pcode::VarNode, u64)> = vec![];
        let mut prev_ft: Option<u64> = None;
        let addrs: Vec<u64> = self.insns.keys().copied().collect();
        let mut decoder = self.lang.decoder();
        let mut param_refs: Vec<(u64, u64)> = vec![];
        for a in addrs {
            if starts.contains(&a) || prev_ft != Some(a) {
                state.clear();
                writer.clear();
            }
            let Some(bytes) = self.prog.memory.bytes_from(a) else {
                continue;
            };
            let before = state.0.clone();
            let Some(nd) = decoder.decode_in(a, bytes, Some(&mut state)) else {
                state.clear();
                writer.clear();
                continue;
            };
            for &(v, val) in &state.0 {
                if !before.contains(&(v, val)) {
                    writer.retain(|(w, _)| *w != v);
                    writer.push((v, a));
                }
            }
            writer.retain(|(w, _)| state.0.iter().any(|(v, _)| v == w));
            let i = self.insns.get_mut(&a).unwrap();
            let mut refs = nd.data_refs;
            for r in self
                .switches
                .values()
                .flat_map(|t| t.refs.iter())
                .filter(|r| r.0 == a)
            {
                if !refs.iter().any(|x| x.0 == r.1) {
                    refs.push((r.1, r.2));
                }
            }
            i.d.data_refs = refs;
            if matches!(i.d.flow, FlowKind::Call | FlowKind::CondCall) {
                // Constant pointers passed in parameter registers are
                // referenced from the instruction that set them.
                for &(v, val) in &state.0 {
                    if args.contains(&v) && self.prog.memory.is_mapped(val) {
                        if let Some(&(_, w)) = writer.iter().find(|(r, _)| *r == v) {
                            param_refs.push((w, val));
                        }
                    }
                }
                state.clear();
                writer.clear();
            }
            prev_ft = i.ft;
        }
        for (w, val) in param_refs {
            if let Some(i) = self.insns.get_mut(&w) {
                if !i.d.data_refs.iter().any(|r| r.0 == val) {
                    i.d.data_refs.push((val, Access::Address));
                }
            }
        }
    }

    fn apply_table(&mut self, at: u64, table: switch::Table) {
        if let Some(i) = self.insns.get_mut(&at) {
            i.d.targets = table.targets.clone();
        }
        for &(from, to, acc) in &table.refs {
            if let Some(i) = self.insns.get_mut(&from) {
                if !i.d.data_refs.iter().any(|r| r.0 == to) {
                    i.d.data_refs.push((to, acc));
                }
            }
        }
        let targets = table.targets.clone();
        self.switches.insert(at, table);
        for t in targets {
            self.disassemble(t);
        }
    }

    fn function_name(&self, entry: u64) -> Option<&str> {
        let syms = &self.prog.symbols;
        let idx = syms.partition_point(|s| s.addr < entry);
        let mut best = None;
        for s in syms[idx..].iter().take_while(|s| s.addr == entry) {
            if s.is_function {
                return Some(&s.name);
            }
            best.get_or_insert(s.name.as_str());
        }
        best
    }

    fn body_of(&self, entry: u64) -> BTreeSet<u64> {
        let mut seen = BTreeSet::new();
        let mut work = vec![entry];
        while let Some(a) = work.pop() {
            if (a != entry && self.funcs.contains_key(&a)) || !seen.insert(a) {
                continue;
            }
            let Some(i) = self.insns.get(&a) else {
                seen.remove(&a);
                continue;
            };
            if let Some(f) = i.ft {
                work.push(f);
            }
            if !matches!(i.d.flow, FlowKind::Call | FlowKind::CondCall) {
                work.extend(i.d.targets.iter().copied());
            }
        }
        seen
    }

    /// Known plus discovered non-returning functions. Discovery is a port of
    /// `FindNoReturnFunctionsAnalyzer`: a call site is suspicious when what
    /// follows it looks like it is never reached (`checkNonReturningIndicators`);
    /// a target becomes non-returning after `NORETURN_EVIDENCE` suspicious
    /// call sites, or when every path through it ends in a call to a
    /// non-returning function (`targetOnlyCallsNoReturn`).
    fn compute_noreturn(&mut self) {
        let mut nr: HashSet<u64> = self.noreturn.clone();
        for &e in self.funcs.keys() {
            let named = self
                .function_name(e)
                .is_some_and(|n| self.names.contains(n));
            let thunk_named = matches!(self.thunks.get(&e), Some(ThunkTarget::External(n)) if self.names.contains(n));
            if named || thunk_named {
                nr.insert(e);
            }
        }
        // References to each address: (from, is_call, is_read_or_write).
        let mut refs_to: BTreeMap<u64, Vec<(u64, bool, bool)>> = BTreeMap::new();
        let mut callers: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
        for i in self.insns.values() {
            let is_call = matches!(i.d.flow, FlowKind::Call | FlowKind::CondCall);
            for &t in &i.d.targets {
                refs_to
                    .entry(t)
                    .or_default()
                    .push((i.d.addr, is_call, false));
                if is_call {
                    callers.entry(t).or_default().push(i.d.addr);
                }
            }
            for &(t, acc) in &i.d.data_refs {
                refs_to
                    .entry(t)
                    .or_default()
                    .push((i.d.addr, false, acc != Access::Address));
            }
        }
        let entries: Vec<u64> = self.funcs.keys().copied().collect();
        loop {
            let mut changed = false;
            self.inherit_thunk_noreturn(&mut nr);
            let mut checked: HashSet<u64> = HashSet::new();
            for i in self.insns.values() {
                if !matches!(i.d.flow, FlowKind::Call)
                    || !i.d.has_fallthrough
                    || !checked.insert(i.d.addr)
                {
                    continue;
                }
                if !self.noreturn_indicators(i, &entries, &refs_to) {
                    continue;
                }
                for &t in &i.d.targets {
                    if nr.contains(&t) {
                        continue;
                    }
                    let mut count = 1;
                    for &c in callers.get(&t).map(Vec::as_slice).unwrap_or(&[]) {
                        if !checked.insert(c) {
                            continue;
                        }
                        if self
                            .insns
                            .get(&c)
                            .is_some_and(|ci| self.noreturn_indicators(ci, &entries, &refs_to))
                        {
                            count += 1;
                            if count >= NORETURN_EVIDENCE {
                                break;
                            }
                        }
                    }
                    if count >= NORETURN_EVIDENCE || self.only_calls_noreturn(t, &nr) {
                        nr.insert(t);
                        changed = true;
                    }
                }
            }
            if !changed {
                break;
            }
        }
        self.inherit_thunk_noreturn(&mut nr);
        self.noreturn = nr;
    }

    fn inherit_thunk_noreturn(&self, nr: &mut HashSet<u64>) {
        loop {
            let add: Vec<u64> = self
                .thunks
                .iter()
                .filter(|(e, t)| {
                    !nr.contains(e) && matches!(t, ThunkTarget::Internal(t) if nr.contains(t))
                })
                .map(|(e, _)| *e)
                .collect();
            if add.is_empty() {
                break;
            }
            nr.extend(add);
        }
    }

    /// `checkNonReturningIndicators`: walks the fallthrough chain after a
    /// call looking for signs it is never executed.
    fn noreturn_indicators(
        &self,
        call: &Insn,
        entries: &[u64],
        refs_to: &BTreeMap<u64, Vec<(u64, bool, bool)>>,
    ) -> bool {
        let mut ft = call.end();
        let calling = self.function_containing(call.d.addr);
        let next_func = entries.get(entries.partition_point(|e| *e < ft)).copied();
        let x86 = self.lang.id.starts_with("x86");
        loop {
            if next_func == Some(ft) {
                return true; // function defined after call
            }
            let Some(i) = self.insns.get(&ft) else {
                return true; // falls into data / undefined bytes
            };
            if next_func.is_some_and(|nf| nf > ft && nf < i.end()) {
                return true; // function defined inside instruction after call
            }
            for &(from, is_call, rw) in refs_to.get(&ft).map(Vec::as_slice).unwrap_or(&[]) {
                if is_call {
                    return true; // call reference after call
                }
                if rw && from < ft && calling.is_some() && self.function_containing(from) == calling
                {
                    return true; // data reference from same function after call
                }
            }
            if x86 && i.d.mnemonic == "INT3" {
                return true;
            }
            if i.d.flow == FlowKind::Fallthrough && i.d.has_fallthrough {
                ft = i.end();
            } else {
                return false;
            }
        }
    }

    fn function_containing(&self, addr: u64) -> Option<u64> {
        // Nearest preceding entry whose flow reaches `addr` is too costly to
        // compute per query; the preceding entry is what Ghidra's contiguous
        // bodies give in practice.
        self.funcs.range(..=addr).next_back().map(|(e, _)| *e)
    }

    /// `targetOnlyCallsNoReturn`: every path from `entry` ends in a call to
    /// a non-returning function.
    fn only_calls_noreturn(&self, entry: u64, nr: &HashSet<u64>) -> bool {
        let mut work = vec![entry];
        let mut seen = HashSet::new();
        let mut hit = false;
        while let Some(a) = work.pop() {
            if !seen.insert(a) {
                continue;
            }
            let Some(i) = self.insns.get(&a) else {
                return false;
            };
            match i.d.flow {
                FlowKind::Return | FlowKind::CondReturn | FlowKind::Terminator => return false,
                FlowKind::Call | FlowKind::CondCall => {
                    for t in &i.d.targets {
                        if nr.contains(t) {
                            hit = true;
                        } else if i.ft.is_none() {
                            return false;
                        }
                    }
                    if i.d.targets.is_empty() && i.ft.is_none() {
                        return false;
                    }
                    if let Some(f) = i.ft {
                        work.push(f);
                    }
                }
                FlowKind::Jump | FlowKind::CondJump => {
                    if i.d.targets.is_empty() && i.ft.is_none() {
                        return false; // unresolved indirect jump
                    }
                    for &t in &i.d.targets {
                        if nr.contains(&t) {
                            hit = true;
                        } else {
                            work.push(t);
                        }
                    }
                    if let Some(f) = i.ft {
                        work.push(f);
                    }
                }
                FlowKind::Fallthrough => match i.ft {
                    Some(f) => work.push(f),
                    None => return false,
                },
            }
        }
        hit
    }

    fn build_functions(&self) -> BTreeMap<u64, Function> {
        let mut out = BTreeMap::new();
        for (&e, &source) in &self.funcs {
            if !self.insns.contains_key(&e) {
                continue;
            }
            let body = ranges(self.body_of(e).iter().map(|a| (*a, self.insns[a].end())));
            out.insert(
                e,
                Function {
                    entry: e,
                    source,
                    thunk: self.thunks.get(&e).cloned(),
                    no_return: self.noreturn.contains(&e),
                    body,
                },
            );
        }
        out
    }
}

fn is_tail_call(i: &Insn, is_func: impl Fn(u64) -> bool) -> bool {
    i.d.flow == FlowKind::Jump
        && !i.d.has_fallthrough
        && matches!(i.d.targets[..], [t] if is_func(t))
}

/// Evidence threshold of `FindNoReturnFunctionsAnalyzer` ("Function
/// Non-return Threshold", default 3).
const NORETURN_EVIDENCE: u32 = 3;

/// Instructions that may precede a thunk's jump (CET/BTI landing pads, NOP).
fn is_marker(m: &str) -> bool {
    is_landing_pad(m) || m == "NOP"
}

fn is_landing_pad(m: &str) -> bool {
    matches!(m, "ENDBR64" | "ENDBR32" | "BTI")
}

fn ranges(mut it: impl Iterator<Item = (u64, u64)>) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = vec![];
    if let Some(first) = it.next() {
        out.push(first);
    }
    for (s, e) in it {
        let last = out.last_mut().unwrap();
        if s <= last.1 {
            last.1 = last.1.max(e);
        } else {
            out.push((s, e));
        }
    }
    out
}

/// One demangled name per address (see `report`).
fn demangle_symbols(
    prog: &Program,
    kind: ra_demangle::ProgramKind,
) -> BTreeMap<u64, ra_demangle::Demangled> {
    let mut by_addr: BTreeMap<u64, Vec<&ra_loader::LoadedSymbol>> = BTreeMap::new();
    for s in &prog.symbols {
        by_addr.entry(s.addr).or_default().push(s);
    }
    let mut out = BTreeMap::new();
    for (addr, mut syms) in by_addr {
        // Primary first: function symbols, then unversioned names.
        syms.sort_by_key(|s| (!s.is_function, s.name.contains('@')));
        if let Some(d) = syms
            .iter()
            .find_map(|s| ra_demangle::demangle_symbol(&s.name, kind))
        {
            out.insert(addr, d);
        }
    }
    out
}

/// Ghidra default label: prefix plus the address zero-padded to 8 digits.
fn ghidra_default_name(prefix: &str, addr: u64) -> String {
    format!("{prefix}_{addr:08x}")
}

/// Converts analysis results into the normalized report.
pub fn report(prog: &Program, analysis: &Analysis) -> AnalysisReport {
    let mem = &prog.memory;
    let mut r = AnalysisReport {
        schema_version: SCHEMA_VERSION,
        producer: format!("ra {}", env!("CARGO_PKG_VERSION")),
        binary: BinaryInfo {
            path: prog.path.clone(),
            sha256: prog.sha256.clone(),
            format: prog.format.clone(),
            language: prog.language.clone(),
            image_base: prog.image_base,
        },
        ..Default::default()
    };
    r.memory = mem
        .blocks()
        .iter()
        .map(|b| MemoryInfo {
            name: b.name.clone(),
            start: b.start,
            end: b.end(),
            read: b.perms.read,
            write: b.perms.write,
            execute: b.perms.execute,
            initialized: b.is_initialized(),
        })
        .collect();

    // Demangler analyzers (AbstractDemanglerAnalyzer): one demangled name
    // per address, from the primary symbol or else the first alternate that
    // demangles; it becomes the primary name, the mangled one stays a label.
    let kind = ra_demangle::ProgramKind {
        windows: prog.format == "PE",
        rust: prog.is_rust,
    };
    let demangled = demangle_symbols(prog, kind);

    let mut named: HashSet<u64> = HashSet::new();
    for s in &prog.symbols {
        let kind = if analysis.functions.contains_key(&s.addr) {
            "function"
        } else if s.is_data {
            "data"
        } else {
            "label"
        };
        named.insert(s.addr);
        r.symbols.push(SymbolInfo {
            addr: s.addr,
            name: s.name.clone(),
            namespace: None,
            kind: kind.into(),
            source: s.source,
        });
    }
    for (&addr, d) in &demangled {
        let kind = if analysis.functions.contains_key(&addr) {
            "function"
        } else if prog.symbols.iter().any(|s| s.addr == addr && s.is_data) {
            "data"
        } else {
            "label"
        };
        r.symbols.push(SymbolInfo {
            addr,
            name: d.name.clone(),
            namespace: d.namespace_string(),
            kind: kind.into(),
            source: SymbolSource::Analysis,
        });
    }
    let import_names: std::collections::HashMap<&str, ra_demangle::Demangled> = prog
        .imports
        .iter()
        .filter_map(|i| ra_demangle::demangle_symbol(&i.name, kind).map(|d| (i.name.as_str(), d)))
        .collect();

    for f in analysis.functions.values() {
        // Name priority: demangled name, function symbol, loader fallback
        // name (`entry`, `_INIT_0`, `_DT_INIT`), other label, thunked
        // import, `FUN_`.
        let at: Vec<&ra_loader::LoadedSymbol> =
            prog.symbols.iter().filter(|s| s.addr == f.entry).collect();
        let sym_name = at
            .iter()
            .find(|s| s.is_function)
            .map(|s| s.name.clone())
            .or_else(|| prog.fallback_names.get(&f.entry).cloned())
            .or_else(|| {
                at.iter()
                    .find(|s| !s.name.starts_with("__DT_"))
                    .map(|s| s.name.clone())
            });
        let (name, namespace, source) = match (demangled.get(&f.entry), &sym_name, &f.thunk) {
            (Some(d), _, _) => (d.name.clone(), d.namespace_string(), SymbolSource::Analysis),
            (None, Some(n), _) => (n.clone(), None, SymbolSource::Imported),
            (None, None, Some(ThunkTarget::External(n))) => match import_names.get(n.as_str()) {
                Some(d) => (d.name.clone(), d.namespace_string(), SymbolSource::Default),
                None => (n.clone(), None, SymbolSource::Default),
            },
            (None, None, _) => (
                ghidra_default_name("FUN", f.entry),
                None,
                SymbolSource::Default,
            ),
        };
        if !at.iter().any(|s| s.name == name) && !demangled.contains_key(&f.entry) {
            r.symbols.push(SymbolInfo {
                addr: f.entry,
                name: name.clone(),
                namespace: namespace.clone(),
                kind: "function".into(),
                source,
            });
        }
        r.functions.push(FunctionInfo {
            entry: f.entry,
            name,
            namespace,
            source,
            thunk: f.thunk.is_some(),
            thunk_target: match f.thunk {
                Some(ThunkTarget::Internal(t)) => Some(t),
                _ => None,
            },
            no_return: f.no_return,
            body: f.body.clone(),
        });
    }

    r.imports = prog
        .imports
        .iter()
        .map(|i| {
            let d = import_names.get(i.name.as_str());
            ImportInfo {
                name: d.map(|d| d.name.clone()).unwrap_or_else(|| i.name.clone()),
                namespace: d.and_then(|d| d.namespace_string()),
                library: i.library.clone(),
                addr: i.slot,
            }
        })
        .collect();
    r.exports = prog
        .exports
        .iter()
        .map(|(a, n)| ExportInfo {
            addr: *a,
            name: n.clone(),
        })
        .collect();
    let exported: HashSet<u64> = prog.exports.iter().map(|(a, _)| *a).collect();
    for (&addr, d) in &demangled {
        if exported.contains(&addr) {
            r.exports.push(ExportInfo {
                addr,
                name: d.name.clone(),
            });
        }
    }

    // Owning function of each instruction, for tail-call classification: a
    // jump back to the function's own entry is a loop, not a tail call.
    let mut owner: std::collections::HashMap<u64, u64> = std::collections::HashMap::new();
    for f in analysis.functions.values() {
        for &(s, e) in &f.body {
            for (&a, _) in analysis.insns.range(s..e) {
                owner.entry(a).or_insert(f.entry);
            }
        }
    }
    let tail = |i: &Insn| {
        is_tail_call(i, |t| {
            analysis.functions.contains_key(&t) && owner.get(&i.d.addr) != Some(&t)
        })
    };
    for i in analysis.insns.values() {
        r.instructions.push(InstructionInfo {
            addr: i.d.addr,
            len: i.d.len,
            mnemonic: i.d.mnemonic.clone(),
        });
        let flow_kind = match i.d.flow {
            FlowKind::Call | FlowKind::CondCall => XrefKind::Call,
            // Jump with fallthrough: PLT0 call override.
            FlowKind::Jump if i.d.has_fallthrough => XrefKind::Call,
            _ if tail(i) => XrefKind::Call,
            FlowKind::CondJump => XrefKind::CondJump,
            _ => XrefKind::Jump,
        };
        for &t in &i.d.targets {
            // Ghidra records no flow reference from an instruction to itself
            // (`HLT` is `goto inst_start`).
            if mem.is_mapped(t) && t != i.d.addr {
                r.xrefs.push(XrefInfo {
                    from: i.d.addr,
                    to: t,
                    kind: flow_kind,
                });
            }
        }
        for &(t, acc) in &i.d.data_refs {
            if !mem.is_mapped(t) || i.d.targets.contains(&t) {
                continue;
            }
            let kind = match acc {
                // The pointer slot of an indirect jump is a DATA ref (READ for calls).
                Access::Read if i.d.indirect_via == Some(t) && i.d.flow == FlowKind::Jump => {
                    XrefKind::Data
                }
                Access::Read => XrefKind::Read,
                Access::Write => XrefKind::Write,
                Access::Address => XrefKind::Data,
            };
            r.xrefs.push(XrefInfo {
                from: i.d.addr,
                to: t,
                kind,
            });
        }
    }
    for (&slot, &t) in &prog.marked_pointers {
        if mem.is_mapped(t) {
            r.xrefs.push(XrefInfo {
                from: slot,
                to: t,
                kind: XrefKind::Data,
            });
        }
    }

    // Basic blocks (Ghidra BasicBlockModel): a block starts at a labelled
    // instruction (function entry, symbol, or any reference target) or after
    // an instruction that does not fall through or ends a block (jump,
    // return, terminator); calls do not end blocks.
    let mut labels: HashSet<u64> = named;
    labels.extend(analysis.functions.keys().copied());
    labels.extend(r.xrefs.iter().map(|x| x.to));
    labels.extend(analysis.switch_jumps.iter().copied());
    let ends_block = |i: &Insn| {
        i.ft.is_none()
            || matches!(
                i.d.flow,
                FlowKind::Jump
                    | FlowKind::CondJump
                    | FlowKind::Return
                    | FlowKind::CondReturn
                    | FlowKind::Terminator
            )
    };
    let insns = &analysis.insns;
    let mut cur: Option<(u64, u64)> = None;
    let mut blocks: Vec<(u64, u64, u64)> = vec![]; // start, end, last insn
    let mut prev: Option<&Insn> = None;
    for i in insns.values() {
        let a = i.d.addr;
        let contiguous = prev.is_some_and(|p| p.ft == Some(a) && !ends_block(p));
        if !contiguous || labels.contains(&a) {
            if let (Some((s, e)), Some(p)) = (cur, prev) {
                blocks.push((s, e, p.d.addr));
            }
            cur = Some((a, i.end()));
        } else if let Some(c) = cur.as_mut() {
            c.1 = i.end();
        }
        prev = Some(i);
    }
    if let (Some((s, e)), Some(p)) = (cur, prev) {
        blocks.push((s, e, p.d.addr));
    }
    let block_starts: HashSet<u64> = blocks.iter().map(|b| b.0).collect();
    for &(s, e, last) in &blocks {
        r.blocks.push(BlockInfo { start: s, end: e });
        let li = &insns[&last];
        if let Some(ft) = li.ft {
            if li.d.flow != FlowKind::Jump && block_starts.contains(&ft) {
                r.edges.push(EdgeInfo {
                    from: s,
                    to: ft,
                    kind: EdgeKind::Fallthrough,
                });
            }
        }
        let overridden = li.d.flow == FlowKind::Jump && li.d.has_fallthrough;
        if matches!(li.d.flow, FlowKind::Jump | FlowKind::CondJump) && !tail(li) && !overridden {
            let kind = if li.d.flow == FlowKind::CondJump {
                EdgeKind::CondJump
            } else {
                EdgeKind::Jump
            };
            for &t in &li.d.targets {
                if block_starts.contains(&t) && t != last {
                    r.edges.push(EdgeInfo {
                        from: s,
                        to: t,
                        kind,
                    });
                }
            }
        }
    }
    r.normalize();
    r
}

#[cfg(test)]
mod tests {
    #[test]
    fn ranges_merge_adjacent() {
        assert_eq!(
            super::ranges([(0, 2), (2, 5), (7, 8)].into_iter()),
            vec![(0, 5), (7, 8)]
        );
    }
}
