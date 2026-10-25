//! SLEIGH front end: compiles Ghidra `.slaspec` files (via Icicle's SLEIGH
//! implementation) and turns each decoded instruction into the flow and
//! reference facts the analyzers need.
//!
//! Java counterparts: `SleighLanguage`, `InstructionPrototype.getFlowType`,
//! `getFlows`, and the operand reference scan in `OperandReferenceAnalyzer`.

use std::path::{Path, PathBuf};

use pcode::{BranchHint, Op, Value, VarNode};
use sleigh_runtime::{Runtime, SleighData};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("language {0} not found in any .ldefs under {1}")]
    LanguageNotFound(String, PathBuf),
    #[error("failed to build SLEIGH language {0}: {1}")]
    Build(String, String),
}

/// A compiled SLEIGH language.
pub struct Language {
    pub id: String,
    /// The `.ldefs` file that declared this language.
    pub ldefs: PathBuf,
    pub sleigh: SleighData,
    pub initial_ctx: u64,
    pub big_endian: bool,
    /// Address size in bytes.
    pub pointer_size: u32,
    pub pc: VarNode,
    pub sp: VarNode,
    /// Integer parameter registers of the default calling convention (cspec).
    pub int_args: Vec<VarNode>,
}

/// Locates the `Ghidra/Processors` directory: `$RA_PROCESSORS`, then the
/// directory this crate was built from (repo checkout), then `./Processors`.
pub fn default_processors_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("RA_PROCESSORS") {
        return PathBuf::from(p);
    }
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../Ghidra/Processors");
    if repo.is_dir() {
        return repo.canonicalize().unwrap_or(repo);
    }
    PathBuf::from("Processors")
}

/// Finds the `.ldefs` file that declares `lang_id`.
pub fn find_ldefs(processors: &Path, lang_id: &str) -> Option<PathBuf> {
    let needle = format!("id=\"{lang_id}\"");
    let mut dirs: Vec<_> = std::fs::read_dir(processors)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    dirs.sort();
    for dir in dirs {
        let langs = dir.join("data/languages");
        let Ok(entries) = std::fs::read_dir(&langs) else {
            continue;
        };
        let mut files: Vec<_> = entries.flatten().map(|e| e.path()).collect();
        files.sort();
        for f in files {
            if f.extension().is_some_and(|e| e == "ldefs")
                && std::fs::read_to_string(&f).is_ok_and(|s| s.contains(&needle))
            {
                return Some(f);
            }
        }
    }
    None
}

impl Language {
    pub fn load(processors: &Path, lang_id: &str) -> Result<Self, Error> {
        let ldefs = find_ldefs(processors, lang_id)
            .ok_or_else(|| Error::LanguageNotFound(lang_id.into(), processors.into()))?;
        // Ghidra compiles specs without Icicle's `ICICLE` define; matching that
        // keeps instruction semantics identical to the oracle.
        let built = sleigh_compile::ldef::SleighLanguageBuilder::new(&ldefs, lang_id)
            .clear_defines()
            .build()
            .map_err(|e| Error::Build(lang_id.into(), e.to_string()))?;
        let lang = built;
        Ok(Self {
            id: lang_id.into(),
            ldefs,
            initial_ctx: lang.initial_ctx,
            big_endian: matches!(lang.endian, sleigh_compile::ldef::Endianness::Big),
            pointer_size: lang.size / 8,
            pc: lang.pc,
            sp: lang.sp,
            int_args: lang.default_calling_cov.int_args.clone(),
            sleigh: lang.sleigh,
        })
    }

    pub fn decoder(&self) -> Decoder<'_> {
        Decoder {
            lang: self,
            rt: Runtime::new(self.initial_ctx),
        }
    }
}

/// Coarse flow classification (Ghidra `FlowType`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowKind {
    Fallthrough,
    Jump,
    CondJump,
    Call,
    CondCall,
    Return,
    CondReturn,
    /// Instruction with no fallthrough and no known successor (e.g. `HLT`,
    /// `UD2`, faulting trap).
    Terminator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    /// Address computed but not dereferenced in this instruction.
    Address,
}

#[derive(Debug, Clone)]
pub struct Decoded {
    pub addr: u64,
    pub len: u32,
    pub mnemonic: String,
    pub text: String,
    pub flow: FlowKind,
    pub has_fallthrough: bool,
    /// Direct branch/call targets.
    pub targets: Vec<u64>,
    /// Indirect branch/call (target computed at run time).
    pub indirect: bool,
    /// Indirect target read from memory at a constant address
    /// (`JMP [0x1234]`, `CALL qword ptr [RIP+x]`).
    pub indirect_via: Option<u64>,
    /// Constant addresses read, written or computed by the instruction.
    pub data_refs: Vec<(u64, Access)>,
    /// Constants added to a run-time value (e.g. the table base in
    /// `JMP [T + RCX*8]`); candidates for table addresses.
    pub addends: Vec<u64>,
    /// Loads from a run-time computed address (table reads).
    pub indexed_load: bool,
}

pub struct Decoder<'a> {
    lang: &'a Language,
    rt: Runtime,
}

impl Decoder<'_> {
    pub fn language(&self) -> &Language {
        self.lang
    }

    /// Decodes and lifts one instruction. `bytes` must start at `addr`.
    pub fn decode(&mut self, addr: u64, bytes: &[u8]) -> Option<Decoded> {
        self.decode_in(addr, bytes, None)
    }

    /// Like [`decode`](Self::decode), seeding register values from `state`
    /// and writing back the registers known to hold constants afterwards
    /// (block-local constant propagation).
    pub fn decode_in(
        &mut self,
        addr: u64,
        bytes: &[u8],
        state: Option<&mut RegState>,
    ) -> Option<Decoded> {
        let sleigh = &self.lang.sleigh;
        self.rt.context = self.lang.initial_ctx;
        let inst = self.rt.decode(sleigh, addr, bytes)?;
        let len = inst.inst_next.checked_sub(inst.inst_start)? as u32;
        if len == 0 || len as usize > bytes.len() {
            return None;
        }
        let text = self.rt.disasm(sleigh).unwrap_or("").to_string();
        let mnemonic = text
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_uppercase();
        let block = self.rt.lift(sleigh).ok()?.clone();
        let mut d = Decoded {
            addr,
            len,
            mnemonic,
            text,
            flow: FlowKind::Fallthrough,
            has_fallthrough: true,
            targets: Vec::new(),
            indirect: false,
            indirect_via: None,
            data_refs: Vec::new(),
            addends: Vec::new(),
            indexed_load: false,
        };
        let base = d.clone();
        analyze_pcode(
            &block.instructions,
            addr,
            addr + len as u64,
            self.lang.pc,
            &[],
            &mut d,
        );
        if let Some(st) = state {
            // Second pass with incoming register values: only its memory
            // accesses are kept (references at the use site); operand
            // references come from the state-free pass above.
            let mut seeded = base;
            st.0 = analyze_pcode(
                &block.instructions,
                addr,
                addr + len as u64,
                self.lang.pc,
                &st.0.clone(),
                &mut seeded,
            );
            for (a, acc) in seeded.data_refs {
                if acc != Access::Address && !d.data_refs.iter().any(|r| r.0 == a) {
                    d.data_refs.push((a, acc));
                }
            }
        }
        recover_branch_to_next(&block.instructions, addr + len as u64, &mut d);
        Some(d)
    }
}

/// Register values known to be constant at an instruction boundary.
#[derive(Debug, Clone, Default)]
pub struct RegState(pub Vec<(VarNode, u64)>);

impl RegState {
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// Tracks constant values of varnodes within a single instruction.
#[derive(Default)]
struct Consts {
    vals: Vec<(VarNode, u64)>,
    /// Varnodes holding a value loaded from a constant address.
    loaded_from: Vec<(VarNode, u64)>,
}

impl Consts {
    fn get(&self, v: Value) -> Option<u64> {
        match v {
            Value::Const(c, _) => Some(c),
            Value::Var(var) => self
                .vals
                .iter()
                .rev()
                .find(|(k, _)| *k == var)
                .map(|(_, c)| *c),
        }
    }

    fn loaded(&self, v: Value) -> Option<u64> {
        match v {
            Value::Var(var) => self
                .loaded_from
                .iter()
                .rev()
                .find(|(k, _)| *k == var)
                .map(|(_, a)| *a),
            _ => None,
        }
    }

    fn set(&mut self, var: VarNode, val: Option<u64>) {
        self.vals.retain(|(k, _)| !overlaps(*k, var));
        self.loaded_from.retain(|(k, _)| !overlaps(*k, var));
        if let Some(v) = val {
            let bits = var.size as u32 * 8;
            let v = if bits >= 64 {
                v
            } else {
                v & ((1u64 << bits) - 1)
            };
            self.vals.push((var, v));
        }
    }
}

fn overlaps(a: VarNode, b: VarNode) -> bool {
    a.id == b.id
        && (a.offset as u32) < b.offset as u32 + b.size as u32
        && (b.offset as u32) < a.offset as u32 + a.size as u32
}

fn analyze_pcode(
    ops: &[pcode::Instruction],
    inst_start: u64,
    inst_next: u64,
    pc: VarNode,
    seed: &[(VarNode, u64)],
    d: &mut Decoded,
) -> Vec<(VarNode, u64)> {
    let mut c = Consts::default();
    for &(v, val) in seed {
        c.set(v, Some(val));
    }
    // Reading the program counter yields the current instruction address in
    // SLEIGH semantics for most processors.
    c.set(pc, Some(inst_start));

    let last_label = ops.iter().rposition(|o| matches!(o.op, Op::PcodeLabel(_)));
    let mut saw_call = false;
    let mut saw_cond_call = false;
    let mut saw_return = false;
    let mut saw_cond_return = false;
    let mut saw_jump = false;
    let mut saw_cond_jump = false;
    let mut terminates = false;

    for (idx, op) in ops.iter().enumerate() {
        let [a, b] = op.inputs.get();
        match op.op {
            Op::Branch(hint) => {
                let cond = c.get(a);
                let unconditional = cond.is_some_and(|v| v != 0);
                if cond == Some(0) {
                    continue;
                }
                let target = c.get(b);
                // A branch is only final when no internal label follows it,
                // i.e. no p-code path can skip over it.
                let final_branch = unconditional && last_label.is_none_or(|l| l < idx);
                match hint {
                    BranchHint::Call => {
                        if unconditional {
                            saw_call = true;
                        } else {
                            saw_cond_call = true;
                        }
                    }
                    BranchHint::Return => {
                        if final_branch {
                            saw_return = true;
                            terminates = true;
                        } else {
                            saw_cond_return = true;
                        }
                    }
                    BranchHint::Jump => {
                        if target == Some(inst_next) && !final_branch {
                            // Conditional skip to the next instruction.
                            continue;
                        }
                        if final_branch {
                            saw_jump = true;
                            terminates = true;
                        } else {
                            saw_cond_jump = true;
                        }
                    }
                }
                if hint != BranchHint::Return {
                    match target {
                        // REP-style loops branch back to their own start.
                        Some(t) if t == inst_start && !final_branch => {}
                        Some(t) => {
                            if !d.targets.contains(&t) {
                                d.targets.push(t);
                            }
                        }
                        None => {
                            d.indirect = true;
                            if d.indirect_via.is_none() {
                                d.indirect_via = c.loaded(b);
                            }
                        }
                    }
                }
            }
            Op::Exception | Op::Invalid => {
                if last_label.is_none_or(|l| l < idx) {
                    terminates = true;
                }
            }
            Op::Load(_) => {
                if let Some(addr) = c.get(a) {
                    push_ref(d, addr, Access::Read);
                    c.set(op.output, None);
                    c.loaded_from.push((op.output, addr));
                } else {
                    d.indexed_load = true;
                    c.set(op.output, None);
                }
            }
            Op::Store(_) => {
                if let Some(addr) = c.get(a) {
                    push_ref(d, addr, Access::Write);
                }
            }
            _ => {
                if op.output.is_invalid() {
                    continue;
                }
                if op.op == Op::IntAdd {
                    for (k, other) in [(a, b), (b, a)] {
                        if let (Some(v), None) = (c.get(k), c.get(other)) {
                            if v >= 0x100 && !d.addends.contains(&v) {
                                d.addends.push(v);
                            }
                        }
                    }
                }
                let val = eval(op.op, c.get(a), c.get(b), op.output.size);
                // Constants materialized into architectural registers from an
                // immediate operand may be addresses (LEA, MOV imm, ADD #lo12).
                // Plain register copies of known values are not references,
                // and neither is a return address (`inst_next`).
                let immediate = matches!(a, Value::Const(..))
                    || matches!(b, Value::Const(..))
                    || matches!(a, Value::Var(v) if v.is_temp() && c.get(a).is_some());
                if let (Some(v), false, true) = (val, op.output.is_temp(), immediate) {
                    if op.output != pc && v != inst_next && !d.mnemonic.starts_with("ADRP") {
                        push_ref(d, v, Access::Address);
                    }
                }
                c.set(op.output, val);
            }
        }
    }

    d.has_fallthrough = !terminates;
    let out_state: Vec<(VarNode, u64)> = c
        .vals
        .iter()
        .filter(|(v, _)| !v.is_temp() && *v != pc)
        .copied()
        .collect();
    d.flow = if saw_return {
        FlowKind::Return
    } else if saw_jump {
        FlowKind::Jump
    } else if saw_call {
        FlowKind::Call
    } else if saw_cond_call {
        FlowKind::CondCall
    } else if saw_cond_jump {
        FlowKind::CondJump
    } else if saw_cond_return {
        FlowKind::CondReturn
    } else if terminates {
        FlowKind::Terminator
    } else {
        FlowKind::Fallthrough
    };
    out_state
}

/// Icicle's lifter rewrites a branch whose target is `inst_next` into an
/// internal branch to the end of the block, dropping the CALL/JUMP hint
/// (e.g. `CALL $+5`, `JMP $+5`). Ghidra keeps those as real flows, so
/// recover them; the hint comes from the mnemonic.
fn recover_branch_to_next(ops: &[pcode::Instruction], inst_next: u64, d: &mut Decoded) {
    let n = ops.len();
    if n < 2 || d.flow != FlowKind::Fallthrough || !d.targets.is_empty() {
        return;
    }
    let (Op::PcodeBranch(id), Op::PcodeLabel(end)) = (ops[n - 2].op, ops[n - 1].op) else {
        return;
    };
    let cond = ops[n - 2].inputs.first();
    if id != end || !matches!(cond, Value::Const(c, _) if c != 0) {
        return;
    }
    let m = d.mnemonic.as_str();
    let is_call =
        m.contains("CALL") || matches!(m, "BL" | "BLX" | "JAL" | "JALR" | "BSR" | "BALC" | "JSR");
    d.targets.push(inst_next);
    if is_call {
        d.flow = FlowKind::Call;
    } else {
        d.flow = FlowKind::Jump;
        d.has_fallthrough = false;
    }
}

fn push_ref(d: &mut Decoded, addr: u64, access: Access) {
    if let Some(r) = d.data_refs.iter_mut().find(|(a, _)| *a == addr) {
        // Prefer the most specific access for the same address.
        if r.1 == Access::Address {
            r.1 = access;
        }
        return;
    }
    d.data_refs.push((addr, access));
}

fn eval(op: Op, a: Option<u64>, b: Option<u64>, out_size: u8) -> Option<u64> {
    let mask = |v: u64| {
        if out_size >= 8 {
            v
        } else {
            v & ((1u64 << (out_size as u32 * 8)) - 1)
        }
    };
    let r = match op {
        Op::Copy | Op::ZeroExtend => a?,
        Op::SignExtend => a?, // value is masked by `Consts::set`; sign is irrelevant for addresses
        Op::Subpiece(off) => a? >> (off as u32 * 8),
        Op::IntAdd => a?.wrapping_add(b?),
        Op::IntSub => a?.wrapping_sub(b?),
        Op::IntAnd => a? & b?,
        Op::IntOr => a? | b?,
        Op::IntXor => a? ^ b?,
        Op::IntMul => a?.wrapping_mul(b?),
        Op::IntLeft => a?.checked_shl(b? as u32).unwrap_or(0),
        Op::IntRight => a?.checked_shr(b? as u32).unwrap_or(0),
        _ => return None,
    };
    Some(mask(r))
}
