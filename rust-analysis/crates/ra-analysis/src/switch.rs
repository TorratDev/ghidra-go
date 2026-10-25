//! Jump table recovery for indirect jumps (stand-in for Ghidra's
//! `DecompilerSwitchAnalyzer`, which uses the decompiler). Handles the two
//! common compiler idioms:
//!
//! - absolute: `JMP [T + idx*S]` (non-PIC x86, i386, x86-64 `-fno-pic`)
//! - relative: `LEA r, [T]; MOVSXD x, [r + idx*4]; ADD x, r; JMP x`
//!   (x86-64 PIC, PE x64)
//!
//! The entry count comes from the dominating `CMP idx, N` bound when one is
//! found; otherwise entries are read while they stay inside the function's
//! executable block.

use std::collections::BTreeMap;

use ra_core::MemoryMap;
use ra_sleigh::Access;

use crate::Insn;

#[derive(Debug, Clone)]
pub struct Table {
    pub start: u64,
    pub end: u64,
    pub targets: Vec<u64>,
    /// References Ghidra creates for the table: (from instruction, to, access).
    pub refs: Vec<(u64, u64, Access)>,
}

const MAX_ENTRIES: u64 = 1024;
const LOOKBACK: usize = 12;

pub fn recover(
    jump: u64,
    insns: &BTreeMap<u64, Insn>,
    mem: &MemoryMap,
    be: bool,
    ptr: u32,
) -> Option<Table> {
    let ji = insns.get(&jump)?;
    let exec = mem.block_at(jump)?;
    let prev: Vec<&Insn> = insns
        .range(..jump)
        .rev()
        .take(LOOKBACK)
        .map(|(_, i)| i)
        .collect();
    let bound = find_bound(&prev);

    // Absolute table: the jump itself adds a constant base to idx*S.
    for &base in &ji.d.addends {
        if !mem.is_mapped(base) {
            continue;
        }
        for size in [ptr, 4] {
            if let Some(mut t) = read_table(mem, base, size as u64, bound, be, Some, exec) {
                t.refs.push((jump, base, Access::Address));
                return Some(t);
            }
        }
    }
    // Relative table: the nearest preceding LEA of a mapped address; the
    // entries are signed 32-bit offsets from the table base.
    for (k, i) in prev.iter().enumerate() {
        if i.d.flow != ra_sleigh::FlowKind::Fallthrough {
            break;
        }
        let Some(&(base, _)) =
            i.d.data_refs
                .iter()
                .find(|(a, acc)| *acc == Access::Address && mem.is_mapped(*a))
        else {
            continue;
        };
        let rel = |v: u64| Some(base.wrapping_add(v as u32 as i32 as i64 as u64));
        let mut t = read_table(mem, base, 4, bound, be, rel, exec)?;
        // Ghidra also references the table from the indexed load.
        let _ = k;
        if let Some(load) = prev.iter().find(|p| p.d.indexed_load) {
            t.refs.push((load.d.addr, base, Access::Address));
        }
        return Some(t);
    }
    None
}

/// Function-pointer table behind an indirect call `CALL [T + idx*S]`:
/// entries are read while they point at decodable code in an executable
/// block (Ghidra resolves these through its computed-call references).
pub fn recover_call_table(
    call: &Insn,
    mem: &MemoryMap,
    be: bool,
    ptr: u32,
    is_code: impl Fn(u64) -> bool,
) -> Option<Table> {
    for &base in &call.d.addends {
        if !mem.is_mapped(base) || mem.is_executable(base) {
            continue;
        }
        let mut targets = vec![];
        let mut refs = vec![];
        let mut n = 0u64;
        while n < 64 {
            let slot = base + n * ptr as u64;
            let Some(t) = mem.read_uint(slot, ptr as usize, be) else {
                break;
            };
            if !mem.is_executable(t) || !is_code(t) {
                break;
            }
            if !targets.contains(&t) {
                targets.push(t);
            }
            refs.push((call.d.addr, slot, Access::Read));
            n += 1;
        }
        if n >= 2 {
            return Some(Table {
                start: base,
                end: base + n * ptr as u64,
                targets,
                refs,
            });
        }
    }
    None
}

/// `CMP reg, imm` followed by a conditional jump: entries = imm + 1.
fn find_bound(prev: &[&Insn]) -> Option<u64> {
    for i in prev {
        let text = i.d.text.to_ascii_uppercase();
        if let Some(rest) = text.strip_prefix("CMP ") {
            let imm = rest.rsplit(',').next()?.trim();
            let v = imm
                .strip_prefix("0X")
                .map(|h| u64::from_str_radix(h, 16).ok())
                .unwrap_or_else(|| imm.parse().ok())?;
            return Some(v + 1);
        }
    }
    None
}

fn read_table(
    mem: &MemoryMap,
    base: u64,
    size: u64,
    bound: Option<u64>,
    be: bool,
    decode: impl Fn(u64) -> Option<u64>,
    exec: &ra_core::MemoryBlock,
) -> Option<Table> {
    let limit = bound.unwrap_or(MAX_ENTRIES).min(MAX_ENTRIES);
    let mut targets = vec![];
    let mut n = 0;
    while n < limit {
        let Some(raw) = mem.read_uint(base + n * size, size as usize, be) else {
            break;
        };
        let Some(t) = decode(raw) else { break };
        if !exec.contains(t) {
            break;
        }
        if !targets.contains(&t) {
            targets.push(t);
        }
        n += 1;
    }
    if n < 2 || bound.is_some_and(|b| n < b) {
        return None;
    }
    Some(Table {
        start: base,
        end: base + n * size,
        targets,
        refs: vec![],
    })
}
