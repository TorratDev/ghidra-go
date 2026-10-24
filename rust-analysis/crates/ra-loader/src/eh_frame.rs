//! `.eh_frame` FDE function starts (Ghidra `GccExceptionAnalyzer` creates
//! functions at every FDE `pc_begin`).

use gimli::{BaseAddresses, CieOrFde, EhFrame, NativeEndian, UnwindSection};
use object::{Object, ObjectSection};
use ra_core::MemoryMap;

use crate::SeedKind;

pub fn function_starts(file: &object::File, mem: &MemoryMap, bias: u64) -> Vec<(u64, SeedKind)> {
    let Some(sec) = file.section_by_name(".eh_frame") else {
        return vec![];
    };
    let Ok(data) = sec.uncompressed_data() else {
        return vec![];
    };
    let mut bases = BaseAddresses::default().set_eh_frame(sec.address() + bias);
    if let Some(text) = file.section_by_name(".text") {
        bases = bases.set_text(text.address() + bias);
    }
    if let Some(got) = file.section_by_name(".got") {
        bases = bases.set_got(got.address() + bias);
    }
    let mut eh = EhFrame::new(&data, NativeEndian);
    eh.set_address_size(if file.is_64() { 8 } else { 4 });
    let mut out = vec![];
    let mut entries = eh.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        if let CieOrFde::Fde(partial) = entry {
            if let Ok(fde) = partial.parse(|s, b, o| s.cie_from_offset(b, o)) {
                let a = fde.initial_address();
                if fde.len() > 0 && mem.is_executable(a) {
                    out.push((a, SeedKind::ExceptionTable));
                }
            }
        }
    }
    out
}
