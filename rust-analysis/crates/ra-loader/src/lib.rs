//! Binary loaders.
//!
//! Java counterparts: `ElfLoader`, `PeLoader`, `MachoLoader`, `BinaryLoader`
//! and the format analyzers (`ElfAnalyzer`, `PortableExecutableAnalyzer`,
//! `MachoAnalyzer`, `MachoFunctionStartsAnalyzer`, `GccExceptionAnalyzer`
//! function seeding) under `Ghidra/Features/Base`.

mod eh_frame;

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use object::{
    read::elf::{Dyn, ElfFile, FileHeader, ProgramHeader},
    Architecture, BinaryFormat, Endianness, Object, ObjectSection, ObjectSegment, ObjectSymbol,
    ObjectSymbolTable, RelocationTarget, SectionFlags, SectionKind, SymbolKind,
};
use ra_core::{MemoryBlock, MemoryMap, Perms, SymbolSource};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedSymbol {
    pub addr: u64,
    pub name: String,
    pub is_function: bool,
    pub is_data: bool,
    pub source: SymbolSource,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Import {
    pub name: String,
    pub library: Option<String>,
    /// Pointer slot (GOT/IAT/la_symbol_ptr) resolved to this import, if any.
    pub slot: Option<u64>,
}

/// Why an address is a function start candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SeedKind {
    Entry,
    Export,
    Symbol,
    InitArray,
    ExceptionTable,
    FunctionStarts,
}

#[derive(Debug, Clone)]
pub struct Program {
    pub path: String,
    pub sha256: String,
    pub format: String,
    pub language: String,
    pub image_base: u64,
    pub big_endian: bool,
    pub pointer_size: u32,
    pub memory: MemoryMap,
    pub symbols: Vec<LoadedSymbol>,
    pub imports: Vec<Import>,
    pub exports: Vec<(u64, String)>,
    pub entry: Option<u64>,
    /// Function start candidates with their provenance.
    pub seeds: BTreeMap<u64, SeedKind>,
    /// Pointer slots that hold the address of a named external.
    pub import_slots: BTreeMap<u64, String>,
    /// Pointer-sized locations known (from relocations) to hold an internal
    /// address: slot -> target.
    pub pointers: BTreeMap<u64, u64>,
    /// Pointers the loader marks up as data (init/fini arrays), which Ghidra
    /// turns into references.
    pub marked_pointers: BTreeMap<u64, u64>,
    /// Pointers whose code targets are disassembled but not made functions
    /// (PE base relocations).
    pub code_pointers: BTreeMap<u64, u64>,
    /// External entry points (Ghidra `SymbolTable.addExternalEntryPoint`);
    /// every symbol at one of these is an export.
    pub entry_points: std::collections::BTreeSet<u64>,
    /// Names the loader gives to functions that have no symbol (`entry`,
    /// `_INIT_0`, `_DT_INIT`, ...), as Ghidra's ElfProgramBuilder does.
    pub fallback_names: BTreeMap<u64, String>,
    /// Tagged as a Rust program the way Ghidra's loaders do
    /// (`RustUtilities.isRust` on `.rodata` / `.rdata` / `__const`).
    pub is_rust: bool,
}

pub fn load_path(path: &std::path::Path, language_override: Option<&str>) -> Result<Program> {
    let data = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    load_bytes(&data, &path.display().to_string(), language_override)
}

pub fn load_bytes(data: &[u8], path: &str, language_override: Option<&str>) -> Result<Program> {
    let sha256 = Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let mut p = match object::File::parse(data) {
        Ok(file) => load_object(&file, data, path)?,
        Err(_) => {
            let Some(lang) = language_override else {
                bail!("{path}: unrecognized format; pass --language to load as raw binary");
            };
            load_raw(data, path, lang)
        }
    };
    p.sha256 = sha256;
    if let Some(l) = language_override {
        p.language = l.to_string();
    }
    Ok(p)
}

/// Raw image at address 0 (Ghidra `BinaryLoader`).
fn load_raw(data: &[u8], path: &str, lang: &str) -> Program {
    let mut memory = MemoryMap::default();
    memory.add(MemoryBlock {
        name: "ram".into(),
        start: 0,
        size: data.len() as u64,
        perms: Perms {
            read: true,
            write: true,
            execute: true,
        },
        data: data.to_vec(),
    });
    let big_endian = lang.contains(":BE:");
    let pointer_size = lang
        .split(':')
        .nth(2)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(32)
        / 8;
    Program {
        path: path.into(),
        sha256: String::new(),
        format: "Raw".into(),
        language: lang.into(),
        image_base: 0,
        big_endian,
        pointer_size,
        memory,
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        entry: None,
        seeds: BTreeMap::new(),
        import_slots: BTreeMap::new(),
        pointers: BTreeMap::new(),
        marked_pointers: BTreeMap::new(),
        code_pointers: BTreeMap::new(),
        entry_points: Default::default(),
        fallback_names: BTreeMap::new(),
        is_rust: false,
    }
}

pub fn language_for(
    arch: Architecture,
    endian: Endianness,
    format: BinaryFormat,
) -> Option<&'static str> {
    let be = endian == Endianness::Big;
    Some(match (arch, be) {
        (Architecture::X86_64, _) => "x86:LE:64:default",
        (Architecture::I386, _) => "x86:LE:32:default",
        (Architecture::Aarch64, false) => {
            if format == BinaryFormat::MachO {
                "AARCH64:LE:64:AppleSilicon"
            } else {
                "AARCH64:LE:64:v8A"
            }
        }
        (Architecture::Aarch64, true) => "AARCH64:BE:64:v8A",
        (Architecture::Arm, false) => "ARM:LE:32:v8",
        (Architecture::Arm, true) => "ARM:BE:32:v8",
        (Architecture::Mips, true) => "MIPS:BE:32:default",
        (Architecture::Mips, false) => "MIPS:LE:32:default",
        (Architecture::Mips64, true) => "MIPS:BE:64:default",
        (Architecture::Mips64, false) => "MIPS:LE:64:default",
        (Architecture::PowerPc, _) => "PowerPC:BE:32:default",
        (Architecture::PowerPc64, true) => "PowerPC:BE:64:default",
        (Architecture::PowerPc64, false) => "PowerPC:LE:64:default",
        (Architecture::Riscv32, _) => "RISCV:LE:32:default",
        (Architecture::Riscv64, _) => "RISCV:LE:64:default",
        (Architecture::Sparc64, _) => "sparc:BE:64:default",
        _ => return None,
    })
}

fn load_object(file: &object::File, data: &[u8], path: &str) -> Result<Program> {
    let format = match file.format() {
        BinaryFormat::Elf => "ELF",
        BinaryFormat::Pe => "PE",
        BinaryFormat::MachO => "MachO",
        BinaryFormat::Coff => "COFF",
        other => bail!("{path}: {other:?} is not supported yet"),
    };
    let language = language_for(file.architecture(), file.endianness(), file.format())
        .with_context(|| {
            format!(
                "{path}: architecture {:?} not supported yet",
                file.architecture()
            )
        })?;
    let big_endian = !file.is_little_endian();
    let pointer_size = if file.is_64() { 8 } else { 4 };
    let bias = elf_load_bias(file);

    let mut p = Program {
        path: path.into(),
        sha256: String::new(),
        format: format.into(),
        language: language.into(),
        image_base: file.relative_address_base(),
        big_endian,
        pointer_size,
        memory: build_memory(file, bias),
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        entry: None,
        seeds: BTreeMap::new(),
        import_slots: BTreeMap::new(),
        pointers: BTreeMap::new(),
        marked_pointers: BTreeMap::new(),
        code_pointers: BTreeMap::new(),
        entry_points: Default::default(),
        fallback_names: BTreeMap::new(),
        is_rust: false,
    };
    p.is_rust = detect_rust(file);
    if format == "PE" {
        // Ghidra's image base for PE is the optional header ImageBase.
        p.image_base = file.relative_address_base();
    } else if format == "ELF" {
        p.image_base = if bias != 0 {
            bias
        } else {
            min_load_vaddr(file).unwrap_or(0)
        };
    }

    let entry = file.entry().wrapping_add(bias);
    if entry != 0 && p.memory.is_mapped(entry) {
        p.entry = Some(entry);
        p.seeds.insert(entry, SeedKind::Entry);
        p.fallback_names.insert(entry, "entry".into());
    }

    collect_symbols(file, &mut p, bias);
    match file.format() {
        BinaryFormat::Elf => elf_specific(file, data, &mut p, bias),
        BinaryFormat::Pe => pe_specific(data, &mut p),
        BinaryFormat::MachO => macho_specific(data, &mut p),
        _ => {}
    }
    for (addr, kind) in eh_frame::function_starts(file, &p.memory, bias) {
        p.seeds.entry(addr).or_insert(kind);
    }
    let mem = &p.memory;
    p.seeds.retain(|a, _| mem.is_executable(*a));
    {
        let mut exports = vec![];
        for s in &p.symbols {
            if p.entry_points.contains(&s.addr) {
                exports.push((s.addr, s.name.clone()));
            }
        }
        p.exports.extend(exports);
    }
    p.symbols
        .sort_by(|a, b| (a.addr, &a.name).cmp(&(b.addr, &b.name)));
    p.symbols.dedup();
    p.imports
        .sort_by(|a, b| (&a.name, a.slot).cmp(&(&b.name, b.slot)));
    p.imports.dedup();
    p.exports.sort();
    p.exports.dedup();
    Ok(p)
}

/// Ghidra rebases position-independent ELF images whose lowest load address
/// is 0 (`ElfLoaderOptionsFactory.IMAGE64_BASE_DEFAULT` / `IMAGE32_BASE_DEFAULT`).
fn elf_load_bias(file: &object::File) -> u64 {
    if file.format() != BinaryFormat::Elf {
        return 0;
    }
    let pic = matches!(
        file.kind(),
        object::ObjectKind::Dynamic | object::ObjectKind::Relocatable
    );
    if pic && min_load_vaddr(file).unwrap_or(0) == 0 {
        if file.is_64() {
            0x10_0000
        } else {
            0x1_0000
        }
    } else {
        0
    }
}

fn min_load_vaddr(file: &object::File) -> Option<u64> {
    file.segments()
        .filter(|s| s.size() > 0)
        .map(|s| s.address())
        .min()
}

/// HIGHLOW / DIR64 base relocations: (slot address, pointer value).
fn pe_base_relocs(data: &[u8], base: u64, ptr: u32) -> Vec<(u64, u64)> {
    let mut out = vec![];
    let Ok(file) = object::File::parse(data) else {
        return out;
    };
    let rel = match &file {
        object::File::Pe32(f) => f
            .data_directories()
            .relocation_blocks(data, &f.section_table()),
        object::File::Pe64(f) => f
            .data_directories()
            .relocation_blocks(data, &f.section_table()),
        _ => return out,
    };
    let Ok(Some(mut blocks)) = rel else {
        return out;
    };
    while let Ok(Some(block)) = blocks.next() {
        for r in block {
            if !matches!(
                r.typ,
                object::pe::IMAGE_REL_BASED_HIGHLOW | object::pe::IMAGE_REL_BASED_DIR64
            ) {
                continue;
            }
            let _ = ptr;
            out.push((base + r.virtual_address as u64, 0));
        }
    }
    out
}

/// `RustConstants.RUST_SIGNATURES` searched in the read-only data section
/// the Ghidra loader checks for the format.
fn detect_rust(file: &object::File) -> bool {
    const SIGS: [&[u8]; 3] = [b"RUST_BACKTRACE", b"RUST_MIN_STACK", b"/rustc/"];
    let section = match file.format() {
        BinaryFormat::Elf => file.section_by_name(".rodata"),
        BinaryFormat::Pe => file.section_by_name(".rdata"),
        BinaryFormat::MachO => file.section_by_name("__const"),
        _ => None,
    };
    let Some(data) = section.and_then(|s| s.data().ok()) else {
        return false;
    };
    SIGS.iter()
        .any(|sig| data.windows(sig.len()).any(|w| w == *sig))
}

fn build_memory(file: &object::File, bias: u64) -> MemoryMap {
    let mut m = MemoryMap::default();
    let mut any_section = false;
    for s in file.sections() {
        let alloc = match s.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags & u64::from(object::elf::SHF_ALLOC) != 0,
            _ => !matches!(
                s.kind(),
                SectionKind::Metadata | SectionKind::Debug | SectionKind::Linker
            ),
        };
        if !alloc || s.size() == 0 || (file.format() == BinaryFormat::Elf && s.address() == 0) {
            continue;
        }
        any_section = true;
        let name = s.name().unwrap_or("").to_string();
        let perms = section_perms(file, &s);
        let data = if matches!(
            s.kind(),
            SectionKind::UninitializedData | SectionKind::UninitializedTls
        ) {
            vec![]
        } else {
            s.uncompressed_data()
                .map(|d| d.into_owned())
                .unwrap_or_default()
        };
        let mut data = data;
        let size = s.size();
        data.truncate(size as usize);
        m.add(MemoryBlock {
            name,
            start: s.address() + bias,
            size,
            perms,
            data,
        });
    }
    if !any_section {
        for (i, seg) in file.segments().enumerate() {
            let data = seg.data().unwrap_or(&[]).to_vec();
            let perms = match seg.flags() {
                object::SegmentFlags::Elf { p_flags } => Perms {
                    read: p_flags & object::elf::PF_R != 0,
                    write: p_flags & object::elf::PF_W != 0,
                    execute: p_flags & object::elf::PF_X != 0,
                },
                _ => Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
            };
            let name = seg
                .name()
                .ok()
                .flatten()
                .map(str::to_string)
                .unwrap_or_else(|| format!("segment_{i}"));
            m.add(MemoryBlock {
                name,
                start: seg.address() + bias,
                size: seg.size(),
                perms,
                data,
            });
        }
    }
    m
}

fn section_perms(_file: &object::File, s: &object::Section) -> Perms {
    match s.flags() {
        SectionFlags::Elf { sh_flags } => Perms {
            read: true,
            write: sh_flags & u64::from(object::elf::SHF_WRITE) != 0,
            execute: sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0,
        },
        SectionFlags::Coff { characteristics } => Perms {
            read: characteristics & object::pe::IMAGE_SCN_MEM_READ != 0,
            write: characteristics & object::pe::IMAGE_SCN_MEM_WRITE != 0,
            execute: characteristics
                & (object::pe::IMAGE_SCN_MEM_EXECUTE | object::pe::IMAGE_SCN_CNT_CODE)
                != 0,
        },
        SectionFlags::MachO { flags } => {
            let exec = flags
                & (object::macho::S_ATTR_PURE_INSTRUCTIONS
                    | object::macho::S_ATTR_SOME_INSTRUCTIONS)
                != 0;
            let seg = s.segment_name().ok().flatten().unwrap_or("");
            Perms {
                read: true,
                write: seg != "__TEXT" && !exec,
                execute: exec,
            }
        }
        _ => Perms {
            read: true,
            write: false,
            execute: s.kind() == SectionKind::Text,
        },
    }
}

fn collect_symbols(file: &object::File, p: &mut Program, bias: u64) {
    let push = |sym: &object::Symbol, p: &mut Program| {
        let Ok(name) = sym.name() else { return };
        if name.is_empty() || sym.kind() == SymbolKind::Section || sym.kind() == SymbolKind::File {
            return;
        }
        if sym.is_undefined() {
            return;
        }
        if sym.address() == 0 {
            return;
        }
        let addr = sym.address() + bias;
        if !p.memory.is_mapped(addr) {
            return;
        }
        let is_function = sym.kind() == SymbolKind::Text;
        p.symbols.push(LoadedSymbol {
            addr,
            name: name.to_string(),
            is_function,
            is_data: sym.kind() == SymbolKind::Data,
            source: SymbolSource::Imported,
        });
        if is_function {
            p.seeds.entry(addr).or_insert(SeedKind::Symbol);
        }
        if sym.is_global() && !sym.is_undefined() && file.format() != BinaryFormat::Pe {
            p.entry_points.insert(addr);
        }
    };
    for sym in file.symbols() {
        push(&sym, p);
    }
    for sym in file.dynamic_symbols() {
        push(&sym, p);
    }
    if file.format() == BinaryFormat::Pe {
        if let Ok(exports) = file.exports() {
            for e in exports {
                let name = String::from_utf8_lossy(e.name()).into_owned();
                let addr = e.address();
                if p.memory.is_executable(addr) {
                    p.seeds.insert(addr, SeedKind::Export);
                }
                p.symbols.push(LoadedSymbol {
                    addr,
                    name: name.clone(),
                    is_function: p.memory.is_executable(addr),
                    is_data: false,
                    source: SymbolSource::Imported,
                });
                p.exports.push((addr, name));
            }
        }
    }
    if let Ok(imports) = file.imports() {
        for i in imports {
            let name = String::from_utf8_lossy(i.name()).into_owned();
            let library =
                Some(String::from_utf8_lossy(i.library()).into_owned()).filter(|l| !l.is_empty());
            if p.imports
                .iter()
                .any(|x| x.name == name && x.library == library)
            {
                continue;
            }
            p.imports.push(Import {
                name,
                library,
                slot: None,
            });
        }
    }
}

fn elf_specific(file: &object::File, data: &[u8], p: &mut Program, bias: u64) {
    // Dynamic relocations: GOT/JUMP_SLOT slots name their imports, and
    // RELATIVE relocations are applied so pointer tables hold real targets.
    let mut copied = vec![];
    let mut slot_syms: std::collections::HashSet<String> = Default::default();
    if let Some(relocs) = file.dynamic_relocations() {
        for (offset, r) in relocs {
            let offset = offset + bias;
            // Dynamic relocations index the dynamic symbol table.
            let sym_name = match r.target() {
                RelocationTarget::Symbol(idx) => file
                    .dynamic_symbol_table()
                    .and_then(|t| t.symbol_by_index(idx).ok())
                    .and_then(|s| s.name().ok().map(str::to_string))
                    .filter(|n| !n.is_empty()),
                _ => None,
            };
            if let (Some(name), true) = (&sym_name, is_copy_reloc(file.architecture(), r.flags())) {
                // COPY-relocated data lives in this image; Ghidra does not
                // treat it as an external.
                copied.push(name.clone());
                continue;
            }
            if let Some(name) = sym_name {
                if is_slot_reloc(file.architecture(), r.flags()) {
                    slot_syms.insert(name.clone());
                }
                p.import_slots.entry(offset).or_insert(name.clone());
                for imp in p
                    .imports
                    .iter_mut()
                    .filter(|i| i.name == name && i.slot.is_none())
                {
                    imp.slot = Some(offset);
                }
            } else if matches!(r.target(), RelocationTarget::Absolute) && !r.has_implicit_addend() {
                // R_*_RELATIVE (RELA form): value = base (0) + addend. REL
                // forms already hold the addend in place.
                let addend = r.addend() as u64;
                if addend != 0 {
                    let addend = addend.wrapping_add(bias);
                    let bytes = if p.big_endian {
                        addend.to_be_bytes()[8 - p.pointer_size as usize..].to_vec()
                    } else {
                        addend.to_le_bytes()[..p.pointer_size as usize].to_vec()
                    };
                    p.memory.write(offset, &bytes);
                    p.pointers.insert(offset, addend);
                }
            }
        }
    }
    p.imports.retain(|i| !copied.contains(&i.name));
    // Data symbols referenced only by absolute data relocations (vtable /
    // typeinfo pointers in .data.rel.ro) get no external location in Ghidra.
    let data_syms: std::collections::HashSet<String> = file
        .dynamic_symbols()
        .filter(|s| s.is_undefined() && s.kind() == SymbolKind::Data)
        .filter_map(|s| s.name().ok().map(str::to_string))
        .collect();
    p.imports
        .retain(|i| !data_syms.contains(&i.name) || slot_syms.contains(&i.name));
    // .init_array / .fini_array / .preinit_array entries are function pointers
    // (ElfLoader marks them up and creates functions at their targets).
    for s in file.sections() {
        let name = s.name().unwrap_or("");
        let prefix = match name {
            ".init_array" | ".ctors" => "_INIT",
            ".fini_array" | ".dtors" => "_FINI",
            ".preinit_array" => "_PREINIT",
            _ => continue,
        };
        let ps = p.pointer_size as u64;
        let mut a = s.address() + bias;
        let mut index = 0;
        while a + ps <= s.address() + bias + s.size() {
            if let Some(t) = p.memory.read_uint(a, ps as usize, p.big_endian) {
                if t != 0 && t != u64::MAX && p.memory.is_executable(t) {
                    p.fallback_names
                        .entry(t)
                        .or_insert(format!("{prefix}_{index}"));
                    index += 1;
                    p.seeds.entry(t).or_insert(SeedKind::InitArray);
                    p.pointers.insert(a, t);
                    p.marked_pointers.insert(a, t);
                    p.entry_points.insert(t);
                }
            }
            a += ps;
        }
    }
    // Address-valued dynamic tags get `__DT_<TAG>` labels (ElfProgramBuilder
    // markup); DT_INIT / DT_FINI are entry points.
    if let Some(info) = elf_dynamic_info(file, data) {
        for (tag, value) in info.address_tags {
            let addr = value + bias;
            if !p.memory.is_mapped(addr) {
                continue;
            }
            p.symbols.push(LoadedSymbol {
                addr,
                name: format!("__DT_{tag}"),
                is_function: false,
                is_data: false,
                source: SymbolSource::Imported,
            });
            if matches!(tag, "INIT" | "FINI") {
                p.entry_points.insert(addr);
                p.fallback_names.entry(addr).or_insert(format!("_DT_{tag}"));
                if p.memory.is_executable(addr) {
                    p.seeds.entry(addr).or_insert(SeedKind::Entry);
                }
            }
        }
        // PT_GNU_RELRO ranges are read-only after relocation; Ghidra shows
        // the sections inside them without write permission.
        for (start, size) in info.relro {
            p.memory.clear_write(start + bias, start + bias + size);
        }
    }
}

/// GOT / PLT slot relocations (GLOB_DAT, JUMP_SLOT).
fn is_slot_reloc(arch: Architecture, flags: object::RelocationFlags) -> bool {
    let object::RelocationFlags::Elf { r_type } = flags else {
        return false;
    };
    use object::elf::*;
    match arch {
        Architecture::X86_64 => matches!(r_type, R_X86_64_GLOB_DAT | R_X86_64_JUMP_SLOT),
        Architecture::I386 => matches!(r_type, R_386_GLOB_DAT | R_386_JMP_SLOT),
        Architecture::Aarch64 => matches!(r_type, R_AARCH64_GLOB_DAT | R_AARCH64_JUMP_SLOT),
        Architecture::Arm => matches!(r_type, R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT),
        _ => true,
    }
}

fn is_copy_reloc(arch: Architecture, flags: object::RelocationFlags) -> bool {
    let object::RelocationFlags::Elf { r_type } = flags else {
        return false;
    };
    match arch {
        Architecture::X86_64 => r_type == object::elf::R_X86_64_COPY,
        Architecture::I386 => r_type == object::elf::R_386_COPY,
        Architecture::Aarch64 => r_type == object::elf::R_AARCH64_COPY,
        Architecture::Arm => r_type == object::elf::R_ARM_COPY,
        _ => false,
    }
}

struct DynamicInfo {
    address_tags: Vec<(&'static str, u64)>,
    relro: Vec<(u64, u64)>,
}

/// Dynamic tags whose value is an address (Ghidra `ElfDynamicType` with
/// `DynamicValueType.ADDRESS`).
fn dt_address_name(tag: u64) -> Option<&'static str> {
    use object::elf::*;
    Some(match tag as u32 {
        DT_PLTGOT => "PLTGOT",
        DT_HASH => "HASH",
        DT_STRTAB => "STRTAB",
        DT_SYMTAB => "SYMTAB",
        DT_RELA => "RELA",
        DT_INIT => "INIT",
        DT_FINI => "FINI",
        DT_REL => "REL",
        DT_JMPREL => "JMPREL",
        DT_INIT_ARRAY => "INIT_ARRAY",
        DT_FINI_ARRAY => "FINI_ARRAY",
        DT_PREINIT_ARRAY => "PREINIT_ARRAY",
        DT_GNU_HASH => "GNU_HASH",
        DT_VERSYM => "VERSYM",
        DT_VERNEED => "VERNEED",
        DT_VERDEF => "VERDEF",
        0x24 => "RELR",
        _ => return None,
    })
}

fn elf_dynamic_info(file: &object::File, data: &[u8]) -> Option<DynamicInfo> {
    fn scan<H: FileHeader<Endian = Endianness>>(elf: &ElfFile<H>) -> Option<DynamicInfo> {
        let endian = elf.endian();
        let mut out = DynamicInfo {
            address_tags: vec![],
            relro: vec![],
        };
        for seg in elf.elf_program_headers() {
            if seg.p_type(endian) == object::elf::PT_GNU_RELRO {
                out.relro
                    .push((seg.p_vaddr(endian).into(), seg.p_memsz(endian).into()));
            }
            if let Ok(Some(dynamic)) = seg.dynamic(endian, elf.data()) {
                for d in dynamic {
                    let tag: u64 = d.d_tag(endian).into();
                    if tag == 0 {
                        break;
                    }
                    if let Some(name) = dt_address_name(tag) {
                        out.address_tags.push((name, d.d_val(endian).into()));
                    }
                }
            }
        }
        Some(out)
    }
    match file {
        object::File::Elf64(_) => {
            scan(&object::read::elf::ElfFile64::<Endianness>::parse(data).ok()?)
        }
        object::File::Elf32(_) => {
            scan(&object::read::elf::ElfFile32::<Endianness>::parse(data).ok()?)
        }
        _ => None,
    }
}

fn pe_specific(data: &[u8], p: &mut Program) {
    let Ok(pe) = goblin::pe::PE::parse(data) else {
        return;
    };
    let base = pe.image_base as u64;
    if let Some(opt) = pe.header.optional_header {
        // PeLoader maps the headers as a "Headers" block.
        let size = (opt.windows_fields.size_of_headers as usize).min(data.len());
        p.memory.add(MemoryBlock {
            name: "Headers".into(),
            start: base,
            size: size as u64,
            perms: Perms {
                read: true,
                write: false,
                execute: false,
            },
            data: data[..size].to_vec(),
        });
        // `entry` labels the entry point; a DLL without one (entry RVA 0)
        // gets the label at the image base.
        let entry = base + opt.standard_fields.address_of_entry_point;
        p.symbols.push(LoadedSymbol {
            addr: entry,
            name: "entry".into(),
            is_function: false,
            is_data: entry == base,
            source: SymbolSource::Imported,
        });
        p.entry_points.insert(entry);
    }
    // PeLoader sizes section blocks max(VirtualSize, SizeOfRawData), filled
    // with the raw data (the tail past VirtualSize is file padding).
    for sec in &pe.sections {
        let raw = sec.size_of_raw_data as u64;
        let start = base + sec.virtual_address as u64;
        let off = sec.pointer_to_raw_data as usize;
        if raw > sec.virtual_size as u64 {
            if let Some(bytes) = data.get(off..off + raw as usize) {
                p.memory.grow(start, raw, bytes);
            }
        }
    }
    // Base relocations mark pointer slots (vtables, function tables).
    for (slot, _) in pe_base_relocs(data, base, p.pointer_size) {
        if let Some(target) = p.memory.read_uint(slot, p.pointer_size as usize, false) {
            if p.memory.is_mapped(target) {
                p.code_pointers.insert(slot, target);
            }
        }
    }
    // Every exported address gets an `Ordinal_<n>` label besides its name.
    if let Some(ed) = &pe.export_data {
        let ord_base = ed.export_directory_table.ordinal_base as u64;
        for (i, e) in ed.export_address_table.iter().enumerate() {
            if let goblin::pe::export::ExportAddressTableEntry::ExportRVA(rva) = e {
                if *rva == 0 {
                    continue;
                }
                let addr = base + *rva as u64;
                p.symbols.push(LoadedSymbol {
                    addr,
                    name: format!("Ordinal_{}", ord_base + i as u64),
                    is_function: false,
                    is_data: false,
                    source: SymbolSource::Imported,
                });
                p.entry_points.insert(addr);
            }
        }
    }
    for imp in &pe.imports {
        let slot = base + imp.offset as u64;
        let name = imp.name.to_string();
        p.import_slots.insert(slot, name.clone());
        let lib = Some(imp.dll.to_string());
        if let Some(i) = p.imports.iter_mut().find(|i| {
            i.name == name
                && i.library.as_deref().map(str::to_ascii_lowercase)
                    == lib.as_deref().map(str::to_ascii_lowercase)
        }) {
            i.slot.get_or_insert(slot);
        } else {
            p.imports.push(Import {
                name,
                library: lib,
                slot: Some(slot),
            });
        }
    }
    // x64 .pdata RUNTIME_FUNCTION entries (PortableExecutableAnalyzer).
    if let Some(ex) = &pe.exception_data {
        for f in ex.functions().flatten() {
            p.seeds
                .entry(base + f.begin_address as u64)
                .or_insert(SeedKind::ExceptionTable);
        }
    }
    // TLS callbacks are entry points too.
    if let Some(tls) = pe.tls_data.as_ref() {
        for cb in &tls.callbacks {
            p.seeds.entry(*cb).or_insert(SeedKind::Entry);
        }
    }
}

fn macho_specific(data: &[u8], p: &mut Program) {
    let Ok(goblin::mach::Mach::Binary(m)) = goblin::mach::Mach::parse(data) else {
        return;
    };
    if let Ok(imports) = m.imports() {
        for imp in imports {
            let name = imp.name.trim_start_matches('_').to_string();
            let raw = imp.name.to_string();
            p.import_slots.insert(imp.address, raw.clone());
            if let Some(i) = p
                .imports
                .iter_mut()
                .find(|i| i.name == raw || i.name == name)
            {
                i.slot.get_or_insert(imp.address);
            } else {
                p.imports.push(Import {
                    name: raw,
                    library: Some(imp.dylib.to_string()),
                    slot: Some(imp.address),
                });
            }
        }
    }
    // LC_FUNCTION_STARTS (MachoFunctionStartsAnalyzer).
    let text_base = m
        .segments
        .iter()
        .find(|s| s.name().ok() == Some("__TEXT"))
        .map(|s| s.vmaddr)
        .unwrap_or(0);
    for lc in &m.load_commands {
        if let goblin::mach::load_command::CommandVariant::FunctionStarts(fs) = &lc.command {
            let start = fs.dataoff as usize;
            let Some(bytes) = data.get(start..start + fs.datasize as usize) else {
                continue;
            };
            let mut addr = text_base;
            let mut i = 0;
            while i < bytes.len() {
                let (delta, n) = uleb(&bytes[i..]);
                if delta == 0 || n == 0 {
                    break;
                }
                i += n;
                addr += delta;
                p.seeds.entry(addr).or_insert(SeedKind::FunctionStarts);
            }
        }
    }
}

fn uleb(b: &[u8]) -> (u64, usize) {
    let mut v = 0u64;
    let mut shift = 0;
    for (i, byte) in b.iter().enumerate() {
        if shift < 64 {
            v |= u64::from(byte & 0x7f) << shift;
        }
        shift += 7;
        if byte & 0x80 == 0 {
            return (v, i + 1);
        }
    }
    (v, 0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn uleb_decodes_multibyte() {
        assert_eq!(super::uleb(&[0xe5, 0x8e, 0x26]), (624485, 3));
        assert_eq!(super::uleb(&[0x80]), (0, 0));
    }
}
