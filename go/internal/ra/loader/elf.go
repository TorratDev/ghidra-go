package loader

import (
	"bytes"
	"cmp"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

// Ghidra rebases position-independent ELF images whose lowest load address is
// 0 (ElfLoaderOptionsFactory IMAGE32_BASE_DEFAULT / IMAGE64_BASE_DEFAULT).
const (
	image32BaseDefault = 0x10000
	image64BaseDefault = 0x100000
)

func languageFor(f *elf.File) (string, bool) {
	be := f.Data == elf.ELFDATA2MSB
	is64 := f.Class == elf.ELFCLASS64
	pick := func(le, bige string) (string, bool) {
		if be {
			return bige, true
		}
		return le, true
	}
	switch f.Machine {
	case elf.EM_X86_64:
		if is64 { // x32 is not supported
			return "x86:LE:64:default", true
		}
	case elf.EM_386:
		return "x86:LE:32:default", true
	case elf.EM_AARCH64:
		return pick("AARCH64:LE:64:v8A", "AARCH64:BE:64:v8A")
	case elf.EM_ARM:
		return pick("ARM:LE:32:v8", "ARM:BE:32:v8")
	case elf.EM_MIPS:
		if is64 {
			return pick("MIPS:LE:64:default", "MIPS:BE:64:default")
		}
		return pick("MIPS:LE:32:default", "MIPS:BE:32:default")
	case elf.EM_PPC:
		return "PowerPC:BE:32:default", true
	case elf.EM_PPC64:
		return pick("PowerPC:LE:64:default", "PowerPC:BE:64:default")
	case elf.EM_RISCV:
		if is64 {
			return "RISCV:LE:64:default", true
		}
		return "RISCV:LE:32:default", true
	case elf.EM_SPARCV9:
		return "sparc:BE:64:default", true
	}
	return "", false
}

func loadELF(f *elf.File, path string) (*Program, error) {
	lang, ok := languageFor(f)
	if !ok {
		return nil, fmt.Errorf("%s: architecture %v not supported yet", path, f.Machine)
	}
	p := newProgram(path, "ELF", lang)
	p.BigEndian = f.Data == elf.ELFDATA2MSB
	p.PointerSize = 4
	if f.Class == elf.ELFCLASS64 {
		p.PointerSize = 8
	}
	bias := elfLoadBias(f)
	p.Memory = *buildMemory(f, bias)
	p.IsRust = detectRust(f)
	p.ImageBase = bias
	if bias == 0 {
		p.ImageBase, _ = minLoadVaddr(f)
	}

	if entry := f.Entry + bias; entry != 0 && p.Memory.IsMapped(entry) {
		p.Entry = &entry
		p.Seeds[entry] = SeedEntry
		p.FallbackNames[entry] = "entry"
	}

	collectSymbols(f, p, bias)
	elfSpecific(f, p, bias)
	for _, s := range ehFrameStarts(f, &p.Memory, bias) {
		if _, ok := p.Seeds[s]; !ok {
			p.Seeds[s] = SeedExceptionTable
		}
	}
	for a := range p.Seeds {
		if !p.Memory.IsExecutable(a) {
			delete(p.Seeds, a)
		}
	}
	for _, s := range p.Symbols {
		if p.EntryPoints[s.Addr] {
			p.Exports = append(p.Exports, Export{s.Addr, s.Name})
		}
	}
	slices.SortStableFunc(p.Symbols, func(a, b LoadedSymbol) int {
		return cmp.Or(cmp.Compare(a.Addr, b.Addr), cmp.Compare(a.Name, b.Name))
	})
	p.Symbols = slices.CompactFunc(p.Symbols, func(a, b LoadedSymbol) bool { return a == b })
	slices.SortStableFunc(p.Imports, func(a, b Import) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmpOpt(a.Slot, b.Slot))
	})
	p.Imports = slices.CompactFunc(p.Imports, func(a, b Import) bool {
		return a.Name == b.Name && eqOpt(a.Library, b.Library) && eqOpt(a.Slot, b.Slot)
	})
	slices.SortStableFunc(p.Exports, func(a, b Export) int {
		return cmp.Or(cmp.Compare(a.Addr, b.Addr), cmp.Compare(a.Name, b.Name))
	})
	p.Exports = slices.Compact(p.Exports)
	return p, nil
}

func cmpOpt[T cmp.Ordered](a, b *T) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return -1
	case b == nil:
		return 1
	}
	return cmp.Compare(*a, *b)
}

func eqOpt[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func elfLoadBias(f *elf.File) uint64 {
	pic := f.Type == elf.ET_DYN || f.Type == elf.ET_REL
	if lo, _ := minLoadVaddr(f); pic && lo == 0 {
		if f.Class == elf.ELFCLASS64 {
			return image64BaseDefault
		}
		return image32BaseDefault
	}
	return 0
}

// minLoadVaddr is the lowest address of a non-empty PT_LOAD segment.
func minLoadVaddr(f *elf.File) (uint64, bool) {
	var lo uint64
	found := false
	for _, pr := range f.Progs {
		if pr.Type == elf.PT_LOAD && pr.Memsz > 0 && (!found || pr.Vaddr < lo) {
			lo, found = pr.Vaddr, true
		}
	}
	return lo, found
}

// detectRust is ElfRustSourceLanguage.existsIn: a "rustc version " string in
// .comment, else RustConstants.RUST_SIGNATURES searched in .rodata.
func detectRust(f *elf.File) bool {
	if c := f.Section(".comment"); c != nil && c.Type != elf.SHT_NOBITS {
		if d, err := c.Data(); err == nil {
			for _, s := range bytes.Split(d, []byte{0}) {
				if bytes.HasPrefix(s, []byte("rustc version ")) {
					return true
				}
			}
		}
	}
	s := f.Section(".rodata")
	if s == nil || s.Type == elf.SHT_NOBITS {
		return false
	}
	d, err := s.Data()
	if err != nil {
		return false
	}
	for _, sig := range []string{"RUST_BACKTRACE", "RUST_MIN_STACK", "/rustc/"} {
		if bytes.Contains(d, []byte(sig)) {
			return true
		}
	}
	return false
}

func buildMemory(f *elf.File, bias uint64) *core.MemoryMap {
	m := &core.MemoryMap{}
	any := false
	for _, s := range f.Sections {
		if s.Type == elf.SHT_NULL || s.Flags&elf.SHF_ALLOC == 0 || s.Size == 0 || s.Addr == 0 {
			continue
		}
		// Fix over the Rust loader: .tbss is a template that occupies no
		// address space, but its sh_addr overlaps the sections that follow it.
		// MemoryMap.Add keeps the first block, so adding it dropped
		// .init_array and .fini_array.
		if s.Flags&elf.SHF_TLS != 0 && s.Type == elf.SHT_NOBITS {
			continue
		}
		any = true
		var data []byte
		if s.Type != elf.SHT_NOBITS {
			data, _ = s.Data()
			if uint64(len(data)) > s.Size {
				data = data[:s.Size]
			}
		}
		m.Add(core.MemoryBlock{
			Name: s.Name, Start: s.Addr + bias, Size: s.Size, Data: data,
			Perms: core.Perms{
				Read:    true,
				Write:   s.Flags&elf.SHF_WRITE != 0,
				Execute: s.Flags&elf.SHF_EXECINSTR != 0,
			},
		})
	}
	if !any {
		i := 0
		for _, pr := range f.Progs {
			if pr.Type != elf.PT_LOAD {
				continue
			}
			data := make([]byte, pr.Filesz)
			if _, err := pr.ReadAt(data, 0); err != nil {
				data = nil
			}
			m.Add(core.MemoryBlock{
				Name: fmt.Sprintf("segment_%d", i), Start: pr.Vaddr + bias, Size: pr.Memsz, Data: data,
				Perms: core.Perms{
					Read:    pr.Flags&elf.PF_R != 0,
					Write:   pr.Flags&elf.PF_W != 0,
					Execute: pr.Flags&elf.PF_X != 0,
				},
			})
			i++
		}
	}
	return m
}

const (
	sttObject, sttFunc, sttSection, sttFile, sttCommon, sttGNUIFunc = 1, 2, 3, 4, 5, 10
	stbLocal                                                        = 0
)

type elfSym struct {
	elf.Symbol
	typ   byte
	local bool
}

func wrapSyms(syms []elf.Symbol) []elfSym {
	out := make([]elfSym, len(syms))
	for i, s := range syms {
		out[i] = elfSym{s, s.Info & 0xf, s.Info>>4 == stbLocal}
	}
	return out
}

// symbols returns the static and dynamic symbol tables without the null symbol.
func symbols(f *elf.File) (static, dynamic []elfSym) {
	s, _ := f.Symbols()
	d, _ := f.DynamicSymbols()
	return wrapSyms(s), wrapSyms(d)
}

func collectSymbols(f *elf.File, p *Program, bias uint64) {
	push := func(s elfSym) {
		if s.Name == "" || s.typ == sttSection || s.typ == sttFile ||
			s.Section == elf.SHN_UNDEF || s.Value == 0 {
			return
		}
		addr := s.Value + bias
		if !p.Memory.IsMapped(addr) {
			return
		}
		isFunc := s.typ == sttFunc || s.typ == sttGNUIFunc
		p.Symbols = append(p.Symbols, LoadedSymbol{
			Addr: addr, Name: s.Name, IsFunction: isFunc,
			IsData: s.typ == sttObject || s.typ == sttCommon, Source: core.SourceImported,
		})
		if isFunc {
			if _, ok := p.Seeds[addr]; !ok {
				p.Seeds[addr] = SeedSymbol
			}
		}
		if !s.local {
			p.EntryPoints[addr] = true
		}
	}
	static, dynamic := symbols(f)
	for _, s := range static {
		push(s)
	}
	for _, s := range dynamic {
		push(s)
	}
	p.Imports = elfImports(f, dynamic)
}

// elfImports lists undefined dynamic symbols, with the library taken from the
// symbol's GNU version-needed entry.
func elfImports(f *elf.File, dynamic []elfSym) []Import {
	libs := verneedLibraries(f)
	var out []Import
	for i, s := range dynamic {
		if s.Section != elf.SHN_UNDEF || s.Name == "" {
			continue
		}
		var lib *string
		if l, ok := libs[versionIndex(f, i+1)]; ok && l != "" {
			lib = &l
		}
		if slices.ContainsFunc(out, func(x Import) bool { return x.Name == s.Name && eqOpt(x.Library, lib) }) {
			continue
		}
		out = append(out, Import{Name: s.Name, Library: lib})
	}
	return out
}

const (
	shtGNUVerneed = 0x6ffffffe
	shtGNUVersym  = 0x6fffffff
)

// versionIndex is the .gnu.version entry for dynamic symbol index idx (the
// null symbol is index 0), or 0 when there is none.
func versionIndex(f *elf.File, idx int) uint16 {
	for _, s := range f.Sections {
		if s.Type == shtGNUVersym {
			d, err := s.Data()
			if err != nil || 2*idx+2 > len(d) {
				return 0
			}
			return f.ByteOrder.Uint16(d[2*idx:]) & 0x7fff
		}
	}
	return 0
}

// verneedLibraries maps a version index (vna_other) to the library (vn_file)
// that needs it.
func verneedLibraries(f *elf.File) map[uint16]string {
	out := map[uint16]string{}
	for _, s := range f.Sections {
		if s.Type != shtGNUVerneed || int(s.Link) >= len(f.Sections) {
			continue
		}
		d, err := s.Data()
		strs, err2 := f.Sections[s.Link].Data()
		if err != nil || err2 != nil {
			continue
		}
		bo := f.ByteOrder
		str := func(off uint32) string {
			if int(off) >= len(strs) {
				return ""
			}
			e := bytes.IndexByte(strs[off:], 0)
			if e < 0 {
				return ""
			}
			return string(strs[off : int(off)+e])
		}
		for off := 0; off+16 <= len(d); {
			cnt, file, aux, next := bo.Uint16(d[off+2:]), bo.Uint32(d[off+4:]), bo.Uint32(d[off+8:]), bo.Uint32(d[off+12:])
			for a, n := off+int(aux), 0; n < int(cnt) && a+16 <= len(d); n++ {
				out[bo.Uint16(d[a+6:])] = str(file)
				if nx := bo.Uint32(d[a+12:]); nx != 0 {
					a += int(nx)
				} else {
					break
				}
			}
			if next == 0 {
				break
			}
			off += int(next)
		}
	}
	return out
}

// Relocation types that fill GOT/PLT slots or copy data, per architecture.
func isSlotReloc(m elf.Machine, t uint32) bool {
	switch m {
	case elf.EM_X86_64:
		return t == uint32(elf.R_X86_64_GLOB_DAT) || t == uint32(elf.R_X86_64_JMP_SLOT)
	case elf.EM_386:
		return t == uint32(elf.R_386_GLOB_DAT) || t == uint32(elf.R_386_JMP_SLOT)
	case elf.EM_AARCH64:
		return t == uint32(elf.R_AARCH64_GLOB_DAT) || t == uint32(elf.R_AARCH64_JUMP_SLOT)
	case elf.EM_ARM:
		return t == uint32(elf.R_ARM_GLOB_DAT) || t == uint32(elf.R_ARM_JUMP_SLOT)
	}
	return true
}

func isCopyReloc(m elf.Machine, t uint32) bool {
	switch m {
	case elf.EM_X86_64:
		return t == uint32(elf.R_X86_64_COPY)
	case elf.EM_386:
		return t == uint32(elf.R_386_COPY)
	case elf.EM_AARCH64:
		return t == uint32(elf.R_AARCH64_COPY)
	case elf.EM_ARM:
		return t == uint32(elf.R_ARM_COPY)
	}
	return false
}

type reloc struct {
	offset uint64
	sym    uint32 // dynamic symbol index, 0 for none
	typ    uint32
	addend int64
	rel    bool // REL form: the addend is implicit
}

// dynamicRelocs reads the SHT_REL/SHT_RELA sections linked to the dynamic
// symbol table (section 0 when there is none, as the object crate does).
func dynamicRelocs(f *elf.File) []reloc {
	dynsym := 0
	for i, s := range f.Sections {
		if s.Type == elf.SHT_DYNSYM {
			dynsym = i
			break
		}
	}
	is64 := f.Class == elf.ELFCLASS64
	var out []reloc
	for _, s := range f.Sections {
		if (s.Type != elf.SHT_REL && s.Type != elf.SHT_RELA) || int(s.Link) != dynsym {
			continue
		}
		d, err := s.Data()
		if err != nil {
			continue
		}
		rela := s.Type == elf.SHT_RELA
		size := 8
		if is64 {
			size = 16
		}
		if rela {
			size += size / 2
		}
		if len(d)%size != 0 {
			continue
		}
		bo := f.ByteOrder
		for off := 0; off < len(d); off += size {
			var r reloc
			r.rel = !rela
			if is64 {
				info := bo.Uint64(d[off+8:])
				r.offset, r.sym, r.typ = bo.Uint64(d[off:]), uint32(info>>32), uint32(info)
				if rela {
					r.addend = int64(bo.Uint64(d[off+16:]))
				}
			} else {
				info := bo.Uint32(d[off+4:])
				r.offset, r.sym, r.typ = uint64(bo.Uint32(d[off:])), info>>8, info&0xff
				if rela {
					r.addend = int64(int32(bo.Uint32(d[off+8:])))
				}
			}
			out = append(out, r)
		}
	}
	return out
}

func elfSpecific(f *elf.File, p *Program, bias uint64) {
	_, dynamic := symbols(f)
	// Dynamic relocations: GOT/JUMP_SLOT slots name their imports, and RELA
	// relocations without a symbol are applied so pointer tables hold real
	// targets.
	var copied []string
	slotSyms := map[string]bool{}
	for _, r := range dynamicRelocs(f) {
		offset := r.offset + bias
		name := ""
		if r.sym != 0 && int(r.sym) <= len(dynamic) {
			name = dynamic[r.sym-1].Name
		}
		switch {
		case name != "" && isCopyReloc(f.Machine, r.typ):
			// COPY-relocated data lives in this image; Ghidra does not treat
			// it as an external.
			copied = append(copied, name)
		case name != "":
			if isSlotReloc(f.Machine, r.typ) {
				slotSyms[name] = true
			}
			if _, ok := p.ImportSlots[offset]; !ok {
				p.ImportSlots[offset] = name
			}
			for i := range p.Imports {
				if p.Imports[i].Name == name && p.Imports[i].Slot == nil {
					slot := offset
					p.Imports[i].Slot = &slot
				}
			}
		case r.sym == 0 && !r.rel:
			// R_*_RELATIVE (RELA form): value = base + addend. REL forms
			// already hold the addend in place.
			if addend := uint64(r.addend); addend != 0 {
				addend += bias
				buf := make([]byte, 8)
				if p.BigEndian {
					binary.BigEndian.PutUint64(buf, addend)
					buf = buf[8-p.PointerSize:]
				} else {
					binary.LittleEndian.PutUint64(buf, addend)
					buf = buf[:p.PointerSize]
				}
				p.Memory.Write(offset, buf)
				p.Pointers[offset] = addend
			}
		}
	}
	p.Imports = slices.DeleteFunc(p.Imports, func(i Import) bool { return slices.Contains(copied, i.Name) })
	// Data symbols referenced only by absolute data relocations (vtable and
	// typeinfo pointers in .data.rel.ro) get no external location in Ghidra.
	dataSyms := map[string]bool{}
	for _, s := range dynamic {
		if s.Section == elf.SHN_UNDEF && (s.typ == sttObject || s.typ == sttCommon) && s.Name != "" {
			dataSyms[s.Name] = true
		}
	}
	p.Imports = slices.DeleteFunc(p.Imports, func(i Import) bool { return dataSyms[i.Name] && !slotSyms[i.Name] })

	// .init_array / .fini_array / .preinit_array entries are function pointers
	// (ElfLoader marks them up and creates functions at their targets).
	for _, s := range f.Sections {
		var prefix string
		switch s.Name {
		case ".init_array", ".ctors":
			prefix = "_INIT"
		case ".fini_array", ".dtors":
			prefix = "_FINI"
		case ".preinit_array":
			prefix = "_PREINIT"
		default:
			continue
		}
		ps := uint64(p.PointerSize)
		start := s.Addr + bias
		index := 0
		for a := start; a+ps <= start+s.Size; a += ps {
			t, ok := p.Memory.ReadUint(a, int(ps), p.BigEndian)
			if !ok || t == 0 || t == ^uint64(0) || !p.Memory.IsExecutable(t) {
				continue
			}
			if _, ok := p.FallbackNames[t]; !ok {
				p.FallbackNames[t] = fmt.Sprintf("%s_%d", prefix, index)
			}
			index++
			if _, ok := p.Seeds[t]; !ok {
				p.Seeds[t] = SeedInitArray
			}
			p.Pointers[a] = t
			p.MarkedPointers[a] = t
			p.EntryPoints[t] = true
		}
	}

	// Address-valued dynamic tags get __DT_<TAG> labels (ElfProgramBuilder
	// markup); DT_INIT / DT_FINI are entry points.
	tags, relro := dynamicInfo(f)
	for _, t := range tags {
		addr := t.value + bias
		if !p.Memory.IsMapped(addr) {
			continue
		}
		p.Symbols = append(p.Symbols, LoadedSymbol{Addr: addr, Name: "__DT_" + t.name, Source: core.SourceImported})
		if t.name == "INIT" || t.name == "FINI" {
			p.EntryPoints[addr] = true
			if _, ok := p.FallbackNames[addr]; !ok {
				p.FallbackNames[addr] = "_DT_" + t.name
			}
			if _, ok := p.Seeds[addr]; !ok && p.Memory.IsExecutable(addr) {
				p.Seeds[addr] = SeedEntry
			}
		}
	}
	// PT_GNU_RELRO ranges are read-only after relocation; Ghidra shows the
	// sections inside them without write permission.
	for _, r := range relro {
		p.Memory.ClearWrite(r[0]+bias, r[0]+bias+r[1])
	}
}

type dtTag struct {
	name  string
	value uint64
}

const ptGNURelro = elf.ProgType(0x6474e552)

// dynamicInfo returns the address-valued dynamic tags of every PT_DYNAMIC
// segment, in order, and the PT_GNU_RELRO (vaddr, memsz) ranges.
func dynamicInfo(f *elf.File) (tags []dtTag, relro [][2]uint64) {
	word := 4
	if f.Class == elf.ELFCLASS64 {
		word = 8
	}
	rd := func(b []byte) uint64 {
		if word == 8 {
			return f.ByteOrder.Uint64(b)
		}
		return uint64(f.ByteOrder.Uint32(b))
	}
	for _, pr := range f.Progs {
		if pr.Type == ptGNURelro {
			relro = append(relro, [2]uint64{pr.Vaddr, pr.Memsz})
		}
		if pr.Type != elf.PT_DYNAMIC || pr.Filesz%uint64(2*word) != 0 {
			continue
		}
		d := make([]byte, pr.Filesz)
		if _, err := pr.ReadAt(d, 0); err != nil {
			continue
		}
		for off := 0; off+2*word <= len(d); off += 2 * word {
			// Ghidra reads d_tag as an int, so the tag is truncated to 32 bits
			// (ElfDynamic.java, ElfDynamicTable.java).
			tag := uint32(rd(d[off:]))
			if tag == 0 {
				break
			}
			if name, ok := dtAddressName(tag); ok {
				tags = append(tags, dtTag{name, rd(d[off+word:])})
			}
		}
	}
	return tags, relro
}

// dtAddressName names the dynamic tags whose value is an address (Ghidra
// ElfDynamicType with ElfDynamicValueType.ADDRESS). Java also marks
// DT_ANDROID_REL (0x6000000f), DT_ANDROID_RELA (0x60000011), DT_ANDROID_RELR
// (0x6fffe000), DT_GNU_CONFLICT (0x6ffffef8), DT_MOVETAB (0x6ffffefe) and
// DT_SYMINFO (0x6ffffeff); the Rust loader does not label them and neither
// does this port. DT_GNU_XHASH (0x6ffffef4) is labelled here, unlike Rust.
func dtAddressName(tag uint32) (string, bool) {
	switch tag {
	case 3:
		return "PLTGOT", true
	case 4:
		return "HASH", true
	case 5:
		return "STRTAB", true
	case 6:
		return "SYMTAB", true
	case 7:
		return "RELA", true
	case 12:
		return "INIT", true
	case 13:
		return "FINI", true
	case 17:
		return "REL", true
	case 23:
		return "JMPREL", true
	case 25:
		return "INIT_ARRAY", true
	case 26:
		return "FINI_ARRAY", true
	case 32:
		return "PREINIT_ARRAY", true
	case 36:
		return "RELR", true
	case 0x6ffffef4:
		return "GNU_XHASH", true
	case 0x6ffffef5:
		return "GNU_HASH", true
	case 0x6ffffff0:
		return "VERSYM", true
	case 0x6ffffffc:
		return "VERDEF", true
	case 0x6ffffffe:
		return "VERNEED", true
	}
	return "", false
}
