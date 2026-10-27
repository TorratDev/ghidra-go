package loader

import (
	"bytes"
	"cmp"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"slices"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

// Base relocation types that patch a full pointer (IMAGE_REL_BASED_HIGHLOW, DIR64).
const (
	relBasedHighlow = 3
	relBasedDir64   = 10
)

// Ghidra's ThreadEnvironmentBlock for x86-64: 0x1850 bytes at 0xff00000000.
const (
	tebAddr64 = 0xff00000000
	tebSize64 = 0x1850
	tebSelf64 = 0x30
)

// peHeader is the optional header fields the loader reads, for PE32 and PE32+.
type peHeader struct {
	imageBase, sizeOfHeaders uint64
	sectionAlign, fileAlign  uint32
	entry                    uint32
	dirs                     [16]pe.DataDirectory
	is64                     bool
}

// peSectionLayout is Ghidra's SectionHeader aligned sizes: the raw pointer
// and size that are read from the file, and the aligned virtual size. Raw
// pointers are not aligned down (SectionHeader.java:378-381 discards the
// result), so a section's bytes start at its exact PointerToRawData.
func peSectionLayout(s *pe.Section, h peHeader, fileLen uint64) (ptr, raw, virt uint64) {
	va := uint64(s.VirtualSize)
	// Java int: a SizeOfRawData with the sign bit set falls back to VirtualSize.
	if int32(s.Size) < 0 {
		raw = va
	} else {
		raw = alignUp(uint64(s.Size), uint64(h.fileAlign))
	}
	virt = raw // a zero VirtualSize takes the aligned raw size
	if va != 0 {
		virt = alignUp(va, uint64(h.sectionAlign))
	}
	raw = min(raw, virt)
	ptr = uint64(s.Offset)
	if ptr >= fileLen {
		ptr = 0
	}
	if ptr+raw > fileLen {
		raw = fileLen - ptr
	}
	return ptr, raw, virt
}

// alignUp is PeUtils.alignUp: an alignment of 0 leaves the value unchanged.
func alignUp(v, a uint64) uint64 {
	if a == 0 {
		return v
	}
	return (v + a - 1) / a * a
}

func loadPE(f *pe.File, data []byte, path string) (*Program, error) {
	var h peHeader
	switch o := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		h = peHeader{uint64(o.ImageBase), uint64(o.SizeOfHeaders), o.SectionAlignment, o.FileAlignment, o.AddressOfEntryPoint, o.DataDirectory, false}
	case *pe.OptionalHeader64:
		h = peHeader{o.ImageBase, uint64(o.SizeOfHeaders), o.SectionAlignment, o.FileAlignment, o.AddressOfEntryPoint, o.DataDirectory, true}
	default:
		return nil, fmt.Errorf("%s: PE without an optional header is not supported", path)
	}
	lang, ok := peLanguage(f.Machine)
	if !ok {
		return nil, fmt.Errorf("%s: PE machine %#x not supported yet", path, f.Machine)
	}
	p := newProgram(path, "PE", lang)
	p.PointerSize = 4
	if h.is64 {
		p.PointerSize = 8
	}
	p.ImageBase = h.imageBase
	fileLen := uint64(len(data))
	imageBase := h.imageBase

	// PeLoader.getHeaderSize: the NT headers, rounded up to the file alignment.
	lfanew := uint64(binary.LittleEndian.Uint32(data[0x3c:]))
	minOpt := uint64(224) // IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
	if h.is64 {
		minOpt = 240 // IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
	}
	optSize := max(uint64(f.FileHeader.SizeOfOptionalHeader), minOpt)
	hdr := lfanew + 4 + 20 + optSize + 40*uint64(len(f.Sections))
	hdr = alignUp(max(hdr, h.sizeOfHeaders), uint64(h.fileAlign))
	p.Memory.Add(core.MemoryBlock{
		Name: "Headers", Start: imageBase, Size: min(hdr, fileLen),
		Perms: core.Perms{Read: true}, Data: data[:min(hdr, fileLen)],
	})

	mapped := make([]bool, len(f.Sections))
	for i, s := range f.Sections {
		start := imageBase + alignUp(uint64(s.VirtualAddress), uint64(h.sectionAlign))
		ptr, raw, virt := peSectionLayout(s, h, fileLen)
		perms := core.Perms{
			Read:    s.Characteristics&pe.IMAGE_SCN_MEM_READ != 0,
			Write:   s.Characteristics&pe.IMAGE_SCN_MEM_WRITE != 0,
			Execute: s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0,
		}
		// Initialized when the section has file bytes (Ghidra tests the unaligned
		// PointerToRawData). The VirtualSize padding is dropped: its block reuses
		// the section name, MemoryBlockUtils fails on the duplicate and the join
		// is skipped, as the 12.1.4 exports show.
		if s.Offset != 0 && raw != 0 {
			p.Memory.Add(core.MemoryBlock{
				Name: s.Name, Start: start, Size: raw, Perms: perms,
				Data: append([]byte(nil), data[ptr:ptr+raw]...),
			})
			mapped[i] = true
		} else if virt > 0 {
			p.Memory.Add(core.MemoryBlock{Name: s.Name, Start: start, Size: virt, Perms: perms})
			mapped[i] = true
		}
	}

	// Ghidra's TEBAnalyzer (MicrosoftCodeAnalyzer, not the loader) adds the TEB
	// block for x86 PEs: its self pointer is at 0x18 (32-bit) or 0x30 (64-bit).
	// shortcut: the analyzer runs only for VisualStudio/Clang compiler specs, this adds it for every x86 PE; the compare skips "tdb" anyway.
	tebAddr, tebSize, self := uint64(0xffdff000), uint64(0x1000), 0x18
	if h.is64 {
		tebAddr, tebSize, self = tebAddr64, tebSize64, tebSelf64
	}
	teb := make([]byte, self+int(p.PointerSize))
	if h.is64 {
		binary.LittleEndian.PutUint64(teb[self:], tebAddr)
	} else {
		binary.LittleEndian.PutUint32(teb[self:], uint32(tebAddr))
	}
	p.Memory.Add(core.MemoryBlock{
		Name: "tdb", Start: tebAddr, Size: tebSize,
		Perms: core.Perms{Read: true, Write: true}, Data: teb,
	})

	// rvaToPtr is NTHeader.rvaToPointer for the FILE layout: -1 when the RVA
	// has no file bytes.
	rvaToPtr := func(rva uint64) int64 {
		for _, s := range f.Sections {
			va := uint64(s.VirtualAddress)
			if rva >= va && rva < va+uint64(s.VirtualSize) {
				ptr := rva + uint64(s.Offset) - va
				if ptr >= uint64(s.Offset)+uint64(s.Size) {
					return -1
				}
				return int64(ptr)
			}
		}
		if h.fileAlign == h.sectionAlign && h.sectionAlign < 800 && h.fileAlign > 1 {
			return int64(rva)
		}
		return -1
	}
	// at reads n bytes at an RVA; ok is false when there are no file bytes there.
	at := func(rva uint64, n int) ([]byte, bool) {
		off := rvaToPtr(rva)
		if off < 0 || uint64(off)+uint64(n) > fileLen {
			return nil, false
		}
		return data[off : off+int64(n)], true
	}
	u32 := func(rva uint64) uint32 {
		b, _ := at(rva, 4)
		if b == nil {
			return 0
		}
		return binary.LittleEndian.Uint32(b)
	}
	cstr := func(rva uint64) string {
		off := rvaToPtr(rva)
		if off < 0 || off >= int64(fileLen) {
			return ""
		}
		s, _, _ := bytes.Cut(data[off:], []byte{0})
		return string(s)
	}
	ptrSize := uint64(p.PointerSize)

	// Entry: PeLoader.processEntryPoints labels it even at RVA 0, marks it
	// as code and makes it an external entry point.
	entry := imageBase + uint64(h.entry)
	p.Entry = &entry
	p.Seeds[entry] = SeedEntry
	p.FallbackNames[entry] = "entry"
	p.EntryPoints[entry] = true
	p.Symbols = append(p.Symbols, LoadedSymbol{Addr: entry, Name: "entry", IsFunction: true, Source: core.SourceImported})

	// COFF symbols: PeLoader.processSymbols, labels at section address + value.
	for _, sym := range f.Symbols {
		idx := int(sym.SectionNumber) - 1
		if sym.Name == "" || sym.Value == 0 || sym.SectionNumber <= 0 || idx >= len(f.Sections) || !mapped[idx] {
			continue
		}
		s := f.Sections[idx]
		addr := imageBase + alignUp(uint64(s.VirtualAddress), uint64(h.sectionAlign)) + uint64(sym.Value)
		exec := s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE != 0
		p.Symbols = append(p.Symbols, LoadedSymbol{Addr: addr, Name: sym.Name, IsFunction: exec, Source: core.SourceImported})
	}

	// Exports (ExportDataDirectory): name and Ordinal_<n> labels, each an
	// external entry point. Forwarders are skipped; Ghidra's EXTERNAL block is
	// not modelled.
	// shortcut: forwarded exports get no label, Ghidra adds an EXTERNAL block entry for each, upgrade when forwarders matter.
	if d := h.dirs[0]; d.VirtualAddress != 0 {
		if ed, ok := at(uint64(d.VirtualAddress), 40); ok {
			base := binary.LittleEndian.Uint32(ed[16:])
			nFuncs := uint64(binary.LittleEndian.Uint32(ed[20:]))
			nNames := uint64(binary.LittleEndian.Uint32(ed[24:]))
			funcs := uint64(binary.LittleEndian.Uint32(ed[28:]))
			names := uint64(binary.LittleEndian.Uint32(ed[32:]))
			ords := uint64(binary.LittleEndian.Uint32(ed[36:]))
			dirEnd := uint64(d.VirtualAddress) + uint64(d.Size)
			nameOf := map[uint64]string{}
			for j := range nNames {
				if b, ok := at(names+4*j, 4); ok {
					if ob, ok := at(ords+2*j, 2); ok {
						nameOf[uint64(binary.LittleEndian.Uint16(ob))] = cstr(uint64(binary.LittleEndian.Uint32(b)))
					}
				}
			}
			for i := range nFuncs {
				rva := uint64(u32(funcs + 4*i))
				if rva == 0 || (rva >= uint64(d.VirtualAddress) && rva < dirEnd) {
					continue
				}
				addr := imageBase + rva
				p.EntryPoints[addr] = true
				p.Symbols = append(p.Symbols, LoadedSymbol{Addr: addr, Name: fmt.Sprintf("Ordinal_%d", uint64(base)+i), Source: core.SourceImported})
				if n, ok := nameOf[i]; ok {
					p.Symbols = append(p.Symbols, LoadedSymbol{Addr: addr, Name: n, IsFunction: p.Memory.IsExecutable(addr), Source: core.SourceImported})
				}
			}
		}
	}

	// Imports (ImportDataDirectory): each IAT slot is a pointer slot naming
	// its import; the library is upper-cased as Ghidra's external location.
	if d := h.dirs[1]; d.VirtualAddress != 0 {
		for off := uint64(d.VirtualAddress); ; off += 20 {
			desc, ok := at(off, 20)
			if !ok || slices.Equal(desc, make([]byte, 20)) {
				break
			}
			oft, ft, nameRVA := binary.LittleEndian.Uint32(desc), uint64(binary.LittleEndian.Uint32(desc[16:])), binary.LittleEndian.Uint32(desc[12:])
			lib := strings.ToUpper(cstr(uint64(nameRVA)))
			thunks := uint64(oft)
			if thunks == 0 {
				thunks = ft
			}
			for i := uint64(0); ; i++ {
				tb, ok := at(thunks+i*ptrSize, int(ptrSize))
				if !ok {
					break
				}
				v := binary.LittleEndian.Uint64(tb)
				if ptrSize == 4 {
					v = uint64(binary.LittleEndian.Uint32(tb))
				}
				if v == 0 {
					break
				}
				var name string
				if v&(1<<(8*ptrSize-1)) != 0 {
					name = fmt.Sprintf("Ordinal_%d", v&0xffff)
				} else {
					name = cstr(v&0x7fffffff + 2) // skip the 2-byte hint
				}
				slot := imageBase + ft + i*ptrSize
				p.ImportSlots[slot] = name
				p.Imports = appendImport(p.Imports, name, lib, slot)
			}
		}
	}

	// Base relocations (PeLoader.processRelocations, BaseRelocationDataDirectory):
	// every entry is recorded with its type, ABSOLUTE included.
	if d := h.dirs[5]; d.VirtualAddress != 0 {
		start := rvaToPtr(uint64(d.VirtualAddress))
		if start < 0 {
			start = int64(d.VirtualAddress) // Ghidra's getPointer fallback
		}
		stop := uint64(start) + uint64(d.Size)
		for addr := uint64(start); addr < stop; {
			if addr+8 > fileLen {
				break
			}
			blockRVA := binary.LittleEndian.Uint32(data[addr:])
			blockSize := uint64(binary.LittleEndian.Uint32(data[addr+4:]))
			if blockRVA == 0 || blockSize < 8 || addr+blockSize > fileLen {
				break
			}
			for k := uint64(0); k < (blockSize-8)/2; k++ {
				w := binary.LittleEndian.Uint16(data[addr+8+2*k:])
				typ := w >> 12
				p.Relocations = append(p.Relocations, Relocation{Addr: imageBase + uint64(blockRVA) + uint64(w&0xfff), Type: typ})
				if typ == relBasedHighlow || typ == relBasedDir64 {
					slot := imageBase + uint64(blockRVA) + uint64(w&0xfff)
					if v, ok := p.Memory.ReadUint(slot, int(ptrSize), false); ok && p.Memory.IsMapped(v) {
						p.Pointers[slot] = v
					}
				}
			}
			addr += blockSize
		}
	}

	// x64 .pdata RUNTIME_FUNCTION entries seed function starts.
	if d := h.dirs[3]; d.VirtualAddress != 0 {
		if pd, ok := at(uint64(d.VirtualAddress), int(d.Size)); ok {
			for i := 0; i+12 <= len(pd); i += 12 {
				if begin := imageBase + uint64(binary.LittleEndian.Uint32(pd[i:])); begin != imageBase {
					if _, ok := p.Seeds[begin]; !ok {
						p.Seeds[begin] = SeedExceptionTable
					}
				}
			}
		}
	}

	if s := f.Section(".rdata"); s != nil {
		p.IsRust = rustSignatures(data[s.Offset:min(fileLen, uint64(s.Offset)+uint64(s.Size))])
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
	slices.SortStableFunc(p.Exports, func(a, b Export) int {
		return cmp.Or(cmp.Compare(a.Addr, b.Addr), cmp.Compare(a.Name, b.Name))
	})
	p.Exports = slices.Compact(p.Exports)
	return p, nil
}

// appendImport adds a slot to the import with the same name and library, or a new import.
func appendImport(imports []Import, name, lib string, slot uint64) []Import {
	for i := range imports {
		if imports[i].Name == name && eqOpt(imports[i].Library, &lib) {
			if imports[i].Slot == nil {
				imports[i].Slot = &slot
			}
			return imports
		}
	}
	return append(imports, Import{Name: name, Library: &lib, Slot: &slot})
}

func peLanguage(m uint16) (string, bool) {
	switch m {
	case pe.IMAGE_FILE_MACHINE_I386:
		return "x86:LE:32:default", true
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return "x86:LE:64:default", true
	}
	return "", false
}

// rustSignatures is the RUST_SIGNATURES check of detectRust, for .rdata.
func rustSignatures(d []byte) bool {
	for _, sig := range []string{"RUST_BACKTRACE", "RUST_MIN_STACK", "/rustc/"} {
		if bytes.Contains(d, []byte(sig)) {
			return true
		}
	}
	return false
}
