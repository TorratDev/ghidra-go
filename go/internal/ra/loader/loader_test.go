package loader

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"slices"
	"strings"
	"testing"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

type tsec struct {
	name  string
	typ   elf.SectionType
	flags elf.SectionFlag
	addr  uint64
	data  []byte
	size  uint64 // for NOBITS
}

type tseg struct {
	typ   elf.ProgType
	flags elf.ProgFlag
	vaddr uint64
	memsz uint64
	sec   int // index in secs whose data the segment covers, or -1
}

func le64(vs ...uint64) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.LittleEndian.AppendUint64(b, v)
	}
	return b
}

// mkELF builds a little-endian ELF64 x86-64 image.
func mkELF(typ elf.Type, entry uint64, secs []tsec, segs []tseg) []byte {
	const ehsize, phsize, shsize = 64, 56, 64
	shstr := []byte{0}
	nameOff := make([]uint32, len(secs))
	for i, s := range secs {
		nameOff[i] = uint32(len(shstr))
		shstr = append(append(shstr, s.name...), 0)
	}
	shstrOff := uint32(len(shstr))
	shstr = append(append(shstr, ".shstrtab"...), 0)

	off := ehsize + phsize*len(segs)
	secOff := make([]int, len(secs))
	var body []byte
	for i, s := range secs {
		for (off+len(body))%8 != 0 {
			body = append(body, 0)
		}
		secOff[i] = off + len(body)
		if s.typ != elf.SHT_NOBITS {
			body = append(body, s.data...)
		}
	}
	for (off+len(body))%8 != 0 {
		body = append(body, 0)
	}
	strOff := off + len(body)
	body = append(body, shstr...)
	for (off+len(body))%8 != 0 {
		body = append(body, 0)
	}
	shoff := off + len(body)

	var b []byte
	b = append(b, 0x7f, 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(typ))
	b = binary.LittleEndian.AppendUint16(b, uint16(elf.EM_X86_64))
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint64(b, entry)
	b = binary.LittleEndian.AppendUint64(b, ehsize)
	b = binary.LittleEndian.AppendUint64(b, uint64(shoff))
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint16(b, ehsize)
	b = binary.LittleEndian.AppendUint16(b, phsize)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(segs)))
	b = binary.LittleEndian.AppendUint16(b, shsize)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(secs)+2))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(secs)+1))
	for _, g := range segs {
		var o, fsz uint64
		if g.sec >= 0 {
			o, fsz = uint64(secOff[g.sec]), uint64(len(secs[g.sec].data))
		}
		b = binary.LittleEndian.AppendUint32(b, uint32(g.typ))
		b = binary.LittleEndian.AppendUint32(b, uint32(g.flags))
		b = append(b, le64(o, g.vaddr, g.vaddr, fsz, g.memsz, 8)...)
	}
	b = append(b, body...)
	b = append(b, make([]byte, shsize)...) // null section header
	for i, s := range secs {
		size := uint64(len(s.data))
		if s.typ == elf.SHT_NOBITS {
			size = s.size
		}
		b = binary.LittleEndian.AppendUint32(b, nameOff[i])
		b = binary.LittleEndian.AppendUint32(b, uint32(s.typ))
		b = append(b, le64(uint64(s.flags), s.addr, uint64(secOff[i]), size)...)
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = append(b, le64(8, 0)...)
	}
	b = binary.LittleEndian.AppendUint32(b, shstrOff)
	b = binary.LittleEndian.AppendUint32(b, uint32(elf.SHT_STRTAB))
	b = append(b, le64(0, 0, uint64(strOff), uint64(len(shstr)), 0, 1, 0)...)
	return b
}

const (
	alloc = elf.SHF_ALLOC
	wr    = elf.SHF_WRITE
	exec  = elf.SHF_EXECINSTR
)

func block(p *Program, name string) *core.MemoryBlock {
	for _, b := range p.Memory.Blocks() {
		if b.Name == name {
			return &b
		}
	}
	return nil
}

func load(t *testing.T, img []byte, lang string) *Program {
	t.Helper()
	p, err := LoadBytes(img, "test", lang)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// An overlapping .tbss used to be added before .init_array, so MemoryMap.Add
// kept it and dropped the arrays.
func TestTLSOverlapKeepsInitArray(t *testing.T) {
	img := mkELF(elf.ET_EXEC, 0x401000, []tsec{
		{name: ".text", typ: elf.SHT_PROGBITS, flags: alloc | exec, addr: 0x401000, data: []byte{0xc3, 0x90, 0xc3}},
		{name: ".tdata", typ: elf.SHT_PROGBITS, flags: alloc | wr | elf.SHF_TLS, addr: 0x402ff0, data: []byte{1, 2, 3, 4}},
		{name: ".tbss", typ: elf.SHT_NOBITS, flags: alloc | wr | elf.SHF_TLS, addr: 0x403000, size: 0x40},
		{name: ".init_array", typ: elf.SHT_INIT_ARRAY, flags: alloc | wr, addr: 0x403000, data: le64(0x401001)},
		{name: ".fini_array", typ: elf.SHT_FINI_ARRAY, flags: alloc | wr, addr: 0x403008, data: le64(0x401002)},
	}, nil)
	p := load(t, img, "")
	if block(p, ".tbss") != nil {
		t.Error(".tbss was added to memory")
	}
	for _, n := range []string{".tdata", ".init_array", ".fini_array"} {
		if block(p, n) == nil {
			t.Errorf("%s block missing", n)
		}
	}
	if p.FallbackNames[0x401001] != "_INIT_0" || p.FallbackNames[0x401002] != "_FINI_0" {
		t.Errorf("fallback names %v", p.FallbackNames)
	}
	if p.Seeds[0x401001] != SeedInitArray || !p.EntryPoints[0x401001] || p.MarkedPointers[0x403000] != 0x401001 {
		t.Errorf("init array not marked up: seeds %v", p.Seeds)
	}
}

func TestLoadBias(t *testing.T) {
	secs := []tsec{{name: ".text", typ: elf.SHT_PROGBITS, flags: alloc | exec, addr: 0x1000, data: []byte{0xc3}}}
	segs := []tseg{{typ: elf.PT_LOAD, flags: elf.PF_R | elf.PF_X, vaddr: 0, memsz: 0x2000, sec: -1}}
	p := load(t, mkELF(elf.ET_DYN, 0x1000, secs, segs), "")
	if p.ImageBase != image64BaseDefault || block(p, ".text").Start != 0x101000 || *p.Entry != 0x101000 {
		t.Errorf("base %#x, text %#x", p.ImageBase, block(p, ".text").Start)
	}
	p = load(t, mkELF(elf.ET_EXEC, 0x1000, secs, segs), "")
	if p.ImageBase != 0 || block(p, ".text").Start != 0x1000 {
		t.Errorf("ET_EXEC rebased: base %#x", p.ImageBase)
	}
	if image32BaseDefault != 0x10000 || image64BaseDefault != 0x100000 {
		t.Error("default bases")
	}
}

// Every address tag of the table, with the tag numbers of Ghidra's
// ElfDynamicType (Features/Base ghidra.app.util.bin.format.elf).
var dtTags = []struct {
	tag  uint64
	name string
}{
	{3, "PLTGOT"}, {4, "HASH"}, {5, "STRTAB"}, {6, "SYMTAB"}, {7, "RELA"}, {12, "INIT"}, {13, "FINI"},
	{17, "REL"}, {23, "JMPREL"}, {25, "INIT_ARRAY"}, {26, "FINI_ARRAY"}, {32, "PREINIT_ARRAY"},
	{36, "RELR"}, {0x6ffffef5, "GNU_HASH"}, {0x6ffffff0, "VERSYM"}, {0x6ffffffc, "VERDEF"}, {0x6ffffffe, "VERNEED"},
}

func TestDTAddressNames(t *testing.T) {
	for _, c := range dtTags {
		if got, ok := dtAddressName(c.tag); !ok || got != c.name {
			t.Errorf("tag %#x: got %q %v, want %q", c.tag, got, ok, c.name)
		}
	}
	// size, string and flag tags are not addresses
	for _, tag := range []uint64{1, 2, 8, 9, 10, 11, 14, 15, 16, 18, 24, 27, 28, 29, 30, 31, 0x6ffffffb, 0x6ffffff9, 0x6ffffffd, 0x100000004} {
		if got, ok := dtAddressName(tag); ok {
			t.Errorf("tag %#x named %q", tag, got)
		}
	}
}

func TestDynamicMarkup(t *testing.T) {
	var dyn []byte
	want := map[string]uint64{}
	for i, c := range dtTags {
		addr := 0x402000 + uint64(i)*0x10
		dyn = append(dyn, le64(c.tag, addr)...)
		want["__DT_"+c.name] = addr
	}
	dyn = append(dyn, le64(1, 0x99)...)      // DT_NEEDED: not an address
	dyn = append(dyn, le64(0, 0)...)         // DT_NULL ends the table
	dyn = append(dyn, le64(12, 0x402300)...) // after DT_NULL: ignored
	img := mkELF(elf.ET_EXEC, 0x401000, []tsec{
		{name: ".text", typ: elf.SHT_PROGBITS, flags: alloc | exec, addr: 0x401000, data: bytes.Repeat([]byte{0xc3}, 0x100)},
		{name: ".data.rel.ro", typ: elf.SHT_PROGBITS, flags: alloc | wr, addr: 0x402000, data: make([]byte, 0x400)},
		{name: ".dynamic", typ: elf.SHT_DYNAMIC, flags: alloc | wr, addr: 0x403000, data: dyn},
	}, []tseg{
		{typ: elf.PT_DYNAMIC, flags: elf.PF_R, vaddr: 0x403000, memsz: uint64(len(dyn)), sec: 2},
		{typ: ptGNURelro, flags: elf.PF_R, vaddr: 0x402000, memsz: 0x400, sec: -1},
	})
	// DT_INIT and DT_FINI point into executable memory in a real image.
	img = bytes.ReplaceAll(img, le64(12, 0x402000+5*0x10), le64(12, 0x401010))
	img = bytes.ReplaceAll(img, le64(13, 0x402000+6*0x10), le64(13, 0x401020))
	want["__DT_INIT"], want["__DT_FINI"] = 0x401010, 0x401020
	p := load(t, img, "")
	got := map[string]uint64{}
	for _, s := range p.Symbols {
		if strings.HasPrefix(s.Name, "__DT_") {
			got[s.Name] = s.Addr
			if s.IsFunction || s.IsData || s.Source != core.SourceImported {
				t.Errorf("%+v", s)
			}
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d labels, want %d: %v", len(got), len(want), got)
	}
	for n, a := range want {
		if got[n] != a {
			t.Errorf("%s at %#x, want %#x", n, got[n], a)
		}
	}
	if !p.EntryPoints[0x401010] || !p.EntryPoints[0x401020] ||
		p.FallbackNames[0x401010] != "_DT_INIT" || p.FallbackNames[0x401020] != "_DT_FINI" ||
		p.Seeds[0x401010] != SeedEntry {
		t.Errorf("INIT/FINI: entry points %v names %v seeds %v", p.EntryPoints, p.FallbackNames, p.Seeds)
	}
	// RELRO: blocks entirely inside lose write permission, others keep it.
	if block(p, ".data.rel.ro").Perms.Write || !block(p, ".dynamic").Perms.Write {
		t.Error("clear_write")
	}
}

func TestRelativeRelocations(t *testing.T) {
	rela := le64(0x402000, 8, 0x401234) // R_X86_64_RELATIVE: offset, type 8, addend
	img := mkELF(elf.ET_EXEC, 0x401000, []tsec{
		{name: ".text", typ: elf.SHT_PROGBITS, flags: alloc | exec, addr: 0x401000, data: bytes.Repeat([]byte{0xc3}, 0x40)},
		{name: ".data", typ: elf.SHT_PROGBITS, flags: alloc | wr, addr: 0x402000, data: make([]byte, 8)},
		{name: ".rela.dyn", typ: elf.SHT_RELA, flags: alloc, addr: 0x403000, data: rela},
	}, nil)
	p := load(t, img, "")
	if v, ok := p.Memory.ReadUint(0x402000, 8, false); !ok || v != 0x401234 || p.Pointers[0x402000] != 0x401234 {
		t.Errorf("relative reloc not applied: %#x %v", v, p.Pointers)
	}
}

func TestRawImage(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	if _, err := LoadBytes(data, "x.bin", ""); err == nil ||
		err.Error() != "x.bin: unrecognized format; pass --language to load as raw binary" {
		t.Errorf("error %v", err)
	}
	for _, c := range []struct {
		lang string
		ptr  uint32
		be   bool
	}{
		{"x86:LE:64:default", 8, false},
		{"PowerPC:BE:32:default", 4, true},
		{"ARM:LE:16:thumb", 2, false},
		{"weird", 4, false},               // no third field
		{"x86:LE:wide:default", 4, false}, // non-numeric third field
		{"x86:LE:", 4, false},             // empty third field
	} {
		p := load(t, data, c.lang)
		b := block(p, "ram")
		if p.Format != "Raw" || p.Language != c.lang || p.PointerSize != c.ptr || p.BigEndian != c.be || p.ImageBase != 0 {
			t.Errorf("%s: %+v", c.lang, p)
		}
		if b == nil || b.Start != 0 || b.Size != 5 || !b.Perms.Read || !b.Perms.Write || !b.Perms.Execute ||
			!bytes.Equal(b.Data, data) || len(p.Memory.Blocks()) != 1 {
			t.Errorf("%s: block %+v", c.lang, b)
		}
		if len(p.Sha256) != 64 {
			t.Errorf("sha256 %q", p.Sha256)
		}
	}
}

func TestLanguageOverrideOnELF(t *testing.T) {
	img := mkELF(elf.ET_EXEC, 0x401000, []tsec{
		{name: ".text", typ: elf.SHT_PROGBITS, flags: alloc | exec, addr: 0x401000, data: []byte{0xc3}},
	}, nil)
	plain := load(t, img, "")
	over := load(t, img, "x86:LE:32:default")
	if plain.Language != "x86:LE:64:default" || over.Language != "x86:LE:32:default" {
		t.Errorf("languages %q %q", plain.Language, over.Language)
	}
	// only the label changes: format, pointer size and memory stay those of the ELF
	if over.Format != "ELF" || over.PointerSize != 8 || len(over.Memory.Blocks()) != 1 || over.BigEndian {
		t.Errorf("%+v", over)
	}
}

func TestSeedsAreExecutableOnly(t *testing.T) {
	img := mkELF(elf.ET_EXEC, 0x402000, []tsec{
		{name: ".text", typ: elf.SHT_PROGBITS, flags: alloc | exec, addr: 0x401000, data: []byte{0xc3}},
		{name: ".data", typ: elf.SHT_PROGBITS, flags: alloc | wr, addr: 0x402000, data: []byte{1}},
	}, nil)
	p := load(t, img, "")
	if len(p.Seeds) != 0 || p.Entry == nil || *p.Entry != 0x402000 {
		t.Errorf("seeds %v entry %v", p.Seeds, p.Entry)
	}
	if !slices.Equal(p.Symbols, nil) && len(p.Symbols) != 0 {
		t.Errorf("symbols %v", p.Symbols)
	}
}
