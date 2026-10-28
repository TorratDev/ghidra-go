package loader

import (
	"debug/macho"
	"fmt"
	"slices"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

// Ghidra's MachoProgramBuilder builds the memory blocks with processMemoryBlocks
// (segments, then sections) and createMemoryBlock. Memory.split keeps the lower
// part in the block it splits and gives the upper part to a new block. A
// later block that intersects an existing one splits it, then renames and
// re-permissions every block in its range. machoBlock replays that.
type machoBlock struct {
	name, comment string
	start, end    uint64 // end is exclusive
	perms         core.Perms
	initialized   bool
	fileOff       uint64 // file offset of start, when initialized
}

type machoLayout struct {
	blocks []*machoBlock
}

func (l *machoLayout) intersecting(start, end uint64) []*machoBlock {
	var out []*machoBlock
	for _, b := range l.blocks {
		if b.start < end && b.end > start {
			out = append(out, b)
		}
	}
	return out
}

// split is Memory.split: b keeps [start, addr) and the new upper block takes
// [addr, end) with the same attributes.
func (l *machoLayout) split(b *machoBlock, addr uint64) {
	upper := *b
	upper.start = addr
	if b.initialized {
		upper.fileOff = b.fileOff + (addr - b.start)
	}
	b.end = addr
	i := slices.Index(l.blocks, b)
	l.blocks = slices.Insert(l.blocks, i+1, &upper)
}

// create is MachoProgramBuilder.createMemoryBlock. A range that meets no block
// becomes a new block, initialized from the file unless zeroFill. Otherwise
// the range is cut out of the blocks it meets, and those blocks take the new
// name, comment and permissions. The ending check uses the last block met
// before the start split, which is the same object when the start split
// shortened it, so the end split is skipped then, as in Ghidra.
func (l *machoLayout) create(name string, start, fileOff, length uint64, comment string, perms core.Perms, zeroFill bool) {
	end := start + length
	inter := l.intersecting(start, end)
	if len(inter) == 0 {
		b := &machoBlock{name: name, comment: comment, start: start, end: end, perms: perms,
			initialized: !zeroFill, fileOff: fileOff}
		i := 0
		for i < len(l.blocks) && l.blocks[i].start < start {
			i++
		}
		l.blocks = slices.Insert(l.blocks, i, b)
		return
	}
	if first := inter[0]; start > first.start {
		l.split(first, start)
	}
	if last := inter[len(inter)-1]; end < last.end {
		l.split(last, end)
	}
	for _, b := range l.intersecting(start, end) {
		b.name, b.comment, b.perms = name, comment, perms
	}
}

// machoSectionPerms is Section.isRead, isWrite and isExecute: sections carry
// their own permissions, unlike segments.
func machoSectionPerms(s *macho.Section) core.Perms {
	write := strings.HasPrefix(s.Name, "__got") ||
		(s.Seg != "__TEXT" && s.Seg != "__TEXT_EXEC" && s.Seg != "__PRELINK_TEXT" && s.Name != "__const")
	const pureInstructions, someInstructions = 0x80000000, 0x400
	execute := s.Name == "__text" || s.Seg == "__TEXT_EXEC" ||
		s.Flags&(pureInstructions|someInstructions) != 0
	return core.Perms{Read: true, Write: write, Execute: execute}
}

// addSegments is processMemoryBlocks for segments: __PAGEZERO is skipped, and
// a segment gets a file-backed block and an uninitialized tail when vmsize > filesize.
func (l *machoLayout) addSegments(segs []*macho.Segment) {
	for _, s := range segs {
		if s.Name == "__PAGEZERO" || s.Memsz == 0 {
			continue
		}
		perms := core.Perms{Read: s.Prot&1 != 0, Write: s.Prot&2 != 0, Execute: s.Prot&4 != 0}
		if s.Filesz > 0 {
			l.create(s.Name, s.Addr, s.Offset, s.Filesz, s.Name, perms, false)
		}
		if s.Memsz > s.Filesz {
			l.create(s.Name, s.Addr+s.Filesz, 0, s.Memsz-s.Filesz, s.Name, perms, true)
		}
	}
}

// addSections is processMemoryBlocks for sections: a section gets its own block
// when it has bytes or is zerofill, and its permissions come from the section.
func (l *machoLayout) addSections(sections []*macho.Section) {
	for _, s := range sections {
		zero := s.Flags&0xff == 0x1 // S_ZEROFILL
		if s.Size > 0 && (s.Offset > 0 || zero) {
			l.create(s.Name, s.Addr, uint64(s.Offset), s.Size, s.Seg, machoSectionPerms(s), zero)
		}
	}
}

// loadMachO ports the memory layout of Ghidra's MachoProgramBuilder for
// x86_64 images. shortcut: overlay segments (vmsize 0, nonzero address) get no
// block; no corpus binary has one, add their own address space when one does.
func loadMachO(f *macho.File, data []byte, path string) (*Program, error) {
	if f.Cpu != macho.CpuAmd64 {
		return nil, fmt.Errorf("%s: Mach-O CPU %v not supported yet (#38)", path, f.Cpu)
	}
	p := newProgram(path, "MachO", "x86:LE:64:default")
	p.PointerSize = 8

	var segs []*macho.Segment
	for _, ld := range f.Loads {
		if s, ok := ld.(*macho.Segment); ok {
			segs = append(segs, s)
		}
	}
	// MachoProgramBuilder.getMachoBaseAddress: the lowest vmaddr of a segment with file bytes.
	first := true
	for _, s := range segs {
		if s.Filesz > 0 && (first || s.Addr < p.ImageBase) {
			p.ImageBase, first = s.Addr, false
		}
	}

	lay := &machoLayout{}
	// MH_DYLIB_STUB (type 9) gets no blocks at all; the macho package has no constant for it.
	if f.Type != 9 {
		lay.addSegments(segs)
		lay.addSections(f.Sections)
	}

	for _, b := range lay.blocks {
		mb := core.MemoryBlock{Name: b.name, Start: b.start, Size: b.end - b.start, Perms: b.perms}
		if b.initialized {
			if b.fileOff+mb.Size > uint64(len(data)) {
				return nil, fmt.Errorf("%s: block %s runs past the end of the file", path, b.name)
			}
			mb.Data = append([]byte(nil), data[b.fileOff:b.fileOff+mb.Size]...)
		}
		p.Memory.Add(mb)
	}
	return p, nil
}
