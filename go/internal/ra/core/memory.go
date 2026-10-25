package core

import "sort"

type Perms struct {
	Read, Write, Execute bool
}

type MemoryBlock struct {
	Name  string
	Start uint64
	Size  uint64
	Perms Perms
	// Data backs the block; shorter than Size for .bss-like tails, empty for
	// uninitialized blocks.
	Data []byte
}

func (b *MemoryBlock) End() uint64 { return b.Start + b.Size }

func (b *MemoryBlock) Contains(addr uint64) bool { return addr >= b.Start && addr < b.End() }

func (b *MemoryBlock) IsInitialized() bool { return len(b.Data) > 0 }

// MemoryMap is a non-overlapping set of blocks, kept sorted by start address.
type MemoryMap struct {
	blocks []MemoryBlock
}

// Add inserts a block, discarding any part that overlaps an existing block
// (first writer wins, like Ghidra refusing overlapping blocks).
func (m *MemoryMap) Add(block MemoryBlock) {
	if block.Size == 0 {
		return
	}
	for i := range m.blocks {
		b := &m.blocks[i]
		if b.Start <= block.Start && block.Start < b.End() {
			cut := b.End() - block.Start
			if cut >= block.Size {
				return
			}
			block.Start += cut
			block.Size -= cut
			if cut <= uint64(len(block.Data)) {
				block.Data = append([]byte(nil), block.Data[cut:]...)
			} else {
				block.Data = nil
			}
		}
	}
	end := block.End()
	for i := range m.blocks {
		if n := &m.blocks[i]; n.Start > block.Start && n.Start < end {
			keep := n.Start - block.Start
			block.Size = keep
			if keep < uint64(len(block.Data)) {
				block.Data = block.Data[:keep]
			}
			break
		}
	}
	idx := sort.Search(len(m.blocks), func(i int) bool { return m.blocks[i].Start >= block.Start })
	m.blocks = append(m.blocks, MemoryBlock{})
	copy(m.blocks[idx+1:], m.blocks[idx:])
	m.blocks[idx] = block
}

func (m *MemoryMap) Blocks() []MemoryBlock { return m.blocks }

// BlockAt returns the block containing addr, or nil.
func (m *MemoryMap) BlockAt(addr uint64) *MemoryBlock {
	idx := sort.Search(len(m.blocks), func(i int) bool { return m.blocks[i].Start > addr })
	if idx == 0 {
		return nil
	}
	if b := &m.blocks[idx-1]; b.Contains(addr) {
		return b
	}
	return nil
}

func (m *MemoryMap) IsMapped(addr uint64) bool { return m.BlockAt(addr) != nil }

func (m *MemoryMap) IsExecutable(addr uint64) bool {
	b := m.BlockAt(addr)
	return b != nil && b.Perms.Execute
}

// BytesFrom returns the initialized bytes starting at addr, up to the end of
// its block, or nil.
func (m *MemoryMap) BytesFrom(addr uint64) []byte {
	b := m.BlockAt(addr)
	if b == nil {
		return nil
	}
	off := addr - b.Start
	if off >= uint64(len(b.Data)) {
		return nil
	}
	return b.Data[off:]
}

// Read returns n bytes at addr, or nil if they are not all initialized.
func (m *MemoryMap) Read(addr uint64, n int) []byte {
	s := m.BytesFrom(addr)
	if n < 0 || n > len(s) {
		return nil
	}
	return s[:n]
}

// ReadUint reads a size-byte integer. Fix over the Rust version: size 0 or
// above 8 reports false instead of returning 0 or a silently truncated value.
func (m *MemoryMap) ReadUint(addr uint64, size int, bigEndian bool) (uint64, bool) {
	if size <= 0 || size > 8 {
		return 0, false
	}
	b := m.Read(addr, size)
	if b == nil {
		return 0, false
	}
	var v uint64
	for i := 0; i < size; i++ {
		if bigEndian {
			v = v<<8 | uint64(b[i])
		} else {
			v = v<<8 | uint64(b[size-1-i])
		}
	}
	return v, true
}

// Grow grows the block starting at start to size bytes backed by data (never
// past the next block).
func (m *MemoryMap) Grow(start, size uint64, data []byte) {
	var b *MemoryBlock
	next, hasNext := uint64(0), false
	for i := range m.blocks {
		c := &m.blocks[i]
		if c.Start == start && b == nil {
			b = c
		}
		if c.Start > start && (!hasNext || c.Start < next) {
			next, hasNext = c.Start, true
		}
	}
	if b == nil {
		return
	}
	if hasNext {
		size = min(size, next-start)
	}
	if size > b.Size {
		b.Size = size
		b.Data = append([]byte(nil), data[:min(size, uint64(len(data)))]...)
	}
}

// ClearWrite removes write permission from blocks entirely inside [start, end).
func (m *MemoryMap) ClearWrite(start, end uint64) {
	for i := range m.blocks {
		if b := &m.blocks[i]; b.Start >= start && b.End() <= end {
			b.Perms.Write = false
		}
	}
}

// Write copies bytes into the initialized part of the block containing addr.
func (m *MemoryMap) Write(addr uint64, bytes []byte) bool {
	for i := range m.blocks {
		b := &m.blocks[i]
		if !b.Contains(addr) {
			continue
		}
		off := addr - b.Start
		if off+uint64(len(bytes)) > uint64(len(b.Data)) {
			return false
		}
		copy(b.Data[off:], bytes)
		return true
	}
	return false
}
