//! Loaded memory image (Ghidra `Memory` / `MemoryBlock`).

use std::ops::Range;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

#[derive(Debug, Clone)]
pub struct MemoryBlock {
    pub name: String,
    pub start: u64,
    pub size: u64,
    pub perms: Perms,
    /// Bytes backing the block; shorter than `size` for `.bss`-like tails,
    /// empty for uninitialized blocks.
    pub data: Vec<u8>,
}

impl MemoryBlock {
    pub fn end(&self) -> u64 {
        self.start + self.size
    }

    pub fn range(&self) -> Range<u64> {
        self.start..self.end()
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end()
    }

    pub fn is_initialized(&self) -> bool {
        !self.data.is_empty()
    }
}

/// Non-overlapping set of blocks, kept sorted by start address.
#[derive(Debug, Clone, Default)]
pub struct MemoryMap {
    blocks: Vec<MemoryBlock>,
}

impl MemoryMap {
    /// Adds a block, discarding any part that overlaps an existing block
    /// (first writer wins, like Ghidra refusing overlapping blocks).
    pub fn add(&mut self, mut block: MemoryBlock) {
        if block.size == 0 {
            return;
        }
        for b in &self.blocks {
            if b.start <= block.start && block.start < b.end() {
                let cut = b.end() - block.start;
                if cut >= block.size {
                    return;
                }
                block.start += cut;
                block.size -= cut;
                block.data = block
                    .data
                    .get(cut as usize..)
                    .map(<[u8]>::to_vec)
                    .unwrap_or_default();
            }
        }
        let end = block.end();
        if let Some(next) = self
            .blocks
            .iter()
            .find(|b| b.start > block.start && b.start < end)
        {
            let keep = next.start - block.start;
            block.size = keep;
            block.data.truncate(keep as usize);
        }
        let idx = self.blocks.partition_point(|b| b.start < block.start);
        self.blocks.insert(idx, block);
    }

    pub fn blocks(&self) -> &[MemoryBlock] {
        &self.blocks
    }

    pub fn block_at(&self, addr: u64) -> Option<&MemoryBlock> {
        let idx = self.blocks.partition_point(|b| b.start <= addr);
        let b = self.blocks.get(idx.checked_sub(1)?)?;
        b.contains(addr).then_some(b)
    }

    pub fn is_mapped(&self, addr: u64) -> bool {
        self.block_at(addr).is_some()
    }

    pub fn is_executable(&self, addr: u64) -> bool {
        self.block_at(addr).is_some_and(|b| b.perms.execute)
    }

    /// Initialized bytes starting at `addr`, up to the end of its block.
    pub fn bytes_from(&self, addr: u64) -> Option<&[u8]> {
        let b = self.block_at(addr)?;
        b.data
            .get((addr - b.start) as usize..)
            .filter(|s| !s.is_empty())
    }

    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        self.bytes_from(addr)?.get(..len)
    }

    pub fn read_uint(&self, addr: u64, size: usize, big_endian: bool) -> Option<u64> {
        let bytes = self.read(addr, size)?;
        let mut v = 0u64;
        for i in 0..size {
            let b = if big_endian {
                bytes[i]
            } else {
                bytes[size - 1 - i]
            };
            v = (v << 8) | b as u64;
        }
        Some(v)
    }

    /// Grows the block starting at `start` to `size` bytes backed by `data`
    /// (never past the next block).
    pub fn grow(&mut self, start: u64, size: u64, data: &[u8]) {
        let next = self
            .blocks
            .iter()
            .map(|b| b.start)
            .filter(|s| *s > start)
            .min();
        if let Some(b) = self.blocks.iter_mut().find(|b| b.start == start) {
            let size = next.map_or(size, |n| size.min(n - start));
            if size > b.size {
                b.size = size;
                b.data = data[..(size as usize).min(data.len())].to_vec();
            }
        }
    }

    /// Removes write permission from blocks entirely inside `[start, end)`.
    pub fn clear_write(&mut self, start: u64, end: u64) {
        for b in &mut self.blocks {
            if b.start >= start && b.end() <= end {
                b.perms.write = false;
            }
        }
    }

    pub fn write(&mut self, addr: u64, bytes: &[u8]) -> bool {
        let Some(b) = self.blocks.iter_mut().find(|b| b.contains(addr)) else {
            return false;
        };
        let off = (addr - b.start) as usize;
        let Some(dst) = b.data.get_mut(off..off + bytes.len()) else {
            return false;
        };
        dst.copy_from_slice(bytes);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blk(start: u64, size: u64) -> MemoryBlock {
        MemoryBlock {
            name: format!("b{start:x}"),
            start,
            size,
            perms: Perms::default(),
            data: (0..size).map(|i| i as u8).collect(),
        }
    }

    #[test]
    fn lookup_and_overlap_trimming() {
        let mut m = MemoryMap::default();
        m.add(blk(0x1000, 0x100));
        m.add(blk(0x1080, 0x100)); // trimmed to 0x1100..0x1180
        m.add(blk(0x0f00, 0x200)); // trimmed to 0x0f00..0x1000
        let starts: Vec<_> = m.blocks().iter().map(|b| (b.start, b.size)).collect();
        assert_eq!(
            starts,
            vec![(0xf00, 0x100), (0x1000, 0x100), (0x1100, 0x80)]
        );
        assert_eq!(m.read(0x1100, 1), Some(&[0x80u8][..]));
        assert!(!m.is_mapped(0x1180));
    }

    #[test]
    fn read_uint_endianness() {
        let mut m = MemoryMap::default();
        m.add(blk(0, 8));
        assert_eq!(m.read_uint(0, 4, false), Some(0x03020100));
        assert_eq!(m.read_uint(0, 4, true), Some(0x00010203));
    }
}
