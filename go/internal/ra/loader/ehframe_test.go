package loader

import (
	"debug/elf"
	"encoding/binary"
	"slices"
	"testing"
)

const ehAddr = 0x402000

func u32(vs ...uint32) []byte {
	var b []byte
	for _, v := range vs {
		b = binary.LittleEndian.AppendUint32(b, v)
	}
	return b
}

// entry frames body with a length, padded with DW_CFA_nop to a multiple of 4.
func entry(body []byte) []byte {
	for len(body)%4 != 0 {
		body = append(body, 0)
	}
	return append(u32(uint32(len(body))), body...)
}

// cieZR is a version 1 CIE with augmentation "zR" and FDE encoding 0x1b
// (pcrel | sdata4).
func cieZR() []byte {
	return entry(append(u32(0), 1, 'z', 'R', 0, 1, 0x78, 16, 1, 0x1b))
}

// fdeZR is an FDE whose CIE is at cieOff; pos is its own offset in the section.
func fdeZR(pos, cieOff int, target uint64, rng uint32) []byte {
	body := u32(uint32(pos + 4 - cieOff))
	body = append(body, u32(uint32(int32(int64(target)-int64(ehAddr+pos+8))), rng)...)
	return entry(append(body, 0)) // empty augmentation data
}

func ehELF(eh []byte) []byte {
	return mkELF(elf.ET_EXEC, 0x4011f0, []tsec{
		{name: ".text", typ: elf.SHT_PROGBITS, flags: alloc | exec, addr: 0x401000, data: make([]byte, 0x200)},
		{name: ".eh_frame", typ: elf.SHT_PROGBITS, flags: alloc, addr: ehAddr, data: eh},
	}, nil)
}

func ehSeeds(p *Program) []uint64 {
	var out []uint64
	for a, k := range p.Seeds {
		if k == SeedExceptionTable {
			out = append(out, a)
		}
	}
	slices.Sort(out)
	return out
}

func TestEhFrameSkipsCorruptEntries(t *testing.T) {
	var eh []byte
	eh = append(eh, cieZR()...) // CIE at 0
	cie := 0
	add := func(f func(pos int) []byte) { eh = append(eh, f(len(eh))...) }
	add(func(pos int) []byte { return fdeZR(pos, cie, 0x401000, 4) })
	// corrupt: the CIE pointer lands on the first FDE, which is not a CIE
	add(func(pos int) []byte { return fdeZR(pos, len(cieZR()), 0x401010, 4) })
	// corrupt: truncated, the address range is missing
	add(func(pos int) []byte { return entry(append(u32(uint32(pos+4-cie)), 0, 0, 0, 0)) })
	// corrupt: CIE pointer before the start of the section
	add(func(pos int) []byte { return entry(append(u32(uint32(pos+4+100)), make([]byte, 12)...)) })
	add(func(pos int) []byte { return fdeZR(pos, cie, 0x401100, 8) }) // valid, after the corrupt ones
	add(func(pos int) []byte { return fdeZR(pos, cie, 0x401020, 0) }) // zero length: no seed
	add(func(pos int) []byte { return fdeZR(pos, cie, ehAddr, 4) })   // not executable: no seed
	eh = append(eh, u32(0)...)                                        // terminator
	eh = append(eh, fdeZR(len(eh), cie, 0x401180, 4)...)              // after the terminator: not read
	p := load(t, ehELF(eh), "")
	if got := ehSeeds(p); !slices.Equal(got, []uint64{0x401000, 0x401100}) {
		t.Errorf("seeds %#x", got)
	}
}

func TestEhFrameBadLengthStopsWalk(t *testing.T) {
	eh := cieZR()
	eh = append(eh, fdeZR(len(eh), 0, 0x401000, 4)...)
	eh = append(eh, u32(0x7fffffff, 0)...) // length beyond the section: cannot resync
	p := load(t, ehELF(eh), "")
	if got := ehSeeds(p); !slices.Equal(got, []uint64{0x401000}) {
		t.Errorf("seeds %#x", got)
	}
}

func TestEhFrameCorruptCIEOnlyDropsItsFDEs(t *testing.T) {
	bad := entry(append(u32(0), 9, 0, 1, 0x78, 16)) // version 9
	eh := append(cieZR(), bad...)
	eh = append(eh, fdeZR(len(eh), 0, 0x401000, 4)...)
	eh = append(eh, fdeZR(len(eh), len(cieZR()), 0x401100, 4)...) // refers to the bad CIE
	eh = append(eh, fdeZR(len(eh), 0, 0x401040, 4)...)
	p := load(t, ehELF(eh), "")
	if got := ehSeeds(p); !slices.Equal(got, []uint64{0x401000, 0x401040}) {
		t.Errorf("seeds %#x", got)
	}
}

func TestEhFrameAbsoluteEncodingAndAugmentation(t *testing.T) {
	// "zPLR": personality (absptr pointer), LSDA encoding (udata4) and FDE
	// encoding (absptr); the FDE carries an LSDA pointer in its augmentation data.
	aug := []byte{0x00}                  // P: encoding absptr ...
	aug = append(aug, le64(0x401050)...) // ... and the pointer
	aug = append(aug, 0x03, 0x00)        // L: udata4; R: absptr
	body := append(u32(0), 1, 'z', 'P', 'L', 'R', 0, 1, 0x78, 16, byte(len(aug)))
	c := entry(append(body, aug...))
	fde := append(u32(uint32(4+len(c))), le64(0x401100, 8)...)
	fde = append(fde, 4, 0x11, 0x22, 0x33, 0x44) // augmentation length 4: the LSDA
	p := load(t, ehELF(append(c, entry(fde)...)), "")
	if got := ehSeeds(p); !slices.Equal(got, []uint64{0x401100}) {
		t.Errorf("seeds %#x", got)
	}
	// an unknown augmentation character makes the CIE, and so its FDEs, unusable
	body = append(u32(0), 1, 'z', 'Q', 0, 1, 0x78, 16, 0)
	c = entry(body)
	fde = append(u32(uint32(4+len(c))), le64(0x401100, 8)...)
	p = load(t, ehELF(append(c, entry(append(fde, 0))...)), "")
	if got := ehSeeds(p); len(got) != 0 {
		t.Errorf("seeds %#x", got)
	}
}
