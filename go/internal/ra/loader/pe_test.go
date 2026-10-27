package loader

import (
	"debug/pe"
	"os"
	"path/filepath"
	"testing"
)

func TestPESectionLayout(t *testing.T) {
	h := peHeader{sectionAlign: 0x1000, fileAlign: 0x200}
	const fileLen = 0x10000
	cases := []struct {
		name           string
		s              pe.Section
		ptr, raw, virt uint64
	}{
		{"aligned raw, virtual size rounded up to section alignment",
			pe.Section{SectionHeader: pe.SectionHeader{VirtualSize: 0x1234, Size: 0x1000, Offset: 0x400}}, 0x400, 0x1000, 0x2000},
		{"zero virtual size takes the aligned raw size",
			pe.Section{SectionHeader: pe.SectionHeader{Size: 0x200, Offset: 0x400}}, 0x400, 0x200, 0x200},
		{"raw pointer is not aligned down",
			pe.Section{SectionHeader: pe.SectionHeader{VirtualSize: 0x100, Size: 0x200, Offset: 0x3f0}}, 0x3f0, 0x200, 0x1000},
		{"raw pointer past end of file reads from 0",
			pe.Section{SectionHeader: pe.SectionHeader{VirtualSize: 0x100, Size: 0x200, Offset: 0x20000}}, 0, 0x200, 0x1000},
		{"negative SizeOfRawData falls back to VirtualSize",
			pe.Section{SectionHeader: pe.SectionHeader{VirtualSize: 0x500, Size: 0x80000000, Offset: 0x400}}, 0x400, 0x500, 0x1000},
		{"raw size truncated to the file",
			pe.Section{SectionHeader: pe.SectionHeader{VirtualSize: 0x4000, Size: 0x2000, Offset: 0xf000}}, 0xf000, 0x1000, 0x4000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ptr, raw, virt := peSectionLayout(&c.s, h, fileLen)
			if ptr != c.ptr || raw != c.raw || virt != c.virt {
				t.Errorf("got ptr %#x raw %#x virt %#x; want %#x %#x %#x", ptr, raw, virt, c.ptr, c.raw, c.virt)
			}
		})
	}
}

// TestPECorpus loads the PE corpus when RA_PE_CORPUS names its directory.
func TestPECorpus(t *testing.T) {
	dir := os.Getenv("RA_PE_CORPUS")
	if dir == "" {
		t.Skip("RA_PE_CORPUS not set")
	}
	for _, name := range []string{"cxx-msvc-i386.dll", "cxx-msvc-x86_64.dll", "freestanding-i386-pe-clang-O2.exe", "freestanding-x86_64-pe-clang-O2.exe"} {
		t.Run(name, func(t *testing.T) {
			p, err := LoadPath(filepath.Join(dir, name), "")
			if err != nil {
				t.Fatal(err)
			}
			if p.Format != "PE" {
				t.Fatalf("format %q", p.Format)
			}
			hdr := p.Memory.BlockAt(p.ImageBase)
			if hdr == nil || hdr.Name != "Headers" || hdr.Perms.Write || hdr.Perms.Execute {
				t.Errorf("headers block at image base: %+v", hdr)
			}
			if p.Entry == nil || !p.EntryPoints[*p.Entry] {
				t.Errorf("entry %v not an external entry point", p.Entry)
			}
			for _, r := range p.Relocations {
				if !p.Memory.IsMapped(r.Addr) {
					t.Errorf("relocation at unmapped %#x", r.Addr)
					break
				}
			}
		})
	}
}
