// Package loader is the Go port of the ELF, PE and raw-image parts of
// rust-analysis/crates/ra-loader (Ghidra ElfLoader, PeLoader, BinaryLoader and
// the .eh_frame function seeding of GccExceptionAnalyzer). Mach-O is not
// ported (follow-up #38).
package loader

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/TorratDev/ghidra/go/internal/ra/core"
)

type LoadedSymbol struct {
	Addr       uint64
	Name       string
	IsFunction bool
	IsData     bool
	Source     core.SymbolSource
}

type Import struct {
	Name    string
	Library *string
	// Slot is the pointer slot (GOT) resolved to this import, if any.
	Slot *uint64
}

// SeedKind says why an address is a function start candidate.
type SeedKind int

const (
	SeedEntry SeedKind = iota
	SeedExport
	SeedSymbol
	SeedInitArray
	SeedExceptionTable
	SeedFunctionStarts
)

type Program struct {
	Path        string
	Sha256      string
	Format      string
	Language    string
	ImageBase   uint64
	BigEndian   bool
	PointerSize uint32
	Memory      core.MemoryMap
	Symbols     []LoadedSymbol
	Imports     []Import
	Exports     []Export
	Entry       *uint64
	// Seeds are function start candidates with their provenance.
	Seeds map[uint64]SeedKind
	// ImportSlots are pointer slots that hold the address of a named external.
	ImportSlots map[uint64]string
	// Pointers are locations known (from relocations) to hold an internal address.
	Pointers map[uint64]uint64
	// MarkedPointers are pointers the loader marks up as data (init/fini arrays).
	MarkedPointers map[uint64]uint64
	// EntryPoints are external entry points; every symbol at one is an export.
	EntryPoints map[uint64]bool
	// FallbackNames name functions that have no symbol (entry, _INIT_0, _DT_INIT).
	FallbackNames map[uint64]string
	// IsRust is set the way Ghidra's loaders tag Rust programs.
	IsRust bool
	// Relocations are PE base relocation entries, ABSOLUTE included (Ghidra
	// RelocationTable, status SKIPPED).
	Relocations []Relocation
}

type Relocation struct {
	Addr uint64
	Type uint16
}

type Export struct {
	Addr uint64
	Name string
}

func newProgram(path, format, language string) *Program {
	return &Program{
		Path: path, Format: format, Language: language,
		Seeds:          map[uint64]SeedKind{},
		ImportSlots:    map[uint64]string{},
		Pointers:       map[uint64]uint64{},
		MarkedPointers: map[uint64]uint64{},
		EntryPoints:    map[uint64]bool{},
		FallbackNames:  map[uint64]string{},
	}
}

// LoadPath loads a file; languageOverride may be empty.
func LoadPath(path, languageOverride string) (*Program, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return LoadBytes(data, path, languageOverride)
}

// LoadBytes loads an image. A recognised ELF keeps its format and only has its
// language label replaced by languageOverride (Ghidra's -processor); anything
// else needs languageOverride and is loaded raw.
func LoadBytes(data []byte, path, languageOverride string) (*Program, error) {
	sum := sha256.Sum256(data)
	var p *Program
	if f, err := elf.NewFile(bytes.NewReader(data)); err == nil {
		if p, err = loadELF(f, path); err != nil {
			return nil, err
		}
	} else if pf, err := pe.NewFile(bytes.NewReader(data)); err == nil {
		if p, err = loadPE(pf, data, path); err != nil {
			return nil, err
		}
	} else if isMachO(data) {
		return nil, fmt.Errorf("%s: Mach-O is not supported yet (#38)", path)
	} else {
		if languageOverride == "" {
			return nil, fmt.Errorf("%s: unrecognized format; pass --language to load as raw binary", path)
		}
		p = loadRaw(data, path, languageOverride)
	}
	p.Sha256 = hex.EncodeToString(sum[:])
	if languageOverride != "" {
		p.Language = languageOverride
	}
	return p, nil
}

func isMachO(data []byte) bool {
	if f, err := macho.NewFile(bytes.NewReader(data)); err == nil {
		f.Close()
		return true
	}
	if f, err := macho.NewFatFile(bytes.NewReader(data)); err == nil {
		f.Close()
		return true
	}
	return false
}

// loadRaw is Ghidra's BinaryLoader: the whole file as one RWX block at 0.
// The block is named "ram"; Ghidra names it after the language's default
// space, which differs only for a few processors (8051, AVR, PIC: "CODE"),
// and a language-to-space table is not worth carrying without the .ldefs data.
func loadRaw(data []byte, path, lang string) *Program {
	p := newProgram(path, "Raw", lang)
	p.Memory.Add(core.MemoryBlock{
		Name: "ram", Size: uint64(len(data)), Data: append([]byte(nil), data...),
		Perms: core.Perms{Read: true, Write: true, Execute: true},
	})
	p.BigEndian = strings.Contains(lang, ":BE:")
	bits := uint64(32)
	if f := strings.Split(lang, ":"); len(f) > 2 {
		if n, err := strconv.ParseUint(f[2], 10, 32); err == nil {
			bits = n
		}
	}
	p.PointerSize = uint32(bits / 8)
	return p
}
