// Package export reads the project export written by scripts/export/ExportProject.java
// (export.json plus the export.bin sidecar) into typed structures, with lookups by address and name.
package export

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// FormatVersion is the layout this package reads. ExportProject.java does not write a version
// field yet, so an absent "format_version" means this version; any other value is rejected.
const FormatVersion = 1

// ErrNotFound is returned (wrapped) by ReadBytes when no block holds the requested bytes.
// The Find/At/By lookups do not return it: they report absence as a false/empty result.
var ErrNotFound = errors.New("not found")

// Address is a Ghidra address: an address space name and an offset ("ram:02000d6c").
type Address struct {
	Space  string
	Offset uint64
}

// ParseAddress parses "space:hexoffset".
func ParseAddress(s string) (Address, error) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return Address{}, fmt.Errorf("export: bad address %q", s)
	}
	off, err := strconv.ParseUint(s[i+1:], 16, 64)
	if err != nil {
		return Address{}, fmt.Errorf("export: bad address %q: %w", s, err)
	}
	return Address{s[:i], off}, nil
}

func (a Address) String() string { return fmt.Sprintf("%s:%08x", a.Space, a.Offset) }

// UnmarshalJSON accepts an address string. JSON null (a symbol with no address) leaves the zero Address.
func (a *Address) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := ParseAddress(s)
	*a = v
	return err
}

// Block is a memory block. Initialized blocks have their bytes in the sidecar at
// [SidecarOffset, SidecarOffset+SidecarLength).
type Block struct {
	Name          string  `json:"name"`
	Start         Address `json:"start"`
	Size          uint64  `json:"size"`
	Read          bool    `json:"read"`
	Write         bool    `json:"write"`
	Execute       bool    `json:"execute"`
	Type          string  `json:"type"`
	Initialized   bool    `json:"initialized"`
	Volatile      bool    `json:"volatile"`
	Overlay       bool    `json:"overlay"`
	SidecarOffset *uint64 `json:"sidecar_offset"`
	SidecarLength *uint64 `json:"sidecar_length"`
}

// Contains reports whether a lies in the block.
func (b *Block) Contains(a Address) bool {
	return a.Space == b.Start.Space && a.Offset >= b.Start.Offset && a.Offset-b.Start.Offset < b.Size
}

// Symbol is a symbol table entry. Address is the zero Address when the export has none
// (HasAddress is false). TypeID is Ghidra's SymbolType id (Label 0, Function 5, ...).
type Symbol struct {
	Name       string   `json:"name"`
	Address    Address  `json:"address"`
	TypeID     int      `json:"type_id"`
	Type       string   `json:"type"`
	Namespace  []string `json:"namespace"`
	Source     string   `json:"source"`
	Primary    bool     `json:"primary"`
	HasAddress bool     `json:"-"`
}

// Range is an inclusive address range.
type Range struct {
	Start Address `json:"start"`
	End   Address `json:"end"`
}

// Parameter is a function parameter. DataType is a path name that keys Export.DataType.
type Parameter struct {
	Ordinal  int    `json:"ordinal"`
	Name     string `json:"name"`
	DataType string `json:"data_type"`
	Storage  string `json:"storage"`
}

// Function is a function with its prototype.
type Function struct {
	Entry             Address     `json:"entry"`
	Name              string      `json:"name"`
	Namespace         []string    `json:"namespace"`
	CallingConvention string      `json:"calling_convention"`
	Thunk             bool        `json:"thunk"`
	Varargs           bool        `json:"varargs"`
	NoReturn          bool        `json:"no_return"`
	CustomStorage     bool        `json:"custom_storage"`
	Body              []Range     `json:"body"`
	Prototype         string      `json:"prototype"`
	ReturnType        string      `json:"return_type"`
	ReturnStorage     string      `json:"return_storage"`
	Parameters        []Parameter `json:"parameters"`
}

// Component is a member of a structure or union.
type Component struct {
	Ordinal  int    `json:"ordinal"`
	Offset   int    `json:"offset"`
	Name     string `json:"name"`
	DataType string `json:"data_type"`
	Length   int    `json:"length"`
}

// FuncParam is a parameter of a function definition data type.
type FuncParam struct {
	Ordinal  int    `json:"ordinal"`
	Name     string `json:"name"`
	DataType string `json:"data_type"`
}

// DataType is a data type used by an exported function. Which optional fields are set
// depends on Kind (TypeDef, Pointer, Array, Structure, Union, FunctionDefinition, Enum, Other).
type DataType struct {
	Name         string      `json:"name"`
	PathName     string      `json:"path_name"`
	CategoryPath string      `json:"category_path"`
	Length       int         `json:"length"`
	Alignment    int         `json:"alignment"`
	Description  string      `json:"description"`
	Kind         string      `json:"kind"`
	Base         string      `json:"base,omitempty"`
	Elements     int         `json:"elements,omitempty"`
	ElementLen   int         `json:"element_length,omitempty"`
	Components   []Component `json:"components,omitempty"`
	ReturnType   string      `json:"return_type,omitempty"`
	Parameters   []FuncParam `json:"parameters,omitempty"`
}

// Sidecar names the binary file holding the initialized block bytes.
type Sidecar struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Export is a parsed export.json.
type Export struct {
	FormatVersion int        `json:"-"` // set from "format_version"; 1 when the field is absent
	Project       string     `json:"project"`
	Program       string     `json:"program"`
	GhidraVersion string     `json:"ghidra_version"`
	Language      string     `json:"language"`
	CompilerSpec  string     `json:"compiler_spec"`
	ImageBase     Address    `json:"image_base"`
	ExecutableMD5 string     `json:"executable_md5"`
	FunctionCount int        `json:"function_count"` // the manager's count; includes external functions
	Sidecar       Sidecar    `json:"sidecar"`
	Blocks        []Block    `json:"memory_blocks"`
	Symbols       []Symbol   `json:"symbols"`
	Functions     []Function `json:"functions"`
	DataTypes     []DataType `json:"data_types"`

	dir      string
	bySpace  map[string][]*Block // sorted by start
	symAt    map[Address][]*Symbol
	symName  map[string][]*Symbol
	funcAt   map[Address]*Function
	typeName map[string]*DataType

	sumOnce sync.Once
	sumErr  error
}

// Load reads export.json at path. The sidecar is looked up next to it.
func Load(path string) (*Export, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, filepath.Dir(path))
}

// Parse reads an export.json from r; dir is where the sidecar file lives.
func Parse(r io.Reader, dir string) (*Export, error) {
	var e Export
	// Decode the version and symbol addresses raw: a pointer tells absent (nil) from an explicit 0 or null.
	var raw struct {
		FormatVersion *int `json:"format_version"`
		Symbols       []struct {
			Address *string `json:"address"`
		} `json:"symbols"`
	}
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(buf, &e); err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	if err := json.Unmarshal(buf, &raw); err != nil {
		return nil, fmt.Errorf("export: %w", err)
	}
	e.FormatVersion = FormatVersion // field absent: the only layout ExportProject.java writes
	if raw.FormatVersion != nil {
		e.FormatVersion = *raw.FormatVersion
	}
	if e.FormatVersion != FormatVersion {
		return nil, fmt.Errorf("export: unsupported format version %d (this reader supports %d)", e.FormatVersion, FormatVersion)
	}
	if e.Sidecar.File == "" || len(e.Sidecar.SHA256) != sha256.Size*2 {
		return nil, errors.New("export: missing or malformed sidecar reference (file, sha256)")
	}
	if filepath.Base(e.Sidecar.File) != e.Sidecar.File {
		return nil, fmt.Errorf("export: sidecar file %q must be a plain file name", e.Sidecar.File)
	}
	e.dir = dir
	e.index()
	for i := range e.Symbols {
		e.Symbols[i].HasAddress = raw.Symbols[i].Address != nil
	}
	e.indexSymbols()
	for i := range e.Blocks {
		b := &e.Blocks[i]
		if b.Initialized && (b.SidecarOffset == nil || b.SidecarLength == nil || *b.SidecarLength != b.Size) {
			return nil, fmt.Errorf("export: initialized block %q has no matching sidecar range", b.Name)
		}
	}
	return &e, nil
}

func (e *Export) index() {
	e.bySpace = map[string][]*Block{}
	for i := range e.Blocks {
		b := &e.Blocks[i]
		e.bySpace[b.Start.Space] = append(e.bySpace[b.Start.Space], b)
	}
	for _, bs := range e.bySpace {
		sort.Slice(bs, func(i, j int) bool { return bs[i].Start.Offset < bs[j].Start.Offset })
	}
	e.funcAt = make(map[Address]*Function, len(e.Functions))
	for i := range e.Functions {
		e.funcAt[e.Functions[i].Entry] = &e.Functions[i]
	}
	e.typeName = make(map[string]*DataType, len(e.DataTypes))
	for i := range e.DataTypes {
		e.typeName[e.DataTypes[i].PathName] = &e.DataTypes[i]
	}
}

func (e *Export) indexSymbols() {
	e.symAt = map[Address][]*Symbol{}
	e.symName = map[string][]*Symbol{}
	for i := range e.Symbols {
		s := &e.Symbols[i]
		if s.HasAddress {
			e.symAt[s.Address] = append(e.symAt[s.Address], s)
		}
		e.symName[s.Name] = append(e.symName[s.Name], s)
	}
}

// BlockContaining returns the memory block holding a, or false when no block does.
func (e *Export) BlockContaining(a Address) (*Block, bool) {
	bs := e.bySpace[a.Space]
	i := sort.Search(len(bs), func(i int) bool { return bs[i].Start.Offset > a.Offset })
	if i > 0 && bs[i-1].Contains(a) {
		return bs[i-1], true
	}
	return nil, false
}

// SymbolsAt returns the symbols at a (a function and a label can share an address), in export order.
func (e *Export) SymbolsAt(a Address) []*Symbol { return e.symAt[a] }

// SymbolsNamed returns the symbols with the given name (names are not unique across namespaces).
func (e *Export) SymbolsNamed(name string) []*Symbol { return e.symName[name] }

// FunctionAt returns the function whose entry point is a.
func (e *Export) FunctionAt(a Address) (*Function, bool) {
	f, ok := e.funcAt[a]
	return f, ok
}

// DataType returns the data type with the given path name (as used in Parameter.DataType).
func (e *Export) DataType(pathName string) (*DataType, bool) {
	d, ok := e.typeName[pathName]
	return d, ok
}

// VerifySidecar checks the sidecar file's sha256 against the export. The result is cached.
func (e *Export) VerifySidecar() error {
	e.sumOnce.Do(func() {
		f, err := os.Open(filepath.Join(e.dir, e.Sidecar.File))
		if err != nil {
			e.sumErr = fmt.Errorf("export: sidecar: %w", err)
			return
		}
		defer f.Close()
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			e.sumErr = fmt.Errorf("export: sidecar: %w", err)
			return
		}
		if got := hex.EncodeToString(h.Sum(nil)); got != e.Sidecar.SHA256 {
			e.sumErr = fmt.Errorf("export: sidecar %s has sha256 %s, export says %s", e.Sidecar.File, got, e.Sidecar.SHA256)
		}
	})
	return e.sumErr
}

// ReadBytes returns n bytes starting at a from the sidecar, after verifying its sha256. The range
// must lie inside one initialized block; otherwise the error wraps ErrNotFound.
func (e *Export) ReadBytes(a Address, n int) ([]byte, error) {
	b, ok := e.BlockContaining(a)
	if !ok {
		return nil, fmt.Errorf("export: no block contains %s: %w", a, ErrNotFound)
	}
	if !b.Initialized {
		return nil, fmt.Errorf("export: block %q is uninitialized, no bytes at %s: %w", b.Name, a, ErrNotFound)
	}
	if n < 0 || uint64(n) > b.Size-(a.Offset-b.Start.Offset) {
		return nil, fmt.Errorf("export: %d bytes at %s run past the end of block %q: %w", n, a, b.Name, ErrNotFound)
	}
	if err := e.VerifySidecar(); err != nil {
		return nil, err
	}
	f, err := os.Open(filepath.Join(e.dir, e.Sidecar.File))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := make([]byte, n)
	if _, err := f.ReadAt(out, int64(*b.SidecarOffset+(a.Offset-b.Start.Offset))); err != nil {
		return nil, fmt.Errorf("export: sidecar read: %w", err)
	}
	return out, nil
}
