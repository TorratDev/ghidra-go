// Package proto speaks the framed wire protocol of the native Ghidra decompile
// process. See docs/re/decompiler-protocol.md; each marker below is in its
// marker table. Nothing here knows about export or the UI.
package proto

// Marker is the last byte of a 4-byte burst 00 00 01 <marker>. Starts are even, ends odd.
type Marker byte

const (
	CmdStart       Marker = 0x02 // Java to native
	CmdEnd         Marker = 0x03
	QueryStart     Marker = 0x04 // native to Java
	QueryEnd       Marker = 0x05
	RespStart      Marker = 0x06 // native to Java: command response header
	RespEnd        Marker = 0x07
	QueryRespStart Marker = 0x08 // Java to native
	QueryRespEnd   Marker = 0x09
	ExceptionStart Marker = 0x0a // both directions; unverified in the golden transcripts
	ExceptionEnd   Marker = 0x0b
	BytesStart     Marker = 0x0c // Java to native; unverified in the golden transcripts
	BytesEnd       Marker = 0x0d
	StringStart    Marker = 0x0e
	StringEnd      Marker = 0x0f
	ErrorStart     Marker = 0x10 // native to Java, raw text; empty means success
	ErrorEnd       Marker = 0x11
	WarningStart   Marker = 0x12 // native to Java, raw text; unverified in the golden transcripts
	WarningEnd     Marker = 0x13
)

// Command names accepted by the native process. Only the first four are in the golden transcripts.
const (
	CmdRegisterProgram   = "registerProgram"
	CmdDecompileAt       = "decompileAt"
	CmdFlushNative       = "flushNative"
	CmdDeregisterProgram = "deregisterProgram"
)

// Query element ids (ElementId values, ghidra_arch.cc:30-50). Only the ones marked
// "seen" occur in the golden transcripts.
const (
	QueryIsNameUsed          = 239
	QueryGetBytes            = 240
	QueryGetCallFixup        = 241
	QueryGetCallMech         = 242
	QueryGetCallOtherFixup   = 243 // seen
	QueryGetCodeLabel        = 244
	QueryGetComments         = 245 // seen
	QueryGetCPoolRef         = 246
	QueryGetDataType         = 247
	QueryGetExternalRef      = 248
	QueryGetMappedSymbols    = 249 // seen
	QueryGetNamespacePath    = 250
	QueryGetPcode            = 251 // seen
	QueryGetPcodeExecutable  = 252
	QueryGetRegister         = 253 // seen
	QueryGetRegisterName     = 254
	QueryGetStringData       = 255
	QueryGetTrackedRegisters = 256 // seen
	QueryGetUserOpName       = 257 // seen
)

// Element and attribute ids decoded from the golden transcripts.
const (
	ElemAddr = 11
	ElemDoc  = 229

	AttrIndex  = 10
	AttrName   = 14
	AttrOffset = 16
	AttrSize   = 19
	AttrSpace  = 20
	AttrType   = 22
)
