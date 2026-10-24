package proto

// ReplyKind says which frame carries a query answer.
type ReplyKind uint8

const (
	ReplyNone   ReplyKind = iota // no payload: 08 09
	ReplyString                  // 08 0e data 0f 09
	ReplyBytes                   // 08 0c data 0d 09 (getbytes; unverified in the golden transcripts)
)

// Reply is a query answer. The zero value is "no data". An empty ReplyString is
// different from ReplyNone: getuseropname answers an unnamed op that way.
type Reply struct {
	Kind ReplyKind
	Data []byte
}

// String is a reply carried in a string frame (raw text or packed data).
func String(data []byte) Reply { return Reply{ReplyString, data} }

// HexBytes is the getbytes reply: each byte becomes two letters 'A'+nibble, high first
// (DecompileProcess.getBytes). Like Java, no bytes means no 0c/0d frame at all.
func HexBytes(b []byte) Reply {
	if len(b) == 0 {
		return Reply{}
	}
	d := make([]byte, 0, 2*len(b))
	for _, c := range b {
		d = append(d, 'A'+c>>4, 'A'+c&0xf)
	}
	return Reply{ReplyBytes, d}
}

// Handler answers the native process's callbacks, one method per query id. q is the
// decoded query (root element id is the query id). Packed answers are encoded by the
// handler; getuseropname answers raw text. A returned error is sent to the native side
// as an exception frame (unverified in the golden transcripts).
//
// Only the methods for ids marked "seen" in marker.go are exercised by the golden
// transcripts; the argument and answer formats of the others are unverified.
type Handler interface {
	IsNameUsed(q *Element) (Reply, error)
	GetBytes(q *Element) (Reply, error)
	GetCallFixup(q *Element) (Reply, error)
	GetCallMech(q *Element) (Reply, error)
	GetCallOtherFixup(q *Element) (Reply, error)
	GetCodeLabel(q *Element) (Reply, error)
	GetComments(q *Element) (Reply, error)
	GetCPoolRef(q *Element) (Reply, error)
	GetDataType(q *Element) (Reply, error)
	GetExternalRef(q *Element) (Reply, error)
	GetMappedSymbols(q *Element) (Reply, error)
	GetNamespacePath(q *Element) (Reply, error)
	GetPcode(q *Element) (Reply, error)
	GetPcodeExecutable(q *Element) (Reply, error)
	GetRegister(q *Element) (Reply, error)
	GetRegisterName(q *Element) (Reply, error)
	GetStringData(q *Element) (Reply, error)
	GetTrackedRegisters(q *Element) (Reply, error)
	GetUserOpName(q *Element) (Reply, error)
}

func dispatch(h Handler, q *Element) (Reply, error) {
	f := map[uint32]func(*Element) (Reply, error){
		QueryIsNameUsed:          h.IsNameUsed,
		QueryGetBytes:            h.GetBytes,
		QueryGetCallFixup:        h.GetCallFixup,
		QueryGetCallMech:         h.GetCallMech,
		QueryGetCallOtherFixup:   h.GetCallOtherFixup,
		QueryGetCodeLabel:        h.GetCodeLabel,
		QueryGetComments:         h.GetComments,
		QueryGetCPoolRef:         h.GetCPoolRef,
		QueryGetDataType:         h.GetDataType,
		QueryGetExternalRef:      h.GetExternalRef,
		QueryGetMappedSymbols:    h.GetMappedSymbols,
		QueryGetNamespacePath:    h.GetNamespacePath,
		QueryGetPcode:            h.GetPcode,
		QueryGetPcodeExecutable:  h.GetPcodeExecutable,
		QueryGetRegister:         h.GetRegister,
		QueryGetRegisterName:     h.GetRegisterName,
		QueryGetStringData:       h.GetStringData,
		QueryGetTrackedRegisters: h.GetTrackedRegisters,
		QueryGetUserOpName:       h.GetUserOpName,
	}[q.ID]
	if f == nil {
		return Reply{}, errUnsupported
	}
	return f(q)
}
