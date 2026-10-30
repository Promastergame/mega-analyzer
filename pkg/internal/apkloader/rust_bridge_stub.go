//go:build !cgo || skip_rust || !omnisec_rust_ffi

package apkloader

// rustMIRInsn mirrors the packed FFI layout even when Rust FFI is stubbed,
// so layout/parity tests can run without linking native libraries.
type rustMIRInsn struct {
	Kind       uint8
	DataType   uint8
	Cond       uint8
	Pad        uint8
	Offset     uint32
	Dst        int16
	Src1       int16
	Src2       int16
	Pad2       uint16
	Imm        int64
	RefIdx     uint32
	RefKind    uint8
	FieldKind  uint8
	InvokeKind uint8
	Pad3       uint8
	RawFlags   uint16
	Pad4       [6]uint8
}

func DeobfuscateWithRust(mir []MIRInsn, mode uint8) (*DeobfuscationResult, error) {
	return nil, ErrRustNotLinked
}

func ParseDexWithRust(data []byte) ([]byte, error) {
	return nil, ErrRustNotLinked
}

func ScanNativeWithRust(data []byte) (*NativeScanReport, error) {
	return nil, ErrRustNotLinked
}

func ScanNativeWithAetrium(data []byte, anchors []byte, enableWeaponization bool) (*NativeScanReport, error) {
	return nil, ErrRustNotLinked
}

func ReinforceAnchor(anchors []byte, anchorName string, features []float64) ([]byte, error) {
	return nil, ErrRustNotLinked
}

func SymbolicExecuteWithRust(blocks []FfiBlock, entryID uint32, regCount uint32, maxDepth uint32, maxPaths uint32) ([]byte, error) {
	return nil, ErrRustNotLinked
}

func DetectVirtualizationWithRust(blocks []FfiVirtBlock, confidenceThreshold uint8) ([]byte, error) {
	return nil, ErrRustNotLinked
}

// RustCFGBlock is the stub shape — the cgo build replaces it with the
// real one in `rust_bridge.go`. Kept here so other Go code can refer
// to the type unconditionally.
type RustCFGBlock struct {
	ID               uint32   `json:"id"`
	StartAddress     uint64   `json:"start_address"`
	EndAddress       uint64   `json:"end_address"`
	Kind             string   `json:"kind"`
	InstructionCount int      `json:"instruction_count"`
	Successors       []uint32 `json:"successors"`
	Predecessors     []uint32 `json:"predecessors"`
}

// RustCFG is the stub shape mirroring the real one in `rust_bridge.go`.
type RustCFG struct {
	BlockCount       int            `json:"block_count"`
	EdgeCount        int            `json:"edge_count"`
	Entry            uint32         `json:"entry"`
	Blocks           []RustCFGBlock `json:"blocks"`
	ReversePostorder []uint32       `json:"reverse_postorder"`
	Reachable        []uint32       `json:"reachable"`
}

func BuildCFGWithRust(mir []MIRInsn) (*RustCFG, error) {
	return nil, ErrRustNotLinked
}
