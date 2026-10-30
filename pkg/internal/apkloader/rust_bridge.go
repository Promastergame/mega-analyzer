//go:build cgo && omnisec_rust_ffi && !skip_rust

package apkloader

/*
#cgo LDFLAGS: -L${SRCDIR}/../../../rust/target/release -lomnisec_lifter_dalvik -lomnisec_loader_dex -lomnisec_analysis_symbolic -lomnisec_analysis_virt -lomnisec_scan_native
#include <stdint.h>
#include <stdlib.h>

// ByteSlice is the FFI result type shared across all Rust libraries.
typedef struct {
    uint8_t* ptr;
    uint64_t len;
} ByteSlice;

// External functions from omnisec-scan-native
extern void omnisec_scan_native(const uint8_t* elf_buf, uint64_t elf_len, ByteSlice* out);
extern void omnisec_scan_native_ext(const uint8_t* elf_buf, uint64_t elf_len, const uint8_t* anchor_buf, uint64_t anchor_len, uint8_t enable_weaponization, ByteSlice* out);
extern void omnisec_reinforce_anchor(const uint8_t* anchor_buf, uint64_t anchor_len, const uint8_t* name_buf, uint64_t name_len, const double* feature_buf, uint64_t feature_len, ByteSlice* out);
extern void omnisec_free_native_result(ByteSlice result);

// External functions from omnisec-lifter-dalvik
extern void omnisec_deobfuscate_v3(const uint8_t* mir_buf, uint64_t mir_len, uint8_t mode, ByteSlice* out);
extern void omnisec_free_result(ByteSlice result);
extern void omnisec_build_cfg(const uint8_t* mir_buf, uint64_t mir_len, ByteSlice* out);
extern void omnisec_free_cfg_result(ByteSlice result);

// External functions from omnisec-loader-dex
extern void omnisec_parse_dex(const uint8_t* dex_buf, uint64_t dex_len, ByteSlice* out);
extern void omnisec_free_dex_result(ByteSlice result);

// External functions from omnisec-analysis-symbolic
extern void omnisec_symbolic_execute(void* blocks_ptr, uint32_t blocks_count, uint32_t entry_id, uint32_t reg_count, uint32_t max_depth, uint32_t max_paths, ByteSlice* out);
extern void omnisec_free_symbolic_result(ByteSlice result);

// External functions from omnisec-analysis-virt
extern void omnisec_detect_virtualization(void* blocks_ptr, uint32_t blocks_count, uint8_t confidence_threshold, ByteSlice* out);
extern void omnisec_free_virt_result(ByteSlice result);
*/
import "C"
import (
	"encoding/json"
	"unsafe"
)

// rustMIRInsn is used for the packed FFI layout to match Rust's memory representation.
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
	if len(mir) == 0 {
		return &DeobfuscationResult{}, nil
	}

	buf := make([]rustMIRInsn, len(mir))
	for i, m := range mir {
		buf[i] = rustMIRInsn{
			Kind:       uint8(m.Kind),
			DataType:   uint8(m.DataType),
			Cond:       uint8(m.Cond),
			Offset:     m.Offset,
			Dst:        m.Dst,
			Src1:       m.Src1,
			Src2:       m.Src2,
			Imm:        m.Imm,
			RefIdx:     m.RefIdx,
			RefKind:    uint8(m.RefKind),
			FieldKind:  uint8(m.FieldKind),
			InvokeKind: uint8(m.InvokeKind),
			RawFlags:   uint16(m.RawFlags),
		}
	}

	ptr := (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	size := C.uint64_t(len(buf) * 40)

	var res C.ByteSlice
	C.omnisec_deobfuscate_v3(ptr, size, C.uint8_t(mode), &res)
	defer C.omnisec_free_result(res)

	if res.ptr == nil || res.len == 0 {
		return &DeobfuscationResult{}, nil
	}

	jsonData := C.GoBytes(unsafe.Pointer(res.ptr), C.int(res.len))
	var result DeobfuscationResult
	if err := json.Unmarshal(jsonData, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

// ParseDexWithRust parses a raw DEX file using the omnisec-loader-dex crate.
func ParseDexWithRust(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	ptr := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	size := C.uint64_t(len(data))

	var res C.ByteSlice
	C.omnisec_parse_dex(ptr, size, &res)
	defer C.omnisec_free_dex_result(res)

	if res.ptr == nil || res.len == 0 {
		return nil, nil
	}

	// Copy JSON bytes to Go memory before freeing C memory
	return C.GoBytes(unsafe.Pointer(res.ptr), C.int(res.len)), nil
}

// ScanNativeWithRust runs the security scanner on a native ELF (.so) file.
func ScanNativeWithRust(data []byte) (*NativeScanReport, error) {
	if len(data) == 0 {
		return nil, nil
	}

	ptr := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	size := C.uint64_t(len(data))

	var res C.ByteSlice
	C.omnisec_scan_native(ptr, size, &res)
	defer C.omnisec_free_native_result(res)

	if res.ptr == nil || res.len == 0 {
		return nil, nil
	}

	jsonData := C.GoBytes(unsafe.Pointer(res.ptr), C.int(res.len))
	var report NativeScanReport
	if err := json.Unmarshal(jsonData, &report); err != nil {
		return nil, err
	}

	return &report, nil
}

// ScanNativeWithAetrium runs the scanner with ML-Aetrium and ML-Apli-Ex enabled.
func ScanNativeWithAetrium(data []byte, anchors []byte, enableWeaponization bool) (*NativeScanReport, error) {
	if len(data) == 0 {
		return nil, nil
	}

	ptr := (*C.uint8_t)(unsafe.Pointer(&data[0]))
	size := C.uint64_t(len(data))

	var aPtr *C.uint8_t
	var aSize C.uint64_t
	if len(anchors) > 0 {
		aPtr = (*C.uint8_t)(unsafe.Pointer(&anchors[0]))
		aSize = C.uint64_t(len(anchors))
	}

	weaponFlag := C.uint8_t(0)
	if enableWeaponization {
		weaponFlag = 1
	}

	var res C.ByteSlice
	C.omnisec_scan_native_ext(ptr, size, aPtr, aSize, weaponFlag, &res)
	defer C.omnisec_free_native_result(res)

	if res.ptr == nil || res.len == 0 {
		return nil, nil
	}

	jsonData := C.GoBytes(unsafe.Pointer(res.ptr), C.int(res.len))
	var report NativeScanReport
	if err := json.Unmarshal(jsonData, &report); err != nil {
		return nil, err
	}

	return &report, nil
}

// ReinforceAnchor folds a confirmed-positive feature vector into the named
// anchor inside `anchors` and returns the updated anchors-store JSON.
//
// The Rust side maps the feature vector into a deterministic sparse
// hypervector and calls AnchorStore::reinforce, so subsequent scans see
// a signature that has been pulled toward the confirmed example. This
// closes the active-learning loop for HDC: every analyst confirmation
// makes the relevant anchor more sensitive on similar inputs.
//
// Returns the new anchors-store bytes ready to be written to disk. Empty
// or "{}" on failure (e.g. unknown anchor name, malformed input).
func ReinforceAnchor(anchors []byte, anchorName string, features []float64) ([]byte, error) {
	if len(anchors) == 0 || anchorName == "" {
		return nil, nil
	}
	if len(features) == 0 {
		// No features → no signal to reinforce on. Return the input
		// unchanged rather than zeroing the store.
		return anchors, nil
	}

	aPtr := (*C.uint8_t)(unsafe.Pointer(&anchors[0]))
	aLen := C.uint64_t(len(anchors))

	nameBytes := []byte(anchorName)
	nPtr := (*C.uint8_t)(unsafe.Pointer(&nameBytes[0]))
	nLen := C.uint64_t(len(nameBytes))

	fPtr := (*C.double)(unsafe.Pointer(&features[0]))
	fLen := C.uint64_t(len(features))

	var res C.ByteSlice
	C.omnisec_reinforce_anchor(aPtr, aLen, nPtr, nLen, fPtr, fLen, &res)
	defer C.omnisec_free_native_result(res)

	if res.ptr == nil || res.len == 0 {
		return nil, nil
	}
	out := C.GoBytes(unsafe.Pointer(res.ptr), C.int(res.len))
	return out, nil
}

// C-compatible struct for symbolic FFI
type cFfiMirInsn struct {
	Kind   uint8
	Cond   uint8
	_pad   [2]uint8
	Dst    int16
	Src1   int16
	Src2   int16
	_pad2  [2]uint8
	Imm    int64
	RefIdx uint32
	_pad3  [4]uint8
}

type cFfiBlock struct {
	ID        uint32
	InsnCount uint32
	Insns     *cFfiMirInsn
	SuccCount uint32
	Succs     *uint32
}

// SymbolicExecuteWithRust runs symbolic execution via omnisec-analysis-symbolic.
func SymbolicExecuteWithRust(blocks []FfiBlock, entryID uint32, regCount uint32, maxDepth uint32, maxPaths uint32) ([]byte, error) {
	if len(blocks) == 0 {
		return nil, nil
	}

	cBlocks := make([]cFfiBlock, len(blocks))

	// Track allocations to free them later
	var allocations []unsafe.Pointer
	defer func() {
		for _, ptr := range allocations {
			C.free(ptr)
		}
	}()

	for i, b := range blocks {
		cBlocks[i].ID = b.ID

		if len(b.Insns) > 0 {
			cInsns := make([]cFfiMirInsn, len(b.Insns))
			for j, ins := range b.Insns {
				cInsns[j].Kind = ins.Kind
				cInsns[j].Cond = ins.Cond
				cInsns[j].Dst = ins.Dst
				cInsns[j].Src1 = ins.Src1
				cInsns[j].Src2 = ins.Src2
				cInsns[j].Imm = ins.Imm
				cInsns[j].RefIdx = ins.RefIdx
			}

			// Allocate in C memory
			size := C.size_t(len(cInsns) * int(unsafe.Sizeof(cInsns[0])))
			cPtr := C.malloc(size)
			allocations = append(allocations, cPtr)

			// Copy data
			dst := unsafe.Slice((*cFfiMirInsn)(cPtr), len(cInsns))
			copy(dst, cInsns)

			cBlocks[i].InsnCount = uint32(len(cInsns))
			cBlocks[i].Insns = (*cFfiMirInsn)(cPtr)
		}

		if len(b.Succs) > 0 {
			size := C.size_t(len(b.Succs) * 4) // uint32
			cPtr := C.malloc(size)
			allocations = append(allocations, cPtr)

			dst := unsafe.Slice((*uint32)(cPtr), len(b.Succs))
			copy(dst, b.Succs)

			cBlocks[i].SuccCount = uint32(len(b.Succs))
			cBlocks[i].Succs = (*uint32)(cPtr)
		}
	}

	ptr := unsafe.Pointer(&cBlocks[0])
	size := C.uint32_t(len(cBlocks))

	var res C.ByteSlice
	C.omnisec_symbolic_execute(ptr, size, C.uint32_t(entryID), C.uint32_t(regCount), C.uint32_t(maxDepth), C.uint32_t(maxPaths), &res)
	defer C.omnisec_free_symbolic_result(res)

	if res.ptr == nil || res.len == 0 {
		return nil, nil
	}

	return C.GoBytes(unsafe.Pointer(res.ptr), C.int(res.len)), nil
}

// C-compatible struct for virt FFI
type cFfiVirtInsn struct {
	Kind   uint8
	_pad   [3]uint8
	Dst    int16
	Src1   int16
	Src2   int16
	_pad2  [2]uint8
	Imm    int64
	RefIdx uint32
	_pad3  [4]uint8
}

type cFfiVirtBlock struct {
	ID        uint32
	InsnCount uint32
	Insns     *cFfiVirtInsn
	SuccCount uint32
	Succs     *uint32
}

// DetectVirtualizationWithRust runs virtualization detection via omnisec-analysis-virt.
func DetectVirtualizationWithRust(blocks []FfiVirtBlock, confidenceThreshold uint8) ([]byte, error) {
	if len(blocks) == 0 {
		return nil, nil
	}

	cBlocks := make([]cFfiVirtBlock, len(blocks))

	// Track allocations to free them later
	var allocations []unsafe.Pointer
	defer func() {
		for _, ptr := range allocations {
			C.free(ptr)
		}
	}()

	for i, b := range blocks {
		cBlocks[i].ID = b.ID

		if len(b.Insns) > 0 {
			cInsns := make([]cFfiVirtInsn, len(b.Insns))
			for j, ins := range b.Insns {
				cInsns[j].Kind = ins.Kind
				cInsns[j].Dst = ins.Dst
				cInsns[j].Src1 = ins.Src1
				cInsns[j].Src2 = ins.Src2
				cInsns[j].Imm = ins.Imm
				cInsns[j].RefIdx = ins.RefIdx
			}

			// Allocate in C memory
			size := C.size_t(len(cInsns) * int(unsafe.Sizeof(cInsns[0])))
			cPtr := C.malloc(size)
			allocations = append(allocations, cPtr)

			// Copy data
			dst := unsafe.Slice((*cFfiVirtInsn)(cPtr), len(cInsns))
			copy(dst, cInsns)

			cBlocks[i].InsnCount = uint32(len(cInsns))
			cBlocks[i].Insns = (*cFfiVirtInsn)(cPtr)
		}

		if len(b.Succs) > 0 {
			size := C.size_t(len(b.Succs) * 4) // uint32
			cPtr := C.malloc(size)
			allocations = append(allocations, cPtr)

			dst := unsafe.Slice((*uint32)(cPtr), len(b.Succs))
			copy(dst, b.Succs)

			cBlocks[i].SuccCount = uint32(len(b.Succs))
			cBlocks[i].Succs = (*uint32)(cPtr)
		}
	}

	ptr := unsafe.Pointer(&cBlocks[0])
	size := C.uint32_t(len(cBlocks))

	var res C.ByteSlice
	C.omnisec_detect_virtualization(ptr, size, C.uint8_t(confidenceThreshold), &res)
	defer C.omnisec_free_virt_result(res)

	if res.ptr == nil || res.len == 0 {
		return nil, nil
	}

	return C.GoBytes(unsafe.Pointer(res.ptr), C.int(res.len)), nil
}

// ─── CFG construction offload (plan_dex_loader v11.0 task #3) ────────────

// RustCFGBlock is a JSON-decoded basic block coming back from
// `omnisec_build_cfg`.
type RustCFGBlock struct {
	ID               uint32   `json:"id"`
	StartAddress     uint64   `json:"start_address"`
	EndAddress       uint64   `json:"end_address"`
	Kind             string   `json:"kind"`
	InstructionCount int      `json:"instruction_count"`
	Successors       []uint32 `json:"successors"`
	Predecessors     []uint32 `json:"predecessors"`
}

// RustCFG is the JSON shape produced by `omnisec_build_cfg`.
type RustCFG struct {
	BlockCount       int            `json:"block_count"`
	EdgeCount        int            `json:"edge_count"`
	Entry            uint32         `json:"entry"`
	Blocks           []RustCFGBlock `json:"blocks"`
	ReversePostorder []uint32       `json:"reverse_postorder"`
	Reachable        []uint32       `json:"reachable"`
}

// BuildCFGWithRust hands a slice of MIR instructions to the Rust
// `omnisec-cfg` builder via FFI and returns a decoded CFG snapshot.
//
// Returns (nil, nil) for empty input, matching the other Rust-bridge
// helpers. The caller can fall back to the in-process Go `BuildCFG` on
// failure.
func BuildCFGWithRust(mir []MIRInsn) (*RustCFG, error) {
	if len(mir) == 0 {
		return nil, nil
	}

	buf := make([]rustMIRInsn, len(mir))
	for i, m := range mir {
		buf[i] = rustMIRInsn{
			Kind:       uint8(m.Kind),
			DataType:   uint8(m.DataType),
			Cond:       uint8(m.Cond),
			Offset:     m.Offset,
			Dst:        m.Dst,
			Src1:       m.Src1,
			Src2:       m.Src2,
			Imm:        m.Imm,
			RefIdx:     m.RefIdx,
			RefKind:    uint8(m.RefKind),
			FieldKind:  uint8(m.FieldKind),
			InvokeKind: uint8(m.InvokeKind),
			RawFlags:   uint16(m.RawFlags),
		}
	}

	ptr := (*C.uint8_t)(unsafe.Pointer(&buf[0]))
	size := C.uint64_t(len(buf) * 40)

	var res C.ByteSlice
	C.omnisec_build_cfg(ptr, size, &res)
	defer C.omnisec_free_cfg_result(res)

	if res.ptr == nil || res.len == 0 {
		return nil, nil
	}

	jsonData := C.GoBytes(unsafe.Pointer(res.ptr), C.int(res.len))
	// Empty `{}` from Rust on degenerate input: treat as a no-op.
	if len(jsonData) == 2 && jsonData[0] == '{' && jsonData[1] == '}' {
		return nil, nil
	}

	var out RustCFG
	if err := json.Unmarshal(jsonData, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
