//go:build amd64
// +build amd64

package simdleb

// decodeULEB128ArrayAsm is implemented in `simd_amd64.s` (Plan 9 ASM).
// It decodes up to `count` ULEB128 values from `dataPtr[:dataLen]` into
// the uint32 slice at `outPtr` and returns:
//
//	consumed — number of input bytes read (≤ dataLen)
//	emitted  — number of fully-decoded values written (≤ count)
//
// On EOF mid-value or 5-byte overflow it stops early; the caller uses
// `emitted` to trim the result slice and `consumed` to position the
// upstream cursor.
//
//go:noescape
func decodeULEB128ArrayAsm(dataPtr *byte, dataLen int, outPtr *uint32, count uint32) (consumed int, emitted uint32)

// Decode runs the AMD64 assembly path for ULEB128 batch decoding.
// On degenerate input it returns the same `(nil, 0)` shape as the Go
// reference implementation. Truncated streams produce a shortened
// result slice matching the Go contract exactly.
func Decode(data []byte, count uint32) ([]uint32, int) {
	if count == 0 || len(data) == 0 {
		return nil, 0
	}
	result := make([]uint32, count)
	consumed, emitted := decodeULEB128ArrayAsm(&data[0], len(data), &result[0], count)
	return result[:emitted], consumed
}
