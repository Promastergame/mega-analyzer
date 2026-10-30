// Package simdleb is the architecture-specific home for the fast
// ULEB128 batch decoder used by `apkloader`. It lives in its own
// package because the parent `apkloader` package uses cgo, and Go
// forbids mixing cgo with Plan 9 assembly in the same package.
//
// Public API:
//   - `Decode(data, count)` — returns the decoded values + consumed bytes.
//   - `DecodeGo(data, count)` — pure-Go reference implementation (for tests).
//
// On AMD64 `Decode` dispatches to `simd_amd64.s`. Other architectures
// fall back to `DecodeGo` directly.
package simdleb

// DecodeGo is the canonical, allocation-equivalent ULEB128 batch decoder.
// It is exported so unit tests can A/B it against the assembly path.
func DecodeGo(data []byte, count uint32) ([]uint32, int) {
	if count == 0 || len(data) == 0 {
		return nil, 0
	}
	result := make([]uint32, count)
	offset := 0
	dataLen := len(data)

	for i := uint32(0); i < count; i++ {
		var val uint32
		var shift uint
		for {
			if offset >= dataLen {
				return result[:i], offset
			}
			b := data[offset]
			offset++
			val |= uint32(b&0x7F) << shift
			if b&0x80 == 0 {
				break
			}
			shift += 7
			if shift >= 35 {
				return result[:i], offset
			}
		}
		result[i] = val
	}
	return result, offset
}
