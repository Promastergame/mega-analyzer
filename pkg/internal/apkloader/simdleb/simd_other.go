//go:build !amd64

package simdleb

// Decode falls back to the pure-Go reference implementation on
// architectures without an assembly fast path.
func Decode(data []byte, count uint32) ([]uint32, int) {
	return DecodeGo(data, count)
}
