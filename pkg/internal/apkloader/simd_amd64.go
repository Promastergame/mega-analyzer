//go:build amd64
// +build amd64

package apkloader

import "mega-analyzer/pkg/internal/apkloader/simdleb"

// decodeULEB128Array dispatches batch ULEB128 decoding to the AMD64
// assembly path in the `simdleb` subpackage. The split exists because
// `apkloader` itself is a cgo package and Go forbids mixing cgo with
// Plan 9 assembly in the same package.
func decodeULEB128Array(data []byte, count uint32) ([]uint32, int) {
	return simdleb.Decode(data, count)
}
