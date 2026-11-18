//go:build wasm

package apkloader

import "errors"

// WebAssembly has linear memory, so use mapFile's existing heap-read fallback.
func (r *MmapDEXReader) mmapPlatform(size int) ([]byte, error) {
	return nil, errors.New("memory mapping is unavailable in WebAssembly")
}

func (r *MmapDEXReader) munmapPlatform() error { return nil }
