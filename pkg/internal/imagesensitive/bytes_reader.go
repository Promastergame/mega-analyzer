package imagesensitive

import "bytes"

// bytesReader is a tiny helper that returns an *bytes.Reader. Extracted
// to keep detector.go focussed on the heuristic logic.
func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }
