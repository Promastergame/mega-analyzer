package wsx

import (
	"bytes"
	"testing"
)

// FuzzReadFrame: WebSocket frames come from the browser / device side.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0x81, 0x85, 1, 2, 3, 4, 'h' ^ 1, 'e' ^ 2, 'l' ^ 3, 'l' ^ 4, 'o' ^ 1})
	f.Add([]byte{0x82, 0x7e, 0x00, 0x02, 0xaa, 0xbb})
	f.Add([]byte{0x82, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0x88, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _, _ = readFrame(bytes.NewReader(data))
	})
}
