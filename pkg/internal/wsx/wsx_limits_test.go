package wsx

import (
	"bytes"
	"errors"
	"testing"
)

func TestReadFrameRejectsHugeLength(t *testing.T) {
	for _, hdr := range [][]byte{
		{0x82, 0x7f, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // ~9 EiB: used to panic
		{0x82, 0x7f, 0, 0, 0, 1, 0, 0, 0, 0},                         // 4 GiB: used to allocate
	} {
		_, _, _, err := readFrame(bytes.NewReader(hdr))
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Fatalf("header % x: err = %v, want ErrFrameTooLarge", hdr, err)
		}
	}
}

func TestReadFrameSmallStillWorks(t *testing.T) {
	frame := []byte{0x81, 0x85, 1, 2, 3, 4, 'h' ^ 1, 'e' ^ 2, 'l' ^ 3, 'l' ^ 4, 'o' ^ 1}
	fin, op, payload, err := readFrame(bytes.NewReader(frame))
	if err != nil || !fin || op != OpText || string(payload) != "hello" {
		t.Fatalf("fin=%v op=%v payload=%q err=%v", fin, op, payload, err)
	}
}
