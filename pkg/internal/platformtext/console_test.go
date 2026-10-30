package platformtext

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

func TestSandboxReliabilityConsoleEncoding(t *testing.T) {
	text := "Требуются права администратора. 日本語 UTF-8"
	if got := DecodeConsoleOutput([]byte(text)); got != text {
		t.Fatal(got)
	}
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		b := []byte{0xff, 0xfe}
		if order == binary.BigEndian {
			b = []byte{0xfe, 0xff}
		}
		for _, v := range utf16.Encode([]rune(text)) {
			x := make([]byte, 2)
			order.PutUint16(x, v)
			b = append(b, x...)
		}
		if got := DecodeConsoleOutput(b); got != text {
			t.Fatalf("UTF16 = %q", got)
		}
	}
	if got := DecodeConsoleOutput([]byte{'O', 0, 'K', 0}); got != "OK" {
		t.Fatalf("BOM-less UTF16 = %q", got)
	}
	if !utf8.ValidString(DecodeConsoleOutput([]byte{0xff, 0x80, 0x81})) {
		t.Fatal("invalid UTF8 leaked")
	}
}
