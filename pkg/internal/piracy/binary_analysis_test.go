package piracy

import (
	"bytes"
	"context"
	"testing"
)

func TestAnalyzeBinaryEmptyData(t *testing.T) {
	d := NewDetector()
	res, err := d.AnalyzeBinary(context.Background(), "x.so", nil)
	if err != nil {
		t.Fatalf("AnalyzeBinary nil: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	if res.IsPirated {
		t.Errorf("empty data should not be flagged pirated")
	}
}

func TestAnalyzeBinaryWithStrings(t *testing.T) {
	d := NewDetector()
	// Include some printable strings — at least one >6 chars.
	data := []byte("\x00\x01com.example.app\x00\x00LicenseChecker\x00")
	res, err := d.AnalyzeBinary(context.Background(), "lib.so", data)
	if err != nil {
		t.Fatalf("AnalyzeBinary: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
}

func TestAnalyzeBinaryHighEntropy(t *testing.T) {
	d := NewDetector()
	// Construct a buffer of high-entropy bytes (pseudo-random)
	// plus enough printable strings so the analyzer doesn't bail early.
	mixed := bytes.Repeat([]byte("printable_string_keyword "), 4)
	for i := 0; i < 256; i++ {
		mixed = append(mixed, byte(i))
	}
	res, err := d.AnalyzeBinary(context.Background(), "x.bin", mixed)
	if err != nil {
		t.Fatalf("AnalyzeBinary: %v", err)
	}
	if res == nil {
		t.Fatal("nil result")
	}
	// We don't assert encrypted=true because IsLikelyEncrypted depends on
	// distribution; just exercise the path.
}
