package vulnscan

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReadBodyBounded_CapsOversizedBody(t *testing.T) {
	big := strings.NewReader(strings.Repeat("A", 1<<20)) // 1MB
	resp := &http.Response{Body: io.NopCloser(big)}

	body, err := ReadBodyBounded(resp, 1024)
	if err != nil {
		t.Fatalf("ReadBodyBounded: %v", err)
	}
	if len(body) != 1024 {
		t.Errorf("read %d bytes, want exactly 1024 (capped)", len(body))
	}
}

func TestReadBodyBounded_ZeroDefaultsToFullCap(t *testing.T) {
	// 6MB body with a zero bound must still be capped at fullCap (5MB),
	// never read unbounded.
	big := strings.NewReader(strings.Repeat("B", 6<<20))
	resp := &http.Response{Body: io.NopCloser(big)}

	body, err := ReadBodyBounded(resp, 0)
	if err != nil {
		t.Fatalf("ReadBodyBounded: %v", err)
	}
	if len(body) != fullCap {
		t.Errorf("read %d bytes, want %d (default fullCap)", len(body), fullCap)
	}
}

func TestScannerReadBody_HonoursConfiguredMaxBodyBytes(t *testing.T) {
	s, err := NewScanner("http://example.com")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	s.Config.MaxBodyBytes = 2048

	big := strings.NewReader(strings.Repeat("C", 1<<20))
	resp := &http.Response{Body: io.NopCloser(big)}

	body := s.readBody(resp)
	if len(body) != 2048 {
		t.Errorf("readBody returned %d bytes, want 2048 (Config.MaxBodyBytes)", len(body))
	}
}

func TestReadBodyLimited_NilBodySafe(t *testing.T) {
	if got, err := ReadBodyLimited(nil, NeedFull); got != nil || err != nil {
		t.Errorf("ReadBodyLimited(nil) = (%v, %v), want (nil, nil)", got, err)
	}
	if got, err := ReadBodyBounded(nil, 10); got != nil || err != nil {
		t.Errorf("ReadBodyBounded(nil) = (%v, %v), want (nil, nil)", got, err)
	}
}
