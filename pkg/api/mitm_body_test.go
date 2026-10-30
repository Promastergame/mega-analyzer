package api

import (
	"bytes"
	"strings"
	"testing"
)

func TestReadMITMBodyCapsBuffering(t *testing.T) {
	small := bytes.Repeat([]byte("a"), 1024)
	body, ok := readMITMBody(bytes.NewReader(small))
	if !ok || !bytes.Equal(body, small) {
		t.Fatal("small body must pass through intact")
	}
	huge := bytes.NewReader(bytes.Repeat([]byte("b"), int(maxMITMBodyBytes())+16))
	if _, ok := readMITMBody(huge); ok {
		t.Fatal("oversize body must be refused, not buffered")
	}
	t.Setenv("MEGA_ANALYZER_MITM_MAX_BODY_BYTES", "16")
	if got := maxMITMBodyBytes(); got != 16 {
		t.Fatalf("env override = %d, want 16", got)
	}
	t.Setenv("MEGA_ANALYZER_MITM_MAX_BODY_BYTES", "junk")
	if got := maxMITMBodyBytes(); got != 32<<20 {
		t.Fatalf("invalid env must fall back to default, got %d", got)
	}
	if !strings.Contains(truncateBody(bytes.Repeat([]byte("c"), 5000)), "truncated") {
		t.Fatal("preview truncation marker missing")
	}
}
