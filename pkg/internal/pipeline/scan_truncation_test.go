package pipeline

import (
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

// Regression for security_heuristics.go:589. Inputs above maxScanSize were
// silently cut (data = data[:maxScanSize]) and ScanResult carried no marker, so
// a caller could not distinguish "file is clean" from "tail was never scanned".
// Phase-0 measurement: a 5 MB file dropped 2 findings, one of them critical
// ("direct shell path" at offset 1049005), with no signal in the result.
func TestScanContentReportsTruncation(t *testing.T) {
	unit := "invoke-static {}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;\n" +
		"    const-string v0, \"https://api.example.com/v1/track\"\n"

	small := []byte(strings.Repeat(unit, 4))
	res := ScanContent(small, "Small.smali", types.FileTypeSmali, SourceKindSmali, 0)
	if res.Truncated {
		t.Fatalf("small input reported as truncated (total=%d scanned=%d)", res.TotalBytes, res.ScannedBytes)
	}
	if res.TotalBytes != len(small) || res.ScannedBytes != len(small) {
		t.Fatalf("small input counters: total=%d scanned=%d, want both %d", res.TotalBytes, res.ScannedBytes, len(small))
	}

	reps := maxScanSize/len(unit) + 8
	big := []byte(strings.Repeat(unit, reps))
	if len(big) <= maxScanSize {
		t.Fatalf("test payload %d bytes must exceed maxScanSize %d", len(big), maxScanSize)
	}

	res = ScanContent(big, "Big.smali", types.FileTypeSmali, SourceKindSmali, 0)
	if !res.Truncated {
		t.Fatalf("oversized input (%d bytes, limit %d) not reported as truncated", len(big), maxScanSize)
	}
	if res.TotalBytes != len(big) {
		t.Fatalf("TotalBytes=%d, want %d", res.TotalBytes, len(big))
	}
	if res.ScannedBytes != maxScanSize {
		t.Fatalf("ScannedBytes=%d, want %d", res.ScannedBytes, maxScanSize)
	}
	if res.ScannedBytes >= res.TotalBytes {
		t.Fatalf("scanned=%d must be below total=%d", res.ScannedBytes, res.TotalBytes)
	}
}
