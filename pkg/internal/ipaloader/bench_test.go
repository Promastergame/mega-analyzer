package ipaloader

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// makeBenchData builds a pseudo-binary with many embedded strings.
func makeBenchData(n int) []byte {
	buf := make([]byte, 0, n)
	buf = append(buf, 0xCF, 0xFA, 0xED, 0xFE)
	token := []byte("\x00someLongSymbolName_verifyReceipt_1234567890\x00")
	for len(buf) < n {
		buf = append(buf, token...)
	}
	return buf
}

func BenchmarkExtractPrintableStrings(b *testing.B) {
	data := makeBenchData(4 << 20) // 4 MiB
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = extractPrintableStrings(data, 5)
	}
}

func BenchmarkCrackPointsForIPA(b *testing.B) {
	dir := b.TempDir()
	appDir := filepath.Join(dir, "Payload", "App.app")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		b.Fatal(err)
	}
	data := makeBenchData(1 << 20)
	for i := 0; i < 8; i++ {
		name := filepath.Join(appDir, "bin"+string(rune('A'+i)))
		if err := os.WriteFile(name, data, 0o644); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CrackPointsForIPA(context.Background(), dir, "com.app")
	}
}
