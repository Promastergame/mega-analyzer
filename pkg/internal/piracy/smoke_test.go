package piracy

import (
	"context"
	"testing"

	"mega-analyzer/pkg/internal/types"
)

func TestSmokeDetector(t *testing.T) {
	detector := NewDetector()
	if detector == nil {
		t.Fatal("expected detector")
	}

	content := []byte("download at 4pda.ru or happymod.com")
	result, err := detector.Analyze(context.Background(), "classes.smali", content, types.FileTypeSmali)
	if err != nil {
		t.Fatalf("analyze failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
}
