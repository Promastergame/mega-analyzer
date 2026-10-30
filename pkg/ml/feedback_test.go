package ml

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// GenerateFeedbackID
// ═══════════════════════════════════════════════════════════════════════════════

func TestGenerateFeedbackID_Deterministic(t *testing.T) {
	ts := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	id1 := GenerateFeedbackID("test.apk", ts)
	id2 := GenerateFeedbackID("test.apk", ts)

	if id1 != id2 {
		t.Errorf("same input should produce same ID: %q != %q", id1, id2)
	}
}

func TestGenerateFeedbackID_Unique(t *testing.T) {
	ts := time.Now()

	id1 := GenerateFeedbackID("app1.apk", ts)
	id2 := GenerateFeedbackID("app2.apk", ts)

	if id1 == id2 {
		t.Error("different APKs should produce different IDs")
	}
}

func TestGenerateFeedbackID_DifferentTimestamps(t *testing.T) {
	ts1 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ts2 := time.Date(2026, 1, 1, 12, 0, 0, 1, time.UTC) // +1 nanosecond

	id1 := GenerateFeedbackID("test.apk", ts1)
	id2 := GenerateFeedbackID("test.apk", ts2)

	if id1 == id2 {
		t.Error("different timestamps should produce different IDs")
	}
}

func TestGenerateFeedbackID_Length(t *testing.T) {
	id := GenerateFeedbackID("test.apk", time.Now())

	if len(id) != 16 {
		t.Errorf("ID should be 16 chars, got %d: %q", len(id), id)
	}
}

func TestGenerateFeedbackID_EmptyName(t *testing.T) {
	// Не должен паниковать
	id := GenerateFeedbackID("", time.Now())
	if len(id) != 16 {
		t.Errorf("empty name should still produce valid ID, got %d chars", len(id))
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HashAPKFile
// ═══════════════════════════════════════════════════════════════════════════════

func TestHashAPKFile_NormalFile(t *testing.T) {
	// Создаём временный файл > 4KB
	dir := testTempDir(t)
	path := filepath.Join(dir, "test.apk")

	data := make([]byte, 8192) // 8KB
	for i := range data {
		data[i] = byte(i % 256)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := HashAPKFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if len(hash) != 64 { // SHA256 hex = 64 chars
		t.Errorf("expected 64 char hash, got %d: %q", len(hash), hash)
	}

	// Хеш должен покрывать весь файл, а не первые байты (регрессия:
	// раньше читался один Read в буфер 4KB).
	want := sha256.Sum256(data)
	if hash != hex.EncodeToString(want[:]) {
		t.Error("hash does not match sha256 of the full file content")
	}

	// Разные хвосты при одинаковом начале должны давать разные хеши.
	tail := append([]byte(nil), data...)
	tail[len(tail)-1] ^= 0xFF
	if err := os.WriteFile(path, tail, 0644); err != nil {
		t.Fatal(err)
	}
	hash2, err := HashAPKFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if hash2 == hash {
		t.Error("files differing only in the last byte produced identical hashes")
	}
}

func TestHashAPKFile_SmallFile(t *testing.T) {
	// Файл меньше 4KB — должен работать (io.EOF при n>0)
	dir := testTempDir(t)
	path := filepath.Join(dir, "small.apk")

	data := []byte("hello world")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	hash, err := HashAPKFile(path)
	if err != nil {
		t.Fatalf("small file should work: %v", err)
	}

	if len(hash) != 64 {
		t.Errorf("expected 64 char hash, got %d", len(hash))
	}
}

func TestHashAPKFile_EmptyFile(t *testing.T) {
	dir := testTempDir(t)
	path := filepath.Join(dir, "empty.apk")

	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	_, err := HashAPKFile(path)
	if err == nil {
		t.Error("empty file should return error")
	}
}

func TestHashAPKFile_NotExists(t *testing.T) {
	_, err := HashAPKFile("/nonexistent/path/test.apk")
	if err == nil {
		t.Error("nonexistent file should return error")
	}
}

func TestHashAPKFile_Deterministic(t *testing.T) {
	dir := testTempDir(t)
	path := filepath.Join(dir, "test.apk")

	if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	hash1, _ := HashAPKFile(path)
	hash2, _ := HashAPKFile(path)

	if hash1 != hash2 {
		t.Error("same file should produce same hash")
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// KeywordFeedback
// ═══════════════════════════════════════════════════════════════════════════════

func TestKeywordFeedback_AvgImportance(t *testing.T) {
	tests := []struct {
		name     string
		kf       KeywordFeedback
		expected float64
	}{
		{
			name:     "zero triggered",
			kf:       KeywordFeedback{Triggered: 0, SumImportance: 100},
			expected: 0,
		},
		{
			name:     "normal",
			kf:       KeywordFeedback{Triggered: 10, SumImportance: 50},
			expected: 5.0,
		},
		{
			name:     "single",
			kf:       KeywordFeedback{Triggered: 1, SumImportance: 7},
			expected: 7.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.kf.AvgImportance()
			if got != tt.expected {
				t.Errorf("AvgImportance() = %f, want %f", got, tt.expected)
			}
		})
	}
}

func TestKeywordFeedback_AvgRawImportance(t *testing.T) {
	kf := KeywordFeedback{Triggered: 4, SumRawImportance: 20}
	if got := kf.AvgRawImportance(); got != 5.0 {
		t.Errorf("AvgRawImportance() = %f, want 5.0", got)
	}
}

func TestKeywordFeedback_AvgRawImportance_Zero(t *testing.T) {
	kf := KeywordFeedback{Triggered: 0, SumRawImportance: 20}
	if got := kf.AvgRawImportance(); got != 0 {
		t.Errorf("AvgRawImportance() = %f, want 0", got)
	}
}

func TestKeywordFeedback_Precision(t *testing.T) {
	tests := []struct {
		name     string
		kf       KeywordFeedback
		expected float64
	}{
		{
			name:     "no data",
			kf:       KeywordFeedback{MarkedRelevant: 0, MarkedNoise: 0},
			expected: -1,
		},
		{
			name:     "all relevant",
			kf:       KeywordFeedback{MarkedRelevant: 10, MarkedNoise: 0},
			expected: 1.0,
		},
		{
			name:     "all noise",
			kf:       KeywordFeedback{MarkedRelevant: 0, MarkedNoise: 10},
			expected: 0.0,
		},
		{
			name:     "half and half",
			kf:       KeywordFeedback{MarkedRelevant: 5, MarkedNoise: 5},
			expected: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.kf.Precision()
			if got != tt.expected {
				t.Errorf("Precision() = %f, want %f", got, tt.expected)
			}
		})
	}
}

func TestKeywordFeedback_NoiseRatio(t *testing.T) {
	tests := []struct {
		name     string
		kf       KeywordFeedback
		expected float64
	}{
		{
			name:     "zero triggered",
			kf:       KeywordFeedback{Triggered: 0},
			expected: 0,
		},
		{
			name:     "no noise",
			kf:       KeywordFeedback{Triggered: 10, InLibrary: 0, Dampened: 0},
			expected: 0,
		},
		{
			name:     "all library",
			kf:       KeywordFeedback{Triggered: 10, InLibrary: 10, Dampened: 0},
			expected: 1.0,
		},
		{
			name:     "mixed",
			kf:       KeywordFeedback{Triggered: 10, InLibrary: 3, Dampened: 2},
			expected: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.kf.NoiseRatio()
			if got != tt.expected {
				t.Errorf("NoiseRatio() = %f, want %f", got, tt.expected)
			}
		})
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// LibraryFeedback
// ═══════════════════════════════════════════════════════════════════════════════

func TestLibraryFeedback_AvgImportance(t *testing.T) {
	lf := LibraryFeedback{TotalFiles: 5, SumImportance: 25}
	if got := lf.AvgImportance(); got != 5.0 {
		t.Errorf("AvgImportance() = %f, want 5.0", got)
	}
}

func TestLibraryFeedback_AvgImportance_Zero(t *testing.T) {
	lf := LibraryFeedback{TotalFiles: 0, SumImportance: 10}
	if got := lf.AvgImportance(); got != 0 {
		t.Errorf("AvgImportance() = %f, want 0", got)
	}
}

func TestLibraryFeedback_IsAlwaysNoise(t *testing.T) {
	tests := []struct {
		name     string
		lf       LibraryFeedback
		expected bool
	}{
		{
			name:     "always noise",
			lf:       LibraryFeedback{HighValueFiles: 0, MatchedFiles: 10, DampenedMatches: 10},
			expected: true,
		},
		{
			name:     "has high value",
			lf:       LibraryFeedback{HighValueFiles: 1, MatchedFiles: 10, DampenedMatches: 10},
			expected: false,
		},
		{
			name:     "no matches",
			lf:       LibraryFeedback{HighValueFiles: 0, MatchedFiles: 0, DampenedMatches: 0},
			expected: false,
		},
		{
			name:     "partial dampening",
			lf:       LibraryFeedback{HighValueFiles: 0, MatchedFiles: 10, DampenedMatches: 5},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.lf.IsAlwaysNoise()
			if got != tt.expected {
				t.Errorf("IsAlwaysNoise() = %v, want %v", got, tt.expected)
			}
		})
	}
}
