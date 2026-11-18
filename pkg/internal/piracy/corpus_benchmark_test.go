package piracy

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"mega-analyzer/pkg/internal/configs"
	"mega-analyzer/pkg/internal/types"
)

// BenchmarkPiracyCorpus profiles the actual detector with a local decoded APK.
// MEGA_ANALYZER_BENCH_CORPUS supplies the corpus; no sample is committed.
func BenchmarkPiracyCorpus(b *testing.B) {
	root := os.Getenv("MEGA_ANALYZER_BENCH_CORPUS")
	if root == "" {
		b.Skip("set MEGA_ANALYZER_BENCH_CORPUS to a decoded APK directory")
	}
	type sample struct {
		path string
		data []byte
		kind types.FileType
	}
	var samples []sample
	var total int64
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		var kind types.FileType
		switch strings.ToLower(filepath.Ext(path)) {
		case ".smali":
			kind = types.FileTypeSmali
		case ".xml":
			kind = types.FileTypeXML
		case ".json":
			kind = types.FileTypeJSON
		case ".txt":
			kind = types.FileTypeText
		case ".properties":
			kind = types.FileTypeProperties
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		samples = append(samples, sample{filepath.ToSlash(rel), data, kind})
		total += int64(len(data))
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	d, err := NewDetectorFromBytes(configs.PiracySites())
	if err != nil {
		b.Fatal(err)
	}
	// Measure detector work rather than its repeated-input result cache.
	d.cache = nil
	b.ReportAllocs()
	b.SetBytes(total)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, sample := range samples {
			if _, err := d.Analyze(context.Background(), sample.path, sample.data, sample.kind); err != nil {
				b.Fatal(err)
			}
		}
	}
}
