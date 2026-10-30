package web

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestUploadBudgetCapsAndRelease(t *testing.T) {
	if got := maxUploadBytes(); got != 512<<20 {
		t.Fatalf("default per-upload cap = %d", got)
	}
	t.Setenv("MEGA_ANALYZER_MAX_UPLOAD_BYTES", "1024")
	if got := maxUploadBytes(); got != 1024 {
		t.Fatalf("env per-upload cap = %d", got)
	}
	t.Setenv("MEGA_ANALYZER_MAX_UPLOAD_TOTAL_BYTES", "100")
	if got := maxUploadTotalBytes(); got != 100 {
		t.Fatalf("env total cap = %d", got)
	}
	// Atomic admission: second concurrent reservation fails instead of
	// both slipping past a read-then-check.
	if !reserveUpload(60) {
		t.Fatal("60 bytes must fit an empty 100-byte budget")
	}
	if reserveUpload(50) {
		t.Fatal("50 more bytes must breach the 100-byte budget")
	}
	releaseUpload(60)
	if !reserveUpload(100) {
		t.Fatal("released budget must be reusable")
	}
	releaseUpload(100)

	dir := t.TempDir()
	before := uploadInflightBytes.Load()
	// saveUpload is pure disk I/O: the request body is already budgeted by
	// readScanUpload's budgetReader upstream, so it must not touch the gauge
	// itself (otherwise bytes would be counted twice).
	p, n, err := saveUpload(dir, "a.bin", bytes.NewReader(make([]byte, 60)))
	if err != nil {
		t.Fatal(err)
	}
	if n != 60 {
		t.Fatalf("saveUpload wrote %d bytes, want 60", n)
	}
	if fi, err := os.Stat(p); err != nil || fi.Size() != 60 {
		t.Fatalf("saveUpload file missing or wrong size: %v size=%d", err, fi.Size())
	}
	if got := uploadInflightBytes.Load() - before; got != 0 {
		t.Fatalf("saveUpload must not touch gauge, moved by %d", got)
	}
	// Same name twice must fail (O_EXCL) instead of overwriting.
	if _, _, err := saveUpload(dir, "a.bin", bytes.NewReader(make([]byte, 1))); err == nil {
		t.Fatal("second saveUpload with same name must fail")
	}

	// Simulate handleScan ownership transfer: the reservation is held by
	// the job and released exactly once by cleanupUpload.
	if !reserveUpload(60) {
		t.Fatal("must fit 60 bytes for job ownership simulation")
	}
	job := newScanJob("budget-test", dir, filepath.Join(dir, "out"))
	job.uploadBytes = 60
	job.cleanupUpload()
	if got := uploadInflightBytes.Load() - before; got != 0 {
		t.Fatalf("gauge not released, left %d", got)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("temp dir not removed by cleanupUpload")
	}
	// Double cleanup must not drive the gauge negative.
	job.cleanupUpload()
	if got := uploadInflightBytes.Load() - before; got != 0 {
		t.Fatalf("double cleanup moved gauge to %d", got)
	}
}

// chunkReader forces small reads so the test exercises mid-stream aborts
// instead of a single upfront decision.
type chunkReader struct {
	src io.Reader
	max int
}

func (c *chunkReader) Read(p []byte) (int, error) {
	if len(p) > c.max {
		p = p[:c.max]
	}
	return c.src.Read(p)
}

func TestBudgetReaderAbortsOverBudgetStream(t *testing.T) {
	t.Setenv("MEGA_ANALYZER_MAX_UPLOAD_TOTAL_BYTES", "100")
	before := uploadInflightBytes.Load()
	// Unknown-length stream in 40-byte chunks: 40 + 40 fit, the third chunk
	// breaches 100 and aborts mid-stream instead of overshooting.
	br := &budgetReader{src: &chunkReader{src: bytes.NewReader(make([]byte, 300)), max: 40}}
	n, err := io.Copy(io.Discard, br)
	if err == nil {
		t.Fatal("expected budget-exceeded error")
	}
	if n != 80 || br.reserved != 80 {
		t.Fatalf("stream must stop after 2 chunks: copied=%d reserved=%d", n, br.reserved)
	}
	if got := uploadInflightBytes.Load() - before; got != 80 {
		t.Fatalf("gauge must hold exactly the streamed bytes, holds %d", got)
	}
	releaseUpload(br.reserved)
	if got := uploadInflightBytes.Load() - before; got != 0 {
		t.Fatalf("gauge leaked %d", got)
	}
}
