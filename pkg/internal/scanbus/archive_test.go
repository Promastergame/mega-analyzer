package scanbus

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func scanArchiveFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.apk")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	for name, data := range map[string]string{"dir/": "", "dir/Main.SMALI": "smali payload", "assets/code.js": "javascript payload", "ignored.png": "image"} {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	// Unsupported compression and a bad CRC are skipped, never broadcast.
	for _, h := range []*zip.FileHeader{{Name: "unsupported.dex", Method: 99, CompressedSize64: 1, UncompressedSize64: 1}, {Name: "badcrc.dex", Method: zip.Store, CRC32: 1, CompressedSize64: 1, UncompressedSize64: 1}, {Name: "too-big.dex", Method: zip.Store, CompressedSize64: 1, UncompressedSize64: uint64(MaxFileBytes + 1)}} {
		w, err := z.CreateRaw(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = w.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if err = z.Close(); err != nil {
		t.Fatal(err)
	}
	if err = f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestArchiveBroadcastHashesAndFiltering(t *testing.T) {
	path := scanArchiveFixture(t)
	one, two := make(chan File, 10), make(chan File, 10)
	if err := Stream(context.Background(), path, one, two); err != nil {
		t.Fatal(err)
	}
	got := map[string]File{}
	for f := range one {
		got[f.Path] = f
		if f.SHA256 != sha256.Sum256(f.Data) {
			t.Errorf("incorrect digest %s", f.Path)
		}
	}
	if len(got) != 2 || string(got["dir/Main.SMALI"].Data) != "smali payload" || string(got["assets/code.js"].Data) != "javascript payload" {
		t.Fatalf("files=%+v", got)
	}
	n := 0
	for f := range two {
		n++
		a, ok := got[f.Path]
		if !ok || len(f.Data) == 0 || &a.Data[0] != &f.Data[0] {
			t.Fatal("archive consumers must share immutable storage")
		}
	}
	if n != 2 {
		t.Fatalf("second consumer received %d files", n)
	}
}

func TestStreamFailureAndCancellationCloseConsumers(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "notzip.apk")
	if err := os.WriteFile(bad, []byte("not zip"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{bad, bad + ".missing"} {
		ch := make(chan File, 1)
		if err := Stream(context.Background(), path, ch); err == nil {
			t.Fatal("invalid input accepted")
		}
		if _, ok := <-ch; ok {
			t.Fatal("consumer not closed")
		}
	}
	if err := Stream(context.Background(), bad); err != nil {
		t.Fatal("no-consumer fast path")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.dex"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, scanArchiveFixture(t)} {
		ctx, cancel := context.WithCancel(context.Background())
		ch := make(chan File)
		done := make(chan error, 1)
		go func() { done <- Stream(ctx, path, ch) }()
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation=%v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("canceled producer stuck")
		}
		if _, ok := <-ch; ok {
			t.Fatal("consumer not closed after cancellation")
		}
	}
}

func TestInterestingSuffixesAndWorkerBounds(t *testing.T) {
	for _, ext := range []string{"smali", "java", "kt", "dex", "xml", "json", "txt", "properties", "so", "html", "js", "jsx", "bundle"} {
		if !InterestingPath("dir/FILE." + strings.ToUpper(ext)) {
			t.Errorf("missing suffix %s", ext)
		}
	}
	for _, name := range []string{"image.png", "file.js.bak", "noextension"} {
		if InterestingPath(name) {
			t.Errorf("unexpected interesting file %s", name)
		}
	}
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	if workerCount() != 2 {
		t.Fatal("minimum workers")
	}
	runtime.GOMAXPROCS(16)
	if workerCount() != 8 {
		t.Fatal("maximum workers")
	}
}

func TestCancellationWhileBroadcastIsBlocked(t *testing.T) {
	path := scanArchiveFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, blocked := make(chan File, 1), make(chan File)
	done := make(chan error, 1)
	go func() { done <- Stream(ctx, path, first, blocked) }()
	select {
	case <-first: // Production has started; the second consumer cannot accept.
	case <-time.After(5 * time.Second):
		t.Fatal("producer did not start")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked consumer prevented cancellation")
	}
	for range first {
	} // Both consumer channels must be closed on return.
	if _, ok := <-blocked; ok {
		t.Fatal("blocked consumer left open")
	}
	// On Windows a still-open archive prevents this rename. Stream must have
	// joined the producer and closed its handles before returning cancellation.
	if err := os.Rename(path, path+".finished"); err != nil {
		t.Fatal(err)
	}
}
