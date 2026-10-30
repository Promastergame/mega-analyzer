package vmware

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestScreenCaptureUsesGuestLoginAndBoundedHostFile(t *testing.T) {
	vmx := executionFixture(t)
	output := t.TempDir()
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 16, 9))); err != nil {
		t.Fatal(err)
	}
	calls := 0
	controller := New(func(ctx context.Context, args ...string) ([]byte, error) {
		calls++
		if len(args) != 7 || args[0] != "-gu" || args[1] != "MegaLab" || args[2] != "-gp" || args[3] != "test-only" || args[4] != "captureScreen" || args[5] != vmx {
			t.Fatalf("unexpected command %v", args)
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("unbounded screenshot command")
		}
		rel, err := filepath.Rel(output, args[6])
		if err != nil || !filepath.IsLocal(rel) {
			t.Fatal("frame destination escaped output")
		}
		return nil, os.WriteFile(args[6], encoded.Bytes(), 0600)
	}, t.TempDir())
	// Captures must not wait for the analysis/management lock held by RunSession.
	controller.mu.Lock()
	defer controller.mu.Unlock()
	frame, err := controller.CaptureScreen(context.Background(), vmx, "MegaLab", "test-only", output)
	if err != nil || !bytes.Equal(frame, encoded.Bytes()) || calls != 1 {
		t.Fatalf("capture failed: %v", err)
	}
	entries, err := os.ReadDir(output)
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary capture was not removed")
	}
}

func TestScreenCaptureRejectsInvalidFramesAndPropagatesCancellation(t *testing.T) {
	vmx := executionFixture(t)
	for _, data := range [][]byte{[]byte("not a png"), make([]byte, (16<<20)+1)} {
		c := New(func(ctx context.Context, args ...string) ([]byte, error) {
			return nil, os.WriteFile(args[6], data, 0600)
		}, t.TempDir())
		if _, err := c.CaptureScreen(context.Background(), vmx, "MegaLab", "test-only", t.TempDir()); err == nil {
			t.Fatal("invalid frame accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := New(func(ctx context.Context, args ...string) ([]byte, error) { return nil, ctx.Err() }, t.TempDir())
	if _, err := c.CaptureScreen(ctx, vmx, "MegaLab", "test-only", t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
