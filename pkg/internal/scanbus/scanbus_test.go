package scanbus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestStreamBroadcastsSingleImmutableBuffer(t *testing.T) {
	root := t.TempDir()
	payload := []byte(`const endpoint = "https://example.test/api";`)
	if err := os.WriteFile(filepath.Join(root, "bundle.js"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ignored.png"), []byte("image"), 0o600); err != nil {
		t.Fatal(err)
	}
	one := make(chan File, 1)
	two := make(chan File, 1)
	gotOne := make(chan []File, 1)
	gotTwo := make(chan []File, 1)
	collect := func(input <-chan File, output chan<- []File) {
		var files []File
		for file := range input {
			files = append(files, file)
		}
		output <- files
	}
	go collect(one, gotOne)
	go collect(two, gotTwo)
	if err := Stream(context.Background(), root, one, two); err != nil {
		t.Fatal(err)
	}
	a, b := <-gotOne, <-gotTwo
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("broadcast counts = %d/%d, want 1/1", len(a), len(b))
	}
	if a[0].Path != "bundle.js" || string(a[0].Data) != string(payload) || a[0].SHA256 != b[0].SHA256 {
		t.Fatalf("unexpected broadcast values: %#v / %#v", a[0], b[0])
	}
	if &a[0].Data[0] != &b[0].Data[0] {
		t.Fatal("consumers should receive the same immutable backing buffer")
	}
}
