package artifacts

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"mega-analyzer/pkg/internal/report"
)

func TestBuildItemEmptyDataChargesURIPrefix(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.bin")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	budget := NewBudget(1, 1)
	item := buildItem(0, Candidate{Path: "empty.bin", AbsPath: path, Type: TypeOther}, budget, "", Options{})
	if item.EmbeddedDataURI == "" || budget.Used() != int64(len(item.EmbeddedDataURI)) {
		t.Fatalf("empty data must still charge the URI prefix: used=%d URI=%q", budget.Used(), item.EmbeddedDataURI)
	}
	budget.Charge((1 << 20) - budget.Used())
	item = buildItem(1, Candidate{Path: "empty.bin", AbsPath: path, Type: TypeOther}, budget, "", Options{})
	if item.EmbeddedDataURI != "" || len(item.Warnings) == 0 {
		t.Fatalf("exhausted budget must reject the empty data URI: %+v", item)
	}
}

func TestParallelBuildItemsRespectEmbeddedBudget(t *testing.T) {
	data := bytes.Repeat([]byte{'a'}, 128<<10)
	path := filepath.Join(t.TempDir(), "sample.bin")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out := t.TempDir()
	budget := NewBudget(1, 1)
	items := make([]*report.ArtifactItem, 24)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range items {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			items[i] = buildItem(i, Candidate{Path: "sample.bin", AbsPath: path, Size: int64(len(data)), Type: TypeOther},
				budget, filepath.Join(out, "artifacts"), Options{})
		}()
	}
	close(start)
	wg.Wait()
	var embeddedBytes int64
	embedded, external := 0, 0
	for i, item := range items {
		if item.ID != fmt.Sprintf("art_%04d", i+1) {
			t.Errorf("artifact ID changed: %q", item.ID)
		}
		if item.EmbeddedDataURI != "" {
			embedded++
			embeddedBytes += int64(len(item.EmbeddedDataURI))
		} else if item.ExternalPath != "" {
			external++
			got, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(item.ExternalPath)))
			if err != nil || !bytes.Equal(got, data) {
				t.Errorf("external artifact %d was not preserved: %v", i, err)
			}
		} else {
			t.Errorf("artifact %d lost its content: %+v", i, item)
		}
	}
	if embedded == 0 || external == 0 || embedded+external != len(items) {
		t.Errorf("expected both embedded and external artifacts: embedded=%d external=%d", embedded, external)
	}
	if embeddedBytes > 1<<20 || budget.Used() != embeddedBytes {
		t.Errorf("concurrent embedding exceeded or miscounted the budget: embedded=%d used=%d", embeddedBytes, budget.Used())
	}
}
