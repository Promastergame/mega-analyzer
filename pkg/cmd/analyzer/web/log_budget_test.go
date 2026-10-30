package web

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestLogByteBudgetGapAndUTF8(t *testing.T) {
	j := newScanJob("log-budget", "", "")
	line := strings.Repeat("Ж", maxJobLineBytes)
	for i := 0; i < maxJobLogBytes/maxJobLineBytes+50; i++ {
		j.broadcast(line)
	}
	if j.lineBytes > maxJobLogBytes || j.base == 0 {
		t.Fatalf("bytes=%d base=%d", j.lineBytes, j.base)
	}
	for _, text := range j.lines {
		if len(text) > maxJobLineBytes || !utf8.ValidString(text) {
			t.Fatal("event exceeded budget or broke UTF8")
		}
	}
	j.finish(0)
	jobsMu.Lock()
	jobs[j.id] = j
	jobsMu.Unlock()
	t.Cleanup(func() { jobsMu.Lock(); delete(jobs, j.id); jobsMu.Unlock() })
	rr := httptest.NewRecorder()
	(&Server{}).handleEvents(rr, httptest.NewRequest("GET", "/api/events/"+j.id, nil))
	if !strings.Contains(rr.Body.String(), "event: gap\n") || !strings.Contains(rr.Body.String(), "event: done\n") {
		t.Fatal("missing explicit log gap or completion")
	}
}

func TestWorkspaceLogStreamsBeforeCompletion(t *testing.T) {
	_, ws := workspaceServer(t)
	j, rel, err := ws.createScan("Scans", "streaming", "full")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.finish(0) })
	line := strings.Repeat("x", maxJobLineBytes+1)
	j.broadcast(line)
	data, err := os.ReadFile(filepath.Join(ws.path, filepath.FromSlash(rel), "scan.log"))
	if err != nil || string(data) != line+"\n" {
		t.Fatal("original live log not saved", err)
	}
	if len(j.lines[0]) > maxJobLineBytes || !j.liveTruncated {
		t.Fatal("live preview unbounded")
	}
	j.finish(0)
	root, err := os.OpenRoot(ws.path)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	meta, err := readSavedScan(root, rel)
	if err != nil || meta.LogTruncated {
		t.Fatalf("complete disk log marked truncated: %+v %v", meta, err)
	}
	var raw map[string]any
	data, err = os.ReadFile(filepath.Join(ws.path, filepath.FromSlash(rel), workspaceMeta))
	if err != nil || json.Unmarshal(data, &raw) != nil {
		t.Fatal(err)
	}
}
