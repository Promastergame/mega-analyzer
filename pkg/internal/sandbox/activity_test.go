package sandbox

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkspaceDeltaNoInventedAttribution(t *testing.T) {
	before := map[string]workspaceEntry{"old.txt": {size: 1}, "same": {directory: true}}
	after := map[string]workspaceEntry{"new": {directory: true}, "same": {directory: true}}
	events := workspaceDelta(before, after, time.Now())
	if len(events) != 2 {
		t.Fatal(events)
	}
	for _, ev := range events {
		if ev.PID != 0 || ev.Attribution != "unknown" || ev.Source != "workspace_metadata_snapshot" {
			t.Fatal(ev)
		}
	}
	if events[0].Category != "directory" || events[0].Action != "appeared" {
		t.Fatal(events)
	}
}
func TestWorkspaceSnapshotIncludesFoldersSkipsSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "folder"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "folder", "test.txt"), []byte("safe fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Symlink(t.TempDir(), filepath.Join(root, "outside"))
	entries, err := workspaceSnapshot(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatal(entries)
	}
}
func TestActivityJournalValidJSONAndBudget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.jsonl")
	j, err := newActivityJournal(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	j.record(ActivityEvent{Category: "file", Action: "appeared", Object: "test.txt", Source: "test", Attribution: "unknown"})
	j.bytes = activityJournalBudget
	j.record(ActivityEvent{Category: "session", Action: "ended", Source: "test", Attribution: "not_applicable"})
	n, truncated, err := j.close()
	if err != nil || n != 2 || !truncated {
		t.Fatalf("%d %v %v", n, truncated, err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var event ActivityEvent
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(b))), &event); err != nil {
		t.Fatal(err)
	}
	if event.ID != "event-00000001" || event.ObservedAt.IsZero() {
		t.Fatal(event)
	}
}
