package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// ActivityEvent describes an observation, not an inferred causal claim.
// ObservedAt is detection time. Snapshot events never claim exact action times.
type ActivityEvent struct {
	ID          string    `json:"id"`
	ObservedAt  time.Time `json:"observed_at"`
	Category    string    `json:"category"`
	Action      string    `json:"action"`
	PID         int       `json:"pid,omitempty"`
	Process     string    `json:"process,omitempty"`
	Object      string    `json:"object,omitempty"`
	Details     string    `json:"details,omitempty"`
	Source      string    `json:"source"`
	Attribution string    `json:"attribution"`
}

const activityJournalBudget = 64 * 1024 * 1024
const workspaceEntryBudget = 10000

type activityJournal struct {
	mu        sync.Mutex
	file      *os.File
	bytes     int
	count     uint64
	truncated bool
	err       error
	callback  func(ActivityEvent)
}

func newActivityJournal(path string, callback func(ActivityEvent)) (*activityJournal, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &activityJournal{file: f, callback: callback}, nil
}
func (j *activityJournal) record(ev ActivityEvent) {
	j.mu.Lock()
	if ev.ObservedAt.IsZero() {
		ev.ObservedAt = time.Now().UTC()
	}
	j.count++
	ev.ID = fmt.Sprintf("event-%08d", j.count)
	line, err := json.Marshal(ev)
	if err == nil && j.file != nil && j.err == nil && !j.truncated {
		if j.bytes+len(line)+1 > activityJournalBudget {
			j.truncated = true
		} else {
			var n int
			n, err = j.file.Write(append(line, '\n'))
			j.bytes += n
		}
	}
	if err != nil && j.err == nil {
		j.err = err
	}
	callback := j.callback
	// Serialise callbacks too so the UI sees event IDs in journal order.
	if callback != nil {
		callback(ev)
	}
	j.mu.Unlock()
}
func (j *activityJournal) close() (uint64, bool, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.file != nil {
		j.err = errors.Join(j.err, j.file.Sync(), j.file.Close())
		j.file = nil
	}
	return j.count, j.truncated, j.err
}

type workspaceEntry struct {
	directory bool
	size      int64
	modified  int64
}

func workspaceSnapshot(root string) (map[string]workspaceEntry, error) {
	entries := map[string]workspaceEntry{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		// Never follow symlinks or read content from special files.
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if !d.IsDir() && !d.Type().IsRegular() {
			return nil
		}
		if len(entries) >= workspaceEntryBudget {
			return fmt.Errorf("workspace snapshot exceeds %d entries", workspaceEntryBudget)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		entries[filepath.ToSlash(rel)] = workspaceEntry{d.IsDir(), info.Size(), info.ModTime().UnixNano()}
		return nil
	})
	return entries, err
}
func workspaceDelta(before, after map[string]workspaceEntry, at time.Time) []ActivityEvent {
	var events []ActivityEvent
	add := func(path, action string, entry workspaceEntry) {
		category := "file"
		if entry.directory {
			category = "directory"
		}
		events = append(events, ActivityEvent{ObservedAt: at, Category: category, Action: action, Object: path, Source: "workspace_metadata_snapshot", Attribution: "unknown", Details: "Detected between snapshots; exact action time and responsible process are unknown."})
	}
	for path, entry := range after {
		old, exists := before[path]
		if !exists {
			add(path, "appeared", entry)
		} else if old.directory != entry.directory {
			add(path, "disappeared", old)
			add(path, "appeared", entry)
		} else if !entry.directory && (old.size != entry.size || old.modified != entry.modified) {
			add(path, "changed", entry)
		}
	}
	for path, entry := range before {
		if _, ok := after[path]; !ok {
			add(path, "disappeared", entry)
		}
	}
	sort.SliceStable(events, func(i, k int) bool {
		if events[i].Object == events[k].Object {
			return events[i].Action < events[k].Action
		}
		return events[i].Object < events[k].Object
	})
	return events
}
func watchWorkspace(ctx context.Context, root string, every time.Duration, emit func(ActivityEvent)) <-chan struct{} {
	done := make(chan struct{})
	before, err := workspaceSnapshot(root)
	if every < time.Second {
		every = time.Second
	}
	go func() {
		defer close(done)
		if err != nil {
			emit(ActivityEvent{Category: "coverage", Action: "snapshot_failed", Object: root, Source: "workspace_metadata_snapshot", Attribution: "unknown", Details: err.Error()})
			return
		}
		ticker := time.NewTicker(every)
		defer ticker.Stop()
		sample := func() bool {
			after, err := workspaceSnapshot(root)
			if err != nil {
				emit(ActivityEvent{Category: "coverage", Action: "snapshot_failed", Object: root, Source: "workspace_metadata_snapshot", Attribution: "unknown", Details: err.Error()})
				return false
			}
			for _, event := range workspaceDelta(before, after, time.Now().UTC()) {
				emit(event)
			}
			before = after
			return true
		}
		for {
			select {
			case <-ctx.Done():
				sample()
				return
			case <-ticker.C:
				if !sample() {
					return
				}
			}
		}
	}()
	return done
}
