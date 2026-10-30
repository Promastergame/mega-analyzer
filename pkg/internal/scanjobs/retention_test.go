package scanjobs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneRetentionBoundaries(t *testing.T) {
	for _, count := range []int{0, 1, 3, 5} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			root := t.TempDir()
			m := &Manager{
				root: root,
				cfg:  Config{MaxFinishedJobs: 3, ArtifactTTL: time.Hour},
				jobs: make(map[string]*job),
			}
			now := time.Now()
			states := []State{StateSucceeded, StateFailed, StateCanceled}
			for i := 0; i < count; i++ {
				id := fmt.Sprintf("finished-%d", i)
				dir := filepath.Join(root, id)
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				m.jobs[id] = &job{outputDir: dir, snapshot: Snapshot{
					ID: id, State: states[i%len(states)], FinishedAt: now.Add(time.Duration(i) * time.Second),
				}}
			}
			for _, state := range []State{StateQueued, StateRunning} {
				m.jobs[string(state)] = &job{snapshot: Snapshot{ID: string(state), State: state}}
			}
			artifactDir := filepath.Join(root, "artifacts")
			if err := os.Mkdir(artifactDir, 0o700); err != nil {
				t.Fatal(err)
			}
			expired := filepath.Join(artifactDir, "expired.apk")
			if err := os.WriteFile(expired, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chtimes(expired, now.Add(-2*time.Hour), now.Add(-2*time.Hour)); err != nil {
				t.Fatal(err)
			}
			m.prune()
			if got, want := len(m.jobs), min(count, 3)+2; got != want {
				t.Fatalf("retained jobs=%d, want=%d", got, want)
			}
			for i := 0; i < count; i++ {
				id := fmt.Sprintf("finished-%d", i)
				_, retained := m.jobs[id]
				want := i >= count-3
				if retained != want {
					t.Errorf("%s retained=%v, want=%v", id, retained, want)
				}
				_, err := os.Stat(filepath.Join(root, id))
				if (want && err != nil) || (!want && !os.IsNotExist(err)) {
					t.Errorf("%s directory retention: %v", id, err)
				}
			}
			for _, id := range []string{"queued", "running"} {
				if _, ok := m.jobs[id]; !ok {
					t.Errorf("active job %s was pruned", id)
				}
			}
			if _, err := os.Stat(expired); !os.IsNotExist(err) {
				t.Errorf("expired artifact survived pruning: %v", err)
			}
		})
	}
}
