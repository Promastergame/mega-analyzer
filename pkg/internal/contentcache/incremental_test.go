package contentcache

import (
	"os"
	"path/filepath"
	"testing"
)

func setupIncrementalAnalyzer(t *testing.T) (*IncrementalAnalyzer, *Store) {
	t.Helper()
	dir := t.TempDir()
	storeCfg := StoreConfig{
		BaseDir:        filepath.Join(dir, "store"),
		Version:        1,
		MaxMemoryPerNS: 100,
	}
	store, err := NewStore(storeCfg)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	snapshotDir := filepath.Join(dir, "snapshots")
	ia := NewIncrementalAnalyzer(store, snapshotDir)
	return ia, store
}

func TestNewIncrementalAnalyzer(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)
	if ia == nil {
		t.Fatal("expected non-nil IncrementalAnalyzer")
	}
}

func TestNewIncrementalAnalyzer_DefaultDir(t *testing.T) {
	dir := t.TempDir()
	storeCfg := StoreConfig{BaseDir: filepath.Join(dir, "store"), Version: 1}
	store, _ := NewStore(storeCfg)
	ia := NewIncrementalAnalyzer(store, "")
	if ia == nil {
		t.Fatal("expected non-nil")
	}
	if ia.snapshotDir == "" {
		t.Fatal("snapshotDir should have default value")
	}
}

func TestCreateSnapshot(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	// Create a temp file to act as APK
	apkFile := filepath.Join(t.TempDir(), "test.apk")
	os.WriteFile(apkFile, []byte("fake apk content"), 0644)

	methods := []MethodInput{
		{FullSignature: "com/App->check()Z", ClassName: "com/App", Body: []string{"const/4 v0, 0x1", "return v0"}},
		{FullSignature: "com/App->init()V", ClassName: "com/App", Body: []string{"return-void"}},
	}

	snap := ia.CreateSnapshot(apkFile, methods)
	if snap == nil {
		t.Fatal("expected non-nil snapshot")
	}
	if snap.ID == "" {
		t.Fatal("snapshot ID should not be empty")
	}
	if len(snap.Methods) != 2 {
		t.Fatalf("expected 2 methods, got %d", len(snap.Methods))
	}
	if snap.Stats.TotalMethods != 2 {
		t.Fatalf("TotalMethods = %d, want 2", snap.Stats.TotalMethods)
	}
	if snap.APKPath != apkFile {
		t.Fatalf("APKPath = %q, want %q", snap.APKPath, apkFile)
	}
}

func TestCreateSnapshot_MethodEntries(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	apkFile := filepath.Join(t.TempDir(), "test.apk")
	os.WriteFile(apkFile, []byte("content"), 0644)

	methods := []MethodInput{
		{FullSignature: "com/A->m()V", ClassName: "com/A", Body: []string{"line1"}},
	}

	snap := ia.CreateSnapshot(apkFile, methods)
	entry, ok := snap.Methods["com/A->m()V"]
	if !ok {
		t.Fatal("method entry not found")
	}
	if entry.FullSignature != "com/A->m()V" {
		t.Fatalf("FullSignature = %q", entry.FullSignature)
	}
	if entry.ClassName != "com/A" {
		t.Fatalf("ClassName = %q", entry.ClassName)
	}
	if entry.ContentKey.IsZero() {
		t.Fatal("ContentKey should not be zero")
	}
}

func TestDiff_NoChanges(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	key := ComputeKeyFromBody([]string{"body"})
	old := &Snapshot{
		ID:      "old",
		Methods: map[string]MethodEntry{"m1": {FullSignature: "m1", ContentKey: key}},
	}
	new := &Snapshot{
		ID:      "new",
		Methods: map[string]MethodEntry{"m1": {FullSignature: "m1", ContentKey: key}},
	}

	diff := ia.Diff(old, new)
	if len(diff.Added) != 0 {
		t.Fatalf("expected 0 added, got %d", len(diff.Added))
	}
	if len(diff.Removed) != 0 {
		t.Fatalf("expected 0 removed, got %d", len(diff.Removed))
	}
	if len(diff.Modified) != 0 {
		t.Fatalf("expected 0 modified, got %d", len(diff.Modified))
	}
	if diff.Unchanged != 1 {
		t.Fatalf("expected 1 unchanged, got %d", diff.Unchanged)
	}
	if diff.Stats.ReusableRatio != 1.0 {
		t.Fatalf("ReusableRatio = %f, want 1.0", diff.Stats.ReusableRatio)
	}
}

func TestDiff_AddedMethods(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	old := &Snapshot{
		ID:      "old",
		Methods: map[string]MethodEntry{},
	}
	new := &Snapshot{
		ID: "new",
		Methods: map[string]MethodEntry{
			"m1": {FullSignature: "m1", ClassName: "A", ContentKey: ComputeKeyFromBody([]string{"body1"})},
			"m2": {FullSignature: "m2", ClassName: "B", ContentKey: ComputeKeyFromBody([]string{"body2"})},
		},
	}

	diff := ia.Diff(old, new)
	if len(diff.Added) != 2 {
		t.Fatalf("expected 2 added, got %d", len(diff.Added))
	}
	if diff.Stats.AddedCount != 2 {
		t.Fatalf("AddedCount = %d, want 2", diff.Stats.AddedCount)
	}
	for _, m := range diff.Added {
		if m.ChangeType != ChangeAdded {
			t.Fatalf("ChangeType = %s, want added", m.ChangeType)
		}
	}
}

func TestDiff_RemovedMethods(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	old := &Snapshot{
		ID: "old",
		Methods: map[string]MethodEntry{
			"m1": {FullSignature: "m1", ClassName: "A", ContentKey: ComputeKeyFromBody([]string{"body1"})},
		},
	}
	new := &Snapshot{
		ID:      "new",
		Methods: map[string]MethodEntry{},
	}

	diff := ia.Diff(old, new)
	if len(diff.Removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(diff.Removed))
	}
	if diff.Removed[0].ChangeType != ChangeRemoved {
		t.Fatalf("ChangeType = %s, want removed", diff.Removed[0].ChangeType)
	}
}

func TestDiff_ModifiedMethods(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	old := &Snapshot{
		ID: "old",
		Methods: map[string]MethodEntry{
			"m1": {FullSignature: "m1", ClassName: "A", ContentKey: ComputeKeyFromBody([]string{"old body"})},
		},
	}
	new := &Snapshot{
		ID: "new",
		Methods: map[string]MethodEntry{
			"m1": {FullSignature: "m1", ClassName: "A", ContentKey: ComputeKeyFromBody([]string{"new body"})},
		},
	}

	diff := ia.Diff(old, new)
	if len(diff.Modified) != 1 {
		t.Fatalf("expected 1 modified, got %d", len(diff.Modified))
	}
	if diff.Modified[0].ChangeType != ChangeModified {
		t.Fatalf("ChangeType = %s, want modified", diff.Modified[0].ChangeType)
	}
	if diff.Modified[0].OldKey == diff.Modified[0].NewKey {
		t.Fatal("old and new keys should differ")
	}
}

func TestDiff_MixedChanges(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	sameKey := ComputeKeyFromBody([]string{"same"})
	old := &Snapshot{
		ID: "old",
		Methods: map[string]MethodEntry{
			"unchanged": {FullSignature: "unchanged", ContentKey: sameKey},
			"modified":  {FullSignature: "modified", ContentKey: ComputeKeyFromBody([]string{"old"})},
			"removed":   {FullSignature: "removed", ContentKey: ComputeKeyFromBody([]string{"gone"})},
		},
	}
	new := &Snapshot{
		ID: "new",
		Methods: map[string]MethodEntry{
			"unchanged": {FullSignature: "unchanged", ContentKey: sameKey},
			"modified":  {FullSignature: "modified", ContentKey: ComputeKeyFromBody([]string{"new"})},
			"added":     {FullSignature: "added", ContentKey: ComputeKeyFromBody([]string{"fresh"})},
		},
	}

	diff := ia.Diff(old, new)
	if diff.Unchanged != 1 {
		t.Fatalf("Unchanged = %d, want 1", diff.Unchanged)
	}
	if len(diff.Added) != 1 {
		t.Fatalf("Added = %d, want 1", len(diff.Added))
	}
	if len(diff.Modified) != 1 {
		t.Fatalf("Modified = %d, want 1", len(diff.Modified))
	}
	if len(diff.Removed) != 1 {
		t.Fatalf("Removed = %d, want 1", len(diff.Removed))
	}
}

func TestMethodsToReanalyze(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	diff := &DiffResult{
		Added: []MethodDiff{
			{FullSignature: "added1"},
			{FullSignature: "added2"},
		},
		Modified: []MethodDiff{
			{FullSignature: "modified1"},
		},
		Removed: []MethodDiff{
			{FullSignature: "removed1"},
		},
	}

	sigs := ia.MethodsToReanalyze(diff)
	if len(sigs) != 3 {
		t.Fatalf("expected 3 methods to reanalyze, got %d", len(sigs))
	}
	// Should include added and modified, not removed
	sigSet := map[string]bool{}
	for _, s := range sigs {
		sigSet[s] = true
	}
	if !sigSet["added1"] || !sigSet["added2"] || !sigSet["modified1"] {
		t.Fatalf("missing expected signatures: %v", sigs)
	}
	if sigSet["removed1"] {
		t.Fatal("removed methods should not be in reanalyze list")
	}
}

func TestSaveAndLoadSnapshot(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	snap := &Snapshot{
		ID:      "test_snapshot_id",
		APKPath: "/path/to/test.apk",
		Methods: map[string]MethodEntry{
			"m1": {FullSignature: "m1", ClassName: "A", ContentKey: ComputeKeyFromBody([]string{"body"})},
		},
		Classes: map[string]ClassEntry{},
		Stats:   SnapshotStats{TotalMethods: 1},
	}

	err := ia.SaveSnapshot(snap)
	if err != nil {
		t.Fatalf("SaveSnapshot: %v", err)
	}

	loaded, err := ia.LoadSnapshot("test_snapshot_id")
	if err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if loaded.ID != snap.ID {
		t.Fatalf("ID = %q, want %q", loaded.ID, snap.ID)
	}
	if loaded.APKPath != snap.APKPath {
		t.Fatalf("APKPath = %q, want %q", loaded.APKPath, snap.APKPath)
	}
	if len(loaded.Methods) != 1 {
		t.Fatalf("Methods len = %d, want 1", len(loaded.Methods))
	}
}

func TestLoadSnapshot_NotFound(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	_, err := ia.LoadSnapshot("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent snapshot")
	}
}

func TestListSnapshots(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	// Save a couple of snapshots
	snap1 := &Snapshot{ID: "snap1", Methods: map[string]MethodEntry{}, Classes: map[string]ClassEntry{}}
	snap2 := &Snapshot{ID: "snap2", Methods: map[string]MethodEntry{}, Classes: map[string]ClassEntry{}}
	ia.SaveSnapshot(snap1)
	ia.SaveSnapshot(snap2)

	ids, err := ia.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 snapshots, got %d", len(ids))
	}
}

func TestListSnapshots_EmptyDir(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	ids, err := ia.ListSnapshots()
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("expected 0 snapshots, got %d", len(ids))
	}
}

func TestDiffStats_ChangeRatio(t *testing.T) {
	ia, _ := setupIncrementalAnalyzer(t)

	old := &Snapshot{
		ID:      "old",
		Methods: map[string]MethodEntry{},
	}
	new := &Snapshot{
		ID: "new",
		Methods: map[string]MethodEntry{
			"m1": {FullSignature: "m1", ContentKey: ComputeKeyFromBody([]string{"a"})},
			"m2": {FullSignature: "m2", ContentKey: ComputeKeyFromBody([]string{"b"})},
		},
	}

	diff := ia.Diff(old, new)
	// All methods are new, so change ratio should be 1.0
	if diff.Stats.ChangeRatio != 1.0 {
		t.Fatalf("ChangeRatio = %f, want 1.0", diff.Stats.ChangeRatio)
	}
	if diff.Stats.ReusableRatio != 0.0 {
		t.Fatalf("ReusableRatio = %f, want 0.0", diff.Stats.ReusableRatio)
	}
}
