// Package contentcache — Incremental Analysis Engine
//
// Enterprise-grade incremental analysis:
//
//	APK v1 → IR snapshot
//	APK v2 → diff
//	Reuse: CFG, SSA, constant propagation, deobfuscation maps
//
// Use cases:
//   - Nightly scans (only re-analyze changed methods)
//   - Malware evolution tracking
//   - APK patch diffing
package contentcache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SNAPSHOT — Point-in-time state of an APK analysis
// ═══════════════════════════════════════════════════════════════════════════════

// Snapshot represents a complete analysis state for an APK version.
type Snapshot struct {
	ID        string                 `json:"id"` // SHA256 of APK
	CreatedAt time.Time              `json:"created_at"`
	APKPath   string                 `json:"apk_path"`
	Version   string                 `json:"version,omitempty"` // versionName if available
	Methods   map[string]MethodEntry `json:"methods"`           // fullSig → entry
	Classes   map[string]ClassEntry  `json:"classes"`           // className → entry
	Stats     SnapshotStats          `json:"stats"`
}

// MethodEntry tracks a single method's content hash and analysis state.
type MethodEntry struct {
	FullSignature string     `json:"full_sig"`
	ContentKey    ContentKey `json:"content_key"`
	ClassName     string     `json:"class_name"`
	HasCFG        bool       `json:"has_cfg"`
	HasSSA        bool       `json:"has_ssa"`
	HasTaint      bool       `json:"has_taint"`
	HasMetrics    bool       `json:"has_metrics"`
	RiskScore     float64    `json:"risk_score,omitempty"`
}

// ClassEntry tracks a class-level hash.
type ClassEntry struct {
	Name        string     `json:"name"`
	ContentKey  ContentKey `json:"content_key"` // hash of all method bodies combined
	MethodCount int        `json:"method_count"`
	FilePath    string     `json:"file_path"`
}

// SnapshotStats summarizes the snapshot.
type SnapshotStats struct {
	TotalMethods  int   `json:"total_methods"`
	TotalClasses  int   `json:"total_classes"`
	TotalBytes    int64 `json:"total_bytes"`
	CachedMethods int   `json:"cached_methods"` // methods with cached analysis
}

// ═══════════════════════════════════════════════════════════════════════════════
// DIFF — Changes between two snapshots
// ═══════════════════════════════════════════════════════════════════════════════

// DiffResult describes what changed between two APK versions.
type DiffResult struct {
	OldSnapshot string       `json:"old_snapshot"`
	NewSnapshot string       `json:"new_snapshot"`
	CreatedAt   time.Time    `json:"created_at"`
	Added       []MethodDiff `json:"added"`     // new methods
	Removed     []MethodDiff `json:"removed"`   // deleted methods
	Modified    []MethodDiff `json:"modified"`  // changed bytecode
	Unchanged   int          `json:"unchanged"` // count of unchanged methods
	Stats       DiffStats    `json:"stats"`
}

// MethodDiff describes a single method change.
type MethodDiff struct {
	FullSignature string     `json:"full_sig"`
	ClassName     string     `json:"class_name"`
	OldKey        ContentKey `json:"old_key,omitempty"`
	NewKey        ContentKey `json:"new_key,omitempty"`
	ChangeType    ChangeType `json:"change_type"`
}

// ChangeType categorizes a method change.
type ChangeType string

const (
	ChangeAdded    ChangeType = "added"
	ChangeRemoved  ChangeType = "removed"
	ChangeModified ChangeType = "modified"
)

// DiffStats summarizes the diff.
type DiffStats struct {
	AddedCount     int     `json:"added_count"`
	RemovedCount   int     `json:"removed_count"`
	ModifiedCount  int     `json:"modified_count"`
	UnchangedCount int     `json:"unchanged_count"`
	ChangeRatio    float64 `json:"change_ratio"`   // (added+removed+modified) / total
	ReusableRatio  float64 `json:"reusable_ratio"` // unchanged / total
}

// ═══════════════════════════════════════════════════════════════════════════════
// INCREMENTAL ANALYZER
// ═══════════════════════════════════════════════════════════════════════════════

// IncrementalAnalyzer manages snapshots and computes diffs.
type IncrementalAnalyzer struct {
	store       *Store
	snapshotDir string
	mu          sync.RWMutex
	current     *Snapshot
}

// NewIncrementalAnalyzer creates an incremental analyzer.
func NewIncrementalAnalyzer(store *Store, snapshotDir string) *IncrementalAnalyzer {
	if snapshotDir == "" {
		snapshotDir = ".omnisec-cache/snapshots"
	}
	_ = os.MkdirAll(snapshotDir, 0755)

	return &IncrementalAnalyzer{
		store:       store,
		snapshotDir: snapshotDir,
	}
}

// CreateSnapshot builds a snapshot from current analysis state.
func (ia *IncrementalAnalyzer) CreateSnapshot(apkPath string, methods []MethodInput) *Snapshot {
	apkHash := computeFileHash(apkPath)

	snap := &Snapshot{
		ID:        apkHash,
		CreatedAt: time.Now(),
		APKPath:   apkPath,
		Methods:   make(map[string]MethodEntry, len(methods)),
		Classes:   make(map[string]ClassEntry),
	}

	for _, m := range methods {
		key := ComputeKeyFromBody(m.Body)
		entry := MethodEntry{
			FullSignature: m.FullSignature,
			ContentKey:    key,
			ClassName:     m.ClassName,
			HasCFG:        ia.store.Has(NamespaceCFG, key),
			HasSSA:        ia.store.Has(NamespaceSSA, key),
			HasTaint:      ia.store.Has(NamespaceTaint, key),
			HasMetrics:    ia.store.Has(NamespaceMetrics, key),
		}
		snap.Methods[m.FullSignature] = entry
	}

	snap.Stats = SnapshotStats{
		TotalMethods: len(snap.Methods),
		TotalClasses: len(snap.Classes),
	}

	// Count cached
	for _, m := range snap.Methods {
		if m.HasCFG || m.HasSSA || m.HasMetrics {
			snap.Stats.CachedMethods++
		}
	}

	ia.mu.Lock()
	ia.current = snap
	ia.mu.Unlock()

	return snap
}

// Diff computes the difference between two snapshots.
func (ia *IncrementalAnalyzer) Diff(old, new *Snapshot) *DiffResult {
	diff := &DiffResult{
		OldSnapshot: old.ID,
		NewSnapshot: new.ID,
		CreatedAt:   time.Now(),
	}

	// Find added and modified
	for sig, newEntry := range new.Methods {
		oldEntry, exists := old.Methods[sig]
		if !exists {
			diff.Added = append(diff.Added, MethodDiff{
				FullSignature: sig,
				ClassName:     newEntry.ClassName,
				NewKey:        newEntry.ContentKey,
				ChangeType:    ChangeAdded,
			})
		} else if oldEntry.ContentKey != newEntry.ContentKey {
			diff.Modified = append(diff.Modified, MethodDiff{
				FullSignature: sig,
				ClassName:     newEntry.ClassName,
				OldKey:        oldEntry.ContentKey,
				NewKey:        newEntry.ContentKey,
				ChangeType:    ChangeModified,
			})
		} else {
			diff.Unchanged++
		}
	}

	// Find removed
	for sig, oldEntry := range old.Methods {
		if _, exists := new.Methods[sig]; !exists {
			diff.Removed = append(diff.Removed, MethodDiff{
				FullSignature: sig,
				ClassName:     oldEntry.ClassName,
				OldKey:        oldEntry.ContentKey,
				ChangeType:    ChangeRemoved,
			})
		}
	}

	// Compute stats
	total := len(new.Methods)
	if total == 0 {
		total = 1
	}
	diff.Stats = DiffStats{
		AddedCount:     len(diff.Added),
		RemovedCount:   len(diff.Removed),
		ModifiedCount:  len(diff.Modified),
		UnchangedCount: diff.Unchanged,
		ChangeRatio:    float64(len(diff.Added)+len(diff.Removed)+len(diff.Modified)) / float64(total),
		ReusableRatio:  float64(diff.Unchanged) / float64(total),
	}

	return diff
}

// MethodsToReanalyze returns only methods that need fresh analysis.
func (ia *IncrementalAnalyzer) MethodsToReanalyze(diff *DiffResult) []string {
	sigs := make([]string, 0, len(diff.Added)+len(diff.Modified))
	for _, m := range diff.Added {
		sigs = append(sigs, m.FullSignature)
	}
	for _, m := range diff.Modified {
		sigs = append(sigs, m.FullSignature)
	}
	return sigs
}

// ═══════════════════════════════════════════════════════════════════════════════
// SNAPSHOT PERSISTENCE
// ═══════════════════════════════════════════════════════════════════════════════

// SaveSnapshot persists a snapshot to disk.
func (ia *IncrementalAnalyzer) SaveSnapshot(snap *Snapshot) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}

	path := filepath.Join(ia.snapshotDir, snap.ID+".json")
	return os.WriteFile(path, data, 0644)
}

// LoadSnapshot loads a snapshot from disk by ID.
func (ia *IncrementalAnalyzer) LoadSnapshot(id string) (*Snapshot, error) {
	path := filepath.Join(ia.snapshotDir, id+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read snapshot: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	return &snap, nil
}

// LoadLatestSnapshot loads the most recent snapshot for an APK path.
func (ia *IncrementalAnalyzer) LoadLatestSnapshot(apkPath string) (*Snapshot, error) {
	id := computeFileHash(apkPath)
	return ia.LoadSnapshot(id)
}

// ListSnapshots returns all available snapshot IDs.
func (ia *IncrementalAnalyzer) ListSnapshots() ([]string, error) {
	entries, err := os.ReadDir(ia.snapshotDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var ids []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			ids = append(ids, e.Name()[:len(e.Name())-5])
		}
	}
	return ids, nil
}

// ═══════════════════════════════════════════════════════════════════════════════
// INPUT TYPES
// ═══════════════════════════════════════════════════════════════════════════════

// MethodInput is the input for creating a snapshot entry.
type MethodInput struct {
	FullSignature string
	ClassName     string
	Body          []string
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func computeFileHash(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		// Fallback to path hash
		h := sha256.Sum256([]byte(path))
		return hex.EncodeToString(h[:16])
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:16])
}
