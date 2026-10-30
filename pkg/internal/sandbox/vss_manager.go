package sandbox

import "context"

// VSSManager orchestrates Volume Shadow Copy Service (VSS) snapshots and comparisons.
// This interface provides methods for creating system snapshots, deleting them, and
// comparing snapshots to detect changes in files, registry, services, and scheduled tasks.
//
// Validates: Requirements 3.1, 3.4
type VSSManager interface {
	// CreateSnapshot creates a VSS snapshot of the specified volume.
	// The snapshot captures the current state of files, registry, services, and scheduled tasks.
	// Returns a Snapshot containing the snapshot ID, mount point, and captured metadata.
	//
	// Validates: Requirements 3.1, 3.2
	CreateSnapshot(ctx context.Context, volumePath string) (*Snapshot, error)

	// DeleteSnapshot deletes a VSS snapshot by its ID.
	// This should be called after snapshot comparison to clean up resources.
	//
	// Validates: Requirements 3.1
	DeleteSnapshot(snapshotID string) error

	// CompareSnapshots compares two snapshots and returns the differences.
	// Detects changes in files, registry, services, and scheduled tasks.
	// The baseline snapshot should be created before execution, and the current
	// snapshot should be created after execution completes.
	//
	// Validates: Requirements 3.3, 3.4
	CompareSnapshots(baseline, current *Snapshot) (*SnapshotDiff, error)
}

// NewVSSManager creates a new VSS manager instance.
// On Windows, this returns a functional implementation using VSS COM API or PowerShell.
// On other platforms, this returns a stub that returns errors.
func NewVSSManager() VSSManager {
	return newVSSManager()
}
