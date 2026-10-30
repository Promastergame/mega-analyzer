//go:build !windows

package sandbox

import (
	"context"
	"fmt"
)

// vssManagerStub is a stub implementation for non-Windows platforms.
type vssManagerStub struct{}

// newVSSManager creates a stub VSS manager for non-Windows platforms.
func newVSSManager() VSSManager {
	return &vssManagerStub{}
}

// CreateSnapshot returns an error on non-Windows platforms.
func (v *vssManagerStub) CreateSnapshot(ctx context.Context, volumePath string) (*Snapshot, error) {
	return nil, fmt.Errorf("VSS snapshots are only supported on Windows")
}

// DeleteSnapshot returns an error on non-Windows platforms.
func (v *vssManagerStub) DeleteSnapshot(snapshotID string) error {
	return fmt.Errorf("VSS snapshots are only supported on Windows")
}

// CompareSnapshots returns an error on non-Windows platforms.
func (v *vssManagerStub) CompareSnapshots(baseline, current *Snapshot) (*SnapshotDiff, error) {
	return nil, fmt.Errorf("VSS snapshots are only supported on Windows")
}
