//go:build !windows

package sandbox

import (
	"context"
	"fmt"
)

// windowsEnhancedComponents is a stub for non-Windows platforms.
type windowsEnhancedComponents struct{}

// initializeEnhancedComponents returns an error on non-Windows platforms.
func initializeEnhancedComponents(cfg Config) (*windowsEnhancedComponents, error) {
	return nil, fmt.Errorf("Windows-native sandbox enhancements are only supported on Windows")
}

// startComponents is a no-op on non-Windows platforms.
func (c *windowsEnhancedComponents) startComponents(ctx context.Context, cfg Config, rootPID int) error {
	return nil
}

// stopComponents is a no-op on non-Windows platforms.
func (c *windowsEnhancedComponents) stopComponents(ctx context.Context) []error {
	return nil
}

// cleanup is a no-op on non-Windows platforms.
func (c *windowsEnhancedComponents) cleanup() []error {
	return nil
}

// analyzeAndPopulateReport is a no-op on non-Windows platforms.
func (c *windowsEnhancedComponents) analyzeAndPopulateReport(report *Report) error {
	return nil
}

// exportArtifacts is a no-op on non-Windows platforms.
func (c *windowsEnhancedComponents) exportArtifacts(sessionDir string, report *Report) []error {
	return nil
}

// FollowChildProcess is a no-op outside Windows, matching the platform interface.
func (c *windowsEnhancedComponents) FollowChildProcess(ctx context.Context, childPID int) {}
