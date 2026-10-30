//go:build !windows
// +build !windows

package sandbox

import (
	"context"
	"fmt"
)

// wfpMonitorStub is a no-op implementation for non-Windows platforms.
type wfpMonitorStub struct{}

// NewWFPMonitor creates a stub WFP monitor for non-Windows platforms.
func NewWFPMonitor() WFPMonitor {
	return &wfpMonitorStub{}
}

// Start returns an error indicating WFP monitoring is Windows-only.
func (w *wfpMonitorStub) Start(ctx context.Context, targetPIDs []int) error {
	return fmt.Errorf("WFP monitoring is only available on Windows")
}

// Stop is a no-op on non-Windows platforms.
func (w *wfpMonitorStub) Stop() error {
	return nil
}

// Connections returns an empty slice on non-Windows platforms.
func (w *wfpMonitorStub) Connections() []NetworkConnection {
	return []NetworkConnection{}
}

// DNSQueries returns an empty slice on non-Windows platforms.
func (w *wfpMonitorStub) DNSQueries() []DNSQuery {
	return []DNSQuery{}
}

// TLSMetadata returns an empty slice on non-Windows platforms.
func (w *wfpMonitorStub) TLSMetadata() []TLSConnection {
	return []TLSConnection{}
}

// ExportPCAP returns an error indicating PCAP export is Windows-only.
func (w *wfpMonitorStub) ExportPCAP(outputPath string) error {
	return fmt.Errorf("PCAP export is only available on Windows")
}
