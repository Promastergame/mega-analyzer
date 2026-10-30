// Package sandbox provides Windows-native sandbox capabilities for malware analysis.
package sandbox

import (
	"context"
)

// WFPMonitor captures network traffic at the Windows Filtering Platform layer.
// It provides comprehensive network visibility including connection tracking,
// DNS query logging, TLS metadata extraction, and PCAP export.
//
// Implementation uses ETW (Event Tracing for Windows) as a simpler alternative
// to WFP callout drivers for the MVP. ETW provides network event tracing without
// requiring kernel-mode driver development.
//
// Validates: Requirements 7.1, 7.4
type WFPMonitor interface {
	// Start begins network monitoring for the specified target processes.
	// It registers ETW providers for network events and starts capturing.
	//
	// Parameters:
	//   - ctx: Context for cancellation and timeout control
	//   - targetPIDs: Process IDs to monitor (empty slice monitors all processes)
	//
	// Returns error if:
	//   - Insufficient privileges (requires Administrator)
	//   - ETW session creation fails
	//   - Network provider registration fails
	Start(ctx context.Context, targetPIDs []int) error

	// Stop terminates network monitoring and flushes buffered events.
	// It unregisters ETW providers and closes the capture session.
	//
	// Returns error if cleanup fails (non-fatal, logged as warning).
	Stop() error

	// Connections returns all captured network connections.
	// Includes TCP/UDP connections with process attribution, addresses,
	// ports, byte counts, and connection states.
	//
	// Validates: Requirement 7.1
	Connections() []NetworkConnection

	// DNSQueries returns all captured DNS queries with responses.
	// Includes query name, type, response records, and process attribution.
	//
	// Validates: Requirement 7.2
	DNSQueries() []DNSQuery

	// TLSMetadata returns captured TLS/SSL handshake metadata.
	// Includes SNI, certificate details, TLS version, and cipher suite.
	// Extracted by intercepting Schannel API calls.
	//
	// Validates: Requirement 7.3
	TLSMetadata() []TLSConnection

	// ExportPCAP exports captured packets to PCAP format for Wireshark analysis.
	// Implements size limits and rotation (default 100 MB).
	//
	// Parameters:
	//   - outputPath: Destination file path for PCAP export
	//
	// Returns error if:
	//   - File creation fails
	//   - PCAP format conversion fails
	//   - Write operation fails
	//
	// Validates: Requirement 7.4
	ExportPCAP(outputPath string) error
}
