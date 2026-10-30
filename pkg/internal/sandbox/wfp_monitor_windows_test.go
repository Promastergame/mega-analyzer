//go:build windows
// +build windows

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestWFPMonitor_NewWFPMonitor tests WFP monitor creation.
// Validates: Requirement 7.1
func TestWFPMonitor_NewWFPMonitor(t *testing.T) {
	monitor := NewWFPMonitor()
	if monitor == nil {
		t.Fatal("NewWFPMonitor returned nil")
	}

	impl, ok := monitor.(*wfpMonitorImpl)
	if !ok {
		t.Fatal("NewWFPMonitor did not return *wfpMonitorImpl")
	}

	// Verify initialization
	if impl.targetPIDs == nil {
		t.Error("targetPIDs map not initialized")
	}
	if impl.connections == nil {
		t.Error("connections slice not initialized")
	}
	if impl.dnsQueries == nil {
		t.Error("dnsQueries slice not initialized")
	}
	if impl.tlsMetadata == nil {
		t.Error("tlsMetadata slice not initialized")
	}
	if impl.packets == nil {
		t.Error("packets slice not initialized")
	}

	// Verify limits
	if impl.maxConnections != 10000 {
		t.Errorf("maxConnections = %d, want 10000", impl.maxConnections)
	}
	if impl.maxDNSQueries != 5000 {
		t.Errorf("maxDNSQueries = %d, want 5000", impl.maxDNSQueries)
	}
	if impl.maxTLSRecords != 1000 {
		t.Errorf("maxTLSRecords = %d, want 1000", impl.maxTLSRecords)
	}
	if impl.maxPackets != 100000 {
		t.Errorf("maxPackets = %d, want 100000", impl.maxPackets)
	}
	if impl.maxPCAPSize != 100*1024*1024 {
		t.Errorf("maxPCAPSize = %d, want %d", impl.maxPCAPSize, 100*1024*1024)
	}
}

// TestWFPMonitor_StartStop tests starting and stopping the monitor.
// Validates: Requirement 7.1
func TestWFPMonitor_StartStop(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	ctx := context.Background()
	targetPIDs := []int{1234, 5678}

	// Test Start
	err := monitor.Start(ctx, targetPIDs)
	if err != nil {
		if !isAdmin() {
			t.Logf("Start failed (expected without admin): %v", err)
		} else {
			t.Fatalf("Start failed: %v", err)
		}
	}

	// Verify target PIDs stored
	if len(impl.targetPIDs) != 2 {
		t.Errorf("targetPIDs length = %d, want 2", len(impl.targetPIDs))
	}

	// Verify target PIDs stored
	if len(impl.targetPIDs) != 2 {
		t.Errorf("targetPIDs length = %d, want 2", len(impl.targetPIDs))
	}
	if !impl.targetPIDs[1234] || !impl.targetPIDs[5678] {
		t.Error("Target PIDs not stored correctly")
	}

	// Test double start
	err = monitor.Start(ctx, targetPIDs)
	if err == nil {
		t.Error("Expected error when starting already running monitor")
	}

	// Test Stop
	err = monitor.Stop()
	if err != nil {
		t.Errorf("Stop failed: %v", err)
	}

	// Verify stopped state
	if impl.running {
		t.Error("Monitor still marked as running after Stop")
	}

	// Test double stop (should not error)
	err = monitor.Stop()
	if err != nil {
		t.Errorf("Stop on stopped monitor failed: %v", err)
	}
}

// TestWFPMonitor_ConnectionTracking tests connection tracking functionality.
// Validates: Requirement 7.1
func TestWFPMonitor_ConnectionTracking(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Add test connections
	conn1 := NetworkConnection{
		Timestamp:     time.Now(),
		ProcessID:     1234,
		ProcessName:   "test.exe",
		Protocol:      "TCP",
		LocalAddr:     "192.168.1.100",
		LocalPort:     50000,
		RemoteAddr:    "93.184.216.34",
		RemotePort:    443,
		Direction:     "Outbound",
		BytesSent:     1024,
		BytesReceived: 2048,
		State:         "ESTABLISHED",
	}

	conn2 := NetworkConnection{
		Timestamp:     time.Now(),
		ProcessID:     5678,
		ProcessName:   "other.exe",
		Protocol:      "UDP",
		LocalAddr:     "192.168.1.100",
		LocalPort:     51000,
		RemoteAddr:    "8.8.8.8",
		RemotePort:    53,
		Direction:     "Outbound",
		BytesSent:     64,
		BytesReceived: 128,
		State:         "",
	}

	impl.addConnection(conn1)
	impl.addConnection(conn2)

	// Retrieve connections
	connections := monitor.Connections()

	if len(connections) != 2 {
		t.Fatalf("Expected 2 connections, got %d", len(connections))
	}

	// Verify first connection
	if connections[0].ProcessID != 1234 {
		t.Errorf("Connection 0 ProcessID = %d, want 1234", connections[0].ProcessID)
	}
	if connections[0].Protocol != "TCP" {
		t.Errorf("Connection 0 Protocol = %s, want TCP", connections[0].Protocol)
	}
	if connections[0].RemotePort != 443 {
		t.Errorf("Connection 0 RemotePort = %d, want 443", connections[0].RemotePort)
	}
	if connections[0].BytesSent != 1024 {
		t.Errorf("Connection 0 BytesSent = %d, want 1024", connections[0].BytesSent)
	}
	if connections[0].BytesReceived != 2048 {
		t.Errorf("Connection 0 BytesReceived = %d, want 2048", connections[0].BytesReceived)
	}

	// Verify second connection
	if connections[1].ProcessID != 5678 {
		t.Errorf("Connection 1 ProcessID = %d, want 5678", connections[1].ProcessID)
	}
	if connections[1].Protocol != "UDP" {
		t.Errorf("Connection 1 Protocol = %s, want UDP", connections[1].Protocol)
	}
}

// TestWFPMonitor_ConnectionFiltering tests PID-based connection filtering.
// Validates: Requirement 7.1
func TestWFPMonitor_ConnectionFiltering(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Set target PIDs
	impl.targetPIDs[1234] = true

	// Add connection from target PID
	conn1 := NetworkConnection{
		Timestamp:   time.Now(),
		ProcessID:   1234,
		ProcessName: "target.exe",
		Protocol:    "TCP",
	}
	impl.addConnection(conn1)

	// Add connection from non-target PID
	conn2 := NetworkConnection{
		Timestamp:   time.Now(),
		ProcessID:   9999,
		ProcessName: "other.exe",
		Protocol:    "TCP",
	}
	impl.addConnection(conn2)

	// Verify only target PID connection was added
	connections := monitor.Connections()
	if len(connections) != 1 {
		t.Fatalf("Expected 1 connection, got %d", len(connections))
	}
	if connections[0].ProcessID != 1234 {
		t.Errorf("Connection ProcessID = %d, want 1234", connections[0].ProcessID)
	}
}

// TestWFPMonitor_ConnectionLimit tests connection count limit enforcement.
// Validates: Requirement 7.1
func TestWFPMonitor_ConnectionLimit(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Set low limit for testing
	impl.maxConnections = 10

	// Add connections beyond limit
	for i := 0; i < 15; i++ {
		conn := NetworkConnection{
			Timestamp:   time.Now(),
			ProcessID:   1234,
			ProcessName: "test.exe",
			Protocol:    "TCP",
			LocalPort:   uint16(50000 + i),
		}
		impl.addConnection(conn)
	}

	// Verify limit enforced
	connections := monitor.Connections()
	if len(connections) != 10 {
		t.Errorf("Expected 10 connections (limit), got %d", len(connections))
	}
}

// TestWFPMonitor_DNSQueryLogging tests DNS query logging functionality.
// Validates: Requirement 7.2
func TestWFPMonitor_DNSQueryLogging(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Add test DNS queries
	query1 := DNSQuery{
		Timestamp:    time.Now(),
		ProcessID:    1234,
		ProcessName:  "test.exe",
		QueryName:    "example.com",
		QueryType:    "A",
		Response:     []string{"93.184.216.34"},
		ResponseCode: "NOERROR",
	}

	query2 := DNSQuery{
		Timestamp:    time.Now(),
		ProcessID:    1234,
		ProcessName:  "test.exe",
		QueryName:    "example.com",
		QueryType:    "AAAA",
		Response:     []string{"2606:2800:220:1:248:1893:25c8:1946"},
		ResponseCode: "NOERROR",
	}

	impl.addDNSQuery(query1)
	impl.addDNSQuery(query2)

	// Retrieve DNS queries
	queries := monitor.DNSQueries()

	if len(queries) != 2 {
		t.Fatalf("Expected 2 DNS queries, got %d", len(queries))
	}

	// Verify first query
	if queries[0].QueryName != "example.com" {
		t.Errorf("Query 0 QueryName = %s, want example.com", queries[0].QueryName)
	}
	if queries[0].QueryType != "A" {
		t.Errorf("Query 0 QueryType = %s, want A", queries[0].QueryType)
	}
	if len(queries[0].Response) != 1 || queries[0].Response[0] != "93.184.216.34" {
		t.Errorf("Query 0 Response = %v, want [93.184.216.34]", queries[0].Response)
	}
	if queries[0].ResponseCode != "NOERROR" {
		t.Errorf("Query 0 ResponseCode = %s, want NOERROR", queries[0].ResponseCode)
	}

	// Verify second query
	if queries[1].QueryType != "AAAA" {
		t.Errorf("Query 1 QueryType = %s, want AAAA", queries[1].QueryType)
	}
}

// TestWFPMonitor_DNSQueryFiltering tests PID-based DNS query filtering.
// Validates: Requirement 7.2
func TestWFPMonitor_DNSQueryFiltering(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Set target PIDs
	impl.targetPIDs[1234] = true

	// Add query from target PID
	query1 := DNSQuery{
		Timestamp:   time.Now(),
		ProcessID:   1234,
		ProcessName: "target.exe",
		QueryName:   "example.com",
		QueryType:   "A",
	}
	impl.addDNSQuery(query1)

	// Add query from non-target PID
	query2 := DNSQuery{
		Timestamp:   time.Now(),
		ProcessID:   9999,
		ProcessName: "other.exe",
		QueryName:   "other.com",
		QueryType:   "A",
	}
	impl.addDNSQuery(query2)

	// Verify only target PID query was added
	queries := monitor.DNSQueries()
	if len(queries) != 1 {
		t.Fatalf("Expected 1 DNS query, got %d", len(queries))
	}
	if queries[0].ProcessID != 1234 {
		t.Errorf("Query ProcessID = %d, want 1234", queries[0].ProcessID)
	}
}

// TestWFPMonitor_TLSMetadataCapture tests TLS metadata capture functionality.
// Validates: Requirement 7.3
func TestWFPMonitor_TLSMetadataCapture(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Add test TLS metadata
	tls1 := TLSConnection{
		Timestamp:          time.Now(),
		ProcessID:          1234,
		RemoteAddr:         "93.184.216.34",
		RemotePort:         443,
		SNI:                "example.com",
		CertificateSubject: "CN=example.com",
		CertificateIssuer:  "CN=DigiCert TLS RSA SHA256 2020 CA1",
		TLSVersion:         "TLS 1.3",
		CipherSuite:        "TLS_AES_256_GCM_SHA384",
	}

	tls2 := TLSConnection{
		Timestamp:          time.Now(),
		ProcessID:          1234,
		RemoteAddr:         "8.8.8.8",
		RemotePort:         443,
		SNI:                "dns.google",
		CertificateSubject: "CN=dns.google",
		CertificateIssuer:  "CN=GTS CA 1C3",
		TLSVersion:         "TLS 1.2",
		CipherSuite:        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	}

	impl.addTLSMetadata(tls1)
	impl.addTLSMetadata(tls2)

	// Retrieve TLS metadata
	tlsData := monitor.TLSMetadata()

	if len(tlsData) != 2 {
		t.Fatalf("Expected 2 TLS connections, got %d", len(tlsData))
	}

	// Verify first TLS connection
	if tlsData[0].SNI != "example.com" {
		t.Errorf("TLS 0 SNI = %s, want example.com", tlsData[0].SNI)
	}
	if tlsData[0].TLSVersion != "TLS 1.3" {
		t.Errorf("TLS 0 TLSVersion = %s, want TLS 1.3", tlsData[0].TLSVersion)
	}
	if tlsData[0].CipherSuite != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("TLS 0 CipherSuite = %s, want TLS_AES_256_GCM_SHA384", tlsData[0].CipherSuite)
	}

	// Verify second TLS connection
	if tlsData[1].SNI != "dns.google" {
		t.Errorf("TLS 1 SNI = %s, want dns.google", tlsData[1].SNI)
	}
	if tlsData[1].TLSVersion != "TLS 1.2" {
		t.Errorf("TLS 1 TLSVersion = %s, want TLS 1.2", tlsData[1].TLSVersion)
	}
}

// TestWFPMonitor_TLSMetadataFiltering tests PID-based TLS metadata filtering.
// Validates: Requirement 7.3
func TestWFPMonitor_TLSMetadataFiltering(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Set target PIDs
	impl.targetPIDs[1234] = true

	// Add TLS metadata from target PID
	tls1 := TLSConnection{
		Timestamp:  time.Now(),
		ProcessID:  1234,
		RemoteAddr: "93.184.216.34",
		SNI:        "example.com",
	}
	impl.addTLSMetadata(tls1)

	// Add TLS metadata from non-target PID
	tls2 := TLSConnection{
		Timestamp:  time.Now(),
		ProcessID:  9999,
		RemoteAddr: "8.8.8.8",
		SNI:        "other.com",
	}
	impl.addTLSMetadata(tls2)

	// Verify only target PID metadata was added
	tlsData := monitor.TLSMetadata()
	if len(tlsData) != 1 {
		t.Fatalf("Expected 1 TLS connection, got %d", len(tlsData))
	}
	if tlsData[0].ProcessID != 1234 {
		t.Errorf("TLS ProcessID = %d, want 1234", tlsData[0].ProcessID)
	}
}

// TestWFPMonitor_PacketCapture tests packet capture functionality.
// Validates: Requirement 7.4
func TestWFPMonitor_PacketCapture(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Add test packets
	packet1 := []byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06}
	packet2 := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11}

	ts1 := time.Now()
	ts2 := ts1.Add(time.Millisecond)

	impl.addPacket(ts1, packet1)
	impl.addPacket(ts2, packet2)

	// Verify packets stored
	if len(impl.packets) != 2 {
		t.Fatalf("Expected 2 packets, got %d", len(impl.packets))
	}

	if impl.packets[0].length != uint32(len(packet1)) {
		t.Errorf("Packet 0 length = %d, want %d", impl.packets[0].length, len(packet1))
	}
	if impl.packets[1].length != uint32(len(packet2)) {
		t.Errorf("Packet 1 length = %d, want %d", impl.packets[1].length, len(packet2))
	}
}

// TestWFPMonitor_PacketLimit tests packet count limit enforcement.
// Validates: Requirement 7.4
func TestWFPMonitor_PacketLimit(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Set low limit for testing
	impl.maxPackets = 10

	// Add packets beyond limit
	packet := []byte{0x45, 0x00, 0x00, 0x3c}
	for i := 0; i < 15; i++ {
		impl.addPacket(time.Now(), packet)
	}

	// Verify limit enforced
	if len(impl.packets) != 10 {
		t.Errorf("Expected 10 packets (limit), got %d", len(impl.packets))
	}
}

// TestWFPMonitor_PCAPSizeLimit tests PCAP size limit enforcement.
// Validates: Requirement 7.4
func TestWFPMonitor_PCAPSizeLimit(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Set low size limit for testing
	impl.maxPCAPSize = 100 // 100 bytes

	// Add packets that exceed size limit
	packet := make([]byte, 50)         // 50 bytes each
	impl.addPacket(time.Now(), packet) // Total: 50 bytes
	impl.addPacket(time.Now(), packet) // Total: 100 bytes
	impl.addPacket(time.Now(), packet) // Should be rejected (would be 150 bytes)

	// Verify size limit enforced
	if len(impl.packets) != 2 {
		t.Errorf("Expected 2 packets (size limit), got %d", len(impl.packets))
	}
}

// TestWFPMonitor_PCAPExport tests PCAP file export functionality.
// Validates: Requirement 7.4
func TestWFPMonitor_PCAPExport(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Add test packets
	packet1 := []byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06}
	packet2 := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11}

	ts1 := time.Now()
	ts2 := ts1.Add(time.Millisecond)

	impl.addPacket(ts1, packet1)
	impl.addPacket(ts2, packet2)

	// Create temp directory for output
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "capture.pcap")

	// Export PCAP
	err := monitor.ExportPCAP(outputPath)
	if err != nil {
		t.Fatalf("ExportPCAP failed: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("PCAP file was not created")
	}

	// Read and verify file content
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read PCAP file: %v", err)
	}

	// Verify PCAP global header (24 bytes)
	if len(data) < 24 {
		t.Fatalf("PCAP file too small: %d bytes", len(data))
	}

	// Verify magic number (0xa1b2c3d4 in little endian)
	magicNumber := uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
	if magicNumber != 0xa1b2c3d4 {
		t.Errorf("Invalid PCAP magic number: 0x%x, want 0xa1b2c3d4", magicNumber)
	}

	// Verify version (2.4)
	versionMajor := uint16(data[4]) | uint16(data[5])<<8
	versionMinor := uint16(data[6]) | uint16(data[7])<<8
	if versionMajor != 2 || versionMinor != 4 {
		t.Errorf("Invalid PCAP version: %d.%d, want 2.4", versionMajor, versionMinor)
	}

	// Verify snaplen (65535)
	snaplen := uint32(data[16]) | uint32(data[17])<<8 | uint32(data[18])<<16 | uint32(data[19])<<24
	if snaplen != 65535 {
		t.Errorf("Invalid PCAP snaplen: %d, want 65535", snaplen)
	}

	// Verify network type (1 = Ethernet)
	network := uint32(data[20]) | uint32(data[21])<<8 | uint32(data[22])<<16 | uint32(data[23])<<24
	if network != 1 {
		t.Errorf("Invalid PCAP network type: %d, want 1", network)
	}
}

// TestWFPMonitor_PCAPExportEmpty tests PCAP export with no packets.
// Validates: Requirement 7.4
func TestWFPMonitor_PCAPExportEmpty(t *testing.T) {
	monitor := NewWFPMonitor()

	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "empty.pcap")

	// Export PCAP with no packets
	err := monitor.ExportPCAP(outputPath)
	if err == nil {
		t.Error("Expected error when exporting empty PCAP")
	}
}

// TestPCAPWriter_WritePacket tests PCAP packet writing.
// Validates: Requirement 7.4
func TestPCAPWriter_WritePacket(t *testing.T) {
	tempDir := t.TempDir()
	outputPath := filepath.Join(tempDir, "test.pcap")

	writer, err := newPCAPWriter(outputPath)
	if err != nil {
		t.Fatalf("newPCAPWriter failed: %v", err)
	}
	defer writer.Close()

	// Write test packet
	packet := []byte{0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06}
	timestamp := time.Now()

	err = writer.WritePacket(timestamp, packet)
	if err != nil {
		t.Fatalf("WritePacket failed: %v", err)
	}

	// Close writer
	err = writer.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// Read and verify file
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read PCAP file: %v", err)
	}

	// Verify file contains global header (24 bytes) + packet header (16 bytes) + packet data
	expectedSize := 24 + 16 + len(packet)
	if len(data) != expectedSize {
		t.Errorf("PCAP file size = %d, want %d", len(data), expectedSize)
	}

	// Verify packet data at end of file
	packetData := data[len(data)-len(packet):]
	for i, b := range packet {
		if packetData[i] != b {
			t.Errorf("Packet data mismatch at byte %d: got 0x%x, want 0x%x", i, packetData[i], b)
		}
	}
}

// TestWFPMonitor_ConcurrentAccess tests thread-safety of WFP monitor.
// Validates: Requirement 7.1
func TestWFPMonitor_ConcurrentAccess(t *testing.T) {
	monitor := NewWFPMonitor()
	impl := monitor.(*wfpMonitorImpl)

	// Concurrently add connections
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			conn := NetworkConnection{
				Timestamp:   time.Now(),
				ProcessID:   1234,
				ProcessName: "test.exe",
				Protocol:    "TCP",
				LocalPort:   uint16(50000 + id),
			}
			impl.addConnection(conn)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all connections added
	connections := monitor.Connections()
	if len(connections) != 10 {
		t.Errorf("Expected 10 connections, got %d", len(connections))
	}
}
