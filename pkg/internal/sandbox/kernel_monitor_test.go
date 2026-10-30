//go:build windows

package sandbox

import (
	"context"
	"testing"
	"time"
)

// TestKernelMonitor_NewKernelMonitor verifies that NewKernelMonitor creates a valid instance.
func TestKernelMonitor_NewKernelMonitor(t *testing.T) {
	km := NewKernelMonitor()
	if km == nil {
		t.Fatal("NewKernelMonitor returned nil")
	}

	// Verify it's the correct implementation type
	impl, ok := km.(*kernelMonitorImpl)
	if !ok {
		t.Fatal("NewKernelMonitor did not return *kernelMonitorImpl")
	}

	// Verify initial state
	if impl.pipeName == "" {
		t.Error("pipeName should not be empty")
	}
	if impl.eventChan == nil {
		t.Error("eventChan should not be nil")
	}
	if impl.stopChan == nil {
		t.Error("stopChan should not be nil")
	}
	if impl.running {
		t.Error("monitor should not be running initially")
	}
}

// TestKernelMonitor_Events verifies that Events() returns a valid channel.
func TestKernelMonitor_Events(t *testing.T) {
	km := NewKernelMonitor()

	eventChan := km.Events()
	if eventChan == nil {
		t.Fatal("Events() returned nil channel")
	}

	// Verify channel is readable (should not panic)
	select {
	case <-eventChan:
		// Channel is closed or has data
	case <-time.After(10 * time.Millisecond):
		// Timeout is expected since no events are being generated
	}
}

// TestKernelMonitor_StopWithoutStart verifies that Stop() is safe to call without Start().
func TestKernelMonitor_StopWithoutStart(t *testing.T) {
	km := NewKernelMonitor()

	err := km.Stop()
	if err != nil {
		t.Errorf("Stop() without Start() should not return error, got: %v", err)
	}
}

// TestKernelMonitor_DoubleStart verifies that calling Start() twice returns an error.
func TestKernelMonitor_DoubleStart(t *testing.T) {
	// This test will fail on non-Windows or without admin privileges
	// We'll skip it if we can't start the monitor
	km := NewKernelMonitor()
	ctx := context.Background()

	err := km.Start(ctx)
	if err != nil {
		// Expected on non-Windows or without privileges
		t.Skipf("Cannot start kernel monitor: %v", err)
	}
	defer km.Stop()

	// Try to start again
	err = km.Start(ctx)
	if err == nil {
		t.Error("Second Start() should return error")
	}
}

// TestKernelMonitor_StartStop verifies basic start/stop lifecycle.
func TestKernelMonitor_StartStop(t *testing.T) {
	km := NewKernelMonitor()
	ctx := context.Background()

	err := km.Start(ctx)
	if err != nil {
		// Expected on non-Windows or without privileges
		t.Skipf("Cannot start kernel monitor: %v", err)
	}

	// Verify we can get the event channel
	eventChan := km.Events()
	if eventChan == nil {
		t.Fatal("Events() returned nil after Start()")
	}

	// Stop the monitor
	err = km.Stop()
	if err != nil {
		t.Errorf("Stop() returned error: %v", err)
	}

	// Verify channel is closed after Stop()
	select {
	case _, ok := <-eventChan:
		if ok {
			t.Error("Event channel should be closed after Stop()")
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Event channel was not closed after Stop()")
	}
}

// TestKernelMonitor_ContextCancellation verifies that context cancellation stops the monitor.
func TestKernelMonitor_ContextCancellation(t *testing.T) {
	km := NewKernelMonitor()
	ctx, cancel := context.WithCancel(context.Background())

	err := km.Start(ctx)
	if err != nil {
		t.Skipf("Cannot start kernel monitor: %v", err)
	}
	defer km.Stop()

	eventChan := km.Events()

	// Cancel context
	cancel()

	// Wait a bit for goroutine to react
	time.Sleep(50 * time.Millisecond)

	// Channel should still be open (Stop() closes it, not context cancellation)
	// But no new events should be generated
	select {
	case _, ok := <-eventChan:
		if !ok {
			// Channel closed, which is acceptable
		}
	case <-time.After(10 * time.Millisecond):
		// Timeout is expected
	}
}

// TestKernelMonitor_EventChannelBuffer verifies that the event channel has appropriate buffering.
func TestKernelMonitor_EventChannelBuffer(t *testing.T) {
	km := NewKernelMonitor()
	impl, ok := km.(*kernelMonitorImpl)
	if !ok {
		t.Fatal("Expected *kernelMonitorImpl")
	}

	// Verify channel has buffer
	if cap(impl.eventChan) == 0 {
		t.Error("Event channel should be buffered for high-frequency events")
	}

	// Verify buffer size is reasonable (at least 100)
	if cap(impl.eventChan) < 100 {
		t.Errorf("Event channel buffer too small: %d (expected >= 100)", cap(impl.eventChan))
	}
}

// TestKernelMonitor_IntegrityLevelParsing verifies integrity level string conversion.
func TestKernelMonitor_IntegrityLevelParsing(t *testing.T) {
	tests := []struct {
		level    uint32
		expected string
	}{
		{0, "Low"},
		{1, "Medium"},
		{2, "High"},
		{3, "System"},
		{99, "Unknown"},
	}

	for _, tt := range tests {
		result := integrityLevelToString(tt.level)
		if result != tt.expected {
			t.Errorf("integrityLevelToString(%d) = %q, want %q", tt.level, result, tt.expected)
		}
	}
}

// TestKernelMonitor_NTStatusParsing verifies NTSTATUS code conversion.
func TestKernelMonitor_NTStatusParsing(t *testing.T) {
	tests := []struct {
		status   uint32
		expected string
	}{
		{0x00000000, "Success"},
		{0xC0000022, "AccessDenied"},
		{0xC0000034, "ObjectNameNotFound"},
		{0xC000003A, "ObjectPathNotFound"},
		{0xC0000043, "SharingViolation"},
	}

	for _, tt := range tests {
		result := ntStatusToString(tt.status)
		if result != tt.expected {
			t.Errorf("ntStatusToString(0x%08X) = %q, want %q", tt.status, result, tt.expected)
		}
	}
}

// TestKernelMonitor_FileTimeConversion verifies Windows FILETIME to time.Time conversion.
func TestKernelMonitor_FileTimeConversion(t *testing.T) {
	// Test a known FILETIME value
	// January 1, 2020 00:00:00 UTC = 132223104000000000 in FILETIME
	ft := int64(132223104000000000)
	result := fileTimeToTime(ft)

	expected := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	// Convert both to Unix timestamps for comparison (avoids timezone issues)
	resultUnix := result.Unix()
	expectedUnix := expected.Unix()

	if resultUnix != expectedUnix {
		t.Errorf("fileTimeToTime(%d) = %v (unix: %d), want %v (unix: %d)",
			ft, result, resultUnix, expected, expectedUnix)
	}
}

// TestKernelMonitor_UTF16Conversion verifies UTF-16 to string conversion.
func TestKernelMonitor_UTF16Conversion(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "simple ASCII",
			input:    []byte{0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x00, 0x00}, // "ABC\0"
			expected: "ABC",
		},
		{
			name:     "empty string",
			input:    []byte{0x00, 0x00},
			expected: "",
		},
		{
			name:     "odd length (invalid)",
			input:    []byte{0x41, 0x00, 0x42},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utf16ToString(tt.input)
			if result != tt.expected {
				t.Errorf("utf16ToString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

// TestKernelMonitor_SetProcessFilter verifies process tree filtering configuration.
func TestKernelMonitor_SetProcessFilter(t *testing.T) {
	km := NewKernelMonitor()
	impl, ok := km.(*kernelMonitorImpl)
	if !ok {
		t.Fatal("Expected *kernelMonitorImpl")
	}

	// Initially, filtering should be disabled
	if impl.filterEnabled {
		t.Error("Filter should be disabled initially")
	}

	// Set process filter with some PIDs
	pids := []int{1234, 5678, 9012}
	impl.SetProcessFilter(pids)

	// Verify filtering is enabled
	if !impl.filterEnabled {
		t.Error("Filter should be enabled after SetProcessFilter")
	}

	// Verify PIDs are stored
	if len(impl.targetPIDs) != len(pids) {
		t.Errorf("Expected %d PIDs, got %d", len(pids), len(impl.targetPIDs))
	}

	for _, pid := range pids {
		if _, exists := impl.targetPIDs[pid]; !exists {
			t.Errorf("PID %d not found in targetPIDs", pid)
		}
	}

	// Set empty filter (should disable filtering)
	impl.SetProcessFilter([]int{})
	if impl.filterEnabled {
		t.Error("Filter should be disabled with empty PID list")
	}

	// Set nil filter (should disable filtering)
	impl.SetProcessFilter(nil)
	if impl.filterEnabled {
		t.Error("Filter should be disabled with nil PID list")
	}
}

// TestKernelMonitor_ShouldFilterEvent verifies event filtering logic.
func TestKernelMonitor_ShouldFilterEvent(t *testing.T) {
	km := NewKernelMonitor()
	impl, ok := km.(*kernelMonitorImpl)
	if !ok {
		t.Fatal("Expected *kernelMonitorImpl")
	}

	// Create test event
	event := KernelEvent{
		ProcessID: 1234,
		EventType: EventFileCreate,
	}

	// With filtering disabled, no events should be filtered
	impl.SetProcessFilter(nil)
	if impl.shouldFilterEvent(event) {
		t.Error("Event should not be filtered when filtering is disabled")
	}

	// Enable filtering with target PIDs
	impl.SetProcessFilter([]int{1234, 5678})

	// Event from target process should not be filtered
	event.ProcessID = 1234
	if impl.shouldFilterEvent(event) {
		t.Error("Event from target process should not be filtered")
	}

	// Event from non-target process should be filtered
	event.ProcessID = 9999
	if !impl.shouldFilterEvent(event) {
		t.Error("Event from non-target process should be filtered")
	}
}

// TestKernelMonitor_ProcessFilterConcurrency verifies thread-safe filter updates.
func TestKernelMonitor_ProcessFilterConcurrency(t *testing.T) {
	km := NewKernelMonitor()
	impl, ok := km.(*kernelMonitorImpl)
	if !ok {
		t.Fatal("Expected *kernelMonitorImpl")
	}

	// Run concurrent filter updates and checks
	done := make(chan bool)

	// Goroutine 1: Update filter
	go func() {
		for i := 0; i < 100; i++ {
			impl.SetProcessFilter([]int{i, i + 1, i + 2})
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	// Goroutine 2: Check filter
	go func() {
		event := KernelEvent{ProcessID: 50}
		for i := 0; i < 100; i++ {
			impl.shouldFilterEvent(event)
			time.Sleep(time.Microsecond)
		}
		done <- true
	}()

	// Wait for both goroutines
	<-done
	<-done
}

// TestKernelEventType_String verifies string representation of event types.
func TestKernelEventType_String(t *testing.T) {
	tests := []struct {
		eventType KernelEventType
		expected  string
	}{
		{EventFileCreate, "FileCreate"},
		{EventFileWrite, "FileWrite"},
		{EventFileDelete, "FileDelete"},
		{EventFileRename, "FileRename"},
		{EventRegSetValue, "RegSetValue"},
		{EventRegDeleteValue, "RegDeleteValue"},
		{EventRegCreateKey, "RegCreateKey"},
		{EventRegDeleteKey, "RegDeleteKey"},
		{KernelEventType(999), "Unknown"},
	}

	for _, tt := range tests {
		result := tt.eventType.String()
		if result != tt.expected {
			t.Errorf("KernelEventType(%d).String() = %q, want %q", tt.eventType, result, tt.expected)
		}
	}
}

// TestKernelMonitor_EnrichEventDetails verifies event detail enrichment.
func TestKernelMonitor_EnrichEventDetails(t *testing.T) {
	km := NewKernelMonitor()
	impl, ok := km.(*kernelMonitorImpl)
	if !ok {
		t.Fatal("Expected *kernelMonitorImpl")
	}

	tests := []struct {
		name         string
		eventType    KernelEventType
		expectedIRP  string
		expectedDesc string
	}{
		{
			name:         "FileCreate",
			eventType:    EventFileCreate,
			expectedIRP:  "IRP_MJ_CREATE",
			expectedDesc: "File or directory open/create operation",
		},
		{
			name:         "FileWrite",
			eventType:    EventFileWrite,
			expectedIRP:  "IRP_MJ_WRITE",
			expectedDesc: "File write operation",
		},
		{
			name:         "RegSetValue",
			eventType:    EventRegSetValue,
			expectedIRP:  "", // Registry events don't have IRP type
			expectedDesc: "Registry value set operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := KernelEvent{
				EventType: tt.eventType,
				Details:   make(map[string]string),
			}

			impl.enrichEventDetails(&event)

			if tt.expectedIRP != "" {
				if irpType, exists := event.Details["irp_type"]; !exists || irpType != tt.expectedIRP {
					t.Errorf("Expected irp_type=%q, got %q", tt.expectedIRP, irpType)
				}
			}

			if desc, exists := event.Details["description"]; !exists || desc != tt.expectedDesc {
				t.Errorf("Expected description=%q, got %q", tt.expectedDesc, desc)
			}
		})
	}
}

// TestKernelMonitor_FilesystemEventCapture verifies filesystem event type mapping.
func TestKernelMonitor_FilesystemEventCapture(t *testing.T) {
	// Verify that filesystem event types are correctly defined
	filesystemEvents := []KernelEventType{
		EventFileCreate,
		EventFileWrite,
		EventFileDelete,
		EventFileRename,
	}

	for _, eventType := range filesystemEvents {
		// Verify each event type has a string representation
		str := eventType.String()
		if str == "Unknown" {
			t.Errorf("Filesystem event type %d has no string representation", eventType)
		}

		// Verify enrichment adds details
		km := NewKernelMonitor()
		impl := km.(*kernelMonitorImpl)
		event := KernelEvent{
			EventType: eventType,
			Details:   make(map[string]string),
		}
		impl.enrichEventDetails(&event)

		if len(event.Details) == 0 {
			t.Errorf("Event type %s has no enriched details", str)
		}
	}
}

// TestKernelMonitor_RegistryEventCapture verifies registry event type mapping.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_RegistryEventCapture(t *testing.T) {
	// Verify that registry event types are correctly defined
	registryEvents := []KernelEventType{
		EventRegSetValue,
		EventRegDeleteValue,
		EventRegCreateKey,
		EventRegDeleteKey,
	}

	for _, eventType := range registryEvents {
		// Verify each event type has a string representation
		str := eventType.String()
		if str == "Unknown" {
			t.Errorf("Registry event type %d has no string representation", eventType)
		}

		// Verify enrichment adds details
		km := NewKernelMonitor()
		impl := km.(*kernelMonitorImpl)
		event := KernelEvent{
			EventType: eventType,
			Details:   make(map[string]string),
		}
		impl.enrichEventDetails(&event)

		if len(event.Details) == 0 {
			t.Errorf("Event type %s has no enriched details", str)
		}

		// Verify callback_type is set for registry events
		if callbackType, exists := event.Details["callback_type"]; !exists {
			t.Errorf("Registry event %s missing callback_type", str)
		} else if callbackType == "" {
			t.Errorf("Registry event %s has empty callback_type", str)
		}
	}
}

// TestKernelMonitor_IsRegistryEvent verifies registry event detection.
// Validates: Requirements 2.2
func TestKernelMonitor_IsRegistryEvent(t *testing.T) {
	tests := []struct {
		eventType KernelEventType
		expected  bool
	}{
		{EventFileCreate, false},
		{EventFileWrite, false},
		{EventFileDelete, false},
		{EventFileRename, false},
		{EventRegSetValue, true},
		{EventRegDeleteValue, true},
		{EventRegCreateKey, true},
		{EventRegDeleteKey, true},
	}

	for _, tt := range tests {
		result := isRegistryEvent(tt.eventType)
		if result != tt.expected {
			t.Errorf("isRegistryEvent(%s) = %v, want %v", tt.eventType.String(), result, tt.expected)
		}
	}
}

// TestKernelMonitor_RegTypeToString verifies registry type conversion.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_RegTypeToString(t *testing.T) {
	tests := []struct {
		regType  uint32
		expected string
	}{
		{0, "REG_NONE"},
		{1, "REG_SZ"},
		{2, "REG_EXPAND_SZ"},
		{3, "REG_BINARY"},
		{4, "REG_DWORD"},
		{5, "REG_DWORD_BIG_ENDIAN"},
		{6, "REG_LINK"},
		{7, "REG_MULTI_SZ"},
		{8, "REG_RESOURCE_LIST"},
		{9, "REG_FULL_RESOURCE_DESCRIPTOR"},
		{10, "REG_RESOURCE_REQUIREMENTS_LIST"},
		{11, "REG_QWORD"},
		{999, "UNKNOWN(0x3e7)"},
	}

	for _, tt := range tests {
		result := regTypeToString(tt.regType)
		if result != tt.expected {
			t.Errorf("regTypeToString(%d) = %q, want %q", tt.regType, result, tt.expected)
		}
	}
}

// TestKernelMonitor_FormatRegistryData_String verifies REG_SZ formatting.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_FormatRegistryData_String(t *testing.T) {
	// REG_SZ: "Test" in UTF-16LE
	data := []byte{0x54, 0x00, 0x65, 0x00, 0x73, 0x00, 0x74, 0x00, 0x00, 0x00}
	result := formatRegistryData(1, data) // REG_SZ = 1
	expected := "Test"
	if result != expected {
		t.Errorf("formatRegistryData(REG_SZ) = %q, want %q", result, expected)
	}
}

// TestKernelMonitor_FormatRegistryData_DWORD verifies REG_DWORD formatting.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_FormatRegistryData_DWORD(t *testing.T) {
	// REG_DWORD: 0x12345678
	data := []byte{0x78, 0x56, 0x34, 0x12} // Little-endian
	result := formatRegistryData(4, data)  // REG_DWORD = 4
	expected := "0x12345678 (305419896)"
	if result != expected {
		t.Errorf("formatRegistryData(REG_DWORD) = %q, want %q", result, expected)
	}
}

// TestKernelMonitor_FormatRegistryData_QWORD verifies REG_QWORD formatting.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_FormatRegistryData_QWORD(t *testing.T) {
	// REG_QWORD: 0x123456789ABCDEF0
	data := []byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12} // Little-endian
	result := formatRegistryData(11, data)                         // REG_QWORD = 11
	expected := "0x123456789abcdef0 (1311768467463790320)"
	if result != expected {
		t.Errorf("formatRegistryData(REG_QWORD) = %q, want %q", result, expected)
	}
}

// TestKernelMonitor_FormatRegistryData_Binary verifies REG_BINARY formatting.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_FormatRegistryData_Binary(t *testing.T) {
	// REG_BINARY: arbitrary bytes
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	result := formatRegistryData(3, data) // REG_BINARY = 3
	expected := "0102030405"
	if result != expected {
		t.Errorf("formatRegistryData(REG_BINARY) = %q, want %q", result, expected)
	}

	// Test truncation for large binary data
	largeData := make([]byte, 100)
	for i := range largeData {
		largeData[i] = byte(i)
	}
	result = formatRegistryData(3, largeData)
	if len(result) > 70 { // 32 bytes * 2 hex chars + "..."
		// Should be truncated
		if result[len(result)-3:] != "..." {
			t.Error("Large binary data should be truncated with '...'")
		}
	}
}

// TestKernelMonitor_FormatRegistryData_MultiSZ verifies REG_MULTI_SZ formatting.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_FormatRegistryData_MultiSZ(t *testing.T) {
	// REG_MULTI_SZ: "First\0Second\0\0" in UTF-16LE
	data := []byte{
		0x46, 0x00, 0x69, 0x00, 0x72, 0x00, 0x73, 0x00, 0x74, 0x00, // "First"
		0x00, 0x00, // Null terminator
		0x53, 0x00, 0x65, 0x00, 0x63, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x64, 0x00, // "Second"
		0x00, 0x00, // Null terminator
		0x00, 0x00, // Double null terminator
	}
	result := formatRegistryData(7, data) // REG_MULTI_SZ = 7
	// Should show first string
	if result != "[First]" {
		t.Errorf("formatRegistryData(REG_MULTI_SZ) = %q, want %q", result, "[First]")
	}
}

// TestKernelMonitor_ParseMultiSZ verifies REG_MULTI_SZ parsing.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_ParseMultiSZ(t *testing.T) {
	// REG_MULTI_SZ: "First\0Second\0Third\0\0" in UTF-16LE
	data := []byte{
		0x46, 0x00, 0x69, 0x00, 0x72, 0x00, 0x73, 0x00, 0x74, 0x00, // "First"
		0x00, 0x00, // Null terminator
		0x53, 0x00, 0x65, 0x00, 0x63, 0x00, 0x6F, 0x00, 0x6E, 0x00, 0x64, 0x00, // "Second"
		0x00, 0x00, // Null terminator
		0x54, 0x00, 0x68, 0x00, 0x69, 0x00, 0x72, 0x00, 0x64, 0x00, // "Third"
		0x00, 0x00, // Null terminator
		0x00, 0x00, // Double null terminator
	}

	result := parseMultiSZ(data)
	expected := []string{"First", "Second", "Third"}

	if len(result) != len(expected) {
		t.Fatalf("parseMultiSZ() returned %d strings, want %d", len(result), len(expected))
	}

	for i, str := range result {
		if str != expected[i] {
			t.Errorf("parseMultiSZ()[%d] = %q, want %q", i, str, expected[i])
		}
	}
}

// TestKernelMonitor_RegistryEventEnrichment verifies registry event enrichment.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_RegistryEventEnrichment(t *testing.T) {
	km := NewKernelMonitor()
	impl, ok := km.(*kernelMonitorImpl)
	if !ok {
		t.Fatal("Expected *kernelMonitorImpl")
	}

	tests := []struct {
		name             string
		eventType        KernelEventType
		expectedCallback string
		expectedDesc     string
	}{
		{
			name:             "RegSetValue",
			eventType:        EventRegSetValue,
			expectedCallback: "RegNtPreSetValueKey",
			expectedDesc:     "Registry value set operation",
		},
		{
			name:             "RegDeleteValue",
			eventType:        EventRegDeleteValue,
			expectedCallback: "RegNtPreDeleteValueKey",
			expectedDesc:     "Registry value deletion operation",
		},
		{
			name:             "RegCreateKey",
			eventType:        EventRegCreateKey,
			expectedCallback: "RegNtPreCreateKeyEx",
			expectedDesc:     "Registry key creation operation",
		},
		{
			name:             "RegDeleteKey",
			eventType:        EventRegDeleteKey,
			expectedCallback: "RegNtPreDeleteKey",
			expectedDesc:     "Registry key deletion operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := KernelEvent{
				EventType: tt.eventType,
				Details:   make(map[string]string),
			}

			impl.enrichEventDetails(&event)

			if callbackType, exists := event.Details["callback_type"]; !exists || callbackType != tt.expectedCallback {
				t.Errorf("Expected callback_type=%q, got %q", tt.expectedCallback, callbackType)
			}

			if desc, exists := event.Details["description"]; !exists || desc != tt.expectedDesc {
				t.Errorf("Expected description=%q, got %q", tt.expectedDesc, desc)
			}
		})
	}
}

// TestKernelMonitor_FormatRegistryData_Empty verifies empty data handling.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_FormatRegistryData_Empty(t *testing.T) {
	result := formatRegistryData(1, []byte{}) // REG_SZ with empty data
	if result != "" {
		t.Errorf("formatRegistryData(empty) = %q, want empty string", result)
	}
}

// TestKernelMonitor_FormatRegistryData_InvalidDWORD verifies invalid DWORD handling.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_FormatRegistryData_InvalidDWORD(t *testing.T) {
	// DWORD with only 2 bytes (invalid)
	data := []byte{0x12, 0x34}
	result := formatRegistryData(4, data) // REG_DWORD = 4
	if result != "<invalid DWORD: 2 bytes>" {
		t.Errorf("formatRegistryData(invalid DWORD) = %q, want error message", result)
	}
}

// TestKernelMonitor_FormatRegistryData_InvalidQWORD verifies invalid QWORD handling.
// Validates: Requirements 2.2, 2.3
func TestKernelMonitor_FormatRegistryData_InvalidQWORD(t *testing.T) {
	// QWORD with only 4 bytes (invalid)
	data := []byte{0x12, 0x34, 0x56, 0x78}
	result := formatRegistryData(11, data) // REG_QWORD = 11
	if result != "<invalid QWORD: 4 bytes>" {
		t.Errorf("formatRegistryData(invalid QWORD) = %q, want error message", result)
	}
}
