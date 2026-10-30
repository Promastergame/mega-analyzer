package sandbox

import (
	"encoding/json"
	"testing"
	"time"
)

// TestConfig_Validate_NewFields tests validation of new Windows-native enhancement fields
func TestConfig_Validate_NewFields(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
	}{
		{
			name: "valid config with all enhancements enabled",
			config: Config{
				TargetPath:          "test.exe",
				Duration:            10 * time.Second,
				MaxMemoryMB:         512,
				MonitorEvery:        time.Second,
				EnableKernelMonitor: true,
				EnableVSS:           true,
				EnableWFP:           true,
				EnableAPITracing:    true,
				EnableTimeManip:     true,
				TimeScaleFactor:     10.0,
				CaptureFullPCAP:     true,
				APITraceCategories:  []string{"Memory", "Process"},
				BehaviorRulesPath:   "rules.json",
			},
			wantErr: false,
		},
		{
			name: "valid config with enhancements disabled",
			config: Config{
				TargetPath:          "test.exe",
				Duration:            10 * time.Second,
				MaxMemoryMB:         512,
				MonitorEvery:        time.Second,
				EnableKernelMonitor: false,
				EnableVSS:           false,
				EnableWFP:           false,
				EnableAPITracing:    false,
				EnableTimeManip:     false,
			},
			wantErr: false,
		},
		{
			name: "valid config with zero time scale factor",
			config: Config{
				TargetPath:      "test.exe",
				Duration:        10 * time.Second,
				MaxMemoryMB:     512,
				MonitorEvery:    time.Second,
				TimeScaleFactor: 0,
			},
			wantErr: false,
		},
		{
			name: "valid config with empty API trace categories",
			config: Config{
				TargetPath:         "test.exe",
				Duration:           10 * time.Second,
				MaxMemoryMB:        512,
				MonitorEvery:       time.Second,
				APITraceCategories: []string{},
			},
			wantErr: false,
		},
		{
			name: "invalid - missing target path",
			config: Config{
				Duration:     10 * time.Second,
				MaxMemoryMB:  512,
				MonitorEvery: time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid - duration too short",
			config: Config{
				TargetPath:   "test.exe",
				Duration:     2 * time.Second,
				MaxMemoryMB:  512,
				MonitorEvery: time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid - max memory too low",
			config: Config{
				TargetPath:   "test.exe",
				Duration:     10 * time.Second,
				MaxMemoryMB:  64,
				MonitorEvery: time.Second,
			},
			wantErr: true,
		},
		{
			name: "invalid - monitor interval too short",
			config: Config{
				TargetPath:   "test.exe",
				Duration:     10 * time.Second,
				MaxMemoryMB:  512,
				MonitorEvery: 100 * time.Millisecond,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestReport_JSONMarshal_NewFields tests JSON marshaling of new Windows-native enhancement fields
func TestReport_JSONMarshal_NewFields(t *testing.T) {
	now := time.Now()
	report := Report{
		SessionID:  "test-session",
		InputType:  "executable",
		StartedAt:  now,
		FinishedAt: now.Add(10 * time.Second),
		DurationMS: 10000,
		KernelEvents: []KernelEvent{
			{
				Timestamp:      now,
				EventType:      EventFileCreate,
				ProcessID:      1234,
				ThreadID:       5678,
				IntegrityLevel: "Medium",
				Path:           "C:\\test\\file.txt",
				Operation:      "IRP_MJ_CREATE",
				Status:         "Success",
				Details:        map[string]string{"access": "read"},
			},
		},
		VSSSnapshots: []Snapshot{
			{
				ID:         "snapshot-1",
				VolumeID:   "volume-c",
				CreatedAt:  now,
				MountPoint: "C:\\",
				Services: []WindowsService{
					{
						Name:        "TestService",
						DisplayName: "Test Service",
						State:       "Running",
						StartType:   "Automatic",
						BinaryPath:  "C:\\service.exe",
					},
				},
				ScheduledTasks: []ScheduledTask{
					{
						Name:    "TestTask",
						Path:    "\\Microsoft\\Windows\\Test",
						State:   "Ready",
						Trigger: "Daily",
						Action:  "Run program",
					},
				},
				RegistryExport: "C:\\registry.reg",
			},
		},
		VSSComparison: &SnapshotDiff{
			FilesAdded: []FileDelta{
				{
					Path:         "C:\\new.txt",
					Size:         1024,
					SHA256:       "abc123",
					ModifiedTime: now,
					Attributes:   0x20,
				},
			},
			RegistryAdded: []RegistryDelta{
				{
					Key:       "HKLM\\Software\\Test",
					ValueName: "TestValue",
					ValueType: "REG_SZ",
					Data:      "test data",
				},
			},
		},
		NetworkCapture: &NetworkCapture{
			PCAPPath: "C:\\capture.pcap",
			Connections: []NetworkConnection{
				{
					Timestamp:     now,
					ProcessID:     1234,
					ProcessName:   "test.exe",
					Protocol:      "TCP",
					LocalAddr:     "192.168.1.100",
					LocalPort:     49152,
					RemoteAddr:    "93.184.216.34",
					RemotePort:    443,
					Direction:     "Outbound",
					BytesSent:     1024,
					BytesReceived: 2048,
					State:         "ESTABLISHED",
				},
			},
			DNSQueries: []DNSQuery{
				{
					Timestamp:    now,
					ProcessID:    1234,
					ProcessName:  "test.exe",
					QueryName:    "example.com",
					QueryType:    "A",
					Response:     []string{"93.184.216.34"},
					ResponseCode: "NOERROR",
				},
			},
			TLSMetadata: []TLSConnection{
				{
					Timestamp:          now,
					ProcessID:          1234,
					RemoteAddr:         "93.184.216.34",
					RemotePort:         443,
					SNI:                "example.com",
					CertificateSubject: "CN=example.com",
					CertificateIssuer:  "CN=DigiCert",
					TLSVersion:         "TLS 1.3",
					CipherSuite:        "TLS_AES_256_GCM_SHA384",
				},
			},
			TotalBytes: 3072,
		},
		APICalls: []APICall{
			{
				Timestamp: now,
				ProcessID: 1234,
				ThreadID:  5678,
				Module:    "kernel32.dll",
				Function:  "VirtualAllocEx",
				Parameters: []APIParameter{
					{Name: "hProcess", Type: "HANDLE", Value: "0x1234"},
					{Name: "lpAddress", Type: "LPVOID", Value: "NULL"},
					{Name: "dwSize", Type: "SIZE_T", Value: "4096"},
				},
				ReturnValue: "0x10000000",
				LastError:   0,
				StackTrace:  []string{"kernel32!VirtualAllocEx", "test.exe!main"},
			},
		},
		TimeManipulation: &TimeManipulationLog{
			Enabled:      true,
			ScaleFactor:  10.0,
			TotalSkipped: 60 * time.Second,
			SkipEvents: []TimeSkipEvent{
				{
					Timestamp:   now,
					Function:    "Sleep",
					RequestedMS: 60000,
					SkippedMS:   60000,
					ProcessID:   1234,
				},
			},
		},
		BehaviorAnalysis: &BehaviorAnalysis{
			RiskScore: 75,
			Techniques: []MITRETechnique{
				{
					ID:          "T1055",
					Name:        "Process Injection",
					Tactic:      "Defense Evasion",
					Description: "Process injection detected",
					Evidence:    []string{"VirtualAllocEx called", "WriteProcessMemory called"},
					Severity:    8,
				},
			},
			Indicators: []BehaviorIndicator{
				{
					Type:        "ProcessInjection",
					Description: "Suspicious memory allocation",
					Severity:    8,
					Timestamp:   now,
					ProcessID:   1234,
					Details:     map[string]interface{}{"target_pid": 5678},
				},
			},
			Classification: "Trojan",
			Confidence:     0.85,
		},
		ProcessGraph: "digraph { A -> B; }",
		Timeline:     "<html><body>Timeline</body></html>",
		AntiSandboxDetected: []AntiSandboxTechnique{
			{
				Type:        "DebuggerCheck",
				Description: "IsDebuggerPresent called",
				Timestamp:   now,
				ProcessID:   1234,
				Details:     map[string]string{"function": "IsDebuggerPresent"},
			},
		},
	}

	// Marshal to JSON
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	// Unmarshal back
	var decoded Report
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}

	// Verify key fields
	if decoded.SessionID != report.SessionID {
		t.Errorf("SessionID = %v, want %v", decoded.SessionID, report.SessionID)
	}

	if len(decoded.KernelEvents) != 1 {
		t.Errorf("len(KernelEvents) = %d, want 1", len(decoded.KernelEvents))
	} else {
		ke := decoded.KernelEvents[0]
		if ke.ProcessID != 1234 {
			t.Errorf("KernelEvent.ProcessID = %d, want 1234", ke.ProcessID)
		}
		if ke.EventType != EventFileCreate {
			t.Errorf("KernelEvent.EventType = %v, want EventFileCreate", ke.EventType)
		}
	}

	if len(decoded.VSSSnapshots) != 1 {
		t.Errorf("len(VSSSnapshots) = %d, want 1", len(decoded.VSSSnapshots))
	} else {
		snap := decoded.VSSSnapshots[0]
		if snap.ID != "snapshot-1" {
			t.Errorf("Snapshot.ID = %v, want snapshot-1", snap.ID)
		}
		if len(snap.Services) != 1 {
			t.Errorf("len(Services) = %d, want 1", len(snap.Services))
		}
	}

	if decoded.VSSComparison == nil {
		t.Error("VSSComparison is nil")
	} else {
		if len(decoded.VSSComparison.FilesAdded) != 1 {
			t.Errorf("len(FilesAdded) = %d, want 1", len(decoded.VSSComparison.FilesAdded))
		}
	}

	if decoded.NetworkCapture == nil {
		t.Error("NetworkCapture is nil")
	} else {
		if len(decoded.NetworkCapture.Connections) != 1 {
			t.Errorf("len(Connections) = %d, want 1", len(decoded.NetworkCapture.Connections))
		}
		if decoded.NetworkCapture.TotalBytes != 3072 {
			t.Errorf("TotalBytes = %d, want 3072", decoded.NetworkCapture.TotalBytes)
		}
	}

	if len(decoded.APICalls) != 1 {
		t.Errorf("len(APICalls) = %d, want 1", len(decoded.APICalls))
	} else {
		api := decoded.APICalls[0]
		if api.Function != "VirtualAllocEx" {
			t.Errorf("APICall.Function = %v, want VirtualAllocEx", api.Function)
		}
		if len(api.Parameters) != 3 {
			t.Errorf("len(Parameters) = %d, want 3", len(api.Parameters))
		}
	}

	if decoded.TimeManipulation == nil {
		t.Error("TimeManipulation is nil")
	} else {
		if decoded.TimeManipulation.ScaleFactor != 10.0 {
			t.Errorf("ScaleFactor = %v, want 10.0", decoded.TimeManipulation.ScaleFactor)
		}
		if len(decoded.TimeManipulation.SkipEvents) != 1 {
			t.Errorf("len(SkipEvents) = %d, want 1", len(decoded.TimeManipulation.SkipEvents))
		}
	}

	if decoded.BehaviorAnalysis == nil {
		t.Error("BehaviorAnalysis is nil")
	} else {
		if decoded.BehaviorAnalysis.RiskScore != 75 {
			t.Errorf("RiskScore = %d, want 75", decoded.BehaviorAnalysis.RiskScore)
		}
		if len(decoded.BehaviorAnalysis.Techniques) != 1 {
			t.Errorf("len(Techniques) = %d, want 1", len(decoded.BehaviorAnalysis.Techniques))
		}
	}

	if decoded.ProcessGraph != "digraph { A -> B; }" {
		t.Errorf("ProcessGraph = %v, want 'digraph { A -> B; }'", decoded.ProcessGraph)
	}

	if len(decoded.AntiSandboxDetected) != 1 {
		t.Errorf("len(AntiSandboxDetected) = %d, want 1", len(decoded.AntiSandboxDetected))
	}
}

// TestReport_JSONMarshal_OmitEmpty tests that omitempty works correctly for new fields
func TestReport_JSONMarshal_OmitEmpty(t *testing.T) {
	report := Report{
		SessionID:  "test-session",
		InputType:  "executable",
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		DurationMS: 1000,
		// All new fields are omitted (nil/empty)
	}

	data, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	jsonStr := string(data)

	// Verify that omitempty fields are not present in JSON
	omitFields := []string{
		"kernel_events",
		"vss_snapshots",
		"vss_comparison",
		"network_capture",
		"api_calls",
		"time_manipulation",
		"behavior_analysis",
		"process_graph",
		"timeline",
		"anti_sandbox_detected",
	}

	for _, field := range omitFields {
		if contains(jsonStr, field) {
			t.Errorf("JSON contains %q but it should be omitted", field)
		}
	}
}

// TestKernelEventType_Values tests that KernelEventType constants are distinct
func TestKernelEventType_Values(t *testing.T) {
	events := []KernelEventType{
		EventFileCreate,
		EventFileWrite,
		EventFileDelete,
		EventFileRename,
		EventRegSetValue,
		EventRegDeleteValue,
		EventRegCreateKey,
		EventRegDeleteKey,
	}

	// Verify all values are distinct
	seen := make(map[KernelEventType]bool)
	for _, e := range events {
		if seen[e] {
			t.Errorf("Duplicate KernelEventType value: %d", e)
		}
		seen[e] = true
	}

	// Verify we have 8 distinct values
	if len(seen) != 8 {
		t.Errorf("Expected 8 distinct KernelEventType values, got %d", len(seen))
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
