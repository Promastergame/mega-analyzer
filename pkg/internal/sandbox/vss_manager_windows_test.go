//go:build windows

package sandbox

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestCompareSnapshots_FileChanges verifies file comparison logic.
// Validates: Requirements 3.3, 3.4
func TestCompareSnapshots_FileChanges(t *testing.T) {
	// Create temporary directories to simulate mount points
	tempDir := t.TempDir()
	baselineMount := tempDir + "\\baseline"
	currentMount := tempDir + "\\current"

	if err := os.Mkdir(baselineMount, 0755); err != nil {
		t.Fatalf("Failed to create baseline mount: %v", err)
	}
	if err := os.Mkdir(currentMount, 0755); err != nil {
		t.Fatalf("Failed to create current mount: %v", err)
	}

	baseline := &Snapshot{
		ID:             "{baseline-id}",
		VolumeID:       "C:",
		CreatedAt:      time.Now(),
		MountPoint:     baselineMount,
		Services:       []WindowsService{},
		ScheduledTasks: []ScheduledTask{},
		RegistryExport: "",
	}

	current := &Snapshot{
		ID:             "{current-id}",
		VolumeID:       "C:",
		CreatedAt:      time.Now(),
		MountPoint:     currentMount,
		Services:       []WindowsService{},
		ScheduledTasks: []ScheduledTask{},
		RegistryExport: "",
	}

	manager := &vssManagerImpl{tempDir: tempDir}

	// Compare empty snapshots - should succeed with no differences
	diff, err := manager.CompareSnapshots(baseline, current)

	if err != nil {
		t.Errorf("CompareSnapshots failed: %v", err)
	}

	if diff == nil {
		t.Fatal("Expected non-nil diff")
	}

	// Verify all diff slices are empty for identical snapshots
	if len(diff.FilesAdded) != 0 {
		t.Errorf("Expected 0 files added, got %d", len(diff.FilesAdded))
	}
	if len(diff.FilesModified) != 0 {
		t.Errorf("Expected 0 files modified, got %d", len(diff.FilesModified))
	}
	if len(diff.FilesDeleted) != 0 {
		t.Errorf("Expected 0 files deleted, got %d", len(diff.FilesDeleted))
	}
}

// TestCompareServices verifies service comparison logic.
// Validates: Requirements 3.3
func TestCompareServices(t *testing.T) {
	baseline := &Snapshot{
		Services: []WindowsService{
			{Name: "service1", DisplayName: "Service 1", State: "RUNNING", StartType: "AUTO"},
			{Name: "service2", DisplayName: "Service 2", State: "STOPPED", StartType: "MANUAL"},
		},
	}

	current := &Snapshot{
		Services: []WindowsService{
			{Name: "service1", DisplayName: "Service 1", State: "STOPPED", StartType: "AUTO"}, // Modified state
			{Name: "service3", DisplayName: "Service 3", State: "RUNNING", StartType: "AUTO"}, // Added
		},
	}

	diff := &SnapshotDiff{
		ServicesAdded:    []WindowsService{},
		ServicesModified: []WindowsService{},
	}

	manager := &vssManagerImpl{}
	manager.compareServices(baseline, current, diff)

	// Verify added services
	if len(diff.ServicesAdded) != 1 {
		t.Errorf("Expected 1 added service, got %d", len(diff.ServicesAdded))
	}
	if len(diff.ServicesAdded) > 0 && diff.ServicesAdded[0].Name != "service3" {
		t.Errorf("Expected service3 to be added, got %s", diff.ServicesAdded[0].Name)
	}

	// Verify modified services
	if len(diff.ServicesModified) != 1 {
		t.Errorf("Expected 1 modified service, got %d", len(diff.ServicesModified))
	}
	if len(diff.ServicesModified) > 0 && diff.ServicesModified[0].Name != "service1" {
		t.Errorf("Expected service1 to be modified, got %s", diff.ServicesModified[0].Name)
	}
}

// TestCompareTasks verifies scheduled task comparison logic.
// Validates: Requirements 3.3
func TestCompareTasks(t *testing.T) {
	baseline := &Snapshot{
		ScheduledTasks: []ScheduledTask{
			{Name: "task1", Path: "\\Microsoft\\Windows\\Task1", State: "Ready"},
			{Name: "task2", Path: "\\Microsoft\\Windows\\Task2", State: "Disabled"},
		},
	}

	current := &Snapshot{
		ScheduledTasks: []ScheduledTask{
			{Name: "task1", Path: "\\Microsoft\\Windows\\Task1", State: "Running"}, // Modified state
			{Name: "task3", Path: "\\Microsoft\\Windows\\Task3", State: "Ready"},   // Added
		},
	}

	diff := &SnapshotDiff{
		TasksAdded:    []ScheduledTask{},
		TasksModified: []ScheduledTask{},
	}

	manager := &vssManagerImpl{}
	manager.compareTasks(baseline, current, diff)

	// Verify added tasks
	if len(diff.TasksAdded) != 1 {
		t.Errorf("Expected 1 added task, got %d", len(diff.TasksAdded))
	}
	if len(diff.TasksAdded) > 0 && diff.TasksAdded[0].Path != "\\Microsoft\\Windows\\Task3" {
		t.Errorf("Expected Task3 to be added, got %s", diff.TasksAdded[0].Path)
	}

	// Verify modified tasks
	if len(diff.TasksModified) != 1 {
		t.Errorf("Expected 1 modified task, got %d", len(diff.TasksModified))
	}
	if len(diff.TasksModified) > 0 && diff.TasksModified[0].Path != "\\Microsoft\\Windows\\Task1" {
		t.Errorf("Expected Task1 to be modified, got %s", diff.TasksModified[0].Path)
	}
}

// TestParseRegistryExport verifies registry export parsing.
// Validates: Requirements 3.3
func TestParseRegistryExport(t *testing.T) {
	registryData := `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\TestKey]
"TestValue"="TestData"
"AnotherValue"="AnotherData"

[HKEY_LOCAL_MACHINE\Software\TestKey2]
"Value1"="Data1"
`

	manager := &vssManagerImpl{}
	regMap := manager.parseRegistryExport(registryData)

	// Verify parsed values
	expectedKeys := []string{
		"HKEY_LOCAL_MACHINE\\Software\\TestKey\\TestValue",
		"HKEY_LOCAL_MACHINE\\Software\\TestKey\\AnotherValue",
		"HKEY_LOCAL_MACHINE\\Software\\TestKey2\\Value1",
	}

	if len(regMap) != len(expectedKeys) {
		t.Errorf("Expected %d registry values, got %d", len(expectedKeys), len(regMap))
	}

	for _, key := range expectedKeys {
		if _, exists := regMap[key]; !exists {
			t.Errorf("Expected registry key %s to be parsed", key)
		}
	}

	// Verify specific value
	testKey := "HKEY_LOCAL_MACHINE\\Software\\TestKey\\TestValue"
	if val, exists := regMap[testKey]; exists {
		if val.Data != "TestData" {
			t.Errorf("Expected TestData, got %s", val.Data)
		}
		if val.ValueName != "TestValue" {
			t.Errorf("Expected TestValue, got %s", val.ValueName)
		}
	}
}

// TestParseScQueryOutput verifies service query output parsing.
// Validates: Requirements 3.2
func TestParseScQueryOutput(t *testing.T) {
	scOutput := `
SERVICE_NAME: wuauserv
DISPLAY_NAME: Windows Update
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 4  RUNNING
        WIN32_EXIT_CODE    : 0  (0x0)

SERVICE_NAME: Spooler
DISPLAY_NAME: Print Spooler
        TYPE               : 110  WIN32_OWN_PROCESS
        STATE              : 1  STOPPED
        WIN32_EXIT_CODE    : 0  (0x0)
`

	manager := &vssManagerImpl{}
	services := manager.parseScQueryOutput(scOutput)

	if len(services) != 2 {
		t.Errorf("Expected 2 services, got %d", len(services))
	}

	// Verify first service
	if len(services) > 0 {
		if services[0].Name != "wuauserv" {
			t.Errorf("Expected wuauserv, got %s", services[0].Name)
		}
		if services[0].DisplayName != "Windows Update" {
			t.Errorf("Expected Windows Update, got %s", services[0].DisplayName)
		}
		if services[0].State != "RUNNING" {
			t.Errorf("Expected RUNNING, got %s", services[0].State)
		}
	}

	// Verify second service
	if len(services) > 1 {
		if services[1].Name != "Spooler" {
			t.Errorf("Expected Spooler, got %s", services[1].Name)
		}
		if services[1].State != "STOPPED" {
			t.Errorf("Expected STOPPED, got %s", services[1].State)
		}
	}
}

// TestParseSchedTasksOutput verifies scheduled task output parsing.
// Validates: Requirements 3.2
func TestParseSchedTasksOutput(t *testing.T) {
	taskOutput := `"TaskName","Next Run Time","Status","Logon Mode"
"Task1","1/1/2024 12:00:00 PM","Ready","Interactive"
"Task2","N/A","Disabled","Background"
"Task3","1/2/2024 1:00:00 PM","Running","Interactive"
`

	manager := &vssManagerImpl{}
	tasks := manager.parseSchedTasksOutput(taskOutput)

	if len(tasks) != 3 {
		t.Errorf("Expected 3 tasks, got %d", len(tasks))
	}

	// Verify first task
	if len(tasks) > 0 {
		if tasks[0].Name != "Task1" {
			t.Errorf("Expected Task1, got %s", tasks[0].Name)
		}
		if tasks[0].State != "Ready" {
			t.Errorf("Expected Ready, got %s", tasks[0].State)
		}
	}

	// Verify second task
	if len(tasks) > 1 {
		if tasks[1].Name != "Task2" {
			t.Errorf("Expected Task2, got %s", tasks[1].Name)
		}
		if tasks[1].State != "Disabled" {
			t.Errorf("Expected Disabled, got %s", tasks[1].State)
		}
	}
}

// TestHashFile verifies SHA256 file hashing.
// Validates: Requirements 3.3
func TestHashFile(t *testing.T) {
	// Create a temporary test file
	tempDir := t.TempDir()
	testFile := tempDir + "\\test.txt"
	testContent := []byte("test content for hashing")

	if err := os.WriteFile(testFile, testContent, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	manager := &vssManagerImpl{}
	hash, err := manager.hashFile(testFile)

	if err != nil {
		t.Errorf("hashFile failed: %v", err)
	}

	// Verify hash is not empty and has correct length (64 hex chars for SHA256)
	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}

	// Hash the same file again and verify consistency
	hash2, err := manager.hashFile(testFile)
	if err != nil {
		t.Errorf("hashFile failed on second call: %v", err)
	}

	if hash != hash2 {
		t.Errorf("Hash inconsistency: %s != %s", hash, hash2)
	}
}

// TestCompareSnapshots_WithFileChanges verifies file comparison detects changes.
// Validates: Requirements 3.3, 3.4
func TestCompareSnapshots_WithFileChanges(t *testing.T) {
	tempDir := t.TempDir()
	baselineMount := tempDir + "\\baseline"
	currentMount := tempDir + "\\current"

	if err := os.Mkdir(baselineMount, 0755); err != nil {
		t.Fatalf("Failed to create baseline mount: %v", err)
	}
	if err := os.Mkdir(currentMount, 0755); err != nil {
		t.Fatalf("Failed to create current mount: %v", err)
	}

	// Create files in baseline
	baselineFile1 := baselineMount + "\\file1.txt"
	baselineFile2 := baselineMount + "\\file2.txt"
	if err := os.WriteFile(baselineFile1, []byte("baseline content 1"), 0644); err != nil {
		t.Fatalf("Failed to create baseline file1: %v", err)
	}
	if err := os.WriteFile(baselineFile2, []byte("baseline content 2"), 0644); err != nil {
		t.Fatalf("Failed to create baseline file2: %v", err)
	}

	// Create files in current (file1 modified, file2 deleted, file3 added)
	currentFile1 := currentMount + "\\file1.txt"
	currentFile3 := currentMount + "\\file3.txt"
	if err := os.WriteFile(currentFile1, []byte("modified content 1"), 0644); err != nil {
		t.Fatalf("Failed to create current file1: %v", err)
	}
	if err := os.WriteFile(currentFile3, []byte("new content 3"), 0644); err != nil {
		t.Fatalf("Failed to create current file3: %v", err)
	}

	baseline := &Snapshot{
		ID:             "{baseline-id}",
		VolumeID:       "C:",
		CreatedAt:      time.Now(),
		MountPoint:     baselineMount,
		Services:       []WindowsService{},
		ScheduledTasks: []ScheduledTask{},
		RegistryExport: "",
	}

	current := &Snapshot{
		ID:             "{current-id}",
		VolumeID:       "C:",
		CreatedAt:      time.Now(),
		MountPoint:     currentMount,
		Services:       []WindowsService{},
		ScheduledTasks: []ScheduledTask{},
		RegistryExport: "",
	}

	manager := &vssManagerImpl{tempDir: tempDir}
	diff, err := manager.CompareSnapshots(baseline, current)

	if err != nil {
		t.Fatalf("CompareSnapshots failed: %v", err)
	}

	// Verify file changes detected
	if len(diff.FilesAdded) != 1 {
		t.Errorf("Expected 1 file added, got %d", len(diff.FilesAdded))
	}
	if len(diff.FilesAdded) > 0 && diff.FilesAdded[0].Path != "file3.txt" {
		t.Errorf("Expected file3.txt to be added, got %s", diff.FilesAdded[0].Path)
	}

	if len(diff.FilesModified) != 1 {
		t.Errorf("Expected 1 file modified, got %d", len(diff.FilesModified))
	}
	if len(diff.FilesModified) > 0 && diff.FilesModified[0].Path != "file1.txt" {
		t.Errorf("Expected file1.txt to be modified, got %s", diff.FilesModified[0].Path)
	}

	if len(diff.FilesDeleted) != 1 {
		t.Errorf("Expected 1 file deleted, got %d", len(diff.FilesDeleted))
	}
	if len(diff.FilesDeleted) > 0 && diff.FilesDeleted[0].Path != "file2.txt" {
		t.Errorf("Expected file2.txt to be deleted, got %s", diff.FilesDeleted[0].Path)
	}
}

// TestCompareRegistry verifies registry comparison logic.
// Validates: Requirements 3.3
func TestCompareRegistry(t *testing.T) {
	tempDir := t.TempDir()

	// Create baseline registry export
	baselineReg := tempDir + "\\baseline.reg"
	baselineContent := `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\TestKey]
"Value1"="Data1"
"Value2"="Data2"
`
	if err := os.WriteFile(baselineReg, []byte(baselineContent), 0644); err != nil {
		t.Fatalf("Failed to create baseline registry: %v", err)
	}

	// Create current registry export (Value2 modified, Value3 added, Value1 deleted)
	currentReg := tempDir + "\\current.reg"
	currentContent := `Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\Software\TestKey]
"Value2"="ModifiedData2"
"Value3"="Data3"
`
	if err := os.WriteFile(currentReg, []byte(currentContent), 0644); err != nil {
		t.Fatalf("Failed to create current registry: %v", err)
	}

	baseline := &Snapshot{
		RegistryExport: baselineReg,
	}

	current := &Snapshot{
		RegistryExport: currentReg,
	}

	diff := &SnapshotDiff{
		RegistryAdded:    []RegistryDelta{},
		RegistryModified: []RegistryDelta{},
		RegistryDeleted:  []RegistryDelta{},
	}

	manager := &vssManagerImpl{}
	err := manager.compareRegistry(baseline, current, diff)

	if err != nil {
		t.Fatalf("compareRegistry failed: %v", err)
	}

	// Verify registry changes detected
	if len(diff.RegistryAdded) != 1 {
		t.Errorf("Expected 1 registry value added, got %d", len(diff.RegistryAdded))
	}

	if len(diff.RegistryModified) != 1 {
		t.Errorf("Expected 1 registry value modified, got %d", len(diff.RegistryModified))
	}

	if len(diff.RegistryDeleted) != 1 {
		t.Errorf("Expected 1 registry value deleted, got %d", len(diff.RegistryDeleted))
	}
}

func TestVSSManager_ErrorHandling(t *testing.T) {
	mgr := newVSSManager()
	ctx := context.Background()

	// 1. CreateSnapshot with invalid volume
	snap, err := mgr.CreateSnapshot(ctx, "Z:\\INVALID_VOLUME_NAME")
	if err == nil {
		t.Error("Expected error for invalid volume, got nil")
	}
	if snap != nil {
		t.Error("Expected nil snapshot for invalid volume")
	}

	// 2. DeleteSnapshot with invalid ID
	err = mgr.DeleteSnapshot("invalid-uuid")
	if err == nil {
		t.Log("DeleteSnapshot returned nil error for invalid ID")
	}
}

func TestVSSManager_Helpers(t *testing.T) {
	mgr, ok := newVSSManager().(*vssManagerImpl)
	if !ok {
		t.Skip("Not vssManagerImpl")
	}

	// createMountPoint
	err := mgr.createMountPoint("dummy-target", os.TempDir())
	if err == nil {
		t.Error("Expected error creating mount point on existing directory")
	}

	// parseVssadminOutput with dummy output
	_, _, err = mgr.parseVssadminOutput("No shadow copies present")
	if err == nil {
		t.Error("Expected error parsing invalid output")
	}

	// exportRegistry
	_, err = mgr.exportRegistry(context.Background(), "invalid-path")
	if err != nil {
		t.Log("exportRegistry error:", err)
	}

	// captureServices
	_, err = mgr.captureServices(context.Background())
	if err != nil {
		t.Log("captureServices error:", err)
	}

	// captureTasks
	_, err = mgr.captureTasks(context.Background())
	if err != nil {
		t.Log("captureTasks error:", err)
	}
}
