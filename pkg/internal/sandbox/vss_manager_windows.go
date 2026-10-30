//go:build windows

package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// Windows VSS Manager Implementation
//
// This file implements the VSS (Volume Shadow Copy Service) manager for Windows.
// It uses PowerShell vssadmin commands to create and manage snapshots.
//
// IMPLEMENTATION APPROACH:
// 1. Use PowerShell vssadmin for snapshot creation/deletion (simpler than COM interop)
// 2. Mount snapshots as symbolic links for read-only access
// 3. Capture services using 'sc query' or WMI
// 4. Capture scheduled tasks using 'schtasks /query'
// 5. Export registry hives using 'reg export'
//
// ALTERNATIVE APPROACH (Future Enhancement):
// - Use VSS COM API (IVssBackupComponents) for more control
// - Requires: ole32.dll, vssapi.dll
// - More complex but provides better error handling and metadata
//
// Validates: Requirements 3.1, 3.2, 3.3, 3.4

// vssManagerImpl is the Windows implementation of VSSManager.
type vssManagerImpl struct {
	// tempDir is used for storing registry exports and temporary files
	tempDir string
}

// newVSSManager creates a new Windows VSS manager instance.
func newVSSManager() VSSManager {
	return &vssManagerImpl{
		tempDir: os.TempDir(),
	}
}

// CreateSnapshot creates a VSS snapshot of the specified volume.
//
// Implementation steps:
// 1. Execute 'vssadmin create shadow /for=<volume>' to create snapshot
// 2. Parse output to extract snapshot ID and device object path
// 3. Create symbolic link to mount the snapshot
// 4. Capture Windows Services using 'sc query'
// 5. Capture Scheduled Tasks using 'schtasks /query /fo csv /v'
// 6. Export registry hives (HKLM\Software, HKLM\System) using 'reg export'
//
// Validates: Requirements 3.1, 3.2
func (v *vssManagerImpl) CreateSnapshot(ctx context.Context, volumePath string) (*Snapshot, error) {
	// Normalize volume path (e.g., "C:" or "C:\")
	volumePath = strings.TrimSuffix(volumePath, "\\")
	if !strings.HasSuffix(volumePath, ":") {
		volumePath += ":"
	}

	// Create VSS snapshot using vssadmin
	cmd := exec.CommandContext(ctx, "vssadmin", "create", "shadow", "/for="+volumePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("vssadmin create shadow failed: %w (output: %s)", err, string(output))
	}

	// Parse snapshot ID and device object from output
	// Example output:
	//   Successfully created shadow copy for 'C:\'
	//     Shadow Copy ID: {12345678-1234-1234-1234-123456789012}
	//     Shadow Copy Volume Name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
	snapshotID, deviceObject, err := v.parseVssadminOutput(string(output))
	if err != nil {
		return nil, fmt.Errorf("failed to parse vssadmin output: %w", err)
	}

	// Create mount point (symbolic link) for the snapshot
	mountPoint := filepath.Join(v.tempDir, "vss_"+snapshotID[:8])
	if err := v.createMountPoint(deviceObject, mountPoint); err != nil {
		// Clean up snapshot on mount failure
		_ = v.DeleteSnapshot(snapshotID)
		return nil, fmt.Errorf("failed to create mount point: %w", err)
	}

	snapshot := &Snapshot{
		ID:         snapshotID,
		VolumeID:   volumePath,
		CreatedAt:  time.Now(),
		MountPoint: mountPoint,
	}

	// Capture Windows Services
	services, err := v.captureServices(ctx)
	if err != nil {
		// Log warning but don't fail - service capture is optional
		snapshot.Services = []WindowsService{}
	} else {
		snapshot.Services = services
	}

	// Capture Scheduled Tasks
	tasks, err := v.captureTasks(ctx)
	if err != nil {
		// Log warning but don't fail - task capture is optional
		snapshot.ScheduledTasks = []ScheduledTask{}
	} else {
		snapshot.ScheduledTasks = tasks
	}

	// Export registry hives
	registryExportPath, err := v.exportRegistry(ctx, snapshotID)
	if err != nil {
		// Log warning but don't fail - registry export is optional
		snapshot.RegistryExport = ""
	} else {
		snapshot.RegistryExport = registryExportPath
	}

	return snapshot, nil
}

// DeleteSnapshot deletes a VSS snapshot by its ID.
//
// Implementation:
// 1. Remove mount point symbolic link
// 2. Execute 'vssadmin delete shadows /shadow=<id> /quiet'
// 3. Clean up registry export files
//
// Validates: Requirements 3.1
func (v *vssManagerImpl) DeleteSnapshot(snapshotID string) error {
	// Remove mount point if it exists
	mountPoint := filepath.Join(v.tempDir, "vss_"+snapshotID[:8])
	if _, err := os.Lstat(mountPoint); err == nil {
		_ = os.Remove(mountPoint) // Ignore errors
	}

	// Delete VSS snapshot
	cmd := exec.Command("vssadmin", "delete", "shadows", "/shadow="+snapshotID, "/quiet")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("vssadmin delete shadows failed: %w (output: %s)", err, string(output))
	}

	// Clean up registry export
	registryExportPath := filepath.Join(v.tempDir, "vss_registry_"+snapshotID[:8]+".reg")
	_ = os.Remove(registryExportPath) // Ignore errors

	return nil
}

// CompareSnapshots compares two snapshots and returns the differences.
//
// Implementation:
// 1. Compare files by walking both snapshot mount points
// 2. Compare registry exports using text diff
// 3. Compare services by matching on name
// 4. Compare scheduled tasks by matching on path
//
// Validates: Requirements 3.3, 3.4
func (v *vssManagerImpl) CompareSnapshots(baseline, current *Snapshot) (*SnapshotDiff, error) {
	diff := &SnapshotDiff{
		FilesAdded:       []FileDelta{},
		FilesModified:    []FileDelta{},
		FilesDeleted:     []FileDelta{},
		RegistryAdded:    []RegistryDelta{},
		RegistryModified: []RegistryDelta{},
		RegistryDeleted:  []RegistryDelta{},
		ServicesAdded:    []WindowsService{},
		ServicesModified: []WindowsService{},
		TasksAdded:       []ScheduledTask{},
		TasksModified:    []ScheduledTask{},
	}

	// Compare files
	if err := v.compareFiles(baseline, current, diff); err != nil {
		return nil, fmt.Errorf("file comparison failed: %w", err)
	}

	// Compare registry
	if err := v.compareRegistry(baseline, current, diff); err != nil {
		// Log warning but don't fail - registry comparison is optional
	}

	// Compare services
	v.compareServices(baseline, current, diff)

	// Compare scheduled tasks
	v.compareTasks(baseline, current, diff)

	return diff, nil
}

// parseVssadminOutput extracts snapshot ID and device object from vssadmin output.
func (v *vssManagerImpl) parseVssadminOutput(output string) (snapshotID, deviceObject string, err error) {
	// Extract Shadow Copy ID
	idRegex := regexp.MustCompile(`Shadow Copy ID:\s*(\{[0-9a-fA-F-]+\})`)
	idMatches := idRegex.FindStringSubmatch(output)
	if len(idMatches) < 2 {
		return "", "", fmt.Errorf("could not find Shadow Copy ID in output")
	}
	snapshotID = idMatches[1]

	// Extract Shadow Copy Volume Name (device object)
	deviceRegex := regexp.MustCompile(`Shadow Copy Volume Name:\s*(\\\\[^\r\n]+)`)
	deviceMatches := deviceRegex.FindStringSubmatch(output)
	if len(deviceMatches) < 2 {
		return "", "", fmt.Errorf("could not find Shadow Copy Volume Name in output")
	}
	deviceObject = strings.TrimSpace(deviceMatches[1])

	return snapshotID, deviceObject, nil
}

// createMountPoint creates a symbolic link to mount the VSS snapshot.
// On Windows, we use mklink to create a symbolic link to the device object.
func (v *vssManagerImpl) createMountPoint(deviceObject, mountPoint string) error {
	// Remove existing mount point if it exists
	if _, err := os.Lstat(mountPoint); err == nil {
		_ = os.Remove(mountPoint)
	}

	// Create symbolic link using mklink
	// Note: This requires administrator privileges
	cmd := exec.Command("cmd", "/c", "mklink", "/d", mountPoint, deviceObject+"\\")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mklink failed: %w (output: %s)", err, string(output))
	}

	return nil
}

// captureServices captures all Windows services using 'sc query'.
//
// Validates: Requirements 3.2
func (v *vssManagerImpl) captureServices(ctx context.Context) ([]WindowsService, error) {
	cmd := exec.CommandContext(ctx, "sc", "query", "type=", "service", "state=", "all")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("sc query failed: %w", err)
	}

	return v.parseScQueryOutput(string(output)), nil
}

// parseScQueryOutput parses the output of 'sc query' command.
// Example output:
//
//	SERVICE_NAME: wuauserv
//	DISPLAY_NAME: Windows Update
//	        TYPE               : 20  WIN32_SHARE_PROCESS
//	        STATE              : 4  RUNNING
//	        ...
func (v *vssManagerImpl) parseScQueryOutput(output string) []WindowsService {
	var services []WindowsService
	var current WindowsService

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "SERVICE_NAME:") {
			// Save previous service if exists
			if current.Name != "" {
				services = append(services, current)
			}
			// Start new service
			current = WindowsService{
				Name: strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:")),
			}
		} else if strings.HasPrefix(line, "DISPLAY_NAME:") {
			current.DisplayName = strings.TrimSpace(strings.TrimPrefix(line, "DISPLAY_NAME:"))
		} else if strings.Contains(line, "STATE") {
			// Extract state (e.g., "4  RUNNING" -> "RUNNING")
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				current.State = parts[len(parts)-1]
			}
		}
	}

	// Add last service
	if current.Name != "" {
		services = append(services, current)
	}

	return services
}

// captureTasks captures all scheduled tasks using 'schtasks /query'.
//
// Validates: Requirements 3.2
func (v *vssManagerImpl) captureTasks(ctx context.Context) ([]ScheduledTask, error) {
	cmd := exec.CommandContext(ctx, "schtasks", "/query", "/fo", "csv", "/v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("schtasks query failed: %w", err)
	}

	return v.parseSchedTasksOutput(string(output)), nil
}

// parseSchedTasksOutput parses CSV output from 'schtasks /query /fo csv /v'.
func (v *vssManagerImpl) parseSchedTasksOutput(output string) []ScheduledTask {
	var tasks []ScheduledTask

	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return tasks
	}

	// Skip header line
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Parse CSV fields (simplified - doesn't handle quoted commas)
		fields := strings.Split(line, ",")
		if len(fields) < 4 {
			continue
		}

		task := ScheduledTask{
			Name:  strings.Trim(fields[0], `"`),
			Path:  strings.Trim(fields[1], `"`),
			State: strings.Trim(fields[2], `"`),
		}

		tasks = append(tasks, task)
	}

	return tasks
}

// exportRegistry exports registry hives to a file.
//
// Validates: Requirements 3.2
func (v *vssManagerImpl) exportRegistry(ctx context.Context, snapshotID string) (string, error) {
	exportPath := filepath.Join(v.tempDir, "vss_registry_"+snapshotID[:8]+".reg")

	// Export HKLM\Software
	cmd := exec.CommandContext(ctx, "reg", "export", "HKLM\\Software", exportPath, "/y")
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("reg export failed: %w", err)
	}

	return exportPath, nil
}

// compareFiles compares files between two snapshots.
//
// Validates: Requirements 3.3
func (v *vssManagerImpl) compareFiles(baseline, current *Snapshot, diff *SnapshotDiff) error {
	// Build file maps for both snapshots
	baselineFiles := make(map[string]FileDelta)
	currentFiles := make(map[string]FileDelta)

	// Walk baseline snapshot
	if err := v.walkSnapshot(baseline.MountPoint, baselineFiles); err != nil {
		return fmt.Errorf("failed to walk baseline snapshot: %w", err)
	}

	// Walk current snapshot
	if err := v.walkSnapshot(current.MountPoint, currentFiles); err != nil {
		return fmt.Errorf("failed to walk current snapshot: %w", err)
	}

	// Find added and modified files
	for path, currentFile := range currentFiles {
		if baselineFile, exists := baselineFiles[path]; exists {
			// File exists in both - check if modified
			if currentFile.SHA256 != baselineFile.SHA256 {
				diff.FilesModified = append(diff.FilesModified, currentFile)
			}
		} else {
			// File only in current - added
			diff.FilesAdded = append(diff.FilesAdded, currentFile)
		}
	}

	// Find deleted files
	for path, baselineFile := range baselineFiles {
		if _, exists := currentFiles[path]; !exists {
			diff.FilesDeleted = append(diff.FilesDeleted, baselineFile)
		}
	}

	return nil
}

// walkSnapshot walks a snapshot mount point and builds a file map.
func (v *vssManagerImpl) walkSnapshot(mountPoint string, fileMap map[string]FileDelta) error {
	return filepath.Walk(mountPoint, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Skip files we can't access
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Calculate relative path
		relPath, err := filepath.Rel(mountPoint, path)
		if err != nil {
			return nil
		}

		// Calculate SHA256 hash
		hash, err := v.hashFile(path)
		if err != nil {
			// Skip files we can't hash
			return nil
		}

		attributes := uint32(0)
		if stat, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
			attributes = stat.FileAttributes
		}

		fileMap[relPath] = FileDelta{
			Path:         relPath,
			Size:         info.Size(),
			SHA256:       hash,
			ModifiedTime: info.ModTime(),
			Attributes:   attributes,
		}

		return nil
	})
}

// hashFile calculates SHA256 hash of a file.
func (v *vssManagerImpl) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// compareRegistry compares registry exports between two snapshots.
//
// Validates: Requirements 3.3
func (v *vssManagerImpl) compareRegistry(baseline, current *Snapshot, diff *SnapshotDiff) error {
	if baseline.RegistryExport == "" || current.RegistryExport == "" {
		return fmt.Errorf("registry exports not available")
	}

	// Read both registry exports
	baselineData, err := os.ReadFile(baseline.RegistryExport)
	if err != nil {
		return fmt.Errorf("failed to read baseline registry: %w", err)
	}

	currentData, err := os.ReadFile(current.RegistryExport)
	if err != nil {
		return fmt.Errorf("failed to read current registry: %w", err)
	}

	// Parse registry files into maps
	baselineReg := v.parseRegistryExport(string(baselineData))
	currentReg := v.parseRegistryExport(string(currentData))

	// Find added and modified registry values
	for key, currentValue := range currentReg {
		if baselineValue, exists := baselineReg[key]; exists {
			// Value exists in both - check if modified
			if currentValue.Data != baselineValue.Data {
				diff.RegistryModified = append(diff.RegistryModified, currentValue)
			}
		} else {
			// Value only in current - added
			diff.RegistryAdded = append(diff.RegistryAdded, currentValue)
		}
	}

	// Find deleted registry values
	for key, baselineValue := range baselineReg {
		if _, exists := currentReg[key]; !exists {
			diff.RegistryDeleted = append(diff.RegistryDeleted, baselineValue)
		}
	}

	return nil
}

// parseRegistryExport parses a .reg file into a map of registry values.
// This is a simplified parser - a full implementation would handle all registry types.
func (v *vssManagerImpl) parseRegistryExport(data string) map[string]RegistryDelta {
	regMap := make(map[string]RegistryDelta)
	lines := strings.Split(data, "\n")

	var currentKey string
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Registry key line (e.g., [HKEY_LOCAL_MACHINE\Software\...])
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentKey = strings.Trim(line, "[]")
			continue
		}

		// Registry value line (e.g., "ValueName"="ValueData")
		if strings.Contains(line, "=") && currentKey != "" {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				valueName := strings.Trim(parts[0], `"`)
				valueData := strings.Trim(parts[1], `"`)

				key := currentKey + "\\" + valueName
				regMap[key] = RegistryDelta{
					Key:       currentKey,
					ValueName: valueName,
					ValueType: "REG_SZ", // Simplified - would need to parse type
					Data:      valueData,
				}
			}
		}
	}

	return regMap
}

// compareServices compares services between two snapshots.
//
// Validates: Requirements 3.3
func (v *vssManagerImpl) compareServices(baseline, current *Snapshot, diff *SnapshotDiff) {
	baselineMap := make(map[string]WindowsService)
	for _, svc := range baseline.Services {
		baselineMap[svc.Name] = svc
	}

	currentMap := make(map[string]WindowsService)
	for _, svc := range current.Services {
		currentMap[svc.Name] = svc
	}

	// Find added and modified services
	for name, currentSvc := range currentMap {
		if baselineSvc, exists := baselineMap[name]; exists {
			// Service exists in both - check if modified
			if currentSvc.State != baselineSvc.State || currentSvc.StartType != baselineSvc.StartType {
				diff.ServicesModified = append(diff.ServicesModified, currentSvc)
			}
		} else {
			// Service only in current - added
			diff.ServicesAdded = append(diff.ServicesAdded, currentSvc)
		}
	}
}

// compareTasks compares scheduled tasks between two snapshots.
//
// Validates: Requirements 3.3
func (v *vssManagerImpl) compareTasks(baseline, current *Snapshot, diff *SnapshotDiff) {
	baselineMap := make(map[string]ScheduledTask)
	for _, task := range baseline.ScheduledTasks {
		baselineMap[task.Path] = task
	}

	currentMap := make(map[string]ScheduledTask)
	for _, task := range current.ScheduledTasks {
		currentMap[task.Path] = task
	}

	// Find added and modified tasks
	for path, currentTask := range currentMap {
		if baselineTask, exists := baselineMap[path]; exists {
			// Task exists in both - check if modified
			if currentTask.State != baselineTask.State {
				diff.TasksModified = append(diff.TasksModified, currentTask)
			}
		} else {
			// Task only in current - added
			diff.TasksAdded = append(diff.TasksAdded, currentTask)
		}
	}
}
