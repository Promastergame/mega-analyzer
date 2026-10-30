//go:build windows

package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"mega-analyzer/pkg/internal/platformtext"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	th32csSnapProcess               = 0x00000002
	jobObjectExtendedLimitInfoClass = 9
	jobObjectLimitKillOnJobClose    = 0x00002000
	jobObjectLimitProcessMemory     = 0x00000100
	jobObjectLimitActiveProcess     = 0x00000008
	processSetQuota                 = 0x0100
	processTerminate                = 0x0001
)

var (
	modKernel32                   = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW          = modKernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject   = modKernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObj     = modKernel32.NewProc("AssignProcessToJobObject")
	procQueryInformationJobObject = modKernel32.NewProc("QueryInformationJobObject")
	procCreateToolhelp32Snap      = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW           = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW            = modKernel32.NewProc("Process32NextW")
	procThread32First             = modKernel32.NewProc("Thread32First")
	procThread32Next              = modKernel32.NewProc("Thread32Next")
	procOpenThread                = modKernel32.NewProc("OpenThread")
	procResumeThread              = modKernel32.NewProc("ResumeThread")
	procSetProcessAffinityMask    = modKernel32.NewProc("SetProcessAffinityMask")
)

const (
	createSuspended     = 0x00000004
	createNewConsole    = 0x00000010
	th32csSnapThread    = 0x00000004
	threadSuspendResume = 0x0002
	resumeThreadFailed  = 0xFFFFFFFF
)

type windowsThreadEntry struct {
	size           uint32
	usage          uint32
	threadID       uint32
	ownerProcessID uint32
	basePriority   int32
	deltaPriority  int32
	flags          uint32
}

var registryValueLine = regexp.MustCompile(`^\s+(.+?)\s{2,}(REG_[A-Z0-9_]+)\s{2,}(.*)$`)

type windowsProcessGuard struct {
	job syscall.Handle
}

type windowsNetworkGuard struct {
	exePath string
	rules   []string
}

type windowsProcessEntry struct {
	size              uint32
	usage             uint32
	processID         uint32
	defaultHeapID     uintptr
	moduleID          uint32
	threads           uint32
	parentProcessID   uint32
	priorityClassBase int32
	flags             uint32
	exeFile           [syscall.MAX_PATH]uint16
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

type processEntry struct {
	PID       int
	ParentPID int
	Name      string
}

type win32ProcessInfo struct {
	ProcessID      int    `json:"ProcessId"`
	ExecutablePath string `json:"ExecutablePath"`
	CommandLine    string `json:"CommandLine"`
}

func prepareCommand(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | createSuspended | createNewConsole,
		HideWindow:    false,
	}
}

// applyCPUAffinity restricts a process to the first n logical CPU cores by
// setting its affinity mask. It is best-effort: n <= 0 is a no-op, and any
// failure is returned for the caller to log without aborting the run.
func applyCPUAffinity(pid, cores int) error {
	if cores <= 0 {
		return nil
	}
	const processSetInformation = 0x0200
	handle, err := syscall.OpenProcess(processSetInformation, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("OpenProcess for affinity: %w", err)
	}
	defer syscall.CloseHandle(handle)

	if cores > 64 {
		cores = 64
	}
	var mask uintptr
	for i := 0; i < cores; i++ {
		mask |= 1 << uint(i)
	}
	r1, _, callErr := procSetProcessAffinityMask.Call(uintptr(handle), mask)
	if r1 == 0 {
		return fmt.Errorf("SetProcessAffinityMask: %w", callErr)
	}
	return nil
}

// resumeProcess resumes every thread of a process that was created suspended.
// The sandbox target is started suspended so it can be assigned to the Job
// Object before it executes a single instruction; without this the sample (and
// any children it spawns in the gap) could escape the job's memory/process
// limits.
func resumeProcess(pid int) error {
	r1, _, err := procCreateToolhelp32Snap.Call(th32csSnapThread, 0)
	if r1 == uintptr(syscall.InvalidHandle) {
		return fmt.Errorf("CreateToolhelp32Snapshot(threads): %w", err)
	}
	snapshot := syscall.Handle(r1)
	defer syscall.CloseHandle(snapshot)

	entry := windowsThreadEntry{size: uint32(unsafe.Sizeof(windowsThreadEntry{}))}
	r1, _, err = procThread32First.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return fmt.Errorf("Thread32First: %w", err)
	}

	resumed := false
	for {
		if int(entry.ownerProcessID) == pid {
			if err := resumeThread(entry.threadID); err != nil {
				return err
			}
			resumed = true
		}
		r1, _, _ = procThread32Next.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry)))
		if r1 == 0 {
			break
		}
	}

	if !resumed {
		return fmt.Errorf("no resumable thread found for pid %d", pid)
	}
	return nil
}

func resumeThread(threadID uint32) error {
	r1, _, err := procOpenThread.Call(uintptr(threadSuspendResume), 0, uintptr(threadID))
	if r1 == 0 {
		return fmt.Errorf("OpenThread(%d): %w", threadID, err)
	}
	thread := syscall.Handle(r1)
	defer syscall.CloseHandle(thread)

	r1, _, err = procResumeThread.Call(uintptr(thread))
	if r1 == resumeThreadFailed {
		return fmt.Errorf("ResumeThread(%d): %w", threadID, err)
	}
	return nil
}

func newProcessGuard(maxMemoryMB int) (processGuard, error) {
	job, err := createJobObject(maxMemoryMB)
	if err != nil {
		return nil, err
	}
	return &windowsProcessGuard{job: job}, nil
}

func (g *windowsProcessGuard) Attach(pid int) error {
	if g.job == 0 {
		return fmt.Errorf("job object is not initialized")
	}

	procHandle, err := syscall.OpenProcess(processSetQuota|processTerminate, false, uint32(pid))
	if err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer syscall.CloseHandle(procHandle)

	r1, _, callErr := procAssignProcessToJobObj.Call(uintptr(g.job), uintptr(procHandle))
	if r1 == 0 {
		return fmt.Errorf("assign process to job object: %w", callErr)
	}
	return nil
}

func (g *windowsProcessGuard) Cleanup() error {
	if g.job == 0 {
		return nil
	}
	err := syscall.CloseHandle(g.job)
	g.job = 0
	return err
}

// Query membership from the kernel: ancestry snapshots lose descendants when
// their launcher exits, and remembered PIDs can be reused by unrelated programs.
func (g *windowsProcessGuard) Snapshot() ([]ObservedProcess, []ObservedConnection, error) {
	var members struct {
		Assigned uint32
		Count    uint32
		PIDs     [sandboxProcessLimit]uintptr
	}
	r1, _, err := procQueryInformationJobObject.Call(uintptr(g.job), 3, uintptr(unsafe.Pointer(&members)), unsafe.Sizeof(members), 0)
	if r1 == 0 {
		return nil, nil, fmt.Errorf("QueryInformationJobObject: %w", err)
	}
	entries, err := snapshotProcesses()
	if err != nil {
		return nil, nil, err
	}
	pids := make(map[int]struct{}, members.Count)
	for i := uint32(0); i < members.Count && i < uint32(len(members.PIDs)); i++ {
		pids[int(members.PIDs[i])] = struct{}{}
	}
	var tree []processEntry
	for _, entry := range entries {
		if _, ok := pids[entry.PID]; ok {
			tree = append(tree, entry)
		}
	}
	return snapshotConnections(tree)
}

func createJobObject(maxMemoryMB int) (syscall.Handle, error) {
	r1, _, err := procCreateJobObjectW.Call(0, 0)
	if r1 == 0 {
		return 0, fmt.Errorf("CreateJobObjectW: %w", err)
	}

	job := syscall.Handle(r1)
	info := jobObjectExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags =
		jobObjectLimitKillOnJobClose |
			jobObjectLimitProcessMemory |
			jobObjectLimitActiveProcess
	info.BasicLimitInformation.ActiveProcessLimit = sandboxProcessLimit
	info.ProcessMemoryLimit = uintptr(maxMemoryMB) * 1024 * 1024

	r1, _, err = procSetInformationJobObject.Call(
		uintptr(job),
		uintptr(jobObjectExtendedLimitInfoClass),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
	)
	if r1 == 0 {
		syscall.CloseHandle(job)
		return 0, fmt.Errorf("SetInformationJobObject: %w", err)
	}

	return job, nil
}

func newBlockingNetworkGuard(exePath, sessionID string) (networkGuard, error) {
	baseName := "MegaAnalyzer Sandbox " + sessionID
	return &windowsNetworkGuard{
		exePath: exePath,
		rules: []string{
			baseName + " outbound",
			baseName + " inbound",
		},
	}, nil
}

func (g *windowsNetworkGuard) Apply() error {
	if err := g.addRule(g.rules[0], "out"); err != nil {
		return err
	}
	if err := g.addRule(g.rules[1], "in"); err != nil {
		_ = g.deleteRule(g.rules[0])
		return err
	}
	return nil
}

func (g *windowsNetworkGuard) Cleanup() error {
	var errs []string
	for _, rule := range g.rules {
		if err := g.deleteRule(rule); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

func (g *windowsNetworkGuard) Mode() string {
	return "blocked"
}

func (g *windowsNetworkGuard) addRule(ruleName, direction string) error {
	args := []string{
		"advfirewall", "firewall", "add", "rule",
		"name=" + ruleName,
		"dir=" + direction,
		"action=block",
		"enable=yes",
		"profile=any",
		"program=" + g.exePath,
	}
	if err := runHidden("netsh", args...); err != nil {
		return fmt.Errorf("create firewall rule %q: %w", ruleName, err)
	}
	return nil
}

func (g *windowsNetworkGuard) deleteRule(ruleName string) error {
	args := []string{
		"advfirewall", "firewall", "delete", "rule",
		"name=" + ruleName,
	}
	if err := runHidden("netsh", args...); err != nil {
		return fmt.Errorf("delete firewall rule %q: %w", ruleName, err)
	}
	return nil
}

func runHidden(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(platformtext.DecodeConsoleOutput(output))
		if out == "" {
			return err
		}
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func collectSnapshot(rootPID int) ([]ObservedProcess, []ObservedConnection, error) {
	entries, err := snapshotProcesses()
	if err != nil {
		return nil, nil, err
	}

	tree := buildProcessTree(entries, rootPID)
	return snapshotConnections(tree)
}

func snapshotConnections(tree []processEntry) ([]ObservedProcess, []ObservedConnection, error) {
	pidSet := make(map[int]struct{}, len(tree))
	processes := make([]ObservedProcess, 0, len(tree))
	for _, entry := range tree {
		pidSet[entry.PID] = struct{}{}
		processes = append(processes, ObservedProcess{
			PID:       entry.PID,
			ParentPID: entry.ParentPID,
			Name:      entry.Name,
		})
	}

	if len(tree) == 0 {
		return processes, nil, nil
	}
	cmd := exec.Command("netstat", "-ano")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	netstatOutput, err := cmd.CombinedOutput()
	if err != nil {
		out := strings.TrimSpace(string(netstatOutput))
		if out == "" {
			return processes, nil, err
		}
		return processes, nil, fmt.Errorf("%w: %s", err, out)
	}

	connections := parseNetstatOutput(string(netstatOutput), pidSet)
	return processes, connections, nil
}

func captureAutorunSnapshot() (map[string]RegistryValue, error) {
	snapshot := make(map[string]RegistryValue)
	var errs []string

	for _, key := range monitoredAutorunRegistryKeys {
		cmd := exec.Command("reg", "query", key)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

		output, err := cmd.CombinedOutput()
		if err != nil {
			text := strings.TrimSpace(platformtext.DecodeConsoleOutput(output))
			lower := strings.ToLower(text)
			if strings.Contains(lower, "unable to find") || strings.Contains(lower, "cannot find") ||
				strings.Contains(lower, "не удалось найти") || strings.Contains(lower, "не удается найти") {
				continue
			}
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				// reg query returns exit code 1 when the specified key or value does not exist.
				continue
			}
			if text == "" {
				errs = append(errs, fmt.Sprintf("%s: %v", key, err))
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: %s", key, text))
			continue
		}

		for _, value := range parseRegQueryOutput(key, platformtext.DecodeConsoleOutput(output)) {
			snapshot[registryValueKey(value)] = value
		}
	}

	if len(errs) > 0 {
		return snapshot, fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return snapshot, nil
}

func parseRegQueryOutput(defaultKey, output string) []RegistryValue {
	currentKey := defaultKey
	lines := strings.Split(output, "\n")
	values := make([]RegistryValue, 0, len(lines))

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "HKEY_") {
			currentKey = trimmed
			continue
		}

		match := registryValueLine.FindStringSubmatch(line)
		if len(match) != 4 {
			continue
		}

		values = append(values, RegistryValue{
			Key:  currentKey,
			Name: strings.TrimSpace(match[1]),
			Type: strings.TrimSpace(match[2]),
			Data: strings.TrimSpace(match[3]),
		})
	}

	return values
}

var (
	processCache = make(map[int]win32ProcessInfo)
	cacheMu      sync.RWMutex
)

func enrichObservedProcesses(processes []ObservedProcess) []ObservedProcess {
	if len(processes) == 0 {
		return processes
	}

	enriched := make([]ObservedProcess, len(processes))
	copy(enriched, processes)

	// Identify which PIDs are NOT in our cache
	var missingPIDs []int
	cacheMu.RLock()
	for _, proc := range enriched {
		if proc.PID <= 0 {
			continue
		}
		if cached, ok := processCache[proc.PID]; ok {
			proc.ExecutablePath = cached.ExecutablePath
			proc.CommandLine = cached.CommandLine
		} else {
			missingPIDs = append(missingPIDs, proc.PID)
		}
	}
	cacheMu.RUnlock()

	// If no PIDs are missing, return early! Zero subprocesses spawned!
	if len(missingPIDs) == 0 {
		// Fill in the cached details for the final returned slice
		cacheMu.RLock()
		for i := range enriched {
			if detail, ok := processCache[enriched[i].PID]; ok {
				enriched[i].ExecutablePath = detail.ExecutablePath
				enriched[i].CommandLine = detail.CommandLine
			}
		}
		cacheMu.RUnlock()
		return enriched
	}

	// Build filter strictly for missing PIDs
	filters := make([]string, 0, len(missingPIDs))
	for _, pid := range missingPIDs {
		filters = append(filters, "ProcessId = "+strconv.Itoa(pid))
	}

	script := "$procs = Get-CimInstance Win32_Process -Filter '" + strings.Join(filters, " OR ") + "' | " +
		"Select-Object ProcessId, ExecutablePath, CommandLine; " +
		"if ($null -eq $procs) { '[]' } else { @($procs) | ConvertTo-Json -Compress }"
	cmd := exec.Command(resolveExecutablePath("powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	output, err := cmd.Output()
	if err != nil {
		// Even if error, fill in what we have in cache
		cacheMu.RLock()
		for i := range enriched {
			if detail, ok := processCache[enriched[i].PID]; ok {
				enriched[i].ExecutablePath = detail.ExecutablePath
				enriched[i].CommandLine = detail.CommandLine
			}
		}
		cacheMu.RUnlock()
		return enriched
	}

	var details []win32ProcessInfo
	if err := json.Unmarshal(output, &details); err != nil {
		cacheMu.RLock()
		for i := range enriched {
			if detail, ok := processCache[enriched[i].PID]; ok {
				enriched[i].ExecutablePath = detail.ExecutablePath
				enriched[i].CommandLine = detail.CommandLine
			}
		}
		cacheMu.RUnlock()
		return enriched
	}

	// Update cache with the new details
	cacheMu.Lock()
	for _, detail := range details {
		processCache[detail.ProcessID] = detail
	}
	cacheMu.Unlock()

	// Fill in the details (both newly retrieved and cached)
	cacheMu.RLock()
	for i := range enriched {
		if detail, ok := processCache[enriched[i].PID]; ok {
			enriched[i].ExecutablePath = detail.ExecutablePath
			enriched[i].CommandLine = detail.CommandLine
		}
	}
	cacheMu.RUnlock()

	return enriched
}

func snapshotProcesses() ([]processEntry, error) {
	r1, _, err := procCreateToolhelp32Snap.Call(th32csSnapProcess, 0)
	if r1 == uintptr(syscall.InvalidHandle) {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot: %w", err)
	}
	snapshot := syscall.Handle(r1)
	defer syscall.CloseHandle(snapshot)

	entry := windowsProcessEntry{size: uint32(unsafe.Sizeof(windowsProcessEntry{}))}
	r1, _, err = procProcess32FirstW.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry)))
	if r1 == 0 {
		return nil, fmt.Errorf("Process32FirstW: %w", err)
	}

	var entries []processEntry
	for {
		entries = append(entries, processEntry{
			PID:       int(entry.processID),
			ParentPID: int(entry.parentProcessID),
			Name:      syscall.UTF16ToString(entry.exeFile[:]),
		})

		r1, _, err = procProcess32NextW.Call(uintptr(snapshot), uintptr(unsafe.Pointer(&entry)))
		if r1 == 0 {
			break
		}
	}

	return entries, nil
}

func buildProcessTree(entries []processEntry, rootPID int) []processEntry {
	children := make(map[int][]processEntry)
	rootSeen := false
	var root processEntry

	for _, entry := range entries {
		children[entry.ParentPID] = append(children[entry.ParentPID], entry)
		if entry.PID == rootPID {
			rootSeen = true
			root = entry
		}
	}

	if !rootSeen {
		return nil
	}

	queue := []processEntry{root}
	result := make([]processEntry, 0, 8)
	seen := map[int]struct{}{rootPID: {}}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		result = append(result, current)

		for _, child := range children[current.PID] {
			if _, ok := seen[child.PID]; ok {
				continue
			}
			seen[child.PID] = struct{}{}
			queue = append(queue, child)
		}
	}

	return result
}
