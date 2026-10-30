package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"mega-analyzer/pkg/internal/androidsdk"
	"mega-analyzer/pkg/internal/apkloader"
)

type processGuard interface {
	Attach(pid int) error
	Snapshot() ([]ObservedProcess, []ObservedConnection, error)
	Cleanup() error
}

type networkGuard interface {
	Apply() error
	Cleanup() error
	Mode() string
}

type noopNetworkGuard struct{}

func (noopNetworkGuard) Apply() error   { return nil }
func (noopNetworkGuard) Cleanup() error { return nil }
func (noopNetworkGuard) Mode() string   { return "live" }

type externalNetworkGuard struct{ noopNetworkGuard }

func (externalNetworkGuard) Mode() string { return "vmware_disconnected" }

const sandboxProcessLimit = 64

var monitoredAutorunRegistryKeys = []string{
	`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
	`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
	`HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`,
	`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`,
	`HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`,
}

type sessionLayout struct {
	outputRoot   string
	sessionDir   string
	workspaceDir string
	profileDir   string
	tempDir      string
	homeDir      string
	appDataDir   string
	localAppData string
	programData  string
	publicDir    string
	stdoutPath   string
	stderrPath   string
	jsonPath     string
	markdownPath string
}

type launchSpec struct {
	executable string
	args       []string
	copiedPath string
	runnable   bool
	reason     string
}

type fileFingerprint struct {
	Path   string
	Size   int64
	SHA256 string
}

type observationCollector struct {
	mu           sync.Mutex
	processes    map[int]ObservedProcess
	connections  map[string]ObservedConnection
	warnings     map[string]struct{}
	onProcess    func(ObservedProcess)
	onConnection func(ObservedConnection)
}

func newObservationCollector() *observationCollector {
	return &observationCollector{
		processes:   make(map[int]ObservedProcess),
		connections: make(map[string]ObservedConnection),
		warnings:    make(map[string]struct{}),
	}
}

func (c *observationCollector) Merge(processes []ObservedProcess, connections []ObservedConnection, now time.Time) {
	var addedProcesses []ObservedProcess
	var addedConnections []ObservedConnection
	c.mu.Lock()
	for _, proc := range processes {
		if proc.PID <= 0 {
			continue
		}
		if _, ok := c.processes[proc.PID]; ok {
			continue
		}
		proc.FirstSeen = now
		c.processes[proc.PID] = proc
		addedProcesses = append(addedProcesses, proc)
	}
	for _, conn := range connections {
		key := connectionKey(conn)
		if _, ok := c.connections[key]; ok {
			continue
		}
		conn.FirstSeen = now
		c.connections[key] = conn
		addedConnections = append(addedConnections, conn)
	}
	c.mu.Unlock()
	// Emission must not hold the snapshot lock or block an Export callback.
	if c.onProcess != nil {
		for _, proc := range addedProcesses {
			c.onProcess(proc)
		}
	}
	if c.onConnection != nil {
		for _, conn := range addedConnections {
			c.onConnection(conn)
		}
	}
}

func (c *observationCollector) AddWarning(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.warnings[msg] = struct{}{}
}

func (c *observationCollector) Export() ([]ObservedProcess, []ObservedConnection, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	processes := make([]ObservedProcess, 0, len(c.processes))
	for _, proc := range c.processes {
		processes = append(processes, proc)
	}

	connections := make([]ObservedConnection, 0, len(c.connections))
	for _, conn := range c.connections {
		connections = append(connections, conn)
	}

	warnings := make([]string, 0, len(c.warnings))
	for warning := range c.warnings {
		warnings = append(warnings, warning)
	}

	sort.Slice(processes, func(i, j int) bool {
		if processes[i].FirstSeen.Equal(processes[j].FirstSeen) {
			return processes[i].PID < processes[j].PID
		}
		return processes[i].FirstSeen.Before(processes[j].FirstSeen)
	})

	sort.Slice(connections, func(i, j int) bool {
		if connections[i].FirstSeen.Equal(connections[j].FirstSeen) {
			if connections[i].PID == connections[j].PID {
				return connectionKey(connections[i]) < connectionKey(connections[j])
			}
			return connections[i].PID < connections[j].PID
		}
		return connections[i].FirstSeen.Before(connections[j].FirstSeen)
	})

	sort.Strings(warnings)
	return processes, connections, warnings
}

func connectionKey(conn ObservedConnection) string {
	return strings.Join([]string{
		conn.Protocol,
		conn.LocalAddr,
		conn.RemoteAddr,
		conn.State,
		fmt.Sprintf("%d", conn.PID),
	}, "|")
}

func errConfig(msg string) error {
	return fmt.Errorf("sandbox config error: %s", msg)
}

// Run starts a best-effort built-in sandbox session.
//
// Important: this is not a hypervisor boundary. It is an OS-level execution
// cage intended to reduce risk and capture behavior, not guarantee immunity.
func Run(parent context.Context, cfg Config) (outReport *Report, runErr error) {
	cfg = cfg.normalized()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// The platform gate lives further down, immediately before the
	// Windows-native execution path. Android detonation drives an external
	// device or emulator over adb, which works on Linux and macOS as well, so
	// gating the whole function on GOOS made that entire code path
	// unreachable off Windows.

	absTarget, err := filepath.Abs(cfg.TargetPath)
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox target: %w", err)
	}

	info, err := os.Stat(absTarget)
	if err != nil {
		return nil, fmt.Errorf("stat sandbox target: %w", err)
	}

	layout, err := prepareSessionLayout(cfg.OutputDir)
	if err != nil {
		return nil, err
	}

	report := &Report{
		SessionID:      filepath.Base(layout.sessionDir),
		InputType:      detectSandboxInputType(absTarget, info.IsDir()),
		TargetOriginal: absTarget,
		OutputRoot:     layout.outputRoot,
		SessionDir:     layout.sessionDir,
		WorkspaceDir:   layout.workspaceDir,
		RedirectedEnv: RedirectedEnv{
			UserProfile:  layout.homeDir,
			AppData:      layout.appDataDir,
			LocalAppData: layout.localAppData,
			ProgramData:  layout.programData,
			PublicDir:    layout.publicDir,
			TempDir:      layout.tempDir,
		},
		StdoutPath:          layout.stdoutPath,
		StderrPath:          layout.stderrPath,
		JSONPath:            layout.jsonPath,
		MarkdownPath:        layout.markdownPath,
		StartedAt:           time.Now().UTC(),
		SandboxPermissions:  buildSandboxPermissions(cfg, layout),
		RequestedComponents: requestedComponents(cfg),
		EffectiveConfig:     buildEffectiveConfig(cfg, layout.outputRoot),
	}
	journal, journalErr := newActivityJournal(filepath.Join(layout.sessionDir, "activity.jsonl"), cfg.OnActivity)
	if journalErr != nil {
		report.Warnings = append(report.Warnings, "activity journal unavailable: "+journalErr.Error())
	} else {
		report.ActivityPath = filepath.Join(layout.sessionDir, "activity.jsonl")
		originalProcess, originalConnection := cfg.OnProcess, cfg.OnConnection
		cfg.OnProcess = func(p ObservedProcess) {
			journal.record(ActivityEvent{ObservedAt: p.FirstSeen, Category: "process", Action: "observed", PID: p.PID, Process: p.Name, Object: p.ExecutablePath, Details: p.CommandLine, Source: "process_observer", Attribution: "observed_process"})
			if originalProcess != nil {
				originalProcess(p)
			}
		}
		cfg.OnConnection = func(c ObservedConnection) {
			journal.record(ActivityEvent{ObservedAt: c.FirstSeen, Category: "network", Action: "observed", PID: c.PID, Object: c.RemoteAddr, Details: c.Protocol + " " + c.State, Source: "connection_observer", Attribution: "reported_pid"})
			if originalConnection != nil {
				originalConnection(c)
			}
		}
		// This runs before the failed-session report defer below. Persist the
		// counters explicitly at close as well; the journal is useful on its own.
		defer func() {
			journal.record(ActivityEvent{Category: "session", Action: "ended", Source: "analyzer", Attribution: "not_applicable"})
			count, truncated, err := journal.close()
			report.ActivityCount, report.ActivityTruncated = count, truncated
			if err != nil {
				report.Warnings = append(report.Warnings, "activity journal: "+err.Error())
			}
			if err := writeReports(report); err != nil {
				runErr = errors.Join(runErr, fmt.Errorf("save activity status: %w", err))
			}
		}()
		journal.record(ActivityEvent{Category: "session", Action: "prepared", Source: "analyzer", Attribution: "not_applicable"})
	}
	// Keep failed sessions inspectable without inventing a successful verdict.
	defer func() {
		if runErr == nil {
			return
		}
		report.ExecutionError = DescribeFailure(runErr)
		report.FinishedAt = time.Now().UTC()
		report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
		if !report.Executed && report.ExecutionSkipReason == "" {
			report.ExecutionSkipReason = report.ExecutionError.Message
		}
		if cfg.BlockNetwork && !report.NetworkGuardApplied {
			report.NetworkMode = "not_applied"
		}
		sortReport(report)
		if err := writeReports(report); err != nil {
			runErr = errors.Join(runErr, fmt.Errorf("save failed session: %w", err))
		}
		outReport = report
	}()
	report.NetworkMode = report.SandboxPermissions.NetworkAccess
	if isAndroidSandboxInputType(report.InputType) {
		report.AndroidSDK = detectAndroidSDKStatus()
	}

	androidProfile, androidWarnings, err := collectAndroidProfile(parent, absTarget, layout.profileDir)
	if err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("android profile failed: %v", err))
	}
	report.AndroidProfile = androidProfile
	report.Warnings = append(report.Warnings, androidWarnings...)

	if cfg.AndroidSandbox || isAndroidSandboxInputType(report.InputType) {
		err := runAndroidSandbox(parent, cfg, layout, report)
		if err != nil {
			return report, err
		}
		return report, nil
	}

	// Everything below executes the sample on THIS host using Windows job
	// objects, registry snapshots and native monitoring, so it genuinely
	// requires Windows.
	if runtime.GOOS != "windows" {
		report.Executed = false
		report.ExecutionSkipReason = "native sample execution requires Windows; " +
			"use an Android target (-android-sandbox) to detonate on this host"
		report.FinishedAt = time.Now().UTC()
		report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
		report.Behavior = buildBehaviorSummary(report)
		sortReport(report)
		if werr := writeReports(report); werr != nil {
			return report, werr
		}
		return report, nil
	}

	spec, err := prepareLaunchSpec(absTarget, info, layout, cfg.RawArgs)
	if err != nil {
		return nil, err
	}
	report.TargetCopied = spec.copiedPath
	report.Executed = false
	report.ExecutionSkipReason = spec.reason

	beforeSnapshot, err := captureFileSnapshot(layout.workspaceDir)
	if err != nil {
		return nil, fmt.Errorf("capture baseline workspace snapshot: %w", err)
	}

	stdoutFile, err := os.Create(layout.stdoutPath)
	if err != nil {
		return nil, fmt.Errorf("create sandbox stdout log: %w", err)
	}
	defer stdoutFile.Close()

	stderrFile, err := os.Create(layout.stderrPath)
	if err != nil {
		return nil, fmt.Errorf("create sandbox stderr log: %w", err)
	}
	defer stderrFile.Close()

	if spec.runnable && !cfg.AllowHostExecution {
		return report, executionError("local_execution_blocked", "preflight", fmt.Errorf("native execution on the analyzer host is blocked; use -sandbox-remote-config for a disposable Windows VM. -sandbox-allow-host-execution is only for explicitly trusted local fixtures"))
	}
	if spec.runnable {
		if err := checkNetworkIsolationPrivilege(cfg.BlockNetwork && cfg.externalNetworkIsolation == "", isAdmin()); err != nil {
			return report, err
		}
	}
	var registryBefore map[string]RegistryValue
	if spec.runnable {
		registryBefore, err = captureAutorunSnapshot()
		if err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("registry baseline snapshot failed: %v", err))
		}
	}

	if !spec.runnable {
		report.FinishedAt = time.Now().UTC()
		report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()
		report.FileChanges = diffSnapshots(beforeSnapshot, beforeSnapshot)
		report.Behavior = buildBehaviorSummary(report)
		report.ExploitAnalysis = analyzeExploitability(report)
		report.MemoryAnalysis = analyzeMemory(report)
		report.CacheAnalysis = analyzeCacheArtifacts(report)
		sortReport(report)
		if err := writeReports(report); err != nil {
			return report, err
		}
		return report, nil
	}

	var netGuard networkGuard = noopNetworkGuard{}
	if cfg.externalNetworkIsolation == "vmware_disconnected" {
		netGuard = externalNetworkGuard{}
	} else if cfg.BlockNetwork {
		netGuard, err = newBlockingNetworkGuard(spec.executable, report.SessionID)
		if err != nil {
			return nil, executionError("network_guard_failed", "preparation", fmt.Errorf("create network guard: %w", err))
		}
	}
	report.NetworkMode = netGuard.Mode()

	if err := netGuard.Apply(); err != nil {
		return nil, executionError("network_guard_failed", "preparation", fmt.Errorf("apply network guard: %w", err))
	}
	report.NetworkGuardApplied = cfg.BlockNetwork
	defer func() {
		if cleanupErr := netGuard.Cleanup(); cleanupErr != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("network cleanup failed: %v", cleanupErr))
		}
	}()

	procGuard, err := newProcessGuard(cfg.MaxMemoryMB)
	if err != nil {
		return nil, fmt.Errorf("create process guard: %w", err)
	}
	defer func() {
		if cleanupErr := procGuard.Cleanup(); cleanupErr != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("job object cleanup failed: %v", cleanupErr))
		}
	}()

	runCtx, cancel := observationContext(parent, cfg.Duration)
	defer cancel()

	cmd := exec.CommandContext(runCtx, spec.executable, spec.args...)
	cmd.Dir = layout.workspaceDir
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile
	cmd.Env = minimalEnvironment(layout)
	prepareCommand(cmd)

	if err := cmd.Start(); err != nil {
		return nil, executionError("launch_failed", "launch", fmt.Errorf("start sandbox target: %w", err))
	}
	report.RootPID = cmd.Process.Pid

	if err := procGuard.Attach(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("attach sandbox target to job object: %w", err)
	}

	// Best-effort: cap the target to the requested number of logical CPU cores
	// before it starts executing. Failures are non-fatal.
	if cfg.MaxCPUCores > 0 {
		if err := applyCPUAffinity(cmd.Process.Pid, cfg.MaxCPUCores); err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("cpu affinity cap failed: %v", err))
		}
	}

	// Initialize and attach Windows-native enhancement components (including
	// the Frida WinAPI tracer) BEFORE resuming the suspended target process so
	// user-mode hooks are installed prior to entry-point execution.
	enhancedComponents, err := initializeEnhancedComponents(cfg)
	if err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("enhanced components init failed: %v", err))
	}

	if enhancedComponents != nil {
		if err := enhancedComponents.startComponents(runCtx, cfg, cmd.Process.Pid); err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("enhanced components start failed: %v", err))
		}

		// Ensure cleanup happens even if resumeProcess fails.
		defer func() {
			stopErrors := enhancedComponents.stopComponents(context.Background())
			for _, stopErr := range stopErrors {
				report.Warnings = append(report.Warnings, stopErr.Error())
			}

			cleanupErrors := enhancedComponents.cleanup()
			for _, cleanupErr := range cleanupErrors {
				report.Warnings = append(report.Warnings, cleanupErr.Error())
			}
		}()
	}

	var workspaceDone <-chan struct{}
	workspaceCtx, stopWorkspace := context.WithCancel(runCtx)
	if journal != nil {
		report.Warnings = append(report.Warnings, "Workspace activity uses periodic metadata snapshots: process attribution and exact action times are unknown; short-lived changes may be missed. Coverage excludes other folders.")
		workspaceDone = watchWorkspace(workspaceCtx, layout.workspaceDir, cfg.MonitorEvery, journal.record)
	}
	defer func() {
		stopWorkspace()
		if workspaceDone != nil {
			<-workspaceDone
		}
	}()

	// The target was created suspended so it could be contained by the job
	// object and attached by the API tracer before executing. Now let it run.
	if err := resumeProcess(cmd.Process.Pid); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("resume sandbox target: %w", err)
	}

	report.Executed = true
	if cfg.OnObserving != nil {
		cfg.OnObserving()
	}
	collector := newObservationCollector()
	collector.onProcess = func(proc ObservedProcess) {
		if enhancedComponents != nil && proc.PID > 0 && proc.PID != cmd.Process.Pid {
			enhancedComponents.FollowChildProcess(runCtx, proc.PID)
		}
		if cfg.OnProcess != nil {
			cfg.OnProcess(proc)
		}
	}
	collector.onConnection = cfg.OnConnection
	collector.Merge([]ObservedProcess{{PID: cmd.Process.Pid, ParentPID: os.Getpid(), Name: filepath.Base(spec.executable), ExecutablePath: spec.executable, CommandLine: strings.Join(append([]string{spec.executable}, spec.args...), " ")}}, nil, time.Now().UTC())
	monitorCtx, monitorCancel := context.WithCancel(context.Background())
	var monitorWG sync.WaitGroup
	monitorWG.Add(1)
	go func() {
		defer monitorWG.Done()
		runMonitor(monitorCtx, procGuard.Snapshot, cfg.MonitorEvery, collector)
	}()

	waitErr := cmd.Wait()
	if cmd.ProcessState != nil {
		report.ExitCode = cmd.ProcessState.ExitCode()
	}
	// A launcher may exit while its children keep running. The observation
	// lifetime belongs to Stop/the configured deadline, never to the root PID.
	if runCtx.Err() == nil {
		details := fmt.Sprintf("Sample process exited (code 0x%08x); observation continues until Stop or the configured deadline.", uint32(report.ExitCode))
		if waitErr != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("sample exited with error: %v", waitErr))
		}
		if journal != nil {
			journal.record(ActivityEvent{Category: "process", Action: "exited", PID: report.RootPID, Process: filepath.Base(spec.executable), Details: details, Source: "process_wait", Attribution: "observed_process"})
		}
		if cfg.LogSink != nil {
			cfg.LogSink(details)
		}
	}
	<-runCtx.Done()
	report.CompletionReason = "stopped"
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		report.TimedOut = true
		report.CompletionReason = "duration_elapsed"
	}
	// Stop the monitor before closing its job handle, and terminate the whole
	// job before final snapshots/report generation. Deferred cleanup is a fallback.
	monitorCancel()
	monitorWG.Wait()
	if cleanupErr := procGuard.Cleanup(); cleanupErr != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("job object cleanup failed: %v", cleanupErr))
	}
	stopWorkspace()
	if workspaceDone != nil {
		<-workspaceDone
	}

	report.FinishedAt = time.Now().UTC()
	report.DurationMS = report.FinishedAt.Sub(report.StartedAt).Milliseconds()

	afterSnapshot, err := captureFileSnapshot(layout.workspaceDir)
	if err != nil {
		report.Warnings = append(report.Warnings, fmt.Sprintf("workspace rescan failed: %v", err))
	}
	report.FileChanges = diffSnapshots(beforeSnapshot, afterSnapshot)

	if registryBefore != nil {
		registryAfter, err := captureAutorunSnapshot()
		if err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("registry after snapshot failed: %v", err))
		} else {
			report.RegistryChanges = diffRegistrySnapshots(registryBefore, registryAfter)
		}
	}

	processes, connections, warnings := collector.Export()
	processes = enrichObservedProcesses(processes)
	report.Processes = processes
	report.Connections = connections
	report.Warnings = append(report.Warnings, warnings...)

	// Perform enhanced analysis and populate report
	if enhancedComponents != nil {
		if err := enhancedComponents.analyzeAndPopulateReport(report); err != nil {
			report.Warnings = append(report.Warnings, fmt.Sprintf("enhanced analysis failed: %v", err))
		}

		// Export artifacts (PCAP, DOT, HTML)
		exportErrors := enhancedComponents.exportArtifacts(layout.sessionDir, report)
		for _, exportErr := range exportErrors {
			report.Warnings = append(report.Warnings, exportErr.Error())
		}
	}

	report.Behavior = buildBehaviorSummary(report)
	report.NeuralAnalysis = buildNeuralAnalysis(report)
	report.ExploitAnalysis = analyzeExploitability(report)
	report.MemoryAnalysis = analyzeMemory(report)
	report.CacheAnalysis = analyzeCacheArtifacts(report)
	sortReport(report)

	if err := writeReports(report); err != nil {
		return report, err
	}

	return report, nil
}

func prepareSessionLayout(outputRoot string) (*sessionLayout, error) {
	absOutput, err := filepath.Abs(outputRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox output dir: %w", err)
	}

	sessionRoot := filepath.Join(absOutput, "sandbox")
	if err := os.MkdirAll(sessionRoot, 0755); err != nil {
		return nil, fmt.Errorf("create sandbox output: %w", err)
	}
	sessionDir, err := os.MkdirTemp(sessionRoot, time.Now().UTC().Format("20060102_150405")+"_")
	if err != nil {
		return nil, fmt.Errorf("create sandbox session: %w", err)
	}
	layout := &sessionLayout{
		outputRoot:   absOutput,
		sessionDir:   sessionDir,
		workspaceDir: filepath.Join(sessionDir, "workspace"),
		profileDir:   filepath.Join(sessionDir, "profile"),
		tempDir:      filepath.Join(sessionDir, "workspace", "tmp"),
		homeDir:      filepath.Join(sessionDir, "workspace", "home"),
		appDataDir:   filepath.Join(sessionDir, "workspace", "appdata"),
		localAppData: filepath.Join(sessionDir, "workspace", "localappdata"),
		programData:  filepath.Join(sessionDir, "workspace", "programdata"),
		publicDir:    filepath.Join(sessionDir, "workspace", "public"),
		stdoutPath:   filepath.Join(sessionDir, "stdout.log"),
		stderrPath:   filepath.Join(sessionDir, "stderr.log"),
		jsonPath:     filepath.Join(sessionDir, "sandbox_report.json"),
		markdownPath: filepath.Join(sessionDir, "sandbox_report.md"),
	}

	dirs := []string{
		sessionDir,
		layout.workspaceDir,
		layout.profileDir,
		layout.tempDir,
		layout.homeDir,
		layout.appDataDir,
		layout.localAppData,
		layout.programData,
		layout.publicDir,
		filepath.Join(layout.homeDir, "Desktop"),
		filepath.Join(layout.homeDir, "Documents"),
		filepath.Join(layout.homeDir, "Downloads"),
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create sandbox dir %s: %w", dir, err)
		}
	}

	return layout, nil
}

func copyIntoWorkspace(srcPath, workspaceDir string) (string, error) {
	srcInfo, err := os.Stat(srcPath)
	if err != nil {
		return "", err
	}

	dstPath := filepath.Join(workspaceDir, filepath.Base(srcPath))
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return "", err
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, srcInfo.Mode())
	if err != nil {
		return "", err
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return "", err
	}

	return dstPath, nil
}

func minimalEnvironment(layout *sessionLayout) []string {
	keys := []string{
		"ComSpec",
		"NUMBER_OF_PROCESSORS",
		"OS",
		"PATH",
		"PATHEXT",
		"PROCESSOR_ARCHITECTURE",
		"PROCESSOR_IDENTIFIER",
		"SystemDrive",
		"SystemRoot",
		"WINDIR",
	}

	env := make([]string, 0, len(keys)+6)
	for _, key := range keys {
		if value := os.Getenv(key); value != "" {
			env = append(env, key+"="+value)
		}
	}

	env = append(env,
		"TEMP="+layout.tempDir,
		"TMP="+layout.tempDir,
		"USERPROFILE="+layout.homeDir,
		"HOMEDRIVE="+filepath.VolumeName(layout.homeDir),
		"HOMEPATH="+strings.TrimPrefix(layout.homeDir, filepath.VolumeName(layout.homeDir)),
		"APPDATA="+layout.appDataDir,
		"LOCALAPPDATA="+layout.localAppData,
		"ProgramData="+layout.programData,
		"PUBLIC="+layout.publicDir,
		"MEGA_ANALYZER_SANDBOX=1",
		"HTTP_PROXY=",
		"HTTPS_PROXY=",
		"ALL_PROXY=",
		"NO_PROXY=127.0.0.1,localhost",
	)
	return env
}

func detectSandboxInputType(target string, isDir bool) string {
	if typ, err := detectAndroidInputType(target); err == nil && typ != "" {
		return typ
	}
	if isDir {
		return "Directory"
	}
	return strings.TrimPrefix(strings.ToLower(filepath.Ext(target)), ".")
}

func detectAndroidInputType(target string) (string, error) {
	typ, err := apkloader.DetectInputType(target)
	if err != nil {
		return "", err
	}
	switch typ {
	case apkloader.InputTypeSmaliFolder, apkloader.InputTypeCacheFolder,
		apkloader.InputTypeAPKFile, apkloader.InputTypeArchiveFile,
		apkloader.InputTypeDEXFile:
		return typ.String(), nil
	default:
		return "", nil
	}
}

func isAndroidSandboxInputType(inputType string) bool {
	switch inputType {
	case apkloader.InputTypeSmaliFolder.String(),
		apkloader.InputTypeCacheFolder.String(),
		apkloader.InputTypeAPKFile.String(),
		apkloader.InputTypeArchiveFile.String(),
		apkloader.InputTypeDEXFile.String():
		return true
	default:
		return false
	}
}

func detectAndroidSDKStatus() *AndroidSDKStatus {
	tc := androidsdk.Detect()
	if !tc.Detected {
		return &AndroidSDKStatus{}
	}
	return &AndroidSDKStatus{
		Detected:          tc.Detected,
		Root:              tc.Root,
		Source:            tc.Source,
		BuildToolsVersion: tc.BuildToolsVersion,
		ADBPath:           tc.ADB,
		AAPT2Path:         tc.AAPT2,
		APKAnalyzerPath:   tc.APKAnalyzer,
		APKSignerPath:     tc.APKSigner,
		ZIPAlignPath:      tc.ZIPAlign,
		EmulatorPath:      tc.Emulator,
		AVDManagerPath:    tc.AVDManager,
	}
}

func prepareLaunchSpec(absTarget string, info os.FileInfo, layout *sessionLayout, rawArgs string) (*launchSpec, error) {
	if info.IsDir() {
		return &launchSpec{
			runnable: false,
			reason:   "target is a directory; static inspection only",
		}, nil
	}

	copiedTarget, err := copyIntoWorkspace(absTarget, layout.workspaceDir)
	if err != nil {
		return nil, fmt.Errorf("copy target into sandbox workspace: %w", err)
	}

	args, err := splitRawArgs(rawArgs)
	if err != nil {
		return nil, fmt.Errorf("parse sandbox args: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(absTarget))
	spec := &launchSpec{
		copiedPath: copiedTarget,
	}

	switch ext {
	case ".exe", ".com":
		spec.executable = copiedTarget
		spec.args = args
		spec.runnable = true
	case ".bat", ".cmd":
		cmdPath := os.Getenv("ComSpec")
		if cmdPath == "" {
			cmdPath = "cmd.exe"
		}
		spec.executable = resolveExecutablePath(cmdPath)
		spec.args = append([]string{"/c", copiedTarget}, args...)
		spec.runnable = true
	case ".ps1":
		spec.executable = resolveExecutablePath("powershell.exe")
		spec.args = append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", copiedTarget}, args...)
		spec.runnable = true
	default:
		spec.reason = "target is not directly executable on Windows; static inspection only"
	}

	return spec, nil
}

func resolveExecutablePath(name string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	return name
}

func buildSandboxPermissions(cfg Config, layout *sessionLayout) SandboxPermissions {
	permissions := SandboxPermissions{
		NetworkAccess:     "live",
		CanSpawnProcesses: true,
		MaxProcessCount:   sandboxProcessLimit,
		MaxMemoryMB:       cfg.MaxMemoryMB,
		ExposedWritePaths: []string{
			layout.workspaceDir,
			layout.tempDir,
			layout.homeDir,
			layout.appDataDir,
			layout.localAppData,
			layout.programData,
			layout.publicDir,
		},
		MonitoredRegistryKeys: append([]string(nil), monitoredAutorunRegistryKeys...),
		Notes: []string{
			"Network access is live by default; set BlockNetwork to deny it.",
			"Child processes stay inside one Windows Job Object and are terminated when the session closes.",
			"USERPROFILE, APPDATA, LOCALAPPDATA, ProgramData, PUBLIC, TEMP, and TMP are redirected into the session directory.",
			"This is an OS-level sandbox, not a hypervisor: absolute-path filesystem and registry access outside redirected paths are monitored imperfectly and are not fully blocked.",
		},
	}
	if cfg.BlockNetwork {
		permissions.NetworkAccess = "blocked"
	}
	return permissions
}

func requestedComponents(cfg Config) []string {
	components := make([]string, 0, 5)
	if cfg.EnableKernelMonitor {
		components = append(components, "kernel_monitor")
	}
	if cfg.EnableVSS {
		components = append(components, "vss")
	}
	if cfg.EnableWFP {
		components = append(components, "wfp")
	}
	if cfg.EnableAPITracing {
		components = append(components, "api_tracing")
	}
	if cfg.EnableTimeManip {
		components = append(components, "time_manipulation")
	}
	return components
}

func buildEffectiveConfig(cfg Config, outputDir string) *EffectiveConfig {
	return &EffectiveConfig{
		SandboxProfile:      cfg.SandboxProfile,
		OutputDir:           outputDir,
		BlockNetwork:        cfg.BlockNetwork,
		DurationSeconds:     int64(cfg.Duration / time.Second),
		MaxMemoryMB:         cfg.MaxMemoryMB,
		MonitorEveryMS:      int64(cfg.MonitorEvery / time.Millisecond),
		VSSRevert:           cfg.VSSRevert,
		TimeScaleFactor:     cfg.TimeScaleFactor,
		APITraceCategories:  append([]string(nil), cfg.APITraceCategories...),
		EnableKernelMonitor: cfg.EnableKernelMonitor,
		EnableVSS:           cfg.EnableVSS,
		EnableWFP:           cfg.EnableWFP,
		EnableAPITracing:    cfg.EnableAPITracing,
		EnableTimeManip:     cfg.EnableTimeManip,
	}
}

func runMonitor(ctx context.Context, snapshot func() ([]ObservedProcess, []ObservedConnection, error), every time.Duration, collector *observationCollector) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()

	sample := func() {
		processes, connections, err := snapshot()
		if err != nil {
			collector.AddWarning(fmt.Sprintf("runtime monitor snapshot failed: %v", err))
		}
		collector.Merge(processes, connections, time.Now().UTC())
	}

	sample()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sample()
		}
	}
}

func captureFileSnapshot(root string) (map[string]fileFingerprint, error) {
	snapshot := make(map[string]fileFingerprint)

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		info, err := d.Info()
		if err != nil {
			return err
		}

		hash, err := hashFile(path)
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}

		snapshot[filepath.ToSlash(relPath)] = fileFingerprint{
			Path:   filepath.ToSlash(relPath),
			Size:   info.Size(),
			SHA256: hash,
		}
		return nil
	})

	return snapshot, err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func diffSnapshots(before, after map[string]fileFingerprint) FileChanges {
	var changes FileChanges

	for path, afterFile := range after {
		beforeFile, ok := before[path]
		if !ok {
			changes.Created = append(changes.Created, FileArtifact{
				Path:   afterFile.Path,
				Size:   afterFile.Size,
				SHA256: afterFile.SHA256,
			})
			continue
		}
		if beforeFile.SHA256 != afterFile.SHA256 || beforeFile.Size != afterFile.Size {
			changes.Modified = append(changes.Modified, FileArtifact{
				Path:   afterFile.Path,
				Size:   afterFile.Size,
				SHA256: afterFile.SHA256,
			})
		}
	}

	for path, beforeFile := range before {
		if _, ok := after[path]; ok {
			continue
		}
		changes.Deleted = append(changes.Deleted, FileArtifact{
			Path:   beforeFile.Path,
			Size:   beforeFile.Size,
			SHA256: beforeFile.SHA256,
		})
	}

	sort.Slice(changes.Created, func(i, j int) bool { return changes.Created[i].Path < changes.Created[j].Path })
	sort.Slice(changes.Modified, func(i, j int) bool { return changes.Modified[i].Path < changes.Modified[j].Path })
	sort.Slice(changes.Deleted, func(i, j int) bool { return changes.Deleted[i].Path < changes.Deleted[j].Path })
	return changes
}

func diffRegistrySnapshots(before, after map[string]RegistryValue) RegistryChanges {
	var changes RegistryChanges

	for key, afterValue := range after {
		beforeValue, ok := before[key]
		if !ok {
			changes.Added = append(changes.Added, afterValue)
			continue
		}
		if beforeValue.Type != afterValue.Type || beforeValue.Data != afterValue.Data {
			changes.Modified = append(changes.Modified, afterValue)
		}
	}

	for key, beforeValue := range before {
		if _, ok := after[key]; ok {
			continue
		}
		changes.Deleted = append(changes.Deleted, beforeValue)
	}

	sort.Slice(changes.Added, func(i, j int) bool { return registryValueKey(changes.Added[i]) < registryValueKey(changes.Added[j]) })
	sort.Slice(changes.Modified, func(i, j int) bool {
		return registryValueKey(changes.Modified[i]) < registryValueKey(changes.Modified[j])
	})
	sort.Slice(changes.Deleted, func(i, j int) bool {
		return registryValueKey(changes.Deleted[i]) < registryValueKey(changes.Deleted[j])
	})
	return changes
}

func registryValueKey(value RegistryValue) string {
	return value.Key + "|" + value.Name
}

func maskUsernameInPath(p string) string {
	if p == "" {
		return ""
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		return p
	}
	lowerP := strings.ToLower(p)
	lowerUser := strings.ToLower(user)
	needles := []struct {
		prefix string
		repl   string
	}{
		{`\users\` + lowerUser, `\Users\%USERNAME%`},
		{`/users/` + lowerUser, `/Users/%USERNAME%`},
		{`/home/` + lowerUser, `/home/%USERNAME%`},
	}
	for _, item := range needles {
		for {
			idx := strings.Index(lowerP, item.prefix)
			if idx == -1 {
				break
			}
			p = p[:idx] + item.repl + p[idx+len(item.prefix):]
			lowerP = lowerP[:idx] + strings.ToLower(item.repl) + lowerP[idx+len(item.prefix):]
		}
	}
	return p
}

func unmaskUsernameInPath(p string) string {
	if p == "" {
		return ""
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		return p
	}
	return strings.ReplaceAll(p, "%USERNAME%", user)
}

func sanitizeReportPaths(r *Report) *Report {
	if r == nil {
		return nil
	}
	cp := *r
	cp.TargetOriginal = maskUsernameInPath(cp.TargetOriginal)
	cp.TargetCopied = maskUsernameInPath(cp.TargetCopied)
	cp.WorkspaceDir = maskUsernameInPath(cp.WorkspaceDir)
	cp.StdoutPath = maskUsernameInPath(cp.StdoutPath)
	cp.StderrPath = maskUsernameInPath(cp.StderrPath)
	cp.ActivityPath = maskUsernameInPath(cp.ActivityPath)
	cp.JSONPath = maskUsernameInPath(cp.JSONPath)
	cp.MarkdownPath = maskUsernameInPath(cp.MarkdownPath)
	cp.OutputRoot = maskUsernameInPath(cp.OutputRoot)
	cp.SessionDir = maskUsernameInPath(cp.SessionDir)
	if r.EffectiveConfig != nil {
		cfg := *r.EffectiveConfig
		cfg.OutputDir = maskUsernameInPath(cfg.OutputDir)
		cp.EffectiveConfig = &cfg
	}
	cp.RedirectedEnv.UserProfile = maskUsernameInPath(cp.RedirectedEnv.UserProfile)
	cp.RedirectedEnv.AppData = maskUsernameInPath(cp.RedirectedEnv.AppData)
	cp.RedirectedEnv.LocalAppData = maskUsernameInPath(cp.RedirectedEnv.LocalAppData)
	cp.RedirectedEnv.TempDir = maskUsernameInPath(cp.RedirectedEnv.TempDir)
	if r.AndroidSDK != nil {
		sdk := *r.AndroidSDK
		sdk.Root = maskUsernameInPath(sdk.Root)
		sdk.Source = maskUsernameInPath(sdk.Source)
		sdk.ADBPath = maskUsernameInPath(sdk.ADBPath)
		sdk.AAPT2Path = maskUsernameInPath(sdk.AAPT2Path)
		sdk.APKAnalyzerPath = maskUsernameInPath(sdk.APKAnalyzerPath)
		sdk.APKSignerPath = maskUsernameInPath(sdk.APKSignerPath)
		sdk.ZIPAlignPath = maskUsernameInPath(sdk.ZIPAlignPath)
		sdk.EmulatorPath = maskUsernameInPath(sdk.EmulatorPath)
		sdk.AVDManagerPath = maskUsernameInPath(sdk.AVDManagerPath)
		cp.AndroidSDK = &sdk
	}
	if len(r.Processes) > 0 {
		procs := make([]ObservedProcess, len(r.Processes))
		for i, p := range r.Processes {
			p.ExecutablePath = maskUsernameInPath(p.ExecutablePath)
			p.CommandLine = maskUsernameInPath(p.CommandLine)
			procs[i] = p
		}
		cp.Processes = procs
	}
	if len(r.FileChanges.Created) > 0 || len(r.FileChanges.Modified) > 0 || len(r.FileChanges.Deleted) > 0 {
		maskArt := func(in []FileArtifact) []FileArtifact {
			out := make([]FileArtifact, len(in))
			for i, a := range in {
				a.Path = maskUsernameInPath(a.Path)
				out[i] = a
			}
			return out
		}
		cp.FileChanges.Created = maskArt(r.FileChanges.Created)
		cp.FileChanges.Modified = maskArt(r.FileChanges.Modified)
		cp.FileChanges.Deleted = maskArt(r.FileChanges.Deleted)
	}
	if len(r.SandboxPermissions.ExposedWritePaths) > 0 {
		paths := make([]string, len(r.SandboxPermissions.ExposedWritePaths))
		for i, p := range r.SandboxPermissions.ExposedWritePaths {
			paths[i] = maskUsernameInPath(p)
		}
		cp.SandboxPermissions.ExposedWritePaths = paths
	}
	return &cp
}

func writeReports(report *Report) error {
	report.CryptoAnalysis = analyzeCryptoMaterial(report)
	sanitized := sanitizeReportPaths(report)
	jsonData, err := json.MarshalIndent(sanitized, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sandbox report: %w", err)
	}
	targetJSONPath := unmaskUsernameInPath(report.JSONPath)
	if err := os.WriteFile(targetJSONPath, jsonData, 0o600); err != nil {
		return fmt.Errorf("write sandbox JSON report: %w", err)
	}

	markdown := renderMarkdownReport(sanitized)
	targetMDPath := unmaskUsernameInPath(report.MarkdownPath)
	if err := os.WriteFile(targetMDPath, []byte(markdown), 0o600); err != nil {
		return fmt.Errorf("write sandbox markdown report: %w", err)
	}

	return nil
}

func renderMarkdownReport(report *Report) string {
	var b strings.Builder
	duration := time.Duration(report.DurationMS) * time.Millisecond

	b.WriteString("# Sandbox Report\n\n")
	b.WriteString(fmt.Sprintf("- Session: `%s`\n", report.SessionID))
	b.WriteString(fmt.Sprintf("- Target: `%s`\n", maskUsernameInPath(report.TargetOriginal)))
	b.WriteString(fmt.Sprintf("- Copied sample: `%s`\n", maskUsernameInPath(report.TargetCopied)))
	b.WriteString(fmt.Sprintf("- Input type: `%s`\n", report.InputType))
	b.WriteString(fmt.Sprintf("- Workspace: `%s`\n", maskUsernameInPath(report.WorkspaceDir)))
	b.WriteString(fmt.Sprintf("- Started: `%s`\n", report.StartedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Finished: `%s`\n", report.FinishedAt.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("- Duration: `%s`\n", duration))
	b.WriteString(fmt.Sprintf("- Network mode: `%s`\n", report.NetworkMode))
	b.WriteString(fmt.Sprintf("- Executed: `%t`\n", report.Executed))
	if report.ExecutionSkipReason != "" {
		b.WriteString(fmt.Sprintf("- Execution skipped: `%s`\n", report.ExecutionSkipReason))
	}
	b.WriteString(fmt.Sprintf("- Exit code: `%d`\n", report.ExitCode))
	b.WriteString(fmt.Sprintf("- Timed out: `%t`\n", report.TimedOut))
	b.WriteString(fmt.Sprintf("- stdout: `%s`\n", maskUsernameInPath(report.StdoutPath)))
	b.WriteString(fmt.Sprintf("- stderr: `%s`\n", maskUsernameInPath(report.StderrPath)))
	if report.ActivityPath != "" {
		b.WriteString(fmt.Sprintf("- Activity journal: `%s`\n", maskUsernameInPath(report.ActivityPath)))
		b.WriteString(fmt.Sprintf("- Activity observations: `%d`; journal truncated: `%t`\n", report.ActivityCount, report.ActivityTruncated))
		b.WriteString("- Workspace activity: metadata snapshots only; exact action times and responsible processes are unknown.\n")
	}

	b.WriteString("\n## Sandbox Permissions\n\n")
	b.WriteString(fmt.Sprintf("- Network access: `%s`\n", report.SandboxPermissions.NetworkAccess))
	b.WriteString(fmt.Sprintf("- Child processes allowed: `%t`\n", report.SandboxPermissions.CanSpawnProcesses))
	b.WriteString(fmt.Sprintf("- Process limit: `%d`\n", report.SandboxPermissions.MaxProcessCount))
	b.WriteString(fmt.Sprintf("- Memory limit: `%d MB`\n", report.SandboxPermissions.MaxMemoryMB))
	if len(report.SandboxPermissions.ExposedWritePaths) > 0 {
		b.WriteString("\n### Exposed Write Paths\n\n")
		for _, path := range report.SandboxPermissions.ExposedWritePaths {
			b.WriteString(fmt.Sprintf("- `%s`\n", path))
		}
	}
	if len(report.SandboxPermissions.MonitoredRegistryKeys) > 0 {
		b.WriteString("\n### Monitored Registry Keys\n\n")
		for _, key := range report.SandboxPermissions.MonitoredRegistryKeys {
			b.WriteString(fmt.Sprintf("- `%s`\n", key))
		}
	}
	if len(report.SandboxPermissions.Notes) > 0 {
		b.WriteString("\n### Notes\n\n")
		for _, note := range report.SandboxPermissions.Notes {
			fmt.Fprintf(&b, "- %s\n", note)
		}
	}

	if report.EffectiveConfig != nil {
		b.WriteString("\n## Effective Sandbox Config\n\n")
		cfg := report.EffectiveConfig
		if cfg.SandboxProfile != "" {
			b.WriteString(fmt.Sprintf("- Profile: `%s`\n", cfg.SandboxProfile))
		}
		b.WriteString(fmt.Sprintf("- Output dir: `%s`\n", cfg.OutputDir))
		b.WriteString(fmt.Sprintf("- Block network: `%t`\n", cfg.BlockNetwork))
		if cfg.DurationSeconds == 0 {
			b.WriteString("- Duration: until stopped (no deadline)\n")
		} else {
			b.WriteString(fmt.Sprintf("- Duration: `%ds`\n", cfg.DurationSeconds))
		}
		b.WriteString(fmt.Sprintf("- Memory limit: `%d MB`\n", cfg.MaxMemoryMB))
		b.WriteString(fmt.Sprintf("- Time scale: `%.2f`\n", cfg.TimeScaleFactor))
		if len(report.RequestedComponents) > 0 {
			b.WriteString(fmt.Sprintf("- Requested components: `%s`\n", strings.Join(report.RequestedComponents, ", ")))
		}
		if len(report.StartedComponents) > 0 {
			b.WriteString(fmt.Sprintf("- Started components: `%s`\n", strings.Join(report.StartedComponents, ", ")))
		}
		if len(report.DegradedComponents) > 0 {
			b.WriteString("\n### Degraded Components\n\n")
			for _, component := range report.DegradedComponents {
				b.WriteString(fmt.Sprintf("- `%s` during `%s`: %s\n", component.Name, component.Phase, component.Reason))
			}
		}
	}

	b.WriteString("\n## Redirected Environment\n\n")
	b.WriteString(fmt.Sprintf("- USERPROFILE: `%s`\n", report.RedirectedEnv.UserProfile))
	b.WriteString(fmt.Sprintf("- APPDATA: `%s`\n", report.RedirectedEnv.AppData))
	b.WriteString(fmt.Sprintf("- LOCALAPPDATA: `%s`\n", report.RedirectedEnv.LocalAppData))
	b.WriteString(fmt.Sprintf("- ProgramData: `%s`\n", report.RedirectedEnv.ProgramData))
	b.WriteString(fmt.Sprintf("- PUBLIC: `%s`\n", report.RedirectedEnv.PublicDir))
	b.WriteString(fmt.Sprintf("- TEMP/TMP: `%s`\n", report.RedirectedEnv.TempDir))

	b.WriteString("\n## Behavior Summary\n\n")
	if len(report.Behavior.Highlights) == 0 {
		b.WriteString("No standout behaviors summarized.\n")
	} else {
		for _, highlight := range report.Behavior.Highlights {
			fmt.Fprintf(&b, "- %s\n", highlight)
		}
	}

	writeExploitAnalysisMarkdown(&b, report.ExploitAnalysis)
	writeCryptoAnalysisMarkdown(&b, report.CryptoAnalysis)
	writeMemoryAnalysisMarkdown(&b, report.MemoryAnalysis)
	writeCacheAnalysisMarkdown(&b, report.CacheAnalysis)
	writeNeuralAnalysisMarkdown(&b, report.NeuralAnalysis)

	if report.AndroidProfile != nil {
		b.WriteString("\n## Android Profile\n\n")
		b.WriteString(fmt.Sprintf("- Package: `%s`\n", report.AndroidProfile.PackageName))
		if report.AndroidProfile.AppLabel != "" {
			b.WriteString(fmt.Sprintf("- Label: `%s`\n", report.AndroidProfile.AppLabel))
		}
		if report.AndroidProfile.VersionName != "" || report.AndroidProfile.VersionCode != "" {
			b.WriteString(fmt.Sprintf("- Version: `%s` (`%s`)\n", report.AndroidProfile.VersionName, report.AndroidProfile.VersionCode))
		}
		if report.AndroidProfile.MinSDK != "" || report.AndroidProfile.TargetSDK != "" {
			b.WriteString(fmt.Sprintf("- SDK: min `%s`, target `%s`\n", report.AndroidProfile.MinSDK, report.AndroidProfile.TargetSDK))
		}
		b.WriteString(fmt.Sprintf("- High-risk permissions: `%d`\n", report.AndroidProfile.HighRiskPermissionCount))
		b.WriteString(fmt.Sprintf("- Dangerous permissions: `%d`\n", report.AndroidProfile.DangerousPermissionCount))
		if len(report.AndroidProfile.Permissions) > 0 {
			b.WriteString("\n### Permissions\n\n")
			for _, permission := range report.AndroidProfile.Permissions {
				b.WriteString(fmt.Sprintf("- `%s` `%s`\n", permission.Name, permission.Risk))
			}
		}
		if len(report.AndroidProfile.ExportedComponents) > 0 {
			b.WriteString("\n### Exported Components\n\n")
			for _, component := range report.AndroidProfile.ExportedComponents {
				status := "internal"
				if component.Exported {
					status = "exported"
				}
				b.WriteString(fmt.Sprintf("- `%s` `%s` `%s`\n", component.Kind, component.Name, status))
			}
		}
	}

	if report.AndroidSDK != nil {
		b.WriteString("\n## Android SDK\n\n")
		b.WriteString(fmt.Sprintf("- Detected: `%t`\n", report.AndroidSDK.Detected))
		if report.AndroidSDK.Root != "" {
			b.WriteString(fmt.Sprintf("- Root: `%s`\n", report.AndroidSDK.Root))
		}
		if report.AndroidSDK.Source != "" {
			b.WriteString(fmt.Sprintf("- Source: `%s`\n", report.AndroidSDK.Source))
		}
		if report.AndroidSDK.BuildToolsVersion != "" {
			b.WriteString(fmt.Sprintf("- Build-tools: `%s`\n", report.AndroidSDK.BuildToolsVersion))
		}
		writeOptionalPathLine(&b, "adb", report.AndroidSDK.ADBPath)
		writeOptionalPathLine(&b, "aapt2", report.AndroidSDK.AAPT2Path)
		writeOptionalPathLine(&b, "apkanalyzer", report.AndroidSDK.APKAnalyzerPath)
		writeOptionalPathLine(&b, "apksigner", report.AndroidSDK.APKSignerPath)
		writeOptionalPathLine(&b, "zipalign", report.AndroidSDK.ZIPAlignPath)
		writeOptionalPathLine(&b, "emulator", report.AndroidSDK.EmulatorPath)
		writeOptionalPathLine(&b, "avdmanager", report.AndroidSDK.AVDManagerPath)
	}

	b.WriteString("\n## Processes\n\n")
	if len(report.Processes) == 0 {
		b.WriteString("No process snapshots captured.\n")
	} else {
		for _, proc := range report.Processes {
			line := fmt.Sprintf("- PID `%d` parent `%d` `%s`", proc.PID, proc.ParentPID, proc.Name)
			if proc.ExecutablePath != "" {
				line += fmt.Sprintf(" exe `%s`", proc.ExecutablePath)
			}
			if proc.CommandLine != "" {
				line += fmt.Sprintf(" cmd `%s`", proc.CommandLine)
			}
			fmt.Fprintf(&b, "%s\n", line)
		}
	}

	b.WriteString("\n## Connections\n\n")
	if len(report.Connections) == 0 {
		b.WriteString("No network connections observed.\n")
	} else {
		for _, conn := range report.Connections {
			line := fmt.Sprintf("- PID `%d` `%s` `%s` -> `%s`", conn.PID, conn.Protocol, conn.LocalAddr, conn.RemoteAddr)
			if conn.State != "" {
				line += fmt.Sprintf(" state `%s`", conn.State)
			}
			fmt.Fprintf(&b, "%s\n", line)
		}
	}

	b.WriteString("\n## File Changes\n\n")
	writeArtifactSection(&b, "Created", report.FileChanges.Created)
	writeArtifactSection(&b, "Modified", report.FileChanges.Modified)
	writeArtifactSection(&b, "Deleted", report.FileChanges.Deleted)

	b.WriteString("\n## Registry Changes\n\n")
	writeRegistrySection(&b, "Added", report.RegistryChanges.Added)
	writeRegistrySection(&b, "Modified", report.RegistryChanges.Modified)
	writeRegistrySection(&b, "Deleted", report.RegistryChanges.Deleted)

	b.WriteString("\n## Warnings\n\n")
	if len(report.Warnings) == 0 {
		b.WriteString("No warnings.\n")
	} else {
		for _, warning := range report.Warnings {
			fmt.Fprintf(&b, "- %s\n", warning)
		}
	}

	return b.String()
}

func writeArtifactSection(b *strings.Builder, title string, artifacts []FileArtifact) {
	fmt.Fprintf(b, "### %s\n\n", title)
	if len(artifacts) == 0 {
		b.WriteString("None.\n\n")
		return
	}
	for _, artifact := range artifacts {
		b.WriteString(fmt.Sprintf("- `%s` (%d bytes)\n", artifact.Path, artifact.Size))
	}
	b.WriteString("\n")
}

func writeExploitAnalysisMarkdown(b *strings.Builder, analysis *ExploitAnalysis) {
	b.WriteString("\n## Network Exploitability Triage\n\n")
	if analysis == nil || len(analysis.Candidates) == 0 {
		b.WriteString("No exploitability candidates were identified from network telemetry.\n")
		return
	}
	b.WriteString(fmt.Sprintf("- Risk score: `%d/100`\n", analysis.RiskScore))
	b.WriteString(fmt.Sprintf("- Confidence: `%.0f%%`\n\n", analysis.Confidence*100))
	for _, candidate := range analysis.Candidates {
		b.WriteString(fmt.Sprintf("- **%s** `%s` severity `%d/10` confidence `%.0f%%`\n",
			candidate.Title, candidate.Type, candidate.Severity, candidate.Confidence*100))
		if candidate.Target != "" {
			b.WriteString(fmt.Sprintf("  Target: `%s`\n", candidate.Target))
		}
		if candidate.Description != "" {
			fmt.Fprintf(b, "  %s\n", candidate.Description)
		}
		for _, evidence := range candidate.Evidence {
			b.WriteString(fmt.Sprintf("  Evidence: `%s`\n", evidence))
		}
	}
}

func writeMemoryAnalysisMarkdown(b *strings.Builder, analysis *MemoryAnalysis) {
	b.WriteString("\n## Memory Triage\n\n")
	if analysis == nil || len(analysis.Findings) == 0 {
		b.WriteString("No suspicious memory-manipulation signals were identified.\n")
		return
	}
	b.WriteString(fmt.Sprintf("- Risk score: `%d/100`\n\n", analysis.RiskScore))
	for _, finding := range analysis.Findings {
		b.WriteString(fmt.Sprintf("- **%s** severity `%d/10` confidence `%.0f%%` PID `%d`\n",
			finding.Type, finding.Severity, finding.Confidence*100, finding.ProcessID))
		if finding.Description != "" {
			fmt.Fprintf(b, "  %s\n", finding.Description)
		}
		for _, evidence := range finding.Evidence {
			b.WriteString(fmt.Sprintf("  Evidence: `%s`\n", evidence))
		}
	}
}

func writeCacheAnalysisMarkdown(b *strings.Builder, analysis *CacheAnalysis) {
	b.WriteString("\n## Post-Run Cache Analysis\n\n")
	if analysis == nil || len(analysis.Findings) == 0 {
		b.WriteString("No suspicious cache artifacts were identified after shutdown.\n")
		return
	}
	b.WriteString(fmt.Sprintf("- Risk score: `%d/100`\n\n", analysis.RiskScore))
	for _, finding := range analysis.Findings {
		b.WriteString(fmt.Sprintf("- **%s** severity `%d/10` `%s` size `%d`\n",
			finding.Type, finding.Severity, finding.Path, finding.Size))
		if finding.Description != "" {
			fmt.Fprintf(b, "  %s\n", finding.Description)
		}
		if finding.SHA256 != "" {
			b.WriteString(fmt.Sprintf("  SHA256: `%s`\n", finding.SHA256))
		}
	}
}

func writeNeuralAnalysisMarkdown(b *strings.Builder, analysis *NeuralAnalysis) {
	b.WriteString("\n## Neural Analysis\n\n")
	if analysis == nil {
		b.WriteString("No neural analysis available.\n")
		return
	}
	b.WriteString(fmt.Sprintf("- Risk score: `%.1f`\n", analysis.RiskScore))
	b.WriteString(fmt.Sprintf("- Timeline score: `%.3f`\n", analysis.TimelineScore))
	b.WriteString(fmt.Sprintf("- Anomaly score: `%.3f`\n", analysis.AnomalyScore))
	b.WriteString(fmt.Sprintf("- Similarity: `%.3f`\n", analysis.Similarity))
	b.WriteString(fmt.Sprintf("- Static score: `%.3f`\n", analysis.StaticScore))
	b.WriteString(fmt.Sprintf("- Sandbox score: `%.3f`\n", analysis.SandboxScore))
	if len(analysis.Signals) > 0 {
		b.WriteString("\n### Signals\n\n")
		limit := len(analysis.Signals)
		if limit > 25 {
			limit = 25
		}
		for i := 0; i < limit; i++ {
			b.WriteString(fmt.Sprintf("- `%s`\n", analysis.Signals[i]))
		}
	}
	if len(analysis.Explanation) > 0 {
		b.WriteString("\n### Notes\n\n")
		for _, note := range analysis.Explanation {
			b.WriteString("- " + note + "\n")
		}
	}
}

func writeRegistrySection(b *strings.Builder, title string, values []RegistryValue) {
	fmt.Fprintf(b, "### %s\n\n", title)
	if len(values) == 0 {
		b.WriteString("None.\n\n")
		return
	}
	for _, value := range values {
		b.WriteString(fmt.Sprintf("- `%s` `%s` = `%s`\n", value.Key, value.Name, value.Data))
	}
	b.WriteString("\n")
}

func writeOptionalPathLine(b *strings.Builder, label, value string) {
	if value == "" {
		return
	}
	b.WriteString(fmt.Sprintf("- %s: `%s`\n", label, value))
}

func sortReport(report *Report) {
	sort.Strings(report.Warnings)
	sort.Slice(report.Processes, func(i, j int) bool {
		if report.Processes[i].FirstSeen.Equal(report.Processes[j].FirstSeen) {
			return report.Processes[i].PID < report.Processes[j].PID
		}
		return report.Processes[i].FirstSeen.Before(report.Processes[j].FirstSeen)
	})
	sort.Slice(report.Connections, func(i, j int) bool {
		if report.Connections[i].FirstSeen.Equal(report.Connections[j].FirstSeen) {
			return connectionKey(report.Connections[i]) < connectionKey(report.Connections[j])
		}
		return report.Connections[i].FirstSeen.Before(report.Connections[j].FirstSeen)
	})
}

func splitRawArgs(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	var (
		args    []string
		current strings.Builder
		quote   rune
		escape  bool
	)

	flush := func() {
		if current.Len() == 0 {
			return
		}
		args = append(args, current.String())
		current.Reset()
	}

	for _, r := range raw {
		switch {
		case escape:
			current.WriteRune(r)
			escape = false
		case r == '\\':
			escape = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				current.WriteRune(r)
			}
		case r == '"' || r == '\'':
			quote = r
		case unicode.IsSpace(r):
			flush()
		default:
			current.WriteRune(r)
		}
	}

	if escape {
		current.WriteRune('\\')
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted argument")
	}
	flush()
	return args, nil
}

func parseNetstatOutput(raw string, pidSet map[int]struct{}) []ObservedConnection {
	lines := strings.Split(raw, "\n")
	connections := make([]ObservedConnection, 0, len(lines))

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		protocol := strings.ToUpper(fields[0])
		switch protocol {
		case "TCP":
			if len(fields) < 5 {
				continue
			}
			pid := parsePID(fields[4])
			if _, ok := pidSet[pid]; !ok {
				continue
			}
			connections = append(connections, ObservedConnection{
				Protocol:   protocol,
				LocalAddr:  fields[1],
				RemoteAddr: fields[2],
				State:      fields[3],
				PID:        pid,
			})
		case "UDP":
			pid := parsePID(fields[len(fields)-1])
			if _, ok := pidSet[pid]; !ok {
				continue
			}
			remote := "*:*"
			if len(fields) >= 4 {
				remote = fields[2]
			}
			connections = append(connections, ObservedConnection{
				Protocol:   protocol,
				LocalAddr:  fields[1],
				RemoteAddr: remote,
				PID:        pid,
			})
		}
	}

	return connections
}

func parsePID(raw string) int {
	var pid int
	fmt.Sscanf(raw, "%d", &pid)
	return pid
}
