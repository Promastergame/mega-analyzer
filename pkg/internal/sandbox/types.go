package sandbox

import (
	"strings"
	"time"

	"mega-analyzer/pkg/internal/types"
)

// Config controls one sandbox detonation session.
type Config struct {
	Name         string
	TargetPath   string
	OutputDir    string
	RawArgs      string
	Duration     time.Duration // 0 = no deadline; positive values must be at least 5s
	MaxMemoryMB  int
	BlockNetwork bool
	MonitorEvery time.Duration
	// Explicit escape hatch for benign local fixtures. Web uploads cannot enable it.
	AllowHostExecution bool `json:"allow_host_execution"`
	// Set only by RunVMwareGuest after checking guest hardware and interfaces.
	externalNetworkIsolation string

	// Windows-native sandbox enhancements
	SandboxProfile      string   `json:"sandbox_profile,omitempty"`
	VSSRevert           bool     `json:"vss_revert"`
	EnableKernelMonitor bool     `json:"enable_kernel_monitor"`
	EnableVSS           bool     `json:"enable_vss"`
	EnableWFP           bool     `json:"enable_wfp"`
	EnableAPITracing    bool     `json:"enable_api_tracing"`
	EnableTimeManip     bool     `json:"enable_time_manip"`
	TimeScaleFactor     float64  `json:"time_scale_factor"`
	CaptureFullPCAP     bool     `json:"capture_full_pcap"`
	APITraceCategories  []string `json:"api_trace_categories"`
	BehaviorRulesPath   string   `json:"behavior_rules_path"`
	AndroidSandbox      bool     `json:"android_sandbox"`
	AndroidAVD          string   `json:"android_avd,omitempty"`
	AndroidAutoAVD      bool     `json:"android_auto_avd"`
	AndroidDevice       string   `json:"android_device,omitempty"` // Exact adb serial; never falls back to another device
	PrivateServer       string   `json:"private_server,omitempty"`

	// Guest environment tuning (honored by the Android emulator; best-effort on Windows host)
	MaxCPUCores    int    `json:"max_cpu_cores,omitempty"`   // cap guest to N logical cores (0 = engine default)
	Locale         string `json:"locale,omitempty"`          // BCP-47, e.g. en-US
	Timezone       string `json:"timezone,omitempty"`        // IANA, e.g. Europe/Moscow
	Resolution     string `json:"resolution,omitempty"`      // canonical "WxH"
	Orientation    string `json:"orientation,omitempty"`     // portrait|landscape
	UninstallAfter bool   `json:"uninstall_after,omitempty"` // uninstall app when run finishes

	// Network capture (Android only)
	CaptureTraffic bool `json:"capture_traffic,omitempty"` // tcpdump raw PCAP on device
	MITMProxy      bool `json:"mitm_proxy,omitempty"`      // mitmproxy HTTPS interception on host

	// Frida instrumentation. Deliberately three fields rather than one
	// boolean: whether to instrument, whether to do it early enough to see
	// application startup, and what to actually observe are independent
	// decisions, and collapsing them into a single toggle is what makes
	// bolted-on instrumentation useless.
	Frida       bool   `json:"frida,omitempty"`        // attach Frida to the target app
	FridaSpawn  bool   `json:"frida_spawn,omitempty"`  // respawn under Frida for pre-onCreate hooks
	FridaScript string `json:"frida_script,omitempty"` // path to a custom instrumentation script

	// LogSink, when set, receives progress log lines from the Android sandbox
	// (device detection, APK install, launch, errors) instead of fmt.Printf.
	// The streaming runner uses this to forward logs as structured telemetry
	// events without any os.Stdout pipe tricks.
	LogSink func(string) `json:"-"`

	// Real observations only; callbacks run after the collector lock is released.
	OnProcess    func(ObservedProcess)    `json:"-"`
	OnConnection func(ObservedConnection) `json:"-"`
	// OnActivity contains observations with explicit source and attribution.
	OnActivity func(ActivityEvent) `json:"-"`
	// OnDevice fires once the run is bound to a concrete Android serial, so
	// live views and request scoping can pin to it instead of guessing.
	OnDevice func(serial string) `json:"-"`
	// OnObserving fires when the sample itself starts executing (app launched
	// on Android, process started on Windows) — not during upload, install or
	// emulator boot — so the observation clock measures real execution.
	OnObserving func() `json:"-"`
}

func (c Config) normalized() Config {
	if c.OutputDir == "" {
		c.OutputDir = "analysis_output"
	}
	if c.MaxMemoryMB <= 0 {
		c.MaxMemoryMB = 512
	}
	if c.MonitorEvery <= 0 {
		c.MonitorEvery = time.Second
	}
	if c.TimeScaleFactor <= 0 {
		c.TimeScaleFactor = 1.0
	}
	return c
}

// Validate checks config sanity before the sandbox starts.
func (c Config) Validate() error {
	if c.TargetPath == "" {
		return errConfig("target path is required")
	}
	if c.Duration < 0 || (c.Duration > 0 && c.Duration < 5*time.Second) {
		return errConfig("duration must be 0 (no deadline) or at least 5s")
	}
	if c.MaxMemoryMB < 128 {
		return errConfig("max memory must be at least 128 MB")
	}
	if c.MonitorEvery > 0 && c.MonitorEvery < 250*time.Millisecond {
		return errConfig("monitor interval must be at least 250ms")
	}
	return nil
}

// Report is the persisted result of one sandbox run.
type Report struct {
	SessionID           string               `json:"session_id"`
	ActivityPath        string               `json:"activity_path,omitempty"`
	ActivityCount       uint64               `json:"activity_count"`
	ActivityTruncated   bool                 `json:"activity_truncated"`
	ExecutionError      *ExecutionFailure    `json:"execution_error,omitempty"`
	MD5                 string               `json:"md5,omitempty"`
	SHA256              string               `json:"sha256,omitempty"`
	InputType           string               `json:"input_type"`
	TargetOriginal      string               `json:"target_original"`
	TargetCopied        string               `json:"target_copied"`
	OutputRoot          string               `json:"output_root"`
	SessionDir          string               `json:"session_dir"`
	WorkspaceDir        string               `json:"workspace_dir"`
	RedirectedEnv       RedirectedEnv        `json:"redirected_env"`
	StdoutPath          string               `json:"stdout_path"`
	StderrPath          string               `json:"stderr_path"`
	JSONPath            string               `json:"json_path"`
	MarkdownPath        string               `json:"markdown_path"`
	NetworkMode         string               `json:"network_mode"`
	NetworkGuardApplied bool                 `json:"network_guard_applied"`
	SandboxPermissions  SandboxPermissions   `json:"sandbox_permissions"`
	Executed            bool                 `json:"executed"`
	ExecutionSkipReason string               `json:"execution_skip_reason,omitempty"`
	RootPID             int                  `json:"root_pid"`
	ExitCode            int                  `json:"exit_code"`
	TimedOut            bool                 `json:"timed_out"`
	CompletionReason    string               `json:"completion_reason,omitempty"`
	StartedAt           time.Time            `json:"started_at"`
	FinishedAt          time.Time            `json:"finished_at"`
	DurationMS          int64                `json:"duration_ms"`
	Processes           []ObservedProcess    `json:"processes"`
	Connections         []ObservedConnection `json:"connections"`
	FileChanges         FileChanges          `json:"file_changes"`
	RegistryChanges     RegistryChanges      `json:"registry_changes"`
	AndroidProfile      *AndroidProfile      `json:"android_profile,omitempty"`
	AndroidSDK          *AndroidSDKStatus    `json:"android_sdk,omitempty"`
	Behavior            BehaviorSummary      `json:"behavior"`
	NeuralAnalysis      *NeuralAnalysis      `json:"neural_analysis,omitempty"`
	Warnings            []string             `json:"warnings,omitempty"`
	RequestedComponents []string             `json:"requested_components,omitempty"`
	StartedComponents   []string             `json:"started_components,omitempty"`
	DegradedComponents  []ComponentStatus    `json:"degraded_components,omitempty"`
	Frida               *FridaSession        `json:"frida,omitempty"`
	CryptoAnalysis      *CryptoAnalysis      `json:"crypto_analysis,omitempty"`
	RemoteCapture       *RemoteCaptureStatus `json:"remote_capture,omitempty"`
	VMware              *VMwareSessionInfo   `json:"vmware,omitempty"`
	EffectiveConfig     *EffectiveConfig     `json:"effective_config,omitempty"`
	ResourcePressure    *ResourcePressure    `json:"resource_pressure,omitempty"`

	// Windows-native sandbox enhancements
	KernelEvents        []KernelEvent          `json:"kernel_events,omitempty"`
	VSSSnapshots        []Snapshot             `json:"vss_snapshots,omitempty"`
	VSSComparison       *SnapshotDiff          `json:"vss_comparison,omitempty"`
	NetworkCapture      *NetworkCapture        `json:"network_capture,omitempty"`
	APICalls            []APICall              `json:"api_calls,omitempty"`
	TimeManipulation    *TimeManipulationLog   `json:"time_manipulation,omitempty"`
	BehaviorAnalysis    *BehaviorAnalysis      `json:"behavior_analysis,omitempty"`
	ExploitAnalysis     *ExploitAnalysis       `json:"exploit_analysis,omitempty"`
	MemoryAnalysis      *MemoryAnalysis        `json:"memory_analysis,omitempty"`
	CacheAnalysis       *CacheAnalysis         `json:"cache_analysis,omitempty"`
	ProcessGraph        string                 `json:"process_graph,omitempty"`
	Timeline            string                 `json:"timeline,omitempty"`
	AntiSandboxDetected []AntiSandboxTechnique `json:"anti_sandbox_detected,omitempty"`

	// NcerResult is attached after live telemetry reconciliation and then the
	// report is persisted again by the streaming runner.
	NcerResult *types.NcerCausalResult `json:"ncer,omitempty"`
}

// VMwareSessionInfo distinguishes guest observations from host-side artifacts.
type VMwareSessionInfo struct {
	Name            string `json:"name"`
	GuestSessionDir string `json:"guest_session_dir"`
	Transport       string `json:"transport"`
	PoweredOff      bool   `json:"powered_off"`
	Incomplete      bool   `json:"incomplete"`
}

type EffectiveConfig struct {
	SandboxProfile      string   `json:"sandbox_profile,omitempty"`
	OutputDir           string   `json:"output_dir"`
	BlockNetwork        bool     `json:"block_network"`
	DurationSeconds     int64    `json:"duration_seconds"`
	MaxMemoryMB         int      `json:"max_memory_mb"`
	MonitorEveryMS      int64    `json:"monitor_every_ms"`
	VSSRevert           bool     `json:"vss_revert"`
	TimeScaleFactor     float64  `json:"time_scale_factor"`
	APITraceCategories  []string `json:"api_trace_categories,omitempty"`
	EnableKernelMonitor bool     `json:"enable_kernel_monitor"`
	EnableVSS           bool     `json:"enable_vss"`
	EnableWFP           bool     `json:"enable_wfp"`
	EnableAPITracing    bool     `json:"enable_api_tracing"`
	EnableTimeManip     bool     `json:"enable_time_manip"`
}

type ComponentStatus struct {
	Name   string `json:"name"`
	Phase  string `json:"phase"`
	Reason string `json:"reason"`
}

// ObservedProcess is a process seen during sandbox execution.
type ObservedProcess struct {
	PID            int       `json:"pid"`
	ParentPID      int       `json:"parent_pid"`
	Name           string    `json:"name"`
	ExecutablePath string    `json:"executable_path,omitempty"`
	CommandLine    string    `json:"command_line,omitempty"`
	FirstSeen      time.Time `json:"first_seen"`
}

// ObservedConnection is a network connection or listening socket.
type ObservedConnection struct {
	Protocol   string    `json:"protocol"`
	LocalAddr  string    `json:"local_addr"`
	RemoteAddr string    `json:"remote_addr"`
	State      string    `json:"state,omitempty"`
	PID        int       `json:"pid"`
	FirstSeen  time.Time `json:"first_seen"`
}

// FileChanges groups workspace deltas captured before/after execution.
type FileChanges struct {
	Created  []FileArtifact `json:"created"`
	Modified []FileArtifact `json:"modified"`
	Deleted  []FileArtifact `json:"deleted"`
}

// FileArtifact represents a file observed in the workspace.
type FileArtifact struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// RedirectedEnv describes per-session folders exposed to the sample.
type RedirectedEnv struct {
	UserProfile  string `json:"user_profile"`
	AppData      string `json:"appdata"`
	LocalAppData string `json:"local_appdata"`
	ProgramData  string `json:"program_data"`
	PublicDir    string `json:"public_dir"`
	TempDir      string `json:"temp_dir"`
}

// SandboxPermissions describes what the sample is allowed to do in-session.
type SandboxPermissions struct {
	NetworkAccess         string   `json:"network_access"`
	CanSpawnProcesses     bool     `json:"can_spawn_processes"`
	MaxProcessCount       int      `json:"max_process_count"`
	MaxMemoryMB           int      `json:"max_memory_mb"`
	ExposedWritePaths     []string `json:"exposed_write_paths"`
	MonitoredRegistryKeys []string `json:"monitored_registry_keys"`
	Notes                 []string `json:"notes,omitempty"`
}

// RegistryValue is one observed autorun/persistence registry value.
type RegistryValue struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	Type string `json:"type"`
	Data string `json:"data"`
}

// RegistryChanges stores registry deltas for watched persistence keys.
type RegistryChanges struct {
	Added    []RegistryValue `json:"added"`
	Modified []RegistryValue `json:"modified"`
	Deleted  []RegistryValue `json:"deleted"`
}

// AndroidProfile summarizes app metadata extracted from AndroidManifest.xml.
type AndroidProfile struct {
	InputType                string              `json:"input_type"`
	ManifestPath             string              `json:"manifest_path"`
	PackageName              string              `json:"package_name,omitempty"`
	AppLabel                 string              `json:"app_label,omitempty"`
	VersionCode              string              `json:"version_code,omitempty"`
	VersionName              string              `json:"version_name,omitempty"`
	MinSDK                   string              `json:"min_sdk,omitempty"`
	TargetSDK                string              `json:"target_sdk,omitempty"`
	Permissions              []AndroidPermission `json:"permissions"`
	ExportedComponents       []AndroidComponent  `json:"exported_components"`
	DangerousPermissionCount int                 `json:"dangerous_permission_count"`
	HighRiskPermissionCount  int                 `json:"high_risk_permission_count"`
}

// AndroidPermission is one declared permission with risk classification.
type AndroidPermission struct {
	Name       string `json:"name"`
	Risk       string `json:"risk"`
	Suspicious bool   `json:"suspicious"`
}

// AndroidComponent is one component extracted from AndroidManifest.xml.
type AndroidComponent struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	Exported bool   `json:"exported"`
}

// AndroidSDKStatus shows whether an official Android SDK toolchain was found.
type AndroidSDKStatus struct {
	Detected          bool   `json:"detected"`
	Root              string `json:"root,omitempty"`
	Source            string `json:"source,omitempty"`
	BuildToolsVersion string `json:"build_tools_version,omitempty"`
	ADBPath           string `json:"adb_path,omitempty"`
	AAPT2Path         string `json:"aapt2_path,omitempty"`
	APKAnalyzerPath   string `json:"apkanalyzer_path,omitempty"`
	APKSignerPath     string `json:"apksigner_path,omitempty"`
	ZIPAlignPath      string `json:"zipalign_path,omitempty"`
	EmulatorPath      string `json:"emulator_path,omitempty"`
	AVDManagerPath    string `json:"avdmanager_path,omitempty"`
}

// BehaviorSummary condenses dynamic and static observations into quick triage hints.
type BehaviorSummary struct {
	Highlights             []string `json:"highlights"`
	ChildProcessCount      int      `json:"child_process_count"`
	ConnectionCount        int      `json:"connection_count"`
	PublicConnectionCount  int      `json:"public_connection_count"`
	CreatedFileCount       int      `json:"created_file_count"`
	ModifiedFileCount      int      `json:"modified_file_count"`
	DroppedExecutableCount int      `json:"dropped_executable_count"`
	DroppedScriptCount     int      `json:"dropped_script_count"`
	PersistenceCount       int      `json:"persistence_count"`
	PermissionWarningCount int      `json:"permission_warning_count"`
}

// NeuralAnalysis summarizes small neural heuristics over a sandbox session.
type NeuralAnalysis struct {
	RiskScore     float64  `json:"risk_score"`
	TimelineScore float64  `json:"timeline_score"`
	AnomalyScore  float64  `json:"anomaly_score"`
	Similarity    float64  `json:"similarity"`
	StaticScore   float64  `json:"static_score"`
	SandboxScore  float64  `json:"sandbox_score"`
	Signals       []string `json:"signals,omitempty"`
	Explanation   []string `json:"explanation,omitempty"`
}

// KernelEvent represents a kernel-level filesystem or registry event.
type KernelEvent struct {
	Timestamp      time.Time         `json:"timestamp"`
	EventType      KernelEventType   `json:"event_type"`
	ProcessID      int               `json:"process_id"`
	ThreadID       int               `json:"thread_id"`
	IntegrityLevel string            `json:"integrity_level"`
	Path           string            `json:"path"`
	Operation      string            `json:"operation"`
	Status         string            `json:"status"`
	Details        map[string]string `json:"details,omitempty"`
}

// KernelEventType enumerates kernel event categories.
//
// Filesystem Events:
// - EventFileCreate: Corresponds to IRP_MJ_CREATE operations (file/directory open/create)
// - EventFileWrite: Corresponds to IRP_MJ_WRITE operations (file write)
// - EventFileDelete: File deletion operations
// - EventFileRename: File rename operations
//
// Registry Events:
// - EventRegSetValue: Registry value set operations (RegNtPreSetValueKey)
// - EventRegDeleteValue: Registry value deletion operations
// - EventRegCreateKey: Registry key creation operations
// - EventRegDeleteKey: Registry key deletion operations
//
// Validates: Requirements 2.1, 2.2, 2.3
type KernelEventType int

const (
	EventFileCreate KernelEventType = iota
	EventFileWrite
	EventFileDelete
	EventFileRename
	EventRegSetValue
	EventRegDeleteValue
	EventRegCreateKey
	EventRegDeleteKey
)

// String returns the string representation of the kernel event type.
func (t KernelEventType) String() string {
	switch t {
	case EventFileCreate:
		return "FileCreate"
	case EventFileWrite:
		return "FileWrite"
	case EventFileDelete:
		return "FileDelete"
	case EventFileRename:
		return "FileRename"
	case EventRegSetValue:
		return "RegSetValue"
	case EventRegDeleteValue:
		return "RegDeleteValue"
	case EventRegCreateKey:
		return "RegCreateKey"
	case EventRegDeleteKey:
		return "RegDeleteKey"
	default:
		return "Unknown"
	}
}

// Snapshot represents a VSS snapshot of the system volume.
type Snapshot struct {
	ID             string           `json:"id"`
	VolumeID       string           `json:"volume_id"`
	CreatedAt      time.Time        `json:"created_at"`
	MountPoint     string           `json:"mount_point"`
	Services       []WindowsService `json:"services"`
	ScheduledTasks []ScheduledTask  `json:"scheduled_tasks"`
	RegistryExport string           `json:"registry_export"`
}

// WindowsService represents a Windows service.
type WindowsService struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	State       string `json:"state"`
	StartType   string `json:"start_type"`
	BinaryPath  string `json:"binary_path"`
}

// ScheduledTask represents a Windows scheduled task.
type ScheduledTask struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	State   string `json:"state"`
	Trigger string `json:"trigger"`
	Action  string `json:"action"`
}

// SnapshotDiff represents the differences between two VSS snapshots.
type SnapshotDiff struct {
	FilesAdded       []FileDelta      `json:"files_added"`
	FilesModified    []FileDelta      `json:"files_modified"`
	FilesDeleted     []FileDelta      `json:"files_deleted"`
	RegistryAdded    []RegistryDelta  `json:"registry_added"`
	RegistryModified []RegistryDelta  `json:"registry_modified"`
	RegistryDeleted  []RegistryDelta  `json:"registry_deleted"`
	ServicesAdded    []WindowsService `json:"services_added"`
	ServicesModified []WindowsService `json:"services_modified"`
	TasksAdded       []ScheduledTask  `json:"tasks_added"`
	TasksModified    []ScheduledTask  `json:"tasks_modified"`
}

// FileDelta represents a file change between snapshots.
type FileDelta struct {
	Path         string    `json:"path"`
	Size         int64     `json:"size"`
	SHA256       string    `json:"sha256"`
	ModifiedTime time.Time `json:"modified_time"`
	Attributes   uint32    `json:"attributes"`
}

// RegistryDelta represents a registry change between snapshots.
type RegistryDelta struct {
	Key       string `json:"key"`
	ValueName string `json:"value_name"`
	ValueType string `json:"value_type"`
	Data      string `json:"data"`
	DataBytes []byte `json:"data_bytes,omitempty"`
}

// NetworkCapture represents captured network traffic.
type NetworkCapture struct {
	PCAPPath    string              `json:"pcap_path"`
	Connections []NetworkConnection `json:"connections"`
	DNSQueries  []DNSQuery          `json:"dns_queries"`
	TLSMetadata []TLSConnection     `json:"tls_metadata"`
	TotalBytes  uint64              `json:"total_bytes"`
}

// NetworkConnection represents a network connection.
type NetworkConnection struct {
	Timestamp     time.Time `json:"timestamp"`
	ProcessID     int       `json:"process_id"`
	ProcessName   string    `json:"process_name"`
	Protocol      string    `json:"protocol"`
	LocalAddr     string    `json:"local_addr"`
	LocalPort     uint16    `json:"local_port"`
	RemoteAddr    string    `json:"remote_addr"`
	RemotePort    uint16    `json:"remote_port"`
	Direction     string    `json:"direction"`
	BytesSent     uint64    `json:"bytes_sent"`
	BytesReceived uint64    `json:"bytes_received"`
	State         string    `json:"state"`
}

// DNSQuery represents a DNS query.
type DNSQuery struct {
	Timestamp    time.Time `json:"timestamp"`
	ProcessID    int       `json:"process_id"`
	ProcessName  string    `json:"process_name"`
	QueryName    string    `json:"query_name"`
	QueryType    string    `json:"query_type"`
	Response     []string  `json:"response"`
	ResponseCode string    `json:"response_code"`
}

// TLSConnection represents TLS connection metadata.
type TLSConnection struct {
	Timestamp          time.Time `json:"timestamp"`
	ProcessID          int       `json:"process_id"`
	RemoteAddr         string    `json:"remote_addr"`
	RemotePort         uint16    `json:"remote_port"`
	SNI                string    `json:"sni"`
	CertificateSubject string    `json:"certificate_subject"`
	CertificateIssuer  string    `json:"certificate_issuer"`
	TLSVersion         string    `json:"tls_version"`
	CipherSuite        string    `json:"cipher_suite"`
}

// APICall represents an observed user-mode Windows API call.
//
// Every real observation emitted by APITracer populates:
//   - Function: exact exported symbol name (e.g. "VirtualAllocEx", "NtWriteVirtualMemory")
//   - Parameters: ordered slice of {Name, Type, Value} carrying target identity
//     (hProcess/ProcessHandle/dwProcessId/hThread/ThreadHandle) and call arguments
//   - ReturnValue: truthful return value formatted in hex/status notation so
//     isSuccessfulCall() distinguishes Win32 non-zero success from 0x0/NULL/
//     INVALID_HANDLE_VALUE failure and NT/Zw NTSTATUS 0x00000000 success from
//     non-zero failure codes (e.g. 0xC0000022)
//   - LastError: thread Win32 GetLastError() captured at hook exit
type APICall struct {
	Timestamp   time.Time      `json:"timestamp"`
	ProcessID   int            `json:"process_id"`
	ThreadID    int            `json:"thread_id"`
	Module      string         `json:"module"`
	Function    string         `json:"function"`
	Parameters  []APIParameter `json:"parameters"`
	ReturnValue string         `json:"return_value"`
	LastError   uint32         `json:"last_error"`
	StackTrace  []string       `json:"stack_trace,omitempty"`
}

// APIParameter represents a parameter to an API call.
type APIParameter struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ParameterValue returns the value of the first parameter matching name
// (case-insensitive) and whether it was found.
func (c APICall) ParameterValue(name string) (string, bool) {
	needle := strings.TrimSpace(name)
	for _, p := range c.Parameters {
		if strings.EqualFold(strings.TrimSpace(p.Name), needle) {
			return p.Value, true
		}
	}
	return "", false
}

// TimeManipulationLog represents time manipulation activity.
type TimeManipulationLog struct {
	Enabled      bool            `json:"enabled"`
	ScaleFactor  float64         `json:"scale_factor"`
	TotalSkipped time.Duration   `json:"total_skipped"`
	SkipEvents   []TimeSkipEvent `json:"skip_events"`
}

// TimeSkipEvent represents a single time skip event.
type TimeSkipEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Function    string    `json:"function"`
	RequestedMS int64     `json:"requested_ms"`
	SkippedMS   int64     `json:"skipped_ms"`
	ProcessID   int       `json:"process_id"`
}

// BehaviorAnalysis represents automated behavior classification.
type BehaviorAnalysis struct {
	RiskScore      int                 `json:"risk_score"`
	Techniques     []MITRETechnique    `json:"techniques"`
	Indicators     []BehaviorIndicator `json:"indicators"`
	Classification string              `json:"classification"`
	Confidence     float64             `json:"confidence"`
}

// ExploitAnalysis is a read-only triage of network-facing exploitability signals.
type ExploitAnalysis struct {
	RiskScore  int                `json:"risk_score"`
	Confidence float64            `json:"confidence"`
	Candidates []ExploitCandidate `json:"candidates"`
	Notes      []string           `json:"notes,omitempty"`
}

// ExploitCandidate describes a place where an exploit may be relevant.
// It never contains or runs exploit code.
type ExploitCandidate struct {
	Type        string   `json:"type"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Target      string   `json:"target,omitempty"`
	ProcessID   int      `json:"process_id,omitempty"`
	Severity    int      `json:"severity"`
	Confidence  float64  `json:"confidence"`
	Evidence    []string `json:"evidence"`
	NextSteps   []string `json:"next_steps,omitempty"`
}

// MemoryAnalysis summarizes suspicious memory manipulation behavior.
type MemoryAnalysis struct {
	RiskScore int             `json:"risk_score"`
	Findings  []MemoryFinding `json:"findings"`
	Notes     []string        `json:"notes,omitempty"`
}

// MemoryFinding is a simple Cheat-Engine-like signal from API telemetry.
type MemoryFinding struct {
	Type        string   `json:"type"`
	Description string   `json:"description"`
	ProcessID   int      `json:"process_id,omitempty"`
	Severity    int      `json:"severity"`
	Confidence  float64  `json:"confidence"`
	Evidence    []string `json:"evidence"`
}

// CacheAnalysis summarizes artifacts left in cache/temp/profile paths after exit.
type CacheAnalysis struct {
	RiskScore int            `json:"risk_score"`
	Findings  []CacheFinding `json:"findings"`
	Notes     []string       `json:"notes,omitempty"`
}

// CacheFinding is a persisted cache artifact worth analyst review.
type CacheFinding struct {
	Type        string `json:"type"`
	Path        string `json:"path"`
	Description string `json:"description"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256,omitempty"`
	Severity    int    `json:"severity"`
}

// MITRETechnique represents a MITRE ATT&CK technique.
type MITRETechnique struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Tactic      string   `json:"tactic"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
	Severity    int      `json:"severity"`
}

// BehaviorIndicator represents a behavioral indicator.
type BehaviorIndicator struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Severity    int                    `json:"severity"`
	Timestamp   time.Time              `json:"timestamp"`
	ProcessID   int                    `json:"process_id"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// AntiSandboxTechnique represents an anti-sandbox evasion technique.
type AntiSandboxTechnique struct {
	Type        string            `json:"type"`
	Description string            `json:"description"`
	Timestamp   time.Time         `json:"timestamp"`
	ProcessID   int               `json:"process_id"`
	Details     map[string]string `json:"details,omitempty"`
}
