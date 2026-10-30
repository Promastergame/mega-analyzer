// Package correlation post-processes static security-audit findings and
// dynamic runtime-triage signals into a single, explainable view.
//
// It is intentionally a *post-processing* layer: it never produces signals
// of its own and never patches existing detectors. It only consumes their
// output and re-frames it as risks, attack chains, and evidence.
package correlation

import "time"

// SignalKind identifies the source layer that produced the underlying
// observation. It is the coarse-grained "where did this come from".
type SignalKind string

const (
	// KindAudit — static security audit (hardcoded secret, insecure
	// endpoint, weak crypto, ...). No process context.
	KindAudit SignalKind = "audit"

	// KindMemory — dynamic memory triage from sandbox API tracing
	// (RWX allocations, WriteProcessMemory, injection sequences, ...).
	KindMemory SignalKind = "memory"

	// KindNetwork — dynamic network triage (outbound connections,
	// suspicious DNS, opaque TLS, hardcoded IP egress, ...).
	KindNetwork SignalKind = "network"

	// KindBehavior — classified behavior (MITRE ATT&CK technique).
	KindBehavior SignalKind = "behavior"

	// KindExploit — read-only exploitability candidate from sandbox.
	KindExploit SignalKind = "exploit"

	// KindFile — file system observation (drops, created executables,
	// sensitive cache artifacts).
	KindFile SignalKind = "file"

	// KindRegistry — registry observation (autorun, RunOnce, ...).
	KindRegistry SignalKind = "registry"

	// KindAPI — single suspicious API call.
	KindAPI SignalKind = "api"
)

// Standard Type values. These are the strings the correlation engine and
// attack chains match on. Keeping them as constants lets us refactor the
// vocabulary without grepping across the project.
const (
	TypeProcessInjection = "process_injection"
	TypeProcessHollowing = "process_hollowing"
	TypeRWXMemory        = "rwx_memory"
	TypeMemoryWrite      = "memory_write"
	TypeRemoteThread     = "remote_thread"

	TypeOutboundConnection  = "outbound_connection"
	TypePublicEgress        = "public_egress"
	TypeSuspiciousDNS       = "suspicious_dns"
	TypeOpaqueTLS           = "opaque_tls"
	TypeRiskyServicePort    = "risky_service_port"
	TypeHardcodedIPEndpoint = "hardcoded_ip_endpoint"
	TypeScriptStager        = "script_stager"

	TypeRegistryAutorun = "registry_autorun"
	TypeFilePersistence = "file_persistence"
	TypeServiceInstall  = "service_install"
	TypeScheduledTask   = "scheduled_task"
	TypeMassFileChange  = "mass_file_change"
	TypeFileDropExec    = "file_drop_executable"
	TypeFileDropScript  = "file_drop_script"
	TypeSensitiveCache  = "sensitive_cache_artifact"

	TypeHardcodedSecret    = "hardcoded_secret"
	TypeCleartextEndpoint  = "cleartext_endpoint"
	TypeWeakCrypto         = "weak_crypto"
	TypeWebViewJSBridge    = "webview_js_bridge"
	TypeWebViewCleartext   = "webview_cleartext"
	TypeDebugEndpoint      = "debug_endpoint"
	TypeExportedComponent  = "exported_component"
	TypeRootBypass         = "root_bypass"
	TypeAuthGate           = "client_side_auth_gate"
	TypeBooleanGate        = "boolean_decision_point"
	TypeUntrustedIntent    = "untrusted_intent"
	TypeDeepLinkEntry      = "deep_link_entry"
	TypeDangerousSink      = "dangerous_sink"
	TypeWebViewRemoteLoad  = "webview_remote_load"
	TypeJSBridgeCapability = "js_bridge_capability"
	TypeInsecureStorage    = "insecure_storage"
	TypeExportedProvider   = "exported_provider"

	TypeMITREMatch = "mitre_technique"
)

// Tag is a free-form label attached to a Signal so chains and FP-guards
// can refine matching without inventing new Type values.
const (
	TagJIT             = "jit"          // RWX from a known JIT runtime
	TagControllable    = "controllable" // attacker-influenced data
	TagReachable       = "reachable"    // accessible from outside the app
	TagExported        = "exported"     // exported Android component
	TagSensitiveMethod = "sensitive_method"
	TagNoSandboxRun    = "no_sandbox_run" // emitted when runtime is unavailable
)

// Location is an optional source-code anchor for a Signal. Static signals
// usually have a location; runtime signals usually have a process/PID
// instead.
type Location struct {
	File   string `json:"file,omitempty"`
	Line   int    `json:"line,omitempty"`
	Method string `json:"method,omitempty"`
}

// Signal is the unified evidence atom the correlation engine works on.
// One Signal == one observation. The engine never invents Signals; the
// ingest layer normalizes existing finding/event types into Signals.
//
// Signal is plain data — no methods that mutate it — so it is safe to
// share across goroutines once produced.
type Signal struct {
	ID          string     `json:"id"`
	Kind        SignalKind `json:"kind"`
	Type        string     `json:"type"`
	Title       string     `json:"title"`
	Description string     `json:"description,omitempty"`

	// Severity 0..10. We deliberately keep the same scale as
	// sandbox.MemoryFinding/ExploitCandidate so ingest stays trivial.
	Severity   int     `json:"severity"`
	Confidence float64 `json:"confidence"`

	// Timestamp is zero-value for static (audit) signals.
	Timestamp time.Time `json:"timestamp,omitempty"`

	// PID is 0 for static signals.
	PID         int    `json:"pid,omitempty"`
	ProcessName string `json:"process_name,omitempty"`

	// Location is set for static signals. Runtime signals may set it
	// when the source is e.g. a specific dropped file.
	Location Location `json:"location,omitempty"`

	// Target is the "thing" the signal points at: host:port for
	// network, registry key for persistence, file path for drops, etc.
	Target string `json:"target,omitempty"`

	// Evidence is the raw evidence list as produced by the upstream
	// detector, kept verbatim so analysts can audit the chain.
	Evidence []string `json:"evidence,omitempty"`

	// Tags are free-form labels used by chains and FP-guards.
	Tags []string `json:"tags,omitempty"`
}

// HasTag reports whether s carries the given tag.
func (s *Signal) HasTag(tag string) bool {
	if s == nil {
		return false
	}
	for _, t := range s.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

// AddTag adds a tag if it is not already present.
func (s *Signal) AddTag(tag string) {
	if s == nil || tag == "" || s.HasTag(tag) {
		return
	}
	s.Tags = append(s.Tags, tag)
}

// IsRuntime reports whether the signal carries dynamic-execution context
// (i.e. it was actually observed during a sandbox run).
func (s *Signal) IsRuntime() bool {
	if s == nil {
		return false
	}
	switch s.Kind {
	case KindMemory, KindNetwork, KindBehavior, KindExploit, KindFile,
		KindRegistry, KindAPI:
		return true
	default:
		return false
	}
}

// IsStatic reports whether the signal came from static analysis.
func (s *Signal) IsStatic() bool {
	return s != nil && s.Kind == KindAudit
}

// ProcessKey returns a stable per-process identifier suitable for
// grouping. Static signals all share the synthetic "static" key.
func (s *Signal) ProcessKey() string {
	if s == nil {
		return ""
	}
	if s.IsStatic() || s.PID == 0 {
		return "static"
	}
	return processKey(s.PID, s.ProcessName)
}

func processKey(pid int, name string) string {
	if name == "" {
		return formatInt(pid)
	}
	return name + "#" + formatInt(pid)
}

// formatInt avoids importing strconv in this hot path file.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
