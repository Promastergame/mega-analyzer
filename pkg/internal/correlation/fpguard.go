package correlation

import "strings"

// FPGuard performs targeted false-positive reduction *before* findings
// and chains are produced. It does not delete signals — it only
// annotates them with tags and, when appropriate, lowers their
// effective severity.
//
// The goal is the one the user spelled out:
//
//   - WebView bridges: only HIGH when the bridge actually exposes a
//     sensitive method AND the host is reachable.
//   - RWX memory: respect that JIT runtimes (.NET, Java/ART, V8, ...)
//     legitimately allocate executable memory.
//   - Debug endpoints: only HIGH if the component is exported or the
//     endpoint is actually used at runtime.
//
// FPGuard is idempotent: calling it twice on the same signal slice
// changes nothing on the second call.
func FPGuard(signals []*Signal) {
	for _, s := range signals {
		if s == nil {
			continue
		}
		applyJITHint(s)
		applyDebugEndpointHint(s)
		applyWebViewHint(s)
	}
}

// applyJITHint downgrades RWX/memory_write signals when the source
// process is a known JIT runtime. We tag the signal with TagJIT so
// chains and the renderer can see the reason.
func applyJITHint(s *Signal) {
	if s.Type != TypeRWXMemory && s.Type != TypeMemoryWrite {
		return
	}
	if !isJITProcess(s.ProcessName) {
		return
	}
	// Idempotency: if already tagged, don't re-apply.
	if s.HasTag(TagJIT) {
		return
	}
	s.AddTag(TagJIT)
	// Lower confidence and severity but never zero — JIT does
	// occasionally host real injection too.
	if s.Confidence > 0.4 {
		s.Confidence = 0.4
	}
	if s.Severity > 4 {
		s.Severity = 4
	}
	s.Description = strings.TrimSpace(s.Description + " (JIT runtime detected; downgraded)")
}

// jitProcessNames are processes where executable memory is *expected*.
// We keep the list deliberately small and well-known.
var jitProcessNames = []string{
	"dalvikvm", "art", "zygote", "zygote64",
	"java", "java.exe", "javaw.exe",
	"dotnet", "dotnet.exe", "mono", "mono.exe",
	"node", "node.exe", "deno", "deno.exe",
	"chrome", "chrome.exe", "msedge", "msedge.exe",
	"firefox", "firefox.exe",
}

func isJITProcess(name string) bool {
	if name == "" {
		return false
	}
	low := strings.ToLower(name)
	for _, candidate := range jitProcessNames {
		if low == candidate {
			return true
		}
	}
	// trim ".exe" once and compare again (handles "java.exe" → "java")
	if trimmed := strings.TrimSuffix(low, ".exe"); trimmed != low {
		for _, candidate := range jitProcessNames {
			if trimmed == candidate {
				return true
			}
		}
	}
	return false
}

// applyDebugEndpointHint downgrades a debug_endpoint signal that has no
// reach context (not exported, not connected to). The signal stays in
// the report (so the analyst can still see "we found a /debug path"),
// but its severity drops so it doesn't dominate the dashboard.
func applyDebugEndpointHint(s *Signal) {
	if s.Type != TypeDebugEndpoint {
		return
	}
	if s.HasTag(TagExported) || s.HasTag(TagReachable) {
		return // confirmed reachable — leave as-is
	}
	// Idempotency: if already downgraded, don't re-apply.
	if strings.Contains(s.Description, "unreached debug surface") {
		return
	}
	if s.Severity > 4 {
		s.Severity = 4
	}
	if s.Confidence > 0.5 {
		s.Confidence = 0.5
	}
	s.Description = strings.TrimSpace(s.Description + " (unreached debug surface; downgraded)")
}

// applyWebViewHint downgrades a webview_js_bridge signal when there is
// no observed sensitive method exposure. We expect the static layer to
// already tag exposed-bridge signals with TagSensitiveMethod when it
// can prove it; if not, the bridge alone is suspicious but not HIGH.
func applyWebViewHint(s *Signal) {
	if s.Type != TypeWebViewJSBridge {
		return
	}
	if s.HasTag(TagSensitiveMethod) {
		return // confirmed dangerous
	}
	// Idempotency: if already hinted, don't re-apply.
	if strings.Contains(s.Description, "no sensitive method exposure") {
		return
	}
	if s.Severity > 5 {
		s.Severity = 5
	}
	s.Description = strings.TrimSpace(s.Description + " (no sensitive method exposure observed)")
}
