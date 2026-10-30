package correlation

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/types"
)

// ═══════════════════════════════════════════════════════════════════════════════
// SANDBOX → SIGNALS
// ═══════════════════════════════════════════════════════════════════════════════

// IngestSandbox normalizes a sandbox.Report (runtime triage) into our
// unified Signal slice. The mapping is deliberately one-finding-one-signal
// — we don't combine evidence here, that's the correlator's job.
func IngestSandbox(report *sandbox.Report) []*Signal {
	if report == nil {
		return nil
	}

	procName := makeProcessNameLookup(report)
	timeOf := report.StartedAt

	out := make([]*Signal, 0, 32)

	// ── Memory ─────────────────────────────────────────────────────
	if report.MemoryAnalysis != nil {
		for i, f := range report.MemoryAnalysis.Findings {
			out = append(out, &Signal{
				ID:          fmt.Sprintf("mem-%d", i),
				Kind:        KindMemory,
				Type:        memoryFindingType(f.Type),
				Title:       f.Type,
				Description: f.Description,
				Severity:    f.Severity,
				Confidence:  f.Confidence,
				Timestamp:   timeOf,
				PID:         f.ProcessID,
				ProcessName: procName(f.ProcessID),
				Evidence:    append([]string(nil), f.Evidence...),
			})
		}
	}

	// ── Network: ObservedConnection (cheap, always available) ─────
	for i, conn := range report.Connections {
		if conn.RemoteAddr == "" || conn.RemoteAddr == "*:*" {
			continue
		}
		host, port := splitHostPort(conn.RemoteAddr)
		isPub := isPublicIP(host)
		typ := TypeOutboundConnection
		if isPub {
			typ = TypePublicEgress
		}
		sev := 4
		if isPub {
			sev = 5
		}
		out = append(out, &Signal{
			ID:          fmt.Sprintf("net-conn-%d", i),
			Kind:        KindNetwork,
			Type:        typ,
			Title:       fmt.Sprintf("%s outbound %s → %s", conn.Protocol, conn.LocalAddr, conn.RemoteAddr),
			Description: "Sandbox observed an outbound network connection.",
			Severity:    sev,
			Confidence:  0.7,
			Timestamp:   firstNonZero(conn.FirstSeen, timeOf),
			PID:         conn.PID,
			ProcessName: procName(conn.PID),
			Target:      conn.RemoteAddr,
			Evidence:    []string{fmt.Sprintf("%s %s -> %s (port %s)", conn.Protocol, conn.LocalAddr, conn.RemoteAddr, port)},
			Tags:        ifReachable(isPub),
		})
	}

	// ── Network: ExploitAnalysis candidates ────────────────────────
	if report.ExploitAnalysis != nil {
		for i, c := range report.ExploitAnalysis.Candidates {
			out = append(out, &Signal{
				ID:          fmt.Sprintf("exp-%d", i),
				Kind:        KindExploit,
				Type:        c.Type,
				Title:       c.Title,
				Description: c.Description,
				Severity:    c.Severity,
				Confidence:  c.Confidence,
				Timestamp:   timeOf,
				PID:         c.ProcessID,
				ProcessName: procName(c.ProcessID),
				Target:      c.Target,
				Evidence:    append([]string(nil), c.Evidence...),
			})
		}
	}

	// ── Network: DNS + TLS metadata ────────────────────────────────
	if report.NetworkCapture != nil {
		for i, q := range report.NetworkCapture.DNSQueries {
			if !looksSuspiciousDomain(q.QueryName) {
				continue
			}
			out = append(out, &Signal{
				ID:          fmt.Sprintf("net-dns-%d", i),
				Kind:        KindNetwork,
				Type:        TypeSuspiciousDNS,
				Title:       fmt.Sprintf("Suspicious DNS query: %s", q.QueryName),
				Description: "Domain matches dynamic-DNS, paste, or short-link infrastructure often used for staging.",
				Severity:    6,
				Confidence:  0.6,
				Timestamp:   firstNonZero(q.Timestamp, timeOf),
				PID:         q.ProcessID,
				ProcessName: q.ProcessName,
				Target:      q.QueryName,
				Evidence:    []string{fmt.Sprintf("DNS %s = %s", q.QueryName, strings.Join(q.Response, ","))},
			})
		}
		for i, tls := range report.NetworkCapture.TLSMetadata {
			if tls.SNI != "" || tls.RemoteAddr == "" {
				continue
			}
			out = append(out, &Signal{
				ID:          fmt.Sprintf("net-tls-%d", i),
				Kind:        KindNetwork,
				Type:        TypeOpaqueTLS,
				Title:       fmt.Sprintf("Opaque TLS to %s:%d", tls.RemoteAddr, tls.RemotePort),
				Description: "TLS without observable SNI hides destination context.",
				Severity:    5,
				Confidence:  0.45,
				Timestamp:   firstNonZero(tls.Timestamp, timeOf),
				PID:         tls.ProcessID,
				ProcessName: procName(tls.ProcessID),
				Target:      fmt.Sprintf("%s:%d", tls.RemoteAddr, tls.RemotePort),
				Evidence:    []string{"TLS metadata has no SNI"},
			})
		}
	}

	// ── Behavior (MITRE) ───────────────────────────────────────────
	if report.BehaviorAnalysis != nil {
		for i, t := range report.BehaviorAnalysis.Techniques {
			out = append(out, &Signal{
				ID:          fmt.Sprintf("mitre-%d", i),
				Kind:        KindBehavior,
				Type:        TypeMITREMatch,
				Title:       fmt.Sprintf("MITRE %s — %s", t.ID, t.Name),
				Description: t.Description,
				Severity:    t.Severity,
				Confidence:  report.BehaviorAnalysis.Confidence,
				Timestamp:   timeOf,
				Evidence:    append([]string(nil), t.Evidence...),
				Tags:        []string{t.Tactic, t.ID},
			})
		}
		for i, ind := range report.BehaviorAnalysis.Indicators {
			out = append(out, &Signal{
				ID:          fmt.Sprintf("ind-%d", i),
				Kind:        KindBehavior,
				Type:        ind.Type,
				Title:       ind.Description,
				Description: ind.Description,
				Severity:    ind.Severity,
				Confidence:  0.6,
				Timestamp:   firstNonZero(ind.Timestamp, timeOf),
				PID:         ind.ProcessID,
				ProcessName: procName(ind.ProcessID),
			})
		}
	}

	// ── Persistence: registry autoruns ─────────────────────────────
	for i, r := range report.RegistryChanges.Added {
		out = append(out, &Signal{
			ID:          fmt.Sprintf("reg-add-%d", i),
			Kind:        KindRegistry,
			Type:        TypeRegistryAutorun,
			Title:       "Registry autorun added",
			Description: fmt.Sprintf("Persistence value added under %s.", r.Key),
			Severity:    7,
			Confidence:  0.85,
			Timestamp:   timeOf,
			Target:      r.Key + "\\" + r.Name,
			Evidence:    []string{fmt.Sprintf("%s\\%s = %s", r.Key, r.Name, r.Data)},
		})
	}

	// ── Persistence: VSS-detected services / scheduled tasks ──────
	if report.VSSComparison != nil {
		for i, svc := range report.VSSComparison.ServicesAdded {
			out = append(out, &Signal{
				ID:          fmt.Sprintf("svc-%d", i),
				Kind:        KindRegistry,
				Type:        TypeServiceInstall,
				Title:       fmt.Sprintf("New service installed: %s", svc.DisplayName),
				Description: "A Windows service appeared in the post-run snapshot.",
				Severity:    8,
				Confidence:  0.85,
				Timestamp:   timeOf,
				Target:      svc.Name,
				Evidence:    []string{fmt.Sprintf("%s start=%s bin=%s", svc.Name, svc.StartType, svc.BinaryPath)},
			})
		}
		for i, t := range report.VSSComparison.TasksAdded {
			out = append(out, &Signal{
				ID:          fmt.Sprintf("task-%d", i),
				Kind:        KindRegistry,
				Type:        TypeScheduledTask,
				Title:       fmt.Sprintf("Scheduled task added: %s", t.Name),
				Description: "A scheduled task appeared in the post-run snapshot.",
				Severity:    7,
				Confidence:  0.8,
				Timestamp:   timeOf,
				Target:      t.Path,
				Evidence:    []string{fmt.Sprintf("trigger=%s action=%s", t.Trigger, t.Action)},
			})
		}
	}

	// ── File drops ─────────────────────────────────────────────────
	for i, art := range report.FileChanges.Created {
		typ, sev := classifyDroppedFile(art.Path)
		if typ == "" {
			continue
		}
		out = append(out, &Signal{
			ID:          fmt.Sprintf("drop-%d", i),
			Kind:        KindFile,
			Type:        typ,
			Title:       fmt.Sprintf("File dropped: %s", filepath.Base(art.Path)),
			Description: droppedFileDescription(typ),
			Severity:    sev,
			Confidence:  0.7,
			Timestamp:   timeOf,
			Target:      art.Path,
			Evidence:    []string{art.Path},
		})
	}
	if report.CacheAnalysis != nil {
		for i, f := range report.CacheAnalysis.Findings {
			if f.Type == "" {
				continue
			}
			out = append(out, &Signal{
				ID:          fmt.Sprintf("cache-%d", i),
				Kind:        KindFile,
				Type:        cacheFindingType(f.Type),
				Title:       fmt.Sprintf("Cache artifact: %s", filepath.Base(f.Path)),
				Description: f.Description,
				Severity:    f.Severity,
				Confidence:  0.65,
				Timestamp:   timeOf,
				Target:      f.Path,
				Evidence:    []string{f.Path},
			})
		}
	}

	// ── Mass file change (ransomware-ish) ──────────────────────────
	if total := len(report.FileChanges.Created) + len(report.FileChanges.Modified); total > 50 {
		out = append(out, &Signal{
			ID:          "mass-file-change",
			Kind:        KindFile,
			Type:        TypeMassFileChange,
			Title:       fmt.Sprintf("Mass file change (%d files)", total),
			Description: "Sandbox observed a large number of file create/modify operations.",
			Severity:    8,
			Confidence:  0.7,
			Timestamp:   timeOf,
			Evidence:    []string{fmt.Sprintf("created=%d modified=%d", len(report.FileChanges.Created), len(report.FileChanges.Modified))},
		})
	}

	return out
}

// memoryFindingType maps sandbox memory finding types to our vocabulary.
// We keep unknown types as-is so future detectors flow through.
func memoryFindingType(t string) string {
	switch t {
	case "executable_memory":
		return TypeRWXMemory
	case "memory_write":
		return TypeMemoryWrite
	case "process_injection_sequence":
		return TypeProcessInjection
	case "process_hollowing_sequence":
		return TypeProcessHollowing
	default:
		return t
	}
}

func cacheFindingType(t string) string {
	switch t {
	case "executable_cache_artifact":
		return TypeFileDropExec
	case "sensitive_cache_artifact":
		return TypeSensitiveCache
	default:
		return t
	}
}

func classifyDroppedFile(path string) (string, int) {
	lower := strings.ToLower(filepath.Ext(path))
	switch lower {
	case ".exe", ".dll", ".scr":
		return TypeFileDropExec, 9
	case ".ps1", ".bat", ".cmd", ".vbs", ".js", ".py":
		return TypeFileDropScript, 7
	case ".jar", ".dex", ".apk":
		return TypeFileDropExec, 8
	}
	return "", 0
}

func droppedFileDescription(typ string) string {
	switch typ {
	case TypeFileDropExec:
		return "Executable artifact persisted by the sample after exit."
	case TypeFileDropScript:
		return "Script artifact persisted by the sample after exit."
	default:
		return "Suspicious artifact persisted by the sample after exit."
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// STATIC ANALYZER → SIGNALS
// ═══════════════════════════════════════════════════════════════════════════════

// IngestStatic normalizes a static AnalysisResult into Signals. Mapping
// uses the Match.Pattern / Category to pick a Type from our vocabulary.
//
// We only emit signals for the categories that participate in chains
// (network, credentials, vulnerabilities, root bypass, ...). Match
// types that have no chain consumer are skipped so the correlation
// view stays focused.
func IngestStatic(result *types.AnalysisResult) []*Signal {
	if result == nil || len(result.Files) == 0 {
		return nil
	}
	out := make([]*Signal, 0, 32)
	idx := 0
	for _, fa := range result.Files {
		if fa == nil {
			continue
		}
		for _, m := range fa.Matches {
			typ := mapStaticType(m)
			if typ == "" {
				continue
			}
			var conf float64
			switch strings.ToLower(m.Confidence) {
			case "high":
				conf = 0.9
			case "medium":
				conf = 0.7
			case "low":
				conf = 0.4
			default:
				conf = 0.7
			}

			sig := &Signal{
				ID:          fmt.Sprintf("audit-%d", idx),
				Kind:        KindAudit,
				Type:        typ,
				Title:       staticTitle(typ, m),
				Description: m.Pattern,
				Severity:    severityFromMatch(m),
				Confidence:  conf,
				Location: Location{
					File:   m.File,
					Line:   m.Line,
					Method: m.MethodName,
				},
				Target:   m.Text,
				Evidence: []string{m.Pattern},
			}
			if m.IsCritical && sig.Severity < 7 {
				sig.Severity = 7
			}
			// Cleartext / hardcoded IP endpoints are reachable by
			// definition (the URL exists in the binary).
			if typ == TypeCleartextEndpoint || typ == TypeHardcodedIPEndpoint {
				sig.AddTag(TagReachable)
			}
			out = append(out, sig)
			idx++
		}
	}
	// Data-flow findings carry stronger source-to-sink evidence than isolated
	// matches. Normalize both ends so Android IPC chain templates can join them.
	for _, flow := range result.DataFlows {
		typeName := TypeDangerousSink
		if strings.Contains(strings.ToLower(flow.Source), "intent") || flow.Label&uint64(3) != 0 {
			typeName = TypeUntrustedIntent
		}
		sig := &Signal{
			ID: fmt.Sprintf("audit-flow-%d", idx), Kind: KindAudit, Type: typeName,
			Title: flow.Source + " reaches " + flow.Sink, Severity: severityFromString(flow.Severity),
			Confidence: flow.Confidence, Location: Location{File: flow.Location.File, Line: flow.Location.Line, Method: flow.Location.Method},
			Target: flow.Sink, Evidence: []string{flow.Source + " -> " + flow.Sink}, Tags: []string{TagControllable, TagReachable},
		}
		out = append(out, sig)
		idx++
		if typeName == TypeUntrustedIntent {
			copy := *sig
			copy.ID = fmt.Sprintf("audit-sink-%d", idx)
			copy.Type = TypeDangerousSink
			out = append(out, &copy)
			idx++
		}
	}
	// Manifest-level evidence: exported components.
	for _, fa := range result.Files {
		if fa == nil || fa.XMLData == nil {
			continue
		}
		// XMLAnalysis already has Suspicious[]; we surface those as
		// exported_component signals if they look like activities or
		// services (fast heuristic).
		for _, sus := range fa.XMLData.Suspicious {
			if !strings.Contains(strings.ToLower(sus), "exported") {
				continue
			}
			sig := &Signal{
				ID:         fmt.Sprintf("audit-exp-%d", idx),
				Kind:       KindAudit,
				Type:       TypeExportedComponent,
				Title:      sus,
				Severity:   5,
				Confidence: 0.8,
				Location:   Location{File: fa.Path},
				Evidence:   []string{sus},
				Tags:       []string{TagExported},
			}
			out = append(out, sig)
			idx++
		}
	}
	return out
}

// mapStaticType picks a correlation Type from a static Match. Returning
// "" means "skip this match" (it has no chain meaning).
func mapStaticType(m types.Match) string {
	pat := strings.ToLower(m.Pattern)
	if strings.Contains(pat, "private key") ||
		strings.Contains(pat, "bearer token") ||
		strings.Contains(pat, "api key") ||
		strings.Contains(pat, "api secret") ||
		strings.Contains(pat, "hardcoded password") ||
		strings.Contains(pat, "hardcoded secret") ||
		strings.Contains(pat, "aws access key") {
		return TypeHardcodedSecret
	}
	if strings.Contains(pat, "cleartext http") ||
		strings.Contains(pat, "uses-cleartext-traffic") {
		return TypeCleartextEndpoint
	}
	if strings.Contains(pat, "hard-coded public ip") ||
		strings.Contains(pat, "hardcoded ip") {
		return TypeHardcodedIPEndpoint
	}
	if strings.Contains(pat, "rc4") ||
		strings.Contains(pat, "ecb block mode") ||
		strings.Contains(pat, "des cipher") ||
		strings.Contains(pat, "trust-all ssl") ||
		strings.Contains(pat, "tls hostname verification disabled") {
		return TypeWeakCrypto
	}
	if strings.Contains(pat, "@javascriptinterface exposed") {
		return TypeJSBridgeCapability
	}
	if strings.Contains(pat, "webview js bridge") ||
		strings.Contains(pat, "addjavascriptinterface") {
		return TypeWebViewJSBridge
	}
	if strings.Contains(pat, "js enabled in webview") {
		return TypeWebViewCleartext
	}
	if strings.Contains(pat, "remote loadurl") || strings.Contains(pat, "remote webview") {
		return TypeWebViewRemoteLoad
	}
	if strings.Contains(pat, "deep link") || strings.Contains(pat, "deeplink") {
		return TypeDeepLinkEntry
	}
	if strings.Contains(pat, "insecure storage") || strings.Contains(pat, "world readable") ||
		strings.Contains(pat, "world writable") || strings.Contains(pat, "external storage") {
		return TypeInsecureStorage
	}
	if strings.Contains(pat, "exported provider") || strings.Contains(pat, "provider without permission") {
		return TypeExportedProvider
	}
	if strings.Contains(pat, "debug") &&
		(strings.Contains(pat, "endpoint") || strings.Contains(pat, "port")) {
		return TypeDebugEndpoint
	}
	if m.Category == types.CategoryRootBypass ||
		strings.Contains(pat, "rootbeer") ||
		strings.Contains(pat, "magisk") {
		return TypeRootBypass
	}
	switch m.Category {
	case types.CategoryPremiumCheck, types.CategoryPremiumUnlock,
		types.CategoryProFeature, types.CategorySubscriptionCheck,
		types.CategoryLicenseCheck, types.CategoryGoogleLVL,
		types.CategoryTrialCheck:
		// Native .so string blobs (e.g. libunity.so matching "isPro" inside
		// engine strings) are not entitlement gates — the engine binary is
		// not app license logic. Seen in the wild: subwaysurf libunity.so
		// "Pro status check" built a false HIGH auth-bypass chain.
		if isNativeLibPath(m.File) {
			return ""
		}
		// Android accessibility probes share entitlement substrings
		// ("hasAccess" ⊂ "hasAccessibility*"). Belt-and-suspenders next to
		// the detector-level exclusion.
		if isAccessibilityMatchTarget(m.Text) {
			return ""
		}
		return TypeAuthGate
	}
	return ""
}

// isNativeLibPath reports whether a match comes from a native library blob
// (.so). String matches inside engine binaries are unreliable gate evidence.
func isNativeLibPath(file string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(file)), ".so")
}

// isAccessibilityMatchTarget reports whether matched text belongs to an
// Android accessibility API probe rather than an entitlement check.
func isAccessibilityMatchTarget(text string) bool {
	lower := strings.ToLower(text)
	return strings.Contains(lower, "accessibility") ||
		strings.Contains(lower, "daltonizer") ||
		strings.Contains(lower, "captioning") ||
		strings.Contains(lower, "touchexploration")
}

func staticTitle(typ string, m types.Match) string {
	if m.Pattern != "" {
		return m.Pattern
	}
	return typ
}

func severityFromString(value string) int {
	switch strings.ToLower(value) {
	case "critical":
		return 9
	case "high":
		return 7
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 4
	}
}

func severityFromMatch(m types.Match) int {
	switch m.Severity {
	case types.SeverityCritical:
		return 9
	case types.SeverityHigh:
		return 7
	case types.SeverityMedium:
		return 5
	case types.SeverityLow:
		return 3
	default:
		return 2
	}
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════

func makeProcessNameLookup(report *sandbox.Report) func(int) string {
	if report == nil {
		return func(int) string { return "" }
	}
	m := make(map[int]string, len(report.Processes))
	for _, p := range report.Processes {
		if _, ok := m[p.PID]; !ok {
			m[p.PID] = p.Name
		}
	}
	if report.NetworkCapture != nil {
		for _, c := range report.NetworkCapture.Connections {
			if c.ProcessName == "" {
				continue
			}
			if _, ok := m[c.ProcessID]; !ok {
				m[c.ProcessID] = c.ProcessName
			}
		}
	}
	return func(pid int) string { return m[pid] }
}

func splitHostPort(addr string) (string, string) {
	if addr == "" || addr == "*:*" {
		return "", ""
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		return strings.Trim(host, "[]"), port
	}
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, ""
	}
	return strings.Trim(addr[:idx], "[]"), addr[idx+1:]
}

func isPublicIP(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		// hostname (not a literal IP) — treat as "public-ish"
		return host != "" && host != "localhost"
	}
	return !ip.IsLoopback() && !ip.IsPrivate() && !ip.IsLinkLocalUnicast() &&
		!ip.IsMulticast() && !ip.IsUnspecified()
}

func looksSuspiciousDomain(name string) bool {
	if name == "" {
		return false
	}
	low := strings.ToLower(name)
	patterns := []string{"duckdns", "no-ip", "dynu", "pastebin",
		"raw.githubusercontent", "ngrok", "trycloudflare", "serveo",
		"temp.sh", "telegra.ph"}
	for _, p := range patterns {
		if strings.Contains(low, p) {
			return true
		}
	}
	return false
}

func ifReachable(reachable bool) []string {
	if reachable {
		return []string{TagReachable}
	}
	return nil
}

func firstNonZero(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	return a
}
