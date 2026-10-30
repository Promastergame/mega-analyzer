package correlation

import (
	"strings"
	"testing"
	"time"

	"mega-analyzer/pkg/internal/sandbox"
	"mega-analyzer/pkg/internal/types"
)

func TestHasRuntimeNetwork(t *testing.T) {
	// KindNetwork is runtime per IsRuntime()
	s := &Signal{Kind: KindNetwork}
	if !hasRuntimeNetwork([]*Signal{s}) {
		t.Error("KindNetwork signal should return true")
	}
	// nil entry should be skipped
	if hasRuntimeNetwork([]*Signal{nil}) {
		t.Error("nil signal should not match")
	}
	// KindAudit (static) should not count
	audit := &Signal{Kind: KindAudit}
	if hasRuntimeNetwork([]*Signal{audit}) {
		t.Error("audit (static) signal should not match hasRuntimeNetwork")
	}
	if hasRuntimeNetwork(nil) {
		t.Error("nil slice should return false")
	}
}

func TestCacheFindingType(t *testing.T) {
	if got := cacheFindingType("executable_cache_artifact"); got != TypeFileDropExec {
		t.Errorf("got %q, want %q", got, TypeFileDropExec)
	}
	if got := cacheFindingType("sensitive_cache_artifact"); got != TypeSensitiveCache {
		t.Errorf("got %q, want %q", got, TypeSensitiveCache)
	}
	if got := cacheFindingType("other"); got != "other" {
		t.Errorf("unknown type should pass through, got %q", got)
	}
}

func TestClassifyDroppedFile(t *testing.T) {
	cases := []struct {
		path    string
		wantTyp string
		wantPos bool
	}{
		{"payload.exe", TypeFileDropExec, true},
		{"lib.dll", TypeFileDropExec, true},
		{"inject.ps1", TypeFileDropScript, true},
		{"script.bat", TypeFileDropScript, true},
		{"malware.jar", TypeFileDropExec, true},
		{"safe.txt", "", false},
		{"image.png", "", false},
	}
	for _, c := range cases {
		typ, sev := classifyDroppedFile(c.path)
		if c.wantPos {
			if typ != c.wantTyp {
				t.Errorf("classifyDroppedFile(%q) type = %q, want %q", c.path, typ, c.wantTyp)
			}
			if sev <= 0 {
				t.Errorf("classifyDroppedFile(%q) severity = %d, want >0", c.path, sev)
			}
		} else {
			if typ != "" {
				t.Errorf("classifyDroppedFile(%q) should return empty type, got %q", c.path, typ)
			}
		}
	}
}

func TestDroppedFileDescription(t *testing.T) {
	if d := droppedFileDescription(TypeFileDropExec); d == "" {
		t.Error("exec type should have description")
	}
	if d := droppedFileDescription(TypeFileDropScript); d == "" {
		t.Error("script type should have description")
	}
	if d := droppedFileDescription("unknown"); d == "" {
		t.Error("unknown type should have fallback description")
	}
}

func TestLooksSuspiciousDomain(t *testing.T) {
	yes := []string{"evil.duckdns.org", "c2.ngrok.io", "drop.pastebin.com", "data.trycloudflare.com"}
	for _, d := range yes {
		if !looksSuspiciousDomain(d) {
			t.Errorf("looksSuspiciousDomain(%q) = false, want true", d)
		}
	}
	no := []string{"", "google.com", "github.com", "example.com"}
	for _, d := range no {
		if looksSuspiciousDomain(d) {
			t.Errorf("looksSuspiciousDomain(%q) = true, want false", d)
		}
	}
}

// ── guidance.go ───────────────────────────────────────────────────────────────

func TestGuidanceFor_KnownTypes(t *testing.T) {
	// Each of these should return non-nil mitigations.
	knownTypes := []string{
		TypeProcessInjection,
		TypeProcessHollowing,
		TypeRemoteThread,
		TypeRWXMemory,
		TypeMemoryWrite,
		TypeOutboundConnection,
		TypePublicEgress,
		TypeRiskyServicePort,
		TypeSuspiciousDNS,
		TypeOpaqueTLS,
		TypeHardcodedSecret,
		TypeCleartextEndpoint,
		TypeHardcodedIPEndpoint,
		TypeWeakCrypto,
		TypeWebViewJSBridge,
		TypeWebViewCleartext,
		TypeDebugEndpoint,
		TypeExportedComponent,
		TypeRootBypass,
		TypeAuthGate,
		TypeBooleanGate,
		TypeRegistryAutorun,
		TypeServiceInstall,
		TypeScheduledTask,
		TypeFilePersistence,
		TypeFileDropExec,
		TypeFileDropScript,
		TypeSensitiveCache,
		TypeMassFileChange,
		TypeMITREMatch,
		TypeScriptStager,
	}
	for _, typ := range knownTypes {
		mitigations, _ := guidanceFor(typ)
		if len(mitigations) == 0 {
			t.Errorf("guidanceFor(%q) returned no mitigations", typ)
		}
	}
}

func TestGuidanceFor_Unknown(t *testing.T) {
	mitigations, workarounds := guidanceFor("unknown_type")
	if mitigations != nil || workarounds != nil {
		t.Error("unknown type should return nil, nil")
	}
}

func TestGuidanceFor_Workarounds(t *testing.T) {
	// Types that should also return workarounds (not just mitigations).
	typesWithWorkarounds := []string{
		TypeProcessInjection,
		TypeHardcodedSecret,
		TypeOutboundConnection,
		TypeWeakCrypto,
		TypeDebugEndpoint,
		TypeScriptStager,
	}
	for _, typ := range typesWithWorkarounds {
		_, workarounds := guidanceFor(typ)
		if len(workarounds) == 0 {
			t.Errorf("guidanceFor(%q) expected workarounds, got none", typ)
		}
	}
}

func TestGuidanceFor_MITRENoWorkarounds(t *testing.T) {
	_, workarounds := guidanceFor(TypeMITREMatch)
	if workarounds != nil {
		t.Error("MITRE match should have nil workarounds")
	}
}

// ── explain ──────────────────────────────────────────────────────────────────

func TestExplain_NilPrimary(t *testing.T) {
	result := explain(nil, nil, LikelihoodFactors{}, RiskHigh, LikelihoodMedium)
	if result != "" {
		t.Errorf("nil primary should produce empty string, got %q", result)
	}
}

func TestExplain_HardcodedSecret_WithNetwork(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeHardcodedSecret}
	support := []*Signal{{Kind: KindNetwork}} // runtime network
	result := explain(primary, support, LikelihoodFactors{}, RiskHigh, LikelihoodHigh)
	if !strings.Contains(result, "secret") {
		t.Errorf("expected 'secret' in explanation, got %q", result)
	}
	if !strings.Contains(result, "outbound requests") {
		t.Errorf("expected runtime network mention, got %q", result)
	}
}

func TestExplain_HardcodedSecret_NoNetwork(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeHardcodedSecret}
	result := explain(primary, nil, LikelihoodFactors{}, RiskMedium, LikelihoodLow)
	if !strings.Contains(result, "secret") {
		t.Errorf("expected 'secret', got %q", result)
	}
	if !strings.Contains(result, "not corroborated") {
		t.Errorf("expected 'not corroborated' without network, got %q", result)
	}
}

func TestExplain_CleartextEndpoint_WithNetwork(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeCleartextEndpoint}
	support := []*Signal{{Kind: KindNetwork}}
	result := explain(primary, support, LikelihoodFactors{}, RiskHigh, LikelihoodHigh)
	if !strings.Contains(result, "endpoint") {
		t.Errorf("expected 'endpoint', got %q", result)
	}
	if !strings.Contains(result, "exercised") {
		t.Errorf("expected 'exercised', got %q", result)
	}
}

func TestExplain_CleartextEndpoint_NoNetwork(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeCleartextEndpoint}
	result := explain(primary, nil, LikelihoodFactors{}, RiskMedium, LikelihoodLow)
	if !strings.Contains(result, "potential") {
		t.Errorf("expected 'potential', got %q", result)
	}
}

func TestExplain_HardcodedIPEndpoint(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeHardcodedIPEndpoint}
	result := explain(primary, nil, LikelihoodFactors{}, RiskMedium, LikelihoodLow)
	if !strings.Contains(result, "endpoint") {
		t.Errorf("expected 'endpoint', got %q", result)
	}
}

func TestExplain_ProcessInjection(t *testing.T) {
	primary := &Signal{Kind: KindMemory, Type: TypeProcessInjection}
	result := explain(primary, nil, LikelihoodFactors{}, RiskCritical, LikelihoodHigh)
	if !strings.Contains(result, "injection") {
		t.Errorf("expected 'injection', got %q", result)
	}
}

func TestExplain_RWXMemory_JIT(t *testing.T) {
	primary := &Signal{Kind: KindMemory, Type: TypeRWXMemory, Tags: []string{TagJIT}}
	result := explain(primary, nil, LikelihoodFactors{}, RiskLow, LikelihoodLow)
	if !strings.Contains(result, "JIT") {
		t.Errorf("expected 'JIT', got %q", result)
	}
}

func TestExplain_RWXMemory_NotJIT(t *testing.T) {
	primary := &Signal{Kind: KindMemory, Type: TypeRWXMemory}
	result := explain(primary, nil, LikelihoodFactors{}, RiskHigh, LikelihoodMedium)
	if !strings.Contains(result, "injection") {
		t.Errorf("expected 'injection' for non-JIT RWX, got %q", result)
	}
}

func TestExplain_WebViewJSBridge_Sensitive(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeWebViewJSBridge, Tags: []string{TagSensitiveMethod}}
	result := explain(primary, nil, LikelihoodFactors{}, RiskHigh, LikelihoodMedium)
	if !strings.Contains(result, "remote-code-execution") {
		t.Errorf("expected RCE mention, got %q", result)
	}
}

func TestExplain_WebViewJSBridge_NotSensitive(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeWebViewJSBridge}
	result := explain(primary, nil, LikelihoodFactors{}, RiskMedium, LikelihoodLow)
	if !strings.Contains(result, "no evidence") {
		t.Errorf("expected 'no evidence', got %q", result)
	}
}

func TestExplain_DebugEndpoint_Exported(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeDebugEndpoint, Tags: []string{TagExported}}
	result := explain(primary, nil, LikelihoodFactors{}, RiskHigh, LikelihoodHigh)
	if !strings.Contains(result, "reachable") {
		t.Errorf("expected 'reachable', got %q", result)
	}
}

func TestExplain_DebugEndpoint_NotExported(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeDebugEndpoint}
	result := explain(primary, nil, LikelihoodFactors{}, RiskMedium, LikelihoodLow)
	if !strings.Contains(result, "potential") {
		t.Errorf("expected 'potential', got %q", result)
	}
}

func TestExplain_AuthGate_NoServerValidation(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeAuthGate}
	f := LikelihoodFactors{ObservedAtRuntime: false}
	result := explain(primary, nil, f, RiskMedium, LikelihoodMedium)
	if !strings.Contains(result, "gate") {
		t.Errorf("expected 'gate', got %q", result)
	}
	if !strings.Contains(result, "boolean") {
		t.Errorf("expected 'boolean' mention, got %q", result)
	}
}

func TestExplain_Persistence(t *testing.T) {
	primary := &Signal{Kind: KindRegistry, Type: TypeRegistryAutorun}
	result := explain(primary, nil, LikelihoodFactors{}, RiskHigh, LikelihoodHigh)
	if !strings.Contains(result, "persistence") {
		t.Errorf("expected 'persistence', got %q", result)
	}
}

func TestExplain_OutboundConnection_WithSecret(t *testing.T) {
	primary := &Signal{Kind: KindNetwork, Type: TypeOutboundConnection}
	support := []*Signal{{Kind: KindAudit, Type: TypeHardcodedSecret}}
	result := explain(primary, support, LikelihoodFactors{}, RiskHigh, LikelihoodHigh)
	if !strings.Contains(result, "secret") {
		t.Errorf("expected 'secret' for outbound+secret combo, got %q", result)
	}
}

func TestExplain_SuspiciousDNS(t *testing.T) {
	primary := &Signal{Kind: KindNetwork, Type: TypeSuspiciousDNS}
	result := explain(primary, nil, LikelihoodFactors{}, RiskMedium, LikelihoodMedium)
	if !strings.Contains(result, "DNS") {
		t.Errorf("expected 'DNS', got %q", result)
	}
}

func TestExplain_MassFileChange(t *testing.T) {
	primary := &Signal{Kind: KindFile, Type: TypeMassFileChange}
	result := explain(primary, nil, LikelihoodFactors{}, RiskCritical, LikelihoodHigh)
	if !strings.Contains(result, "ransomware") {
		t.Errorf("expected 'ransomware', got %q", result)
	}
}

func TestExplain_Default_WithDescription(t *testing.T) {
	primary := &Signal{Kind: KindBehavior, Type: "unknown_type", Description: "some description"}
	result := explain(primary, nil, LikelihoodFactors{}, RiskLow, LikelihoodLow)
	if !strings.Contains(result, "some description") {
		t.Errorf("expected description, got %q", result)
	}
}

func TestExplain_Default_FallsBackToTitle(t *testing.T) {
	primary := &Signal{Kind: KindBehavior, Type: "unknown_type", Title: "my title", Description: ""}
	result := explain(primary, nil, LikelihoodFactors{}, RiskLow, LikelihoodLow)
	if !strings.Contains(result, "my title") {
		t.Errorf("expected title as fallback, got %q", result)
	}
}

func TestExplain_AlwaysIncludesRiskAndLikelihood(t *testing.T) {
	primary := &Signal{Kind: KindAudit, Type: TypeHardcodedSecret}
	result := explain(primary, nil, LikelihoodFactors{}, RiskHigh, LikelihoodMedium)
	// The format is "Assessed risk: HIGH, likelihood: MEDIUM."
	if !strings.Contains(strings.ToLower(result), "high") {
		t.Errorf("expected risk level in output, got %q", result)
	}
	if !strings.Contains(strings.ToLower(result), "medium") {
		t.Errorf("expected likelihood in output, got %q", result)
	}
}

// ── hasOtherType ─────────────────────────────────────────────────────────────

func TestHasOtherType(t *testing.T) {
	signals := []*Signal{
		{Type: TypeHardcodedSecret},
		{Type: TypeOutboundConnection},
		nil,
	}
	if !hasOtherType(signals, TypeHardcodedSecret) {
		t.Error("should find TypeHardcodedSecret")
	}
	if hasOtherType(signals, TypeMITREMatch) {
		t.Error("should not find TypeMITREMatch")
	}
	if hasOtherType(nil, TypeHardcodedSecret) {
		t.Error("nil slice should return false")
	}
}

// ── correlator.go helpers ────────────────────────────────────────────────────

func TestLocationOf(t *testing.T) {
	// nil signal
	if locationOf(nil) != nil {
		t.Error("nil signal should return nil location")
	}
	// signal with empty location
	s := &Signal{Location: Location{}}
	if locationOf(s) != nil {
		t.Error("empty location should return nil")
	}
	// signal with file set
	s2 := &Signal{Location: Location{File: "com/example/Foo.smali"}}
	loc := locationOf(s2)
	if loc == nil {
		t.Fatal("non-empty location should return non-nil")
	}
	if loc.File != "com/example/Foo.smali" {
		t.Errorf("file = %q", loc.File)
	}
	// signal with only line
	s3 := &Signal{Location: Location{Line: 42}}
	loc3 := locationOf(s3)
	if loc3 == nil {
		t.Fatal("location with line should be non-nil")
	}
	if loc3.Line != 42 {
		t.Errorf("line = %d", loc3.Line)
	}
}

func TestFindingTitle(t *testing.T) {
	s := &Signal{Title: "My Title", Type: TypeHardcodedSecret}
	if got := findingTitle(s); got != "My Title" {
		t.Errorf("got %q, want 'My Title'", got)
	}
	// empty title falls back to type
	s2 := &Signal{Title: "", Type: TypeHardcodedSecret}
	if got := findingTitle(s2); got != TypeHardcodedSecret {
		t.Errorf("got %q, want %q", got, TypeHardcodedSecret)
	}
}

func TestCategoryOfType(t *testing.T) {
	cases := []struct {
		typ  string
		want string
	}{
		{TypeProcessInjection, "memory"},
		{TypeProcessHollowing, "memory"},
		{TypeRWXMemory, "memory"},
		{TypeMemoryWrite, "memory"},
		{TypeRemoteThread, "memory"},
		{TypeOutboundConnection, "network"},
		{TypePublicEgress, "network"},
		{TypeSuspiciousDNS, "network"},
		{TypeOpaqueTLS, "network"},
		{TypeRiskyServicePort, "network"},
		{TypeHardcodedIPEndpoint, "network"},
		{TypeScriptStager, "network"},
		{TypeRegistryAutorun, "persistence"},
		{TypeFilePersistence, "persistence"},
		{TypeServiceInstall, "persistence"},
		{TypeScheduledTask, "persistence"},
		{TypeMassFileChange, "persistence"},
		{TypeFileDropExec, "persistence"},
		{TypeFileDropScript, "persistence"},
		{TypeSensitiveCache, "persistence"},
		{TypeHardcodedSecret, "security_audit"},
		{TypeCleartextEndpoint, "security_audit"},
		{TypeWeakCrypto, "security_audit"},
		{TypeWebViewJSBridge, "security_audit"},
		{TypeWebViewCleartext, "security_audit"},
		{TypeDebugEndpoint, "security_audit"},
		{TypeExportedComponent, "security_audit"},
		{TypeRootBypass, "security_audit"},
		{TypeAuthGate, "security_audit"},
		{TypeBooleanGate, "security_audit"},
		{TypeMITREMatch, "behavior"},
		{"completely_unknown_type", "other"},
	}
	for _, c := range cases {
		if got := categoryOfType(c.typ); got != c.want {
			t.Errorf("categoryOfType(%q) = %q, want %q", c.typ, got, c.want)
		}
	}
}

// ── ingest.go helpers ────────────────────────────────────────────────────────

func TestMemoryFindingType(t *testing.T) {
	cases := []struct{ in, want string }{
		{"executable_memory", TypeRWXMemory},
		{"memory_write", TypeMemoryWrite},
		{"process_injection_sequence", TypeProcessInjection},
		{"process_hollowing_sequence", TypeProcessHollowing},
		{"unknown_memory_type", "unknown_memory_type"}, // pass-through
		{"", ""},
	}
	for _, c := range cases {
		if got := memoryFindingType(c.in); got != c.want {
			t.Errorf("memoryFindingType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		addr     string
		wantHost string
		wantPort string
	}{
		{"", "", ""},
		{"*:*", "", ""},
		{"192.168.1.1:8080", "192.168.1.1", "8080"},
		{"[::1]:443", "::1", "443"},
		{"example.com:80", "example.com", "80"},
		{"noport", "noport", ""},
	}
	for _, c := range cases {
		h, p := splitHostPort(c.addr)
		if h != c.wantHost || p != c.wantPort {
			t.Errorf("splitHostPort(%q) = (%q, %q), want (%q, %q)", c.addr, h, p, c.wantHost, c.wantPort)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"203.0.113.1",
	}
	for _, ip := range public {
		if !isPublicIP(ip) {
			t.Errorf("isPublicIP(%q) = false, want true", ip)
		}
	}

	notPublic := []string{
		"127.0.0.1",
		"192.168.1.1",
		"10.0.0.1",
		"169.254.1.1",
		"::1",
	}
	for _, ip := range notPublic {
		if isPublicIP(ip) {
			t.Errorf("isPublicIP(%q) = true, want false", ip)
		}
	}

	// hostname — treated as public
	if !isPublicIP("example.com") {
		t.Error("isPublicIP(hostname) should be true")
	}
	// empty string
	if isPublicIP("") {
		t.Error("isPublicIP('') should be false")
	}
	// localhost
	if isPublicIP("localhost") {
		t.Error("isPublicIP('localhost') should be false")
	}
}

func TestIfReachable(t *testing.T) {
	if tags := ifReachable(true); len(tags) != 1 || tags[0] != TagReachable {
		t.Errorf("ifReachable(true) = %v, want [%q]", tags, TagReachable)
	}
	if tags := ifReachable(false); tags != nil {
		t.Errorf("ifReachable(false) = %v, want nil", tags)
	}
}

func TestFirstNonZero(t *testing.T) {
	t1 := time.Now()
	t2 := t1.Add(time.Hour)
	var zero time.Time

	if got := firstNonZero(t1, t2); !got.Equal(t1) {
		t.Error("should return first non-zero time")
	}
	if got := firstNonZero(zero, t2); !got.Equal(t2) {
		t.Error("should return second when first is zero")
	}
	if got := firstNonZero(zero, zero); !got.IsZero() {
		t.Error("both zero should return zero")
	}
}

func TestMakeProcessNameLookup(t *testing.T) {
	report := &sandbox.Report{
		Processes: []sandbox.ObservedProcess{
			{PID: 1, Name: "explorer.exe"},
			{PID: 2, Name: "chrome.exe"},
			{PID: 1, Name: "should-be-ignored"}, // duplicate PID
		},
	}
	lookup := makeProcessNameLookup(report)
	if got := lookup(1); got != "explorer.exe" {
		t.Errorf("lookup(1) = %q, want 'explorer.exe'", got)
	}
	if got := lookup(2); got != "chrome.exe" {
		t.Errorf("lookup(2) = %q, want 'chrome.exe'", got)
	}
	if got := lookup(999); got != "" {
		t.Errorf("lookup(unknown) = %q, want ''", got)
	}

	// nil report
	nilLookup := makeProcessNameLookup(nil)
	if got := nilLookup(1); got != "" {
		t.Errorf("nil report lookup should return ''")
	}
}

func TestMakeProcessNameLookup_NetworkCapture(t *testing.T) {
	report := &sandbox.Report{
		NetworkCapture: &sandbox.NetworkCapture{
			Connections: []sandbox.NetworkConnection{
				{ProcessID: 5, ProcessName: "wget"},
			},
		},
	}
	lookup := makeProcessNameLookup(report)
	if got := lookup(5); got != "wget" {
		t.Errorf("lookup from NetworkCapture(5) = %q, want 'wget'", got)
	}
}

func TestStaticTitle(t *testing.T) {
	m := types.Match{Pattern: "hardcoded password"}
	if got := staticTitle(TypeHardcodedSecret, m); got != "hardcoded password" {
		t.Errorf("got %q, want 'hardcoded password'", got)
	}
	// empty pattern falls back to type
	m2 := types.Match{}
	if got := staticTitle(TypeHardcodedSecret, m2); got != TypeHardcodedSecret {
		t.Errorf("got %q, want %q", got, TypeHardcodedSecret)
	}
}

func TestSeverityFromMatch(t *testing.T) {
	cases := []struct {
		sev  types.Severity
		want int
	}{
		{types.SeverityCritical, 9},
		{types.SeverityHigh, 7},
		{types.SeverityMedium, 5},
		{types.SeverityLow, 3},
		{types.SeverityInfo, 2},
	}
	for _, c := range cases {
		m := types.Match{Scored: types.Scored{}}
		m.Severity = c.sev
		if got := severityFromMatch(m); got != c.want {
			t.Errorf("severityFromMatch(severity=%v) = %d, want %d", c.sev, got, c.want)
		}
	}
}

func TestMapStaticType(t *testing.T) {
	cases := []struct {
		pattern  string
		category types.Category
		want     string
	}{
		{"private key detected", "", TypeHardcodedSecret},
		{"bearer token found", "", TypeHardcodedSecret},
		{"api key hardcoded", "", TypeHardcodedSecret},
		{"api secret present", "", TypeHardcodedSecret},
		{"hardcoded password", "", TypeHardcodedSecret},
		{"hardcoded secret", "", TypeHardcodedSecret},
		{"aws access key id", "", TypeHardcodedSecret},
		{"cleartext http endpoint", "", TypeCleartextEndpoint},
		{"uses-cleartext-traffic", "", TypeCleartextEndpoint},
		{"hard-coded public ip address", "", TypeHardcodedIPEndpoint},
		{"hardcoded ip found", "", TypeHardcodedIPEndpoint},
		{"rc4 cipher usage", "", TypeWeakCrypto},
		{"ecb block mode detected", "", TypeWeakCrypto},
		{"des cipher found", "", TypeWeakCrypto},
		{"trust-all ssl context", "", TypeWeakCrypto},
		{"tls hostname verification disabled", "", TypeWeakCrypto},
		{"webview js bridge", "", TypeWebViewJSBridge},
		{"addjavascriptinterface", "", TypeWebViewJSBridge},
		{"js enabled in webview", "", TypeWebViewCleartext},
		{"debug endpoint exposed", "", TypeDebugEndpoint},
		{"debug port open", "", TypeDebugEndpoint},
		{"rootbeer detection", "", TypeRootBypass},
		{"magisk detected", "", TypeRootBypass},
		{"", types.CategoryRootBypass, TypeRootBypass},
		{"", types.CategoryPremiumCheck, TypeAuthGate},
		{"", types.CategoryPremiumUnlock, TypeAuthGate},
		{"", types.CategoryProFeature, TypeAuthGate},
		{"", types.CategorySubscriptionCheck, TypeAuthGate},
		{"", types.CategoryLicenseCheck, TypeAuthGate},
		{"", types.CategoryGoogleLVL, TypeAuthGate},
		{"", types.CategoryTrialCheck, TypeAuthGate},
		{"unrelated pattern text", "", ""},
	}
	for _, c := range cases {
		m := types.Match{Pattern: c.pattern, Categorized: types.Categorized{Category: c.category}}
		got := mapStaticType(m)
		if got != c.want {
			t.Errorf("mapStaticType(pattern=%q, cat=%q) = %q, want %q", c.pattern, c.category, got, c.want)
		}
	}
}

func TestIngestSandbox_Nil(t *testing.T) {
	if got := IngestSandbox(nil); got != nil {
		t.Error("IngestSandbox(nil) should return nil")
	}
}

func TestIngestSandbox_BasicConnections(t *testing.T) {
	report := &sandbox.Report{
		Connections: []sandbox.ObservedConnection{
			{Protocol: "TCP", LocalAddr: "10.0.0.1:54321", RemoteAddr: "8.8.8.8:443"},
			{RemoteAddr: ""},    // should be skipped (empty)
			{RemoteAddr: "*:*"}, // should be skipped
			{Protocol: "TCP", LocalAddr: "10.0.0.1:12345", RemoteAddr: "192.168.1.1:80"}, // private
		},
	}
	signals := IngestSandbox(report)
	// Should have 2: public egress + private outbound
	hasPublicEgress := false
	hasOutbound := false
	for _, s := range signals {
		if s.Type == TypePublicEgress {
			hasPublicEgress = true
		}
		if s.Type == TypeOutboundConnection {
			hasOutbound = true
		}
	}
	if !hasPublicEgress {
		t.Error("expected TypePublicEgress signal for 8.8.8.8")
	}
	if !hasOutbound {
		t.Error("expected TypeOutboundConnection for private address")
	}
}

func TestIngestSandbox_MemoryFindings(t *testing.T) {
	report := &sandbox.Report{
		MemoryAnalysis: &sandbox.MemoryAnalysis{
			Findings: []sandbox.MemoryFinding{
				{Type: "executable_memory", Description: "RWX alloc", Severity: 8, Confidence: 0.9, ProcessID: 100},
				{Type: "process_injection_sequence", Description: "Injection", Severity: 9, Confidence: 0.95},
			},
		},
	}
	signals := IngestSandbox(report)
	if len(signals) != 2 {
		t.Fatalf("expected 2 signals, got %d", len(signals))
	}
	if signals[0].Type != TypeRWXMemory {
		t.Errorf("first signal type = %q, want %q", signals[0].Type, TypeRWXMemory)
	}
	if signals[1].Type != TypeProcessInjection {
		t.Errorf("second signal type = %q, want %q", signals[1].Type, TypeProcessInjection)
	}
}

func TestIngestSandbox_SuspiciousDNS(t *testing.T) {
	report := &sandbox.Report{
		NetworkCapture: &sandbox.NetworkCapture{
			DNSQueries: []sandbox.DNSQuery{
				{QueryName: "evil.duckdns.org", Response: []string{"1.2.3.4"}},
				{QueryName: "google.com"}, // not suspicious
			},
		},
	}
	signals := IngestSandbox(report)
	var dnsSignals []*Signal
	for _, s := range signals {
		if s.Type == TypeSuspiciousDNS {
			dnsSignals = append(dnsSignals, s)
		}
	}
	if len(dnsSignals) != 1 {
		t.Errorf("expected 1 suspicious DNS signal, got %d", len(dnsSignals))
	}
	if !strings.Contains(dnsSignals[0].Target, "duckdns") {
		t.Errorf("target should contain 'duckdns', got %q", dnsSignals[0].Target)
	}
}

func TestIngestSandbox_OpaqueTLS(t *testing.T) {
	report := &sandbox.Report{
		NetworkCapture: &sandbox.NetworkCapture{
			TLSMetadata: []sandbox.TLSConnection{
				{SNI: "", RemoteAddr: "8.8.8.8", RemotePort: 443},           // no SNI = opaque
				{SNI: "google.com", RemoteAddr: "8.8.8.8", RemotePort: 443}, // has SNI = skip
			},
		},
	}
	signals := IngestSandbox(report)
	var tlsSignals []*Signal
	for _, s := range signals {
		if s.Type == TypeOpaqueTLS {
			tlsSignals = append(tlsSignals, s)
		}
	}
	if len(tlsSignals) != 1 {
		t.Errorf("expected 1 opaque TLS signal, got %d", len(tlsSignals))
	}
}

func TestIngestSandbox_RegistryAutorun(t *testing.T) {
	report := &sandbox.Report{
		RegistryChanges: sandbox.RegistryChanges{
			Added: []sandbox.RegistryValue{
				{Key: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, Name: "Updater", Data: "malware.exe"},
			},
		},
	}
	signals := IngestSandbox(report)
	if len(signals) == 0 {
		t.Fatal("expected at least 1 signal")
	}
	if signals[0].Type != TypeRegistryAutorun {
		t.Errorf("type = %q, want %q", signals[0].Type, TypeRegistryAutorun)
	}
}

func TestIngestSandbox_MassFileChange(t *testing.T) {
	// 51 created files should trigger mass file change
	created := make([]sandbox.FileArtifact, 51)
	for i := range created {
		created[i] = sandbox.FileArtifact{Path: "file.txt"} // plain text, not classified
	}
	report := &sandbox.Report{
		FileChanges: sandbox.FileChanges{Created: created},
	}
	signals := IngestSandbox(report)
	var massChange *Signal
	for _, s := range signals {
		if s.Type == TypeMassFileChange {
			massChange = s
			break
		}
	}
	if massChange == nil {
		t.Error("expected TypeMassFileChange signal for 51 created files")
	}
}

func TestIngestSandbox_BehaviorAnalysis(t *testing.T) {
	report := &sandbox.Report{
		BehaviorAnalysis: &sandbox.BehaviorAnalysis{
			Confidence: 0.85,
			Techniques: []sandbox.MITRETechnique{
				{ID: "T1055", Name: "Process Injection", Tactic: "defense-evasion", Severity: 8},
			},
			Indicators: []sandbox.BehaviorIndicator{
				{Type: TypeProcessInjection, Description: "Injection indicator", Severity: 7},
			},
		},
	}
	signals := IngestSandbox(report)
	var mitre, indicator *Signal
	for _, s := range signals {
		if s.Type == TypeMITREMatch {
			mitre = s
		}
		if s.Type == TypeProcessInjection {
			indicator = s
		}
	}
	if mitre == nil {
		t.Error("expected TypeMITREMatch signal")
	}
	if indicator == nil {
		t.Error("expected TypeProcessInjection indicator signal")
	}
}

func TestIngestStatic_Nil(t *testing.T) {
	if got := IngestStatic(nil); got != nil {
		t.Error("IngestStatic(nil) should return nil")
	}
}

func TestIngestStatic_EmptyFiles(t *testing.T) {
	result := types.NewAnalysisResult("")
	if got := IngestStatic(result); got != nil {
		t.Error("IngestStatic with empty result should return nil")
	}
}

func TestIngestStatic_SecretPattern(t *testing.T) {
	result := types.NewAnalysisResult("")
	result.AddFile("Foo.smali", &types.FileAnalysis{
		Path: "Foo.smali",
		Matches: []types.Match{
			{
				Pattern:    "hardcoded secret",
				Confidence: "high",
				Severity:   types.SeverityHigh,
			},
		},
	})
	signals := IngestStatic(result)
	if len(signals) == 0 {
		t.Fatal("expected at least 1 signal")
	}
	if signals[0].Type != TypeHardcodedSecret {
		t.Errorf("type = %q, want %q", signals[0].Type, TypeHardcodedSecret)
	}
	if signals[0].Confidence != 0.9 {
		t.Errorf("confidence = %f, want 0.9 for high", signals[0].Confidence)
	}
}

func TestIngestStatic_ConfidenceLevels(t *testing.T) {
	cases := []struct {
		confStr string
		want    float64
	}{
		{"high", 0.9},
		{"medium", 0.7},
		{"low", 0.4},
		{"unknown", 0.7}, // default
	}
	for _, c := range cases {
		result := types.NewAnalysisResult("")
		result.AddFile("Foo.smali", &types.FileAnalysis{
			Path: "Foo.smali",
			Matches: []types.Match{
				{Pattern: "hardcoded secret", Confidence: c.confStr},
			},
		})
		signals := IngestStatic(result)
		if len(signals) == 0 {
			t.Fatalf("confidence=%q: expected signal", c.confStr)
		}
		if signals[0].Confidence != c.want {
			t.Errorf("confidence=%q: got %f, want %f", c.confStr, signals[0].Confidence, c.want)
		}
	}
}

func TestIngestStatic_IsCriticalBoost(t *testing.T) {
	result := types.NewAnalysisResult("")
	result.AddFile("Foo.smali", &types.FileAnalysis{
		Path: "Foo.smali",
		Matches: []types.Match{
			{
				Pattern:    "hardcoded secret",
				Confidence: "low",
				Severity:   types.SeverityLow, // severity 3
				IsCritical: true,              // should boost to 7
			},
		},
	})
	signals := IngestStatic(result)
	if len(signals) == 0 {
		t.Fatal("expected a signal")
	}
	if signals[0].Severity < 7 {
		t.Errorf("IsCritical should boost severity to >=7, got %d", signals[0].Severity)
	}
}

func TestIngestStatic_CleartextEndpointReachable(t *testing.T) {
	result := types.NewAnalysisResult("")
	result.AddFile("Foo.smali", &types.FileAnalysis{
		Path: "Foo.smali",
		Matches: []types.Match{
			{Pattern: "cleartext http endpoint", Confidence: "medium"},
		},
	})
	signals := IngestStatic(result)
	if len(signals) == 0 {
		t.Fatal("expected a signal")
	}
	if !signals[0].HasTag(TagReachable) {
		t.Error("cleartext endpoint should have TagReachable")
	}
}

func TestIngestStatic_SkipsUnmappedPatterns(t *testing.T) {
	result := types.NewAnalysisResult("")
	result.AddFile("Foo.smali", &types.FileAnalysis{
		Path: "Foo.smali",
		Matches: []types.Match{
			{Pattern: "something totally random and unrelated"},
		},
	})
	signals := IngestStatic(result)
	if len(signals) != 0 {
		t.Errorf("unmapped pattern should be skipped, got %d signals", len(signals))
	}
}

func TestIngestStatic_ExportedComponent(t *testing.T) {
	result := types.NewAnalysisResult("")
	result.AddFile("AndroidManifest.xml", &types.FileAnalysis{
		Path: "AndroidManifest.xml",
		XMLData: &types.XMLAnalysis{
			Suspicious: []string{"exported activity: com.example.MainActivity"},
		},
	})
	signals := IngestStatic(result)
	if len(signals) == 0 {
		t.Fatal("expected exported_component signal")
	}
	if signals[0].Type != TypeExportedComponent {
		t.Errorf("type = %q, want %q", signals[0].Type, TypeExportedComponent)
	}
	if !signals[0].HasTag(TagExported) {
		t.Error("exported component should have TagExported")
	}
}

// ── markdown.go helpers ───────────────────────────────────────────────────────

func TestRiskEmoji(t *testing.T) {
	cases := []struct {
		risk Risk
		want string
	}{
		{RiskCritical, "🔴"},
		{RiskHigh, "🟠"},
		{RiskMedium, "🟡"},
		{RiskLow, "🟢"},
		{RiskInfo, "⚪"},
	}
	for _, c := range cases {
		if got := riskEmoji(c.risk); got != c.want {
			t.Errorf("riskEmoji(%q) = %q, want %q", c.risk, got, c.want)
		}
	}
}

func TestJoinKinds(t *testing.T) {
	if got := joinKinds(nil); got != "—" {
		t.Errorf("empty should return '—', got %q", got)
	}
	kinds := []SignalKind{KindMemory, KindNetwork}
	got := joinKinds(kinds)
	if !strings.Contains(got, "memory") || !strings.Contains(got, "network") {
		t.Errorf("expected memory and network, got %q", got)
	}
}

func TestFactorsShort(t *testing.T) {
	f := LikelihoodFactors{Reachable: true, Controllable: false, ObservedAtRuntime: true}
	got := factorsShort(f)
	if !strings.Contains(got, "R ✓") {
		t.Errorf("expected 'R ✓' for reachable=true, got %q", got)
	}
	if !strings.Contains(got, "C ·") {
		t.Errorf("expected 'C ·' for controllable=false, got %q", got)
	}
	if !strings.Contains(got, "O ✓") {
		t.Errorf("expected 'O ✓' for observed=true, got %q", got)
	}
}

func TestRenderMarkdown_FindingsSection(t *testing.T) {
	result := &Result{
		GeneratedAt:   time.Now(),
		HasRuntime:    true,
		HasStatic:     true,
		OverallRisk:   RiskHigh,
		OverallLikeli: LikelihoodMedium,
		Findings: []Finding{
			{
				ID:          "f1",
				Title:       "Test Finding",
				Category:    "security_audit",
				Risk:        RiskHigh,
				Likelihood:  LikelihoodMedium,
				Evidence:    []*Signal{{Type: TypeHardcodedSecret, Title: "secret found", PID: 100, Target: "endpoint"}},
				Mitigations: []string{"Rotate the key"},
				Workarounds: []string{"Use canary token"},
				Explanation: "A secret was found.",
			},
		},
	}
	md := RenderMarkdown(result)
	if !strings.Contains(md, "Test Finding") {
		t.Error("expected finding title in markdown")
	}
	if !strings.Contains(md, "Rotate the key") {
		t.Error("expected mitigation in markdown")
	}
	if !strings.Contains(md, "canary token") {
		t.Error("expected workaround in markdown")
	}
}

func TestRenderMarkdown_NilResult(t *testing.T) {
	md := RenderMarkdown(nil)
	if !strings.Contains(md, "No data") {
		t.Errorf("nil result should say 'No data', got %q", md)
	}
}

func TestRenderMarkdown_WithChains(t *testing.T) {
	result := &Result{
		GeneratedAt:   time.Now(),
		OverallRisk:   RiskCritical,
		OverallLikeli: LikelihoodHigh,
		Chains: []AttackChain{
			{
				ID:            "chain-1",
				Name:          "Credential Theft Chain",
				Risk:          RiskCritical,
				Likelihood:    LikelihoodHigh,
				Description:   "A secret exfil chain.",
				Explanation:   "The app embeds secrets.",
				Mitigations:   []string{"Rotate secrets"},
				Workarounds:   []string{"Mock server"},
				InvolvedKinds: []SignalKind{KindAudit, KindNetwork},
				Sequence: []AttackChainStep{
					{Order: 1, Component: "static", Title: "Secret found", Description: "Hardcoded key"},
				},
				Evidence: []*Signal{
					{Type: TypeHardcodedSecret, Title: "API Key"},
				},
				ProcessKey: "static",
			},
		},
	}
	md := RenderMarkdown(result)
	if !strings.Contains(md, "Credential Theft Chain") {
		t.Error("expected chain name")
	}
	if !strings.Contains(md, "Rotate secrets") {
		t.Error("expected chain mitigation")
	}
	if !strings.Contains(md, "Mock server") {
		t.Error("expected chain workaround")
	}
}

func TestRenderMarkdown_Timeline(t *testing.T) {
	ts := time.Now()
	result := &Result{
		GeneratedAt:   ts,
		OverallRisk:   RiskLow,
		OverallLikeli: LikelihoodLow,
		Timeline: []TimelineEvent{
			{Order: 1, Timestamp: ts, ProcessKey: "proc#1", Kind: "network", Title: "Outbound conn", Target: "8.8.8.8:443"},
		},
	}
	md := RenderMarkdown(result)
	if !strings.Contains(md, "Timeline") {
		t.Error("expected Timeline section")
	}
	if !strings.Contains(md, "8.8.8.8:443") {
		t.Error("expected target in timeline")
	}
}

func TestRenderMarkdown_WithNotes(t *testing.T) {
	result := &Result{
		GeneratedAt:   time.Now(),
		Notes:         []string{"Note one", "Note two"},
		OverallRisk:   RiskInfo,
		OverallLikeli: LikelihoodLow,
	}
	md := RenderMarkdown(result)
	if !strings.Contains(md, "Note one") {
		t.Error("expected note in markdown")
	}
}

func TestRenderMarkdown_SessionID(t *testing.T) {
	result := &Result{
		SessionID:     "sess-abc123",
		GeneratedAt:   time.Now(),
		OverallRisk:   RiskInfo,
		OverallLikeli: LikelihoodLow,
	}
	md := RenderMarkdown(result)
	if !strings.Contains(md, "sess-abc123") {
		t.Error("expected session ID in markdown")
	}
}

// ── Engine.Run ────────────────────────────────────────────────────────────────

func TestEngineRun_NilInputs(t *testing.T) {
	engine := NewEngine(nil)
	result := engine.Run(Input{})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.OverallRisk != RiskInfo {
		t.Errorf("empty input should produce RiskInfo, got %s", result.OverallRisk)
	}
}

func TestEngineRun_StaticOnly(t *testing.T) {
	ar := types.NewAnalysisResult("")
	ar.AddFile("Foo.smali", &types.FileAnalysis{
		Path: "Foo.smali",
		Matches: []types.Match{
			{Pattern: "hardcoded secret", Confidence: "high", Severity: types.SeverityHigh},
		},
	})
	engine := NewEngine(nil)
	result := engine.Run(Input{Static: ar})
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Stats.TotalSignals == 0 {
		t.Error("expected at least 1 signal from static analysis")
	}
}
