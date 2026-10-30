package correlation

import "testing"

func TestAdjustRisk_HardcodedSecretWithRuntimeNetwork(t *testing.T) {
	primary := &Signal{Type: TypeHardcodedSecret, Kind: KindAudit, Severity: 5}
	support := []*Signal{
		{Type: TypeOutboundConnection, Kind: KindNetwork, Severity: 5},
	}
	got := AdjustRisk(BaseRiskFromSeverity(primary.Severity), primary, support)
	if got != RiskHigh {
		t.Fatalf("hardcoded secret + runtime network should be HIGH, got %s", got)
	}
}

func TestAdjustRisk_HardcodedSecretAlone(t *testing.T) {
	primary := &Signal{Type: TypeHardcodedSecret, Kind: KindAudit, Severity: 3}
	got := AdjustRisk(BaseRiskFromSeverity(primary.Severity), primary, nil)
	if got != RiskMedium {
		t.Fatalf("hardcoded secret alone should be MEDIUM, got %s", got)
	}
}

func TestAdjustRisk_CleartextEndpointDormant(t *testing.T) {
	primary := &Signal{Type: TypeCleartextEndpoint, Kind: KindAudit, Severity: 7}
	got := AdjustRisk(BaseRiskFromSeverity(primary.Severity), primary, nil)
	if got.Rank() > RiskMedium.Rank() {
		t.Fatalf("dormant cleartext endpoint should not exceed MEDIUM, got %s", got)
	}
}

func TestAdjustRisk_CleartextEndpointWithRuntime(t *testing.T) {
	primary := &Signal{Type: TypeCleartextEndpoint, Kind: KindAudit, Severity: 5}
	support := []*Signal{
		{Type: TypePublicEgress, Kind: KindNetwork, Severity: 5},
	}
	got := AdjustRisk(BaseRiskFromSeverity(primary.Severity), primary, support)
	if got != RiskHigh {
		t.Fatalf("cleartext endpoint + runtime network should be HIGH, got %s", got)
	}
}

func TestAdjustRisk_DebugEndpointUnreached(t *testing.T) {
	primary := &Signal{Type: TypeDebugEndpoint, Kind: KindAudit, Severity: 7}
	got := AdjustRisk(BaseRiskFromSeverity(primary.Severity), primary, nil)
	if got.Rank() > RiskMedium.Rank() {
		t.Fatalf("dormant debug endpoint should not exceed MEDIUM, got %s", got)
	}
}

func TestAdjustRisk_DebugEndpointReachable(t *testing.T) {
	primary := &Signal{Type: TypeDebugEndpoint, Kind: KindAudit, Severity: 5}
	support := []*Signal{
		{Type: "x", Kind: KindAudit, Tags: []string{TagExported}},
	}
	got := AdjustRisk(BaseRiskFromSeverity(primary.Severity), primary, support)
	if got != RiskHigh {
		t.Fatalf("debug endpoint + exported should be HIGH, got %s", got)
	}
}

func TestAdjustRisk_WebViewBridgeWithoutRemoteContent(t *testing.T) {
	primary := &Signal{Type: TypeWebViewJSBridge, Kind: KindAudit, Severity: 7}
	got := AdjustRisk(BaseRiskFromSeverity(primary.Severity), primary, nil)
	if got.Rank() > RiskMedium.Rank() {
		t.Fatalf("WebView bridge without remote content should cap at MEDIUM, got %s", got)
	}
}

func TestAdjustRisk_WebViewBridgeWithRemoteContent(t *testing.T) {
	primary := &Signal{Type: TypeWebViewJSBridge, Kind: KindAudit, Severity: 5}
	support := []*Signal{
		{Type: TypeOutboundConnection, Kind: KindNetwork},
	}
	got := AdjustRisk(BaseRiskFromSeverity(primary.Severity), primary, support)
	if got != RiskHigh {
		t.Fatalf("WebView bridge + remote content should be HIGH, got %s", got)
	}
}

func TestBaseRiskFromSeverity(t *testing.T) {
	cases := []struct {
		sev  int
		want Risk
	}{
		{0, RiskInfo},
		{2, RiskLow},
		{5, RiskMedium},
		{7, RiskHigh},
		{9, RiskCritical},
		{10, RiskCritical},
	}
	for _, c := range cases {
		got := BaseRiskFromSeverity(c.sev)
		if got != c.want {
			t.Fatalf("severity=%d -> %s, want %s", c.sev, got, c.want)
		}
	}
}
