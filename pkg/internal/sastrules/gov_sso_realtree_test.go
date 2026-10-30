package sastrules

import (
	"os"
	"testing"
)

// TestGovSSO_RealTreeScan runs the gov-SSO ruleset against a real decoded APK
// tree. Opt-in via GOVSso_TREE so CI never depends on external data.
func TestGovSSO_RealTreeScan(t *testing.T) {
	tree := os.Getenv("GOVSso_TREE")
	if tree == "" {
		t.Skip("GOVSso_TREE not set")
	}
	eng, err := NewEngineFromEmbedded()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	rep, err := eng.Scan(tree)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	counts := map[string]int{}
	for _, m := range rep.Matches {
		counts[m.RuleID]++
	}
	t.Logf("total matches: %d (files scanned: %d, bytes: %d)", len(rep.Matches), rep.FilesScanned, rep.BytesScanned)
	for id, n := range counts {
		t.Logf("  %-32s %d", id, n)
	}
	for _, want := range []string{"webview_ssl_bypass_proceed", "govsso_endpoint_reference", "oauth_uuid_pair_hardcoded"} {
		if counts[want] == 0 {
			t.Errorf("expected at least one %s hit on real tree", want)
		}
	}
}
