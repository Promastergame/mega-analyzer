package sastrules

import (
	"fmt"
	"strings"
	"testing"
)

func TestSummarizeFindingsAggregatesAPIInventory(t *testing.T) {
	rep := &Report{Matches: []Match{
		{RuleID: "api_ipc", RuleSet: APIInventorySetName, Title: "Inter Process Communication", Severity: SevInfo, File: "a.smali"},
		{RuleID: "api_ipc", RuleSet: APIInventorySetName, Title: "Inter Process Communication", Severity: SevInfo, File: "b.smali"},
		{RuleID: "api_clipboard", RuleSet: APIInventorySetName, Title: "Set or Read Clipboard data", Severity: SevInfo, File: "b.smali"},
	}}
	out := SummarizeFindings(rep)
	if len(out) != 1 {
		t.Fatalf("expected 1 aggregated entry, got %d: %+v", len(out), out)
	}
	e := out[0]
	if e.Severity != SevInfo || e.Path != "mobsf/SAST_RULES.md" {
		t.Fatalf("unexpected entry: %+v", e)
	}
	if !strings.Contains(e.Reason, "2 Android API categories") || !strings.Contains(e.Reason, "2 files") {
		t.Fatalf("unexpected reason: %q", e.Reason)
	}
}

func TestSummarizeFindingsCapsNoisyRules(t *testing.T) {
	var ms []Match
	for i := 0; i < MaxFindingsPerRule+3; i++ {
		ms = append(ms, Match{
			RuleID:   "android_ip_disclosure",
			RuleSet:  "android_security_rules",
			Title:    "IP Address disclosure",
			Severity: SevMedium,
			File:     fmt.Sprintf("smali/adapter%02d.smali", i),
		})
	}
	ms = append(ms, Match{
		RuleID:   "secret_google_api_key",
		RuleSet:  "secrets_and_crypto_rules",
		Title:    "Hardcoded Google API Key",
		Severity: SevHigh,
		File:     "res/values/strings.xml",
	})
	out := SummarizeFindings(&Report{Matches: ms})
	if len(out) != MaxFindingsPerRule+2 {
		t.Fatalf("expected %d entries, got %d: %+v", MaxFindingsPerRule+2, len(out), out)
	}
	var aggregate *FindingEntry
	perFile := 0
	for i := range out {
		if strings.Contains(out[i].Reason, "more file(s)") {
			aggregate = &out[i]
			continue
		}
		if out[i].Reason == "[android_ip_disclosure] IP Address disclosure" {
			perFile++
		}
	}
	if perFile != MaxFindingsPerRule {
		t.Fatalf("expected %d per-file entries, got %d", MaxFindingsPerRule, perFile)
	}
	if aggregate == nil || !strings.Contains(aggregate.Reason, "+3 more file(s)") || aggregate.Severity != SevMedium {
		t.Fatalf("bad aggregate entry: %+v", aggregate)
	}
}

func TestSummarizeFindingsEmpty(t *testing.T) {
	if got := SummarizeFindings(nil); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
	if got := SummarizeFindings(&Report{}); got != nil {
		t.Fatalf("expected nil, got %+v", got)
	}
}

func TestIPDisclosureVersionAndLoopbackSkipped(t *testing.T) {
	eng, err := NewEngineFromEmbedded()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	var rule *compiledRule
	for i := range eng.rules {
		if eng.rules[i].src.ID == ipDisclosureRuleID {
			rule = &eng.rules[i]
			break
		}
	}
	if rule == nil {
		t.Fatal("android_ip_disclosure rule not found")
	}

	version := []byte(".method public getAdapterVersion()Ljava/lang/String;\n    const-string v0, \"4.5.2.1\"\n    return-object v0\n.end method\n")
	if rule.match(version) {
		t.Fatal("SDK version string was flagged as IP disclosure")
	}

	loopback := []byte("    const-string v0, \"127.0.0.1\"\n")
	if rule.match(loopback) {
		t.Fatal("loopback address was flagged")
	}

	real := []byte(".method private connect()V\n    const-string v0, \"http://185.220.101.34/gate.php\"\n.end method\n")
	if !rule.match(real) {
		t.Fatal("real hardcoded IP was not flagged")
	}
	line, _, snippet := firstHit(rule, real)
	if line != 2 || !strings.Contains(snippet, "185.220.101.34") {
		t.Fatalf("unexpected hit: line=%d snippet=%q", line, snippet)
	}
}
