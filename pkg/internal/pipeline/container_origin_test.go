package pipeline

import (
	"testing"

	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/rating"
	"mega-analyzer/pkg/internal/types"
)

func TestUnknownContainerOriginDoesNotClaimVulnerability(t *testing.T) {
	flow := types.DataFlowFinding{Source: "[unverified container origin] Landroid/os/Bundle;->getParcelable(Ljava/lang/String;)Landroid/os/Parcelable;", Sink: "Landroid/content/Context;->bindService", Category: "intent_redirection", Severity: "high", Confidence: 0.96}
	item := typedFindingFromDataFlow(flow, nil)
	if item.Kind != finding.KindInventory || item.Severity != "info" || item.Explanation.Status != "unverified_input_origin" {
		t.Fatalf("%+v", item)
	}
	r := &types.AnalysisResult{Findings: []finding.Finding{item}}
	if rating.ComputeResultProfile(r).OverallScore != 0 {
		t.Fatal("unknown-origin observation inflated risk")
	}
	flow.Source = "Landroid/content/Intent;->getParcelableExtra"
	item = typedFindingFromDataFlow(flow, nil)
	if item.Kind != finding.KindVulnerability || item.Severity != "high" {
		t.Fatalf("external flow suppressed: %+v", item)
	}
}
