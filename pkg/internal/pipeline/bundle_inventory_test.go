package pipeline

import (
	"mega-analyzer/pkg/internal/finding"
	"mega-analyzer/pkg/internal/types"
	"testing"
)

func TestBundleInventoryIsNotVulnerability(t *testing.T) {
	artifact := types.ArtifactFinding{Path: "index.android.bundle", Severity: types.SeverityInfo, Reason: "URL reference", Payload: "https://docs.example.org", Stages: []string{"hermes", "endpoint", "inventory"}}
	f := typedFindingFromArtifact(artifact)
	if f.Kind != finding.KindInventory {
		t.Fatalf("%+v", f)
	}
	artifact.Stages = []string{"hermes", "secret"}
	artifact.Severity = types.SeverityHigh
	if typedFindingFromArtifact(artifact).Kind != finding.KindVulnerability {
		t.Fatal("must retain risk detector classification")
	}
}
