package report

import "testing"

// Inventory-grade observations (a standalone numeric literal with no
// credential context) must not display the "Derived Exploit Payload" block:
// the masked digits dress a build constant up as an exploit primitive.
func TestShowsArtifactPayload(t *testing.T) {
	inventoryPin := ArtifactFindingView{
		Payload: "********",
		Stages:  []string{"native", "secret", "numeric-pin", "inventory"},
	}
	if showsArtifactPayload(inventoryPin) {
		t.Error("inventory-grade numeric PIN must not show the payload block")
	}

	confirmedSecret := ArtifactFindingView{
		Payload: "********",
		Stages:  []string{"native", "secret", "llmkeys"},
	}
	if !showsArtifactPayload(confirmedSecret) {
		t.Error("a candidate credential keeps its masked payload block")
	}

	if showsArtifactPayload(ArtifactFindingView{Stages: []string{"native"}}) {
		t.Error("findings without a payload show no payload block")
	}
}
