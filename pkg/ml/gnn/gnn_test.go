package gnn

import "testing"

func TestGNNFindingStruct(t *testing.T) {
	finding := GNNFinding{
		Method:     "Lcom/app/MyClass;->check()V",
		FilePath:   "path/to/MyClass.java",
		VulnClass:  "license-bypass",
		Confidence: 0.95,
		ClassProbs: map[string]float32{
			"license-bypass": 0.95,
			"injection":      0.05,
		},
	}

	if finding.Method != "Lcom/app/MyClass;->check()V" {
		t.Errorf("Expected Method match, got %s", finding.Method)
	}
	if finding.Confidence != 0.95 {
		t.Errorf("Expected Confidence 0.95, got %f", finding.Confidence)
	}
}
