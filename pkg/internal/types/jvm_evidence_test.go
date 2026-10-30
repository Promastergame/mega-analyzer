package types

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestArtifactFindingPreservesJVMEvidence(t *testing.T) {
	value := ArtifactFinding{Path: "app.jar", Severity: SeverityHigh, JVMEvidence: &Match{MethodName: "run", SourceLocation: SourceLocation{File: "demo/App.class", Method: "run()V"}, EvidenceType: "bytecode_invocation", Metadata: map[string]string{"bytecode_offset": "12", "execution_proven": "false"}}}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"jvm_evidence"`, `"method_name":"run"`, `"bytecode_offset":"12"`, `"execution_proven":"false"`} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing %s in %s", want, data)
		}
	}
}
